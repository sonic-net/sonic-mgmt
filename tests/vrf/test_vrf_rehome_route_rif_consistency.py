"""Route/RIF VRF consistency across an interface VRF rehome.

A route for VRF X must never resolve through a RIF of another VRF, and a rehome
must never be silently lost.
"""

import json
import logging
import re
import time
from datetime import datetime

import pytest
from natsort import natsorted

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
]

VRF_A = "Vrf_rehome_a"
DEFAULT_VRF = None

STANDING_ROUTES = {
    DEFAULT_VRF: "192.0.2.0/24",
    VRF_A: "198.51.100.0/25",
}

LL_NEIGH_COUNT = 8
LL_NEIGH_PREFIX = "fe80::a:"

AUDIT_PREFIXES = sorted(STANDING_ROUTES.values())

ASIC_ROUTE_TBL = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY"
ASIC_RIF_TBL = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE"
ASIC_VR_TBL = "ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER"

SWSS_REC = "/var/log/swss/swss.rec"

MAX_ITERATIONS = 20
ITERATION_LEVEL_MAP = {"debug": 2, "basic": 8, "confident": 14, "thorough": 20}

CMD_TIMEOUT = 60
SETTLE_TIMEOUT = 60
ITERATION_BUDGET = 150

WEDGE_PATTERN = "still referenced"


def parse_asic_route_key(key):
    parts = key.split(":", 2)
    if len(parts) != 3 or parts[1] != "SAI_OBJECT_TYPE_ROUTE_ENTRY":
        return None
    try:
        entry = json.loads(parts[2])
    except ValueError:
        return None
    dest, vr = entry.get("dest"), entry.get("vr")
    if not dest or not vr:
        return None
    return dest, vr


def parse_rif_map_line(line):
    fields = line.strip().split("|")
    if len(fields) != 3 or not fields[0].startswith(ASIC_RIF_TBL + ":"):
        return None
    rif_oid = fields[0].split(ASIC_RIF_TBL + ":", 1)[1]
    return rif_oid, fields[1].strip(), fields[2].strip()


def parse_swss_rec_line(line):
    parts = line.strip().split("|")
    if len(parts) < 3:
        return None
    try:
        ts = datetime.strptime(parts[0], "%Y-%m-%d.%H:%M:%S.%f")
    except ValueError:
        return None
    op = parts[2].strip().upper()
    if op not in ("SET", "DEL"):
        return None
    epoch = time.mktime(ts.timetuple()) + ts.microsecond / 1e6
    return epoch, parts[1].strip(), op


def appl_route_key(vrf_name, prefix):
    if vrf_name is DEFAULT_VRF:
        return "ROUTE_TABLE:{}".format(prefix)
    return "ROUTE_TABLE:{}:{}".format(vrf_name, prefix)


def analyze_rehome_window(lines, port, target_route_key):
    intf_key = "INTF_TABLE:{}".format(port)
    result = {"intf_del_seen": False, "intf_del_ts": None, "intf_set_ts": None,
              "del_to_set_ms": None, "target_route_ts": None,
              "route_vs_intf_del_ms": None}
    set_ts_list = []
    for line in lines:
        parsed = parse_swss_rec_line(line)
        if not parsed:
            continue
        ts, table_key, op = parsed
        if table_key == intf_key:
            if op == "DEL":
                result["intf_del_seen"] = True
                if result["intf_del_ts"] is None:
                    result["intf_del_ts"] = ts
            else:
                set_ts_list.append(ts)
        elif table_key == target_route_key and op == "SET":
            if result["target_route_ts"] is None:
                result["target_route_ts"] = ts
    if result["intf_del_ts"] is not None:
        later = [t for t in set_ts_list if t >= result["intf_del_ts"]]
        result["intf_set_ts"] = later[0] if later else None
    elif set_ts_list:
        result["intf_set_ts"] = set_ts_list[0]
    if result["intf_del_ts"] is not None and result["target_route_ts"] is not None:
        result["route_vs_intf_del_ms"] = round(
            (result["target_route_ts"] - result["intf_del_ts"]) * 1000.0, 3)
    if result["intf_del_ts"] is not None and result["intf_set_ts"] is not None:
        result["del_to_set_ms"] = round(
            (result["intf_set_ts"] - result["intf_del_ts"]) * 1000.0, 3)
    return result


def link_local_neighbors():
    return [("{}{}".format(LL_NEIGH_PREFIX, i), "00:11:22:33:44:{:02x}".format(i))
            for i in range(1, LL_NEIGH_COUNT + 1)]


def normalize_iterations(completeness_level):
    level = completeness_level if completeness_level else "basic"
    return min(ITERATION_LEVEL_MAP.get(level, ITERATION_LEVEL_MAP["basic"]),
               MAX_ITERATIONS)


def summarize_margins(margins):
    clean = [m for m in margins if m is not None]
    if not clean:
        return {"samples": 0, "min_ms": None, "median_ms": None, "negative": 0}
    ordered = sorted(clean)
    return {"samples": len(ordered), "min_ms": ordered[0],
            "median_ms": ordered[len(ordered) // 2],
            "negative": len([m for m in ordered if m < 0])}


def _shell(duthost, cmd):
    return duthost.shell(cmd, module_ignore_errors=True).get("stdout", "").strip()


def _run(duthost, cmd, timeout=CMD_TIMEOUT):
    return duthost.shell("timeout {} {}".format(timeout, cmd), module_ignore_errors=True)


def _asic_keys(duthost, pattern):
    out = duthost.shell("sonic-db-cli ASIC_DB KEYS '{}'".format(pattern),
                        module_ignore_errors=True)
    return [ln for ln in out.get("stdout_lines") or [] if ln.startswith("ASIC_STATE:")]


def _hget(duthost, key, field):
    return _shell(duthost, "sonic-db-cli ASIC_DB HGET '{}' {}".format(key, field))


def _vr_oids(duthost):
    return set(k.split(":", 2)[2] for k in _asic_keys(duthost, ASIC_VR_TBL + ":*"))


def _route_keys_by_dest(duthost, prefix):
    return _asic_keys(duthost, '{}:*"dest":"{}"*'.format(ASIC_ROUTE_TBL, prefix))


def _find_route_key(duthost, vr_oid, prefix):
    for key in _route_keys_by_dest(duthost, prefix):
        parsed = parse_asic_route_key(key)
        if parsed and parsed[0] == prefix and parsed[1] == vr_oid:
            return key
    return None


def _rif_map(duthost):
    # </dev/null keeps the inner redis-cli calls from draining the while-read loop's stdin.
    cmd = ("redis-cli -n 1 --raw KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*' | "
           "while read k; do "
           "echo \"$k|$(redis-cli -n 1 --raw HGET \"$k\" SAI_ROUTER_INTERFACE_ATTR_PORT_ID "
           "</dev/null)|$(redis-cli -n 1 --raw HGET \"$k\" "
           "SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID </dev/null)\"; "
           "done")
    out = duthost.shell(cmd, module_ignore_errors=True)
    rifs = {}
    for line in out.get("stdout_lines") or []:
        parsed = parse_rif_map_line(line)
        if parsed:
            rifs[parsed[0]] = (parsed[1], parsed[2])
    return rifs


def _port_rif(duthost, port_oid):
    for rif_oid, (rif_port, vr) in _rif_map(duthost).items():
        if rif_port == port_oid:
            return rif_oid, vr
    return None


def _port_oid(duthost, port):
    return _shell(duthost, "sonic-db-cli COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP {}".format(port))


def _route_consistent(duthost, vr_oid, prefix):
    route_key = _find_route_key(duthost, vr_oid, prefix)
    if route_key is None:
        return False
    nh = _hget(duthost, route_key, "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID")
    rifs = _rif_map(duthost)
    if nh not in rifs:
        return False
    return rifs[nh][1] == vr_oid


def _audit_route_rif_consistency(duthost):
    violations = []
    rifs = _rif_map(duthost)
    for prefix in AUDIT_PREFIXES:
        for key in _route_keys_by_dest(duthost, prefix):
            parsed = parse_asic_route_key(key)
            if not parsed or parsed[0] != prefix:
                continue
            _, route_vr = parsed
            nh = _hget(duthost, key, "SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID")
            if nh in rifs and rifs[nh][1] != route_vr:
                violations.append({"route_key": key, "route_vr": route_vr,
                                   "next_hop_id": nh, "rif_vr": rifs[nh][1],
                                   "rif_port": rifs[nh][0]})
    return violations


def _oper_up(duthost, port):
    return duthost.get_interfaces_status().get(port, {}).get("oper") == "up"


def _orchagent_pid(duthost):
    return _shell(duthost, "pgrep -x orchagent | head -n 1")


def _dut_health(duthost, expected_orch_pid):
    out = _shell(duthost,
                 "timeout 20 bash -c 'pgrep -x orchagent | head -n 1; "
                 "docker inspect -f {{.State.Running}} swss 2>/dev/null; "
                 "sonic-db-cli APPL_DB PING 2>/dev/null'")
    lines = [ln.strip() for ln in out.splitlines()]
    if len(lines) < 3:
        return False, "health probe returned {!r}".format(out)
    pid, swss_running, redis_ping = lines[0], lines[1], lines[2]
    if pid != expected_orch_pid:
        return False, "orchagent PID changed {} -> {}".format(expected_orch_pid, pid)
    if swss_running != "true":
        return False, "swss container not running: {}".format(swss_running)
    if redis_ping.upper() not in ("PONG", "TRUE"):
        return False, "APPL_DB redis not answering: {}".format(redis_ping)
    return True, ""


def _wedge_count(duthost):
    out = _shell(duthost, "grep -ac '{}' /var/log/syslog".format(WEDGE_PATTERN))
    try:
        return int(out)
    except ValueError:
        return 0


def _swss_rec_offset(duthost):
    out = _shell(duthost, "wc -l < {} 2>/dev/null".format(SWSS_REC))
    try:
        return int(out)
    except ValueError:
        return 0


def _swss_rec_stable_offset(duthost):
    prev = _swss_rec_offset(duthost)
    deadline = time.time() + 6
    while time.time() < deadline:
        time.sleep(1)
        cur = _swss_rec_offset(duthost)
        if cur == prev:
            return cur
        prev = cur
    return prev


def _swss_rec_window(duthost, start_line, port):
    current = _swss_rec_offset(duthost)
    start = start_line if current >= start_line else 0
    pattern = "INTF_TABLE:{}|ROUTE_TABLE:".format(re.escape(port))
    out = duthost.shell("tail -n +{} {} 2>/dev/null | grep -aE '{}'".format(
        start + 1, SWSS_REC, pattern), module_ignore_errors=True)
    return out.get("stdout_lines") or []


def _vtysh(duthost, config_cmds, timeout=CMD_TIMEOUT):
    cmd = "docker exec bgp vtysh -c 'configure terminal' {}".format(
        " ".join("-c '{}'".format(c) for c in config_cmds))
    return _run(duthost, cmd, timeout=timeout)


def _set_standing_route(duthost, vrf_name, prefix, port, remove=False):
    no = "no " if remove else ""
    route = "{}ip route {} {}".format(no, prefix, port)
    if vrf_name is DEFAULT_VRF:
        res = _vtysh(duthost, [route])
    else:
        res = _vtysh(duthost, ["vrf {}".format(vrf_name), route, "exit-vrf"])
    return res.get("rc", 1) == 0


def _ensure_l3_port(duthost, port):
    # Addressless on purpose: no connected route, so the only rehome ROUTE_TABLE
    # traffic is the standing route the kernel VRF move activates.
    return duthost.shell(
        "sonic-db-cli CONFIG_DB HSET 'INTERFACE|{}' NULL NULL".format(port),
        module_ignore_errors=True)


def _enable_link_local_only(duthost, port):
    return _run(duthost, "config interface ipv6 enable use-link-local-only {}".format(port))


def _populate_link_local_neighbors(duthost, port):
    adds = "; ".join(
        "ip -6 neigh replace {} lladdr {} dev {} nud permanent 2>/dev/null".format(ip, mac, port)
        for ip, mac in link_local_neighbors())
    duthost.shell("{}; true".format(adds), module_ignore_errors=True)
    return _shell(duthost, "sonic-db-cli APPL_DB KEYS 'NEIGH_TABLE:{}:{}*' | wc -l".format(
        port, LL_NEIGH_PREFIX))


def _rehome(duthost, port, vrf_name):
    if vrf_name is DEFAULT_VRF:
        res = _run(duthost, "config interface vrf unbind {}".format(port), timeout=120)
        if res.get("rc", 1) != 0:
            return False, "vrf unbind rc={} stderr={}".format(res.get("rc"), res.get("stderr", ""))
        _ensure_l3_port(duthost, port)
        return True, ""
    res = _run(duthost, "config interface vrf bind {} {}".format(port, vrf_name))
    if res.get("rc", 1) != 0:
        return False, "vrf bind rc={} stderr={}".format(res.get("rc"), res.get("stderr", ""))
    return True, ""


@pytest.fixture(scope="module")
def rehome_duthost(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    # NOT named `duthost`: a module-scoped shadow of the session-scoped `duthost`
    # fixture makes session autouse fixtures fail with ScopeMismatch.
    return duthosts[enum_rand_one_per_hwsku_frontend_hostname]


@pytest.fixture(scope="module")
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="module")
def rehome_env(rehome_duthost):
    duthost = rehome_duthost
    pytest_assert(not duthost.is_multi_asic,
                  "The t0 regression job must use a single-ASIC DUT")
    pytest_assert(duthost.shell("docker exec bgp vtysh -c 'show version'",
                                module_ignore_errors=True)["rc"] == 0,
                  "vtysh in the bgp container is required")
    for prefix in AUDIT_PREFIXES:
        pytest_assert(not _route_keys_by_dest(duthost, prefix),
                      "Prefix {} already present in ASIC_DB".format(prefix))
    pytest_assert(
        _shell(duthost, "sonic-db-cli CONFIG_DB EXISTS 'VRF|{}'".format(VRF_A)) == "0",
        "VRF {} already exists on the DUT".format(VRF_A))

    pytest_assert(_shell(duthost, "test -f {} && echo yes".format(SWSS_REC)) == "yes",
                  "swss.rec recording is required for the ordering telemetry")

    cfg = json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])
    used = set()
    for tbl in ("PORTCHANNEL_MEMBER", "VLAN_MEMBER"):
        used.update(k.split("|")[1] for k in cfg.get(tbl, {}))
    used.update(k.split("|")[0] for k in cfg.get("INTERFACE", {}))
    used.update(k.split("|")[0].split(".")[0] for k in cfg.get("VLAN_SUB_INTERFACE", {}))
    mux_ports = set(cfg.get("MUX_CABLE", {}))
    used.update(mux_ports)
    interface_status = duthost.get_interfaces_status()
    free = [p for p in natsorted(cfg.get("PORT", {}))
            if p not in used and interface_status.get(p, {}).get("oper") == "up"]
    untagged = natsorted(
        (k.split("|")[0].replace("Vlan", ""), k.split("|")[1])
        for k, v in cfg.get("VLAN_MEMBER", {}).items()
        if v.get("tagging_mode") == "untagged"
        and k.split("|")[1].startswith("Ethernet")
        and k.split("|")[1] not in mux_ports
        and interface_status.get(k.split("|")[1], {}).get("oper") == "up")

    env = {"port": None, "restore_vlan": None,
           "baseline_vrs": _vr_oids(duthost), "orch_pid": _orchagent_pid(duthost)}

    try:
        pytest_assert(env["orch_pid"], "orchagent is not running")
        port = free[0] if free else None
        if port is not None and not _oper_up(duthost, port):
            port = None
        if port is None and untagged:
            vlan_id, member = untagged[0]
            logger.warning("No usable unused port; temporarily removing %s from "
                           "Vlan%s (restored in teardown)", member, vlan_id)
            res = _run(duthost, "config vlan member del {} {}".format(vlan_id, member))
            pytest_assert(res.get("rc") == 0,
                          "Could not free VLAN member {}".format(member))
            env["restore_vlan"] = (vlan_id, member)
            env["port"] = member
            pytest_assert(wait_until(15, 3, 0, lambda: _oper_up(duthost, member)),
                          "Freed VLAN member {} is not oper-up in SONiC".format(member))
            port = member
        pytest_assert(port is not None,
                      "No oper-up front-panel port is available for the mandatory t0 rehome test "
                      "(unused candidates: {}, untagged VLAN members: {})"
                      .format(len(free), len(untagged)))
        env["port"] = port
        _ensure_l3_port(duthost, port)
        env["port_oid"] = _port_oid(duthost, port)
        pytest_assert(env["port_oid"].startswith("oid:"),
                      "No port OID for {} in COUNTERS_PORT_NAME_MAP".format(port))
        pytest_assert(
            wait_until(SETTLE_TIMEOUT, 2, 0,
                       lambda: _port_rif(duthost, env["port_oid"]) is not None),
            "RIF for {} never appeared in ASIC_DB".format(port))
        env["default_vr"] = _port_rif(duthost, env["port_oid"])[1]

        known = _vr_oids(duthost)
        res = _run(duthost, "config vrf add {}".format(VRF_A))
        pytest_assert(res.get("rc") == 0, "config vrf add {} failed".format(VRF_A))
        found = {}

        def _vr_created():
            diff = _vr_oids(duthost) - known
            if len(diff) == 1:
                found["oid"] = next(iter(diff))
                return True
            return False

        pytest_assert(wait_until(SETTLE_TIMEOUT, 2, 0, _vr_created),
                      "Virtual router for {} not created".format(VRF_A))
        env["vr_a"] = found["oid"]

        for vrf_name, prefix in STANDING_ROUTES.items():
            pytest_assert(_set_standing_route(duthost, vrf_name, prefix, port),
                          "Failed to configure standing route {} in {}".format(
                              prefix, vrf_name or "default VRF"))
        pytest_assert(
            wait_until(SETTLE_TIMEOUT, 3, 0,
                       lambda: _route_consistent(duthost, env["default_vr"],
                                                 STANDING_ROUTES[DEFAULT_VRF])),
            "Default-VRF standing route {} was never programmed consistently; the "
            "ordering measurement would be blind".format(STANDING_ROUTES[DEFAULT_VRF]))

        logger.info("rehome_env: port=%s port_oid=%s default_vr=%s vr_a=%s",
                    port, env["port_oid"], env["default_vr"], env["vr_a"])
        yield env
    finally:
        _teardown(duthost, env)


def _teardown(duthost, env):
    port = env.get("port")
    if port is None:
        return
    # Withdraw routes before the unbind: releasing the RouteOrch refs that pin a
    # RIF lets a wedged rehome (the failure under test) unwedge and complete.
    for vrf_name, prefix in STANDING_ROUTES.items():
        _set_standing_route(duthost, vrf_name, prefix, port, remove=True)
    for ip, _mac in link_local_neighbors():
        duthost.shell("ip -6 neigh del {} dev {} 2>/dev/null; true".format(ip, port),
                      module_ignore_errors=True)
    _run(duthost, "config interface vrf unbind {}".format(port), timeout=120)
    _shell(duthost, "sonic-db-cli CONFIG_DB DEL 'INTERFACE|{}'".format(port))
    _run(duthost, "config vrf del {}".format(VRF_A))

    def _converged():
        port_oid = env.get("port_oid", "")
        rif_gone = (not port_oid.startswith("oid:")
                    or _port_rif(duthost, port_oid) is None)
        routes_gone = all(not _route_keys_by_dest(duthost, p) for p in AUDIT_PREFIXES)
        return (rif_gone and routes_gone
                and _vr_oids(duthost) == env["baseline_vrs"])

    if not wait_until(120, 5, 0, _converged):
        logger.warning("Targeted cleanup did not converge; falling back to config_reload")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True,
                      wait_for_bgp=True)
    if env.get("restore_vlan"):
        vlan_id, member = env["restore_vlan"]
        _run(duthost, "config vlan member add {} {} -u".format(vlan_id, member))
        if not wait_until(30, 3, 0, lambda: _shell(
                duthost, "sonic-db-cli CONFIG_DB EXISTS 'VLAN_MEMBER|Vlan{}|{}'".format(
                    vlan_id, member)) == "1"):
            logger.error("VLAN member %s was not restored to Vlan%s; the testbed "
                         "needs manual attention", member, vlan_id)
    try:
        wait_critical_processes(duthost)
    except Exception as err:
        logger.error("Critical processes unhealthy after cleanup: %s", err)


def _expected_vr(env, vrf_name):
    if vrf_name is DEFAULT_VRF:
        return env["default_vr"]
    return env["vr_a"]


def _vrf_label(vrf_name):
    return vrf_name if vrf_name is not DEFAULT_VRF else "the default VRF"


def _fail_with_evidence(duthost, env, label, details, analysis):
    violations = _audit_route_rif_consistency(duthost)
    wedge = _shell(duthost, "grep -a '{}' /var/log/syslog | tail -n 5".format(WEDGE_PATTERN))
    rec = _shell(duthost, "grep -aE '{}' /var/log/swss/sairedis.rec 2>/dev/null | tail -n 5"
                 .format("|".join(re.escape(p) for p in AUDIT_PREFIXES)))
    rif = _port_rif(duthost, env["port_oid"])
    pytest.fail(
        "{} \n{}\nviolations={}\nport_rif={}\n"
        "ordering analysis={}\nwedge logs:\n{}\nsairedis.rec:\n{}".format(
            label, details, violations, rif, analysis, wedge, rec))


def _converge_rehome(duthost, env, target_vrf):
    vr = _expected_vr(env, target_vrf)
    others = [(v, p) for v, p in STANDING_ROUTES.items() if v != target_vrf]
    conditions = [
        ("RIF in {}".format(_vrf_label(target_vrf)),
         lambda: (_port_rif(duthost, env["port_oid"]) or (None, None))[1] == vr),
        ("standing {} consistent".format(STANDING_ROUTES[target_vrf]),
         lambda: _route_consistent(duthost, vr, STANDING_ROUTES[target_vrf])),
        ("standing routes of other VRFs withdrawn",
         lambda: not any(_route_keys_by_dest(duthost, p) for _v, p in others)),
    ]
    for name, cond in conditions:
        if not wait_until(SETTLE_TIMEOUT, 3, 0, cond):
            return False, "did not converge: {}".format(name)
    return True, ""


def _rehome_iteration(duthost, env, target_vrf):
    port = env["port"]
    stats = {"target": target_vrf or "default"}

    _enable_link_local_only(duthost, port)
    stats["ll_neighbors"] = _populate_link_local_neighbors(duthost, port)

    rec_start = _swss_rec_stable_offset(duthost)
    wedge_before = _wedge_count(duthost)
    started = time.time()
    target_key = appl_route_key(target_vrf, STANDING_ROUTES[target_vrf])

    ok, detail = _rehome(duthost, port, target_vrf)
    if not ok:
        window = _swss_rec_window(duthost, rec_start, port)
        _classify_anomaly(duthost, env, target_vrf, detail, window, target_key)
    early = _audit_route_rif_consistency(duthost)
    if early:
        window = _swss_rec_window(duthost, rec_start, port)
        _fail_with_evidence(
            duthost, env, "VRF rehome race reproduced: stale cross-VR route",
            "audit found route/RIF VR mismatches immediately after the rehome",
            analyze_rehome_window(window, port, target_key))
    converged, detail = _converge_rehome(duthost, env, target_vrf)
    if not converged:
        window = _swss_rec_window(duthost, rec_start, port)
        _classify_anomaly(duthost, env, target_vrf, detail, window, target_key)

    violations = _audit_route_rif_consistency(duthost)
    if violations:
        window = _swss_rec_window(duthost, rec_start, port)
        _fail_with_evidence(
            duthost, env, "VRF rehome race reproduced: stale cross-VR route",
            "converged checks passed but the audit found route/RIF VR mismatches",
            analyze_rehome_window(window, port, target_key))

    healthy, reason = _dut_health(duthost, env["orch_pid"])
    if not healthy:
        pytest.fail("DUT unhealthy after rehome to {}: {} — stopping the "
                    "stress immediately".format(_vrf_label(target_vrf), reason))

    window = _swss_rec_window(duthost, rec_start, port)
    stats.update(analyze_rehome_window(window, port, target_key))
    stats["wedge_transients"] = max(0, _wedge_count(duthost) - wedge_before)
    stats["elapsed_s"] = round(time.time() - started, 1)
    return stats


def _classify_anomaly(duthost, env, target_vrf, detail, window_lines, target_key):
    analysis = analyze_rehome_window(window_lines, env["port"], target_key)
    violations = _audit_route_rif_consistency(duthost)
    rif = _port_rif(duthost, env["port_oid"])
    expected_vr = _expected_vr(env, target_vrf)
    if violations:
        _fail_with_evidence(duthost, env,
                            "VRF rehome race reproduced: stale cross-VR route",
                            detail, analysis)
    if analysis["intf_del_seen"] is False and analysis["intf_set_ts"] is not None:
        _fail_with_evidence(
            duthost, env,
            "VRF rehome race reproduced: rehome silently lost (INTF_TABLE DEL was "
            "never consumed, so IntfsOrch saw only a bare SET and ignored the "
            "vrf_name change)", detail, analysis)
    if rif is not None and rif[1] != expected_vr:
        _fail_with_evidence(
            duthost, env,
            "VRF rehome race reproduced: rehome lost (RIF still in VR {} after the "
            "transition)".format(rif[1]), detail, analysis)
    pytest.fail("Test machinery failure (not the race under test): rehome to {} {} "
                "without any race signature (analysis={})".format(
                    _vrf_label(target_vrf), detail, analysis))


def test_vrf_rehome_baseline_converges_consistently(rehome_duthost, rehome_env):
    """Positive control: a single rehome must converge fully route/RIF consistent."""
    duthost = rehome_duthost
    env = rehome_env
    verify_orchagent_running_or_assert(duthost)
    stats = _rehome_iteration(duthost, env, VRF_A)
    logger.info("Baseline rehome telemetry: %s", stats)

    pytest_assert(len({env["default_vr"], env["vr_a"]}) == 2,
                  "Virtual routers are not distinct: {}".format(env))
    pytest_assert(not _route_consistent(duthost, env["default_vr"], STANDING_ROUTES[VRF_A]),
                  "Checker accepted a route/VR pairing that does not exist")
    pytest_assert(stats["intf_del_ts"] is not None or stats["target_route_ts"] is not None,
                  "swss.rec telemetry captured nothing; the ordering analysis "
                  "would be blind during the stress")


def test_vrf_rehome_bounded_stress_keeps_route_rif_vr_consistent(
        rehome_duthost, rehome_env, get_function_completeness_level):
    """Cycle the port between VRF A and the default VRF, asserting route/RIF VR
    consistency and no silently-lost rehome after every transition."""
    duthost = rehome_duthost
    env = rehome_env
    iterations = normalize_iterations(get_function_completeness_level)
    logger.info("Running %d bounded rehome iterations (hard cap %d)",
                iterations, MAX_ITERATIONS)

    cycle = [VRF_A, DEFAULT_VRF]
    bound = _shell(duthost, "sonic-db-cli CONFIG_DB HGET 'INTERFACE|{}' vrf_name".format(env["port"]))
    if bound == cycle[0]:
        cycle = cycle[1:] + cycle[:1]
    all_stats = []
    for index in range(1, iterations + 1):
        target = cycle[(index - 1) % len(cycle)]
        stats = _rehome_iteration(duthost, env, target)
        stats["iteration"] = index
        all_stats.append(stats)
        logger.info("Iteration %d/%d: %s", index, iterations, stats)
        if stats["elapsed_s"] > ITERATION_BUDGET:
            logger.warning("Iteration %d exceeded the %ds budget; stopping "
                           "after %d iterations to stay within bounds",
                           index, ITERATION_BUDGET, index)
            break

    margins = summarize_margins([s.get("route_vs_intf_del_ms") for s in all_stats])
    dels_missing = [s["iteration"] for s in all_stats if not s.get("intf_del_seen")]
    summary = {
        "iterations_run": len(all_stats),
        "route_vs_intf_del_ms": margins,
        "iterations_without_intf_del": dels_missing,
        "wedge_transients_total": sum(s.get("wedge_transients", 0) for s in all_stats),
    }
    logger.info("Bounded stress summary: %s", summary)
    verify_orchagent_running_or_assert(duthost)
