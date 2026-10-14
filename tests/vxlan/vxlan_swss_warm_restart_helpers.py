"""swss warm restart with the freeze warm-reboot does, and the reading of what syncd's compareViews then sent to the
ASIC, for tests/vxlan/test_vxlan_evpn_l2.py's warm-restart case."""

import logging
import re
import time

import pytest

from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.vxlan.vxlan_l2_helpers import AsicView, db_hget, db_keys, pid_of, sh

logger = logging.getLogger(__name__)

# Platforms with an external PHY (gbsyncd) only: orchagent creates the gearbox switches and ports again on a swss warm
# start while gbsyncd keeps them, and a gearbox port create fails (gbsyncd does not support a warm start of swss
# without sonic-net/sonic-swss#3465 and sonic-net/sonic-sairedis#1499). orchagent latches that as unhealthy, which the
# case asserts itself (PROCESS_HEALTH), so the failure names the latch, then recovers with a cold swss restart, whose
# start-up lines on such a platform are the last three.
# Not applied elsewhere: an ALREADY_EXISTS create is exactly what the case must catch on other DUTs.
GEARBOX_WARM_RESTART_LOG = [
    r".*ERR gbsyncd#syncd:.*",
    r".*ERR swss#orchagent:.*initGearboxPort: BOX: Failed to create Gearbox .*-side port for alias:.*",
    (r".*ERR swss#orchagent:.*handleSaiFailure: Encountered failure in create operation, SAI API: SAI_API_PORT, "
     r"status: SAI_STATUS_INVALID_PARAMETER.*"),
    r".*ERR swss#orchagent:.*meta_generic_validation_create: switch id 0x[0-9a-f]+ doesn't exist yet.*",
    r".*ERR swss#orchagent:.*initSaiPhyApi: BOX: Failed to create PHY.*",
    r".*ERR swss#orchagent:.*init_gearbox_phys: BOX: Failed to initialize PHY.*",
    r".*ERR swss#orchagent:.*create: create status: SAI_STATUS_ITEM_ALREADY_EXISTS.*",
    (r".*ERR swss#orchagent:.*start: Encountered failure in create operation, SAI API: SAI_API_PORT, "
     r"status: SAI_STATUS_INVALID_PARAMETER.*"),
    r".*ERR syncd#syncd:.*dnx voq nstat get failed.*",
    r".*ERR syncd#syncd:.*processQuadEvent: attr: SAI_BUFFER_POOL_ATTR_SIZE: .*",
    (r".*ERR syncd#syncd:.*sendApiResponse: api SAI_COMMON_API_SET failed in syncd mode: "
     r"SAI_STATUS_ATTR_NOT_IMPLEMENTED.*"),
]

# What a swss warm restart logs by itself on current images: orchagent's capability queries and serdes counter
# registration at re-init; intfmgrd re-adding the kernel Loopback0, which persists; orchagent's UDF warm-start cleanup
# removing ASIC_DB UDF objects that the restarted orchagent's SAI metadata does not hold (not EVPN); and orchagent
# receiving the VTEP's VXLAN_TUNNEL_TABLE entry again after the restart: VxlanTunnelOrch::addOperation logs that the
# tunnel already exists and returns without a SAI call, so no tunnel is created twice (the case also asserts the
# tunnel bridge ports and compareViews are unchanged).
SWSS_WARM_RESTART_LOG = [
    r".*ERR syncd#syncd:.*sai_query_attribute_capability:.*Query Next hop group member Attr capabilities failed.*",
    r".*ERR syncd#syncd:.*RX_FFE_TAPS_LIST not supported.*",
    r".*ERR syncd#syncd:.*RX FFE COUNT get failed with error.*",
    (r".*ERR syncd#syncd:.*updatePortSerdesTapsCountMap: .*Failed to get port serdes count attr "
     r"SAI_PORT_SERDES_ATTR_RX_FFE_COUNT.*"),
    (r".*ERR swss#orchagent:.*meta_sai_validate_oid: object key SAI_OBJECT_TYPE_UDF(_MATCH|_GROUP)?:oid:0x[0-9a-f]+ "
     r"doesn't exist.*"),
    r".*ERR swss#intfmgrd:.*addLoopbackIntf: Command '/sbin/ip link add Loopback0 .*' failed with rc 2.*",
    r".*ERR swss#orchagent:.*addOperation: Vxlan tunnel 'vtep1' is already exists.*",
]


# The warm-restart freeze (orchagent_restart_check without -n) turns FDB aging and learning off on every bridge port
# (sonic-swss orchdaemon.cpp), so nothing learned during the restart can reference a bridge port the new orchagent
# re-creates; the restarted orchagent turning them back on is the only change compareViews may carry to the ASIC.
_FREEZE_RESTORE = {
    ("SAI_OBJECT_TYPE_SWITCH", "SAI_SWITCH_ATTR_FDB_AGING_TIME"): None,             # any value, current 0
    ("SAI_OBJECT_TYPE_BRIDGE_PORT", "SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE"): "SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW",
}
_FREEZE_CURRENT = {"SAI_SWITCH_ATTR_FDB_AGING_TIME": "0",
                   "SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE": "SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE"}


def compare_views_ops(log):
    """The operations syncd's compareViews executed, from its NOTICE lines: [(op, type, key, [(attr, value, cur)])].

    syncd logs them between "NOT optimized operations" and "optimized operations!" (ComparisonLogic.cpp).
    """
    ops, inside = [], False
    for line in log.splitlines():
        if "executeOperationsOnAsic:" not in line:
            continue
        text = line.split("executeOperationsOnAsic:", 1)[1].strip()
        if text.startswith("NOT optimized operations"):
            inside, ops = True, []
            continue
        if text.startswith("optimized operations!"):
            inside = False
            continue
        if not inside:
            continue
        m = re.match(r"(\w+): (SAI_OBJECT_TYPE_\w+):(\S*)", text)
        if m:
            ops.append((m.group(1), m.group(2), m.group(3), []))
            continue
        m = re.match(r"- (\S+) (.*?)(?: \(current: (.*)\))?$", text)
        if m and ops:
            ops[-1][3].append((m.group(1), m.group(2), m.group(3)))
    return ops


def unexpected_ops(ops, before):
    """The compareViews operations that are not the freeze being undone.

    before = freeze_snapshot(): the aging time before the freeze, and the bridge ports learning in hardware then.
    """
    bad = []
    for op, otype, key, attrs in ops:
        ok = op == "set" and len(attrs) == 1
        if ok:
            attr, value, cur = attrs[0]
            want = _FREEZE_RESTORE.get((otype, attr), "MISSING")
            ok = want != "MISSING" and (want is None or value == want) and cur == _FREEZE_CURRENT.get(attr)
            if ok and attr == "SAI_SWITCH_ATTR_FDB_AGING_TIME" and before.get("aging"):
                ok = value == before["aging"]
            if ok and attr == "SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE":
                ok = key in before.get("hw_ports", set())
        if not ok:
            bad.append((op, otype, key, attrs))
    return bad


def freeze_snapshot(duthost):
    """What the freeze will change, read before it: switch FDB aging time, bridge ports learning in hardware."""
    view = AsicView(duthost, ("SWITCH", "BRIDGE_PORT"))
    switches = list(view.objs["SWITCH"].values())
    return {"aging": switches[0].get("SAI_SWITCH_ATTR_FDB_AGING_TIME", "") if switches else "",
            "hw_ports": {oid for oid, a in view.objs["BRIDGE_PORT"].items()
                         if a.get("SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE") == "SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW"}}


def swss_warm_restart(duthost, marker, timeout=420):
    """One swss warm restart, frozen first as warm-reboot does. Returns a dict (see the keys set below).

    Warm restart of swss is disabled again whatever happens. When orchagent does not reconcile, or anything fails
    after the freeze (a frozen orchagent keeps aging and learning off), swss is restarted cold and res["recovered"]
    is set; res["abort"] holds orchagent's error lines and res["error"] the exception, if any.
    """
    res = {"syncd_before": pid_of(duthost, "syncd"), "orch_before": pid_of(duthost, "orchagent"),
           "orch_reconciled": False, "fdbsyncd_reconciled": False, "error": "", "recovered": False, "cold": False,
           "before": {}}
    frozen = False
    try:
        sh(duthost, "sudo config warm_restart enable swss")
        # a previous run's 'reconciled' would satisfy the waits below before the new processes write theirs
        sh(duthost, "sudo sonic-db-cli STATE_DB HDEL 'WARM_RESTART_TABLE|orchagent' state; "
                    "sudo sonic-db-cli STATE_DB HDEL 'WARM_RESTART_TABLE|fdbsyncd' state")
        sh(duthost, "logger -t vxlan_evpn_l2 '{}'".format(marker))
        res["before"] = freeze_snapshot(duthost)
        frozen = True   # from here on a failure must not leave orchagent frozen
        ready = duthost.shell("docker exec swss /usr/bin/orchagent_restart_check -w 2000 -r 5",
                              module_ignore_errors=True)["rc"] == 0
        # orchagent replies READY before it finishes freezing (aging, learning, flush); wait for its own log line
        res["frozen"] = ready and wait_until(30, 2, 0, lambda: "frozen for warm restart" in sh(
            duthost, "sudo awk '/vxlan_evpn_l2.*{}/{{f=1}} f' /var/log/syslog | "
                     "grep -a 'Orchagent is frozen for warm restart' | grep -a -v ansible; true".format(marker),
            check=False))
        if not res["frozen"]:
            raise RuntimeError("orchagent did not freeze (restart check ready={})".format(ready))
        sh(duthost, "sudo systemctl reset-failed swss; sudo systemctl restart swss")

        def orch_state():
            p = pid_of(duthost, "orchagent")
            if p and p != res["orch_before"] and db_hget(
                    duthost, "STATE_DB", "WARM_RESTART_TABLE|orchagent", "state") == "reconciled":
                return "reconciled"
            st = sh(duthost, "docker exec swss supervisorctl status orchagent 2>/dev/null; true", check=False)
            return "exited" if re.search(r"EXITED|FATAL|BACKOFF", st) else ""
        end = time.time() + timeout
        state = ""
        while time.time() < end and state == "":
            try:
                state = orch_state()
            except Exception as e:  # a DUT read during the restart can fail; keep polling
                logger.debug("poll: %s", e)
            if state == "":
                time.sleep(5)
        res["orch_reconciled"] = state == "reconciled"
        if res["orch_reconciled"]:
            # fdbsyncd reconciles on the bgp warm-restart timer (default 120 s)
            res["fdbsyncd_reconciled"] = wait_until(timeout, 5, 0, lambda: db_hget(
                duthost, "STATE_DB", "WARM_RESTART_TABLE|fdbsyncd", "state") == "reconciled")
    except Exception as e:
        res["error"] = "{}: {}".format(type(e).__name__, e)
        logger.error("swss warm restart: %s", res["error"])
    finally:
        sh(duthost, "sudo config warm_restart disable swss", check=False)
    res["syncd_after"] = pid_of(duthost, "syncd")
    res["orch_after"] = pid_of(duthost, "orchagent")
    window = ("sudo sh -c 'zcat -f /var/log/syslog.2.gz 2>/dev/null; cat /var/log/syslog.1 /var/log/syslog "
              "2>/dev/null' | awk '/vxlan_evpn_l2.*{}/{{f=1}} f' | grep -a -v ansible | ".format(marker))
    log = sh(duthost, window + "grep -a -E 'ASIC operations to execute|ASIC is in inconsistent state|APPLY_VIEW|"
                               "executeOperationsOnAsic'; true", check=False)
    ok = res["orch_reconciled"] and not res["error"]
    res["abort"] = "" if ok else sh(
        duthost, window + "grep -a -E 'ERR swss#orchagent|orchagent terminate called|orchagent +what|"
                          "exited: orchagent' "
                          "| grep -a -v -E 'meta_sai_validate_oid|addOperation: Vxlan tunnel .vtep1.' | head -8; true",
        check=False).strip()
    if frozen and not ok:
        logger.error("swss warm restart failed; restarting swss cold:\n%s", res["abort"])
        res["cold"] = True
        res["recovered"] = cold_restart_swss(duthost)
    counts = [int(x.rsplit(":", 1)[1]) for x in log.splitlines()
              if "ASIC operations to execute:" in x and x.rsplit(":", 1)[1].strip().isdigit()]
    res["compare_views"] = len(counts)
    res["asic_ops"] = sum(counts)
    res["ops"] = compare_views_ops(log)
    res["unexpected_ops"] = unexpected_ops(res["ops"], res["before"])
    res["inconsistent"] = "ASIC is in inconsistent state" in log
    res["log"] = log
    return res


def cold_restart_swss(duthost):
    """Warm restart off, swss (and with it syncd, bgp, teamd) restarted cold; True once ports are back."""
    sh(duthost, "sudo config warm_restart disable swss; sudo systemctl reset-failed swss syncd bgp teamd radv "
                "2>/dev/null; sudo systemctl restart swss", check=False)
    try:
        wait_critical_processes(duthost, timeout=600)
        return wait_until(300, 10, 0, lambda: db_keys(duthost, "APPL_DB", "PORT_TABLE:PortInitDone") != [])
    except (Exception, pytest.fail.Exception) as e:
        logger.error("cold swss restart: %s", e)
        return False


def has_gearbox(duthost):
    """An external-PHY platform: the gbsyncd container runs (plain `docker ps`: no format braces through ansible)."""
    return duthost.shell("docker ps 2>/dev/null | grep -qw gbsyncd", module_ignore_errors=True)["rc"] == 0
