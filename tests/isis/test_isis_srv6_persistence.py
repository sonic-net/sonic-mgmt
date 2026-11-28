"""Exercise CONFIG_DB recovery of one IS-IS instance and its SRv6 configuration."""

import json
import logging
import re
import shlex
import time

import pytest

from tests.common.config_reload import config_reload
from tests.common.reboot import reboot
from tests.common.utilities import wait_until

pytestmark = [pytest.mark.topology("t0")]

logger = logging.getLogger(__name__)
TIMEOUT = 300
BGP_STABLE_SECONDS = 30
BGP_COUNTERS = ("connections established", "connections dropped")
CONFIG_DB = "/etc/sonic/config_db.json"
INTERFACE = "Loopback0"
LOCATOR = "ISIS_PERSIST_TEST"
LOCATOR_PREFIX = "2001:db8:100::/48"
SID = "2001:db8:100:a::/128"
NET = "49.0001.0000.0000.0001.00"

PROFILE = {
    "SRV6_MY_LOCATORS": {
        LOCATOR: {"prefix": LOCATOR_PREFIX, "behavior": "usid", "format": "usid-f3216"},
    },
    "ISIS_GLOBALS": {
        "default": {
            "enabled": "true",
            "net_title": NET,
            "level": "level-2",
            "srv6_locator": LOCATOR,
            "srv6_interface": INTERFACE,
        },
    },
    "ISIS_INTERFACE": {
        INTERFACE: {
            "enabled": "true",
            "ipv4_enabled": "false",
            "ipv6_enabled": "true",
            "passive": "true",
            "metric": "20",
        },
    },
    "SRV6_MY_SIDS": {f"{LOCATOR}|{SID}": {"action": "uN"}},
}


def _config_table(duthost, table, saved=False):
    source = f"-j {CONFIG_DB}" if saved else "-d"
    output = duthost.command(f"sonic-cfggen {source} --var-json {table}")["stdout"]
    return json.loads(output or "{}") or {}


def _db(duthost, *args):
    command = " ".join(shlex.quote(arg) for arg in args)
    return duthost.command(f"sonic-db-cli CONFIG_DB {command}")["stdout"].strip()


def _supervisor(duthost, command):
    return duthost.command(f"docker exec bgp supervisorctl {command}")["stdout"].strip()


def _assert_frrcfgd_stopped(duthost):
    # supervisorctl status reports a non-running process with exit status 3.
    status = duthost.command("docker exec bgp supervisorctl status frrcfgd", module_ignore_errors=True)
    assert status["rc"] == 3 and status["stdout"].split()[:2] == ["frrcfgd", "STOPPED"], status["stdout"]


def _running(duthost):
    return duthost.command("docker exec bgp vtysh -c 'show running-config'")["stdout"]


def _stanza(config, header):
    match = re.search(rf"^{re.escape(header)}\n((?:[ \t]+[^\n]*\n)*)", config + "\n", re.M)
    return set(match.group(1).splitlines()) if match else set()


def _profile_is_applied(config, metric, sid_present):
    interface = _stanza(config, f"interface {INTERFACE}")
    isis = _stanza(config, "router isis default")
    srv6 = _stanza(config, "segment-routing")
    prefix = f"    prefix {LOCATOR_PREFIX} block-len 32 node-len 16"
    expected_sid = f"   sid {SID} locator {LOCATOR} behavior uN"
    return (
        {" ipv6 router isis default", " isis passive", f" isis metric {metric}"} <= interface
        and " ip router isis default" not in interface
        and {f" net {NET}", " is-type level-2-only", " segment-routing srv6",
             f"  locator {LOCATOR}", f"  interface {INTERFACE}"} <= isis
        and {f"   locator {LOCATOR}", "    behavior usid", "    format usid-f3216"} <= srv6
        and bool({prefix, f"{prefix} func-bits 16"} & srv6)
        and (expected_sid in srv6 if sid_present else not any(
            line.strip().startswith(f"sid {SID} ") for line in srv6
        ))
    )


def _bgp_neighbors(duthost):
    return duthost.bgp_facts()["ansible_facts"]["bgp_neighbors"]


def _peer_ready(duthost, peer, minimum_prefixes):
    facts = _bgp_neighbors(duthost).get(peer, {})
    return facts.get("state") == "established" and facts.get("accepted prefixes", 0) >= minimum_prefixes


def _assert_bgp_stable(duthost, peer, minimum_prefixes):
    since = None
    counters = None

    def stable():
        nonlocal since, counters
        try:
            facts = _bgp_neighbors(duthost).get(peer, {})
        except Exception:
            since, counters = None, None
            raise

        if (facts.get("state") != "established" or facts.get("accepted prefixes", 0) < minimum_prefixes
                or not all(counter in facts for counter in BGP_COUNTERS)):
            since, counters = None, None
            return False

        now = time.monotonic()
        current = tuple(facts[counter] for counter in BGP_COUNTERS)
        if since is None or current != counters:
            since, counters = now, current
        return now - since >= BGP_STABLE_SECONDS

    assert wait_until(TIMEOUT, 5, 0, stable), (
        f"BGP peer {peer} did not hold its routes and session for {BGP_STABLE_SECONDS}s after cold boot"
    )


def _assert_config_db(duthost, metric, sid_present, saved=False):
    for table, expected_rows in PROFILE.items():
        actual = _config_table(duthost, table, saved)
        for key, expected_fields in expected_rows.items():
            if table == "SRV6_MY_SIDS" and not sid_present:
                assert key not in actual, f"Deleted CONFIG_DB key {table}|{key} returned"
                continue
            expected = dict(expected_fields)
            if table == "ISIS_INTERFACE":
                expected["metric"] = str(metric)
            row = actual.get(key, {})
            assert all(str(row.get(field)) == value for field, value in expected.items()), (
                f"Unexpected {'saved' if saved else 'live'} CONFIG_DB row {table}|{key}: {row}"
            )


def _assert_recovered(duthost, peer, prefixes, stage, metric=20, sid_present=True):
    logger.info("Checking recovery after %s", stage)
    assert wait_until(TIMEOUT, 5, 0, lambda: _profile_is_applied(_running(duthost), metric, sid_present)), (
        f"IS-IS/SRv6 native configuration did not converge after {stage}"
    )
    _assert_config_db(duthost, metric, sid_present)
    assert wait_until(TIMEOUT, 5, 0, _peer_ready, duthost, peer, prefixes), (
        f"BGP peer {peer} did not recover its baseline prefix count after {stage}"
    )


@pytest.fixture
def persistence_dut(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_multi_asic:
        pytest.skip("Persistence scenario requires a single ASIC and default routing namespace")

    metadata = _config_table(duthost, "DEVICE_METADATA").get("localhost", {})
    if (metadata.get("docker_routing_config_mode") != "unified"
            or metadata.get("use_template_render_for_restore", "true") != "true"):
        pytest.skip("Persistence scenario requires unified FRR with template-based restore")

    # The persistence module is the capability check. A present but broken
    # service on a supporting image is a test failure.
    capability = (
        "import importlib.util as u; "
        "raise SystemExit(42 if u.find_spec('frrcfgd') is None or u.find_spec('frrcfgd.isis_startup') is None else 0)"
    )
    probe = duthost.command(f"docker exec bgp python3 -c {shlex.quote(capability)}", module_ignore_errors=True)
    if probe["rc"] == 42:
        pytest.skip("Image does not provide the IS-IS/SRv6 persistence framework")
    assert probe["rc"] == 0, f"Could not inspect the persistence framework: {probe.get('stderr')}"

    status = _supervisor(duthost, "status frrcfgd").split()
    assert status[:2] == ["frrcfgd", "RUNNING"], f"frrcfgd is not ready: {status}"
    if INTERFACE not in _config_table(duthost, "LOOPBACK_INTERFACE"):
        pytest.skip(f"{INTERFACE} is required for the passive IS-IS fixture")

    for table in (*PROFILE, "ISIS_GLOBALS_TIMERS", "SRV6_MY_SOURCE"):
        if _config_table(duthost, table):
            pytest.skip(f"Test requires an unused IS-IS/SRv6 profile: {table} is populated")
    if re.search(r"^(router isis\b|segment-routing\s*$)", _running(duthost), re.M):
        pytest.skip("Native FRR already has an IS-IS or segment-routing configuration")

    candidates = [
        (peer, facts) for peer, facts in _bgp_neighbors(duthost).items()
        if facts.get("state") == "established"
        and facts.get("accepted prefixes", 0) > 0
        and {"connections established", "connections dropped"} <= facts.keys()
    ]
    assert candidates, "T0 fixture requires an Established BGP peer receiving routes"
    peer, facts = sorted(candidates)[0]

    # Keep the saved file and the live baseline separately: the latter can
    # contain unrelated configuration that had not yet been saved.
    backup = shlex.quote(duthost.command("sudo mktemp -d /host/isis-srv6-persist.XXXXXX")["stdout"].strip())
    duthost.command(f"sudo cp -p {CONFIG_DB} {backup}/saved.json")
    duthost.command(f"sudo config save -y {backup}/running.json")
    try:
        yield duthost, peer, facts["accepted prefixes"]
    finally:
        logger.info("Restoring live and saved CONFIG_DB from %s on %s", backup, duthost.hostname)
        duthost.command(f"sudo cp -p {backup}/running.json {CONFIG_DB}")
        try:
            config_reload(duthost, safe_reload=True)
            assert wait_until(TIMEOUT, 5, 0, _peer_ready, duthost, peer, facts["accepted prefixes"])
            running = _running(duthost)
            assert not _stanza(running, "router isis default"), "Test-owned IS-IS survived cleanup"
            assert not any(line.strip() == f"locator {LOCATOR}"
                           for line in _stanza(running, "segment-routing")), "Test locator survived cleanup"
            for table, rows in PROFILE.items():
                assert not rows.keys() & _config_table(duthost, table).keys(), f"Test rows survived in {table}"
        finally:
            duthost.command(f"sudo cp -p {backup}/saved.json {CONFIG_DB}")
            duthost.command(f"sudo cmp {backup}/saved.json {CONFIG_DB}")
        duthost.command(f"sudo rm {backup}/saved.json {backup}/running.json")
        duthost.command(f"sudo rmdir {backup}")


def test_isis_srv6_config_db_recovery(persistence_dut, localhost):
    duthost, peer, prefixes = persistence_dut
    for table, rows in PROFILE.items():
        for key, fields in rows.items():
            _db(duthost, "HSET", f"{table}|{key}", *(item for pair in fields.items() for item in pair))

    _assert_recovered(duthost, peer, prefixes, "initial CONFIG_DB SET")
    duthost.command("sudo config save -y")
    _assert_config_db(duthost, 20, True, saved=True)

    started_at = duthost.command("docker inspect --format '{{.State.StartedAt}}' bgp")["stdout"]
    duthost.command("sudo systemctl restart bgp")
    assert duthost.command("docker inspect --format '{{.State.StartedAt}}' bgp")["stdout"] != started_at
    _assert_recovered(duthost, peer, prefixes, "routing container restart")

    # Run the stimulus once. A helper that retries config reload or starts BGP
    # neighbors would hide a failed first recovery.
    duthost.command("sudo config reload -y")
    _assert_recovered(duthost, peer, prefixes, "config reload")

    boot_id = duthost.command("cat /proc/sys/kernel/random/boot_id")["stdout"]
    reboot(duthost, localhost, reboot_type="cold")
    assert duthost.command("cat /proc/sys/kernel/random/boot_id")["stdout"] != boot_id
    _assert_recovered(duthost, peer, prefixes, "cold reboot")
    _assert_bgp_stable(duthost, peer, prefixes)

    bgp_before = _bgp_neighbors(duthost)[peer]
    bgpd_pid = _supervisor(duthost, "pid bgpd")
    assert bgpd_pid.isdigit() and int(bgpd_pid) > 0
    _supervisor(duthost, "stop frrcfgd")
    try:
        _assert_frrcfgd_stopped(duthost)
        _db(duthost, "HSET", f"ISIS_INTERFACE|{INTERFACE}", "metric", "30")
        assert _db(duthost, "DEL", f"SRV6_MY_SIDS|{LOCATOR}|{SID}") == "1"
        _assert_config_db(duthost, 30, False)
        assert _profile_is_applied(_running(duthost), 20, True), "Offline writes unexpectedly reached FRR"
    finally:
        _supervisor(duthost, "start frrcfgd")

    _assert_recovered(duthost, peer, prefixes, "frrcfgd restart after offline UPDATE and DELETE", 30, False)
    bgp_after = _bgp_neighbors(duthost)[peer]
    assert _supervisor(duthost, "pid bgpd") == bgpd_pid
    for counter in BGP_COUNTERS:
        assert bgp_after[counter] == bgp_before[counter], f"BGP {peer}: {counter} changed"
