
# Test plan in docs/testplan/LLDP-syncd-test-plan.md
import pytest
import json
from tests.common.helpers.sonic_db import SonicDbCli
import logging
from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.utilities import (
    wait_until,
    get_day_of_week_distributed_ports_from_buckets,
    group_interfaces_by_asic
)
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

APPL_DB = "APPL_DB"

LLDP_BASELINE_NEIGHBOR_TIMEOUT = 250
LLDP_NEIGHBOR_TIMEOUT = 90
LLDP_RECOVERY_NEIGHBOR_TIMEOUT = 300
LLDP_DB_TIMEOUT = 90
LLDP_POLL_INTERVAL = 5
LLDP_STABLE_POLLS = 3

# Keep lldp_syncd's case-sensitive Enum names: it lowercases only the lookup.
# Do not add aliases or capability bits that the producer does not serialize.
LLDP_CAPABILITY_BIT_POSITIONS = {
    "other": 0,
    "repeater": 1,
    "bridge": 2,
    "wlanAccessPoint": 3,
    "router": 4,
    "telephone": 5,
    "docsisCableDevice": 6,
    "stationOnly": 7,
}

pytestmark = [
    pytest.mark.topology("any"),
]


@pytest.fixture(scope="function")
def ignore_expected_loganalyzer_exceptions(duthosts, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend(
                [
                    # Interface flaps in test_lldp_entry_table_after_flap can cause routeCheck to fail momentarily
                    r".*ERR.* 'routeCheck' status failed.*",
                ]
            )


@pytest.fixture(scope="module", autouse=True)
def capture_and_validate_baseline(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Freeze the observed LLDP ports only after their DB mirror has converged."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    appl_db = get_lldp_db_instances(duthost)
    entries = wait_for_lldp_convergence(
        duthost, appl_db,
        neighbor_timeout=LLDP_BASELINE_NEIGHBOR_TIMEOUT,
        phase="Baseline: LLDP synchronization",
    )
    baseline = frozenset(entries)
    logger.info("Captured immutable LLDP interface baseline: %s", sorted(baseline))
    return baseline


@pytest.fixture(autouse="True")
def db_instance(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return get_lldp_db_instances(duthost)


def get_lldp_namespace_ids(duthost):
    namespace_ids, succeeded = duthost.get_namespace_ids("lldp")
    pytest_assert(succeeded and namespace_ids, "Failed to determine LLDP namespaces from FEATURE configuration")
    asic_ids = duthost.get_asic_ids()
    namespace_ids = [ns for ns in namespace_ids if ns is None or int(ns) in asic_ids]
    pytest_assert(namespace_ids, "No configured LLDP namespaces are present on the DUT")
    return namespace_ids


def get_lldp_db_instances(duthost):
    # eth0 belongs to the host LLDP instance, not an indexed ASIC instance.
    return [
        SonicDbCli(duthost if ns is None else duthost.asic_instance(int(ns)), APPL_DB)
        for ns in get_lldp_namespace_ids(duthost)
    ]


def get_lldp_entries(dbs):
    entries = {}
    for db in dbs:
        # One dump per namespace avoids hundreds of remote HGETALL calls on
        # high-radix systems and keeps each comparison's sampling window short.
        for key, entry in db.dump("LLDP_ENTRY_TABLE:").items():
            entries[key.split(":", 1)[1]] = entry["value"]
    return entries


# Helper function to get lldptcl output
def get_lldpctl_facts_output(duthost, enum_frontend_asic_index):
    lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=enum_frontend_asic_index,
        skip_interface_pattern_list=["Ethernet-BP", "Ethernet-IB"],
    )["ansible_facts"]
    return lldpctl_facts


def get_lldpctl_output(duthost):
    interfaces = []
    for ns in get_lldp_namespace_ids(duthost):
        container = "lldp{}".format("" if ns is None else ns)
        result = duthost.shell("docker exec {} /usr/sbin/lldpctl -f json".format(container))["stdout"]
        current = json.loads(result)["lldp"].get("interface", [])
        for name, neighbors in _build_lldpctl_lookup_map(current).items():
            interfaces.extend({name: neighbor} for neighbor in neighbors)
    return {"lldp": {"interface": interfaces}}


# Helper function to get show lldp table output
def get_show_lldp_table_output(duthost):
    lines = duthost.shell("show lldp table")["stdout"].split("\n")[3:-2]
    interface_list = [line.split()[0] for line in lines]
    # Deduplicate: in dualtor / physical fanout topologies, an uplink port may
    # have multiple LLDP neighbors (T1 switch + fanout), causing duplicate
    # interface entries.
    return list(dict.fromkeys(interface_list))


def _shutdown_startup_interface(duthost, interface, asic_str=""):
    """Shutdown and startup a single interface."""
    duthost.shell("sudo config interface {} shutdown {}".format(asic_str, interface))
    duthost.shell("sudo config interface {} startup {}".format(asic_str, interface))


def _build_lldpctl_lookup_map(lldpctl_interfaces):
    """Group all neighbors by interface without dropping fanout duplicates."""
    if isinstance(lldpctl_interfaces, dict):
        lldpctl_interfaces = [{name: neighbor} for name, neighbor in lldpctl_interfaces.items()]
    if not isinstance(lldpctl_interfaces, list):
        raise TypeError("Unexpected type for lldpctl interfaces: {}".format(type(lldpctl_interfaces)))
    lldpctl_map = {}
    for iface in lldpctl_interfaces:
        for name, neighbor in iface.items():
            lldpctl_map.setdefault(name, []).append(neighbor)
    return lldpctl_map


def _lldp_neighbor_signature(interfaces):
    # Neighbor age changes continuously; list order and local record IDs are
    # not neighbor content either. Compare the advertised chassis and port.
    return {
        name: sorted(json.dumps({"chassis": neighbor["chassis"], "port": neighbor["port"]}, sort_keys=True)
                     for neighbor in neighbors)
        for name, neighbors in _build_lldpctl_lookup_map(interfaces).items()
    }


def assert_lldp_interfaces(
    lldp_entry_keys, show_lldp_table_int_list, lldpctl_interface
):
    """
    Assert that LLDP_ENTRY_TABLE keys match show lldp table output and lldpctl output
    """
    db_set = set(lldp_entry_keys)
    cli_set = set(show_lldp_table_int_list)
    pytest_assert(
        db_set == cli_set,
        "LLDP_ENTRY_TABLE keys do not match 'show lldp table' output. "
        "In DB but not in CLI: {}. In CLI but not in DB: {}".format(
            db_set - cli_set, cli_set - db_set
        ),
    )

    # The DB has one entry per interface, including eth0, while lldpctl can
    # report multiple neighbors for the same interface.
    lldpctl_ports = set(_build_lldpctl_lookup_map(lldpctl_interface))
    pytest_assert(
        db_set == lldpctl_ports,
        "LLDP_ENTRY_TABLE keys do not match lldpctl interface indexes. "
        "In DB but not in lldpctl: {}. In lldpctl but not in DB: {}".format(
            db_set - lldpctl_ports,
            lldpctl_ports - db_set,
        ),
    )


def get_lldp_capability_bitmaps(capabilities):
    """Model the supported/enabled fields currently serialized by lldp_syncd."""
    if capabilities is None:
        # lldp_syncd uses an empty string when no capabilities are advertised.
        return "", ""
    if isinstance(capabilities, dict):
        capabilities = [capabilities]
    if not isinstance(capabilities, list):
        raise ValueError("Expected LLDP capabilities as a list or dictionary")
    if not capabilities:
        return "", ""

    supported = enabled = 0
    for capability in capabilities:
        if not isinstance(capability, dict):
            raise ValueError("Invalid LLDP capability entry: {}".format(capability))
        capability_type = capability.get("type")
        if not isinstance(capability_type, str):
            raise ValueError("Invalid LLDP system capability type: {}".format(capability_type))
        position = LLDP_CAPABILITY_BIT_POSITIONS.get(capability_type.lower())
        if position is None:
            logger.debug("Ignoring LLDP capability %r unsupported by lldp_syncd", capability_type)
            continue
        if not isinstance(capability.get("enabled"), bool):
            raise ValueError("Invalid enabled flag for LLDP capability: {}".format(capability))
        bit = 128 >> position
        supported |= bit
        if capability["enabled"]:
            enabled |= bit
    return "{:02X} 00".format(supported), "{:02X} 00".format(enabled)


def assert_lldp_entry_content(interface, entry_content, lldpctl_interface):
    """
    Assert that LLDP_ENTRY_TABLE content matches lldpctl output
    """
    pytest_assert(
        lldpctl_interface,
        "No LLDP data found for {} in lldpctl output".format(interface),
    )

    required_fields = {
        "lldp_rem_sys_name", "lldp_rem_chassis_id", "lldp_rem_port_id",
        "lldp_rem_sys_desc", "lldp_rem_port_desc", "lldp_rem_man_addr",
        "lldp_rem_sys_cap_supported", "lldp_rem_sys_cap_enabled",
    }
    pytest_assert(
        required_fields <= set(entry_content),
        "Incomplete LLDP_ENTRY_TABLE entry for {}: missing {}".format(interface, required_fields - set(entry_content)),
    )
    pytest_assert(
        entry_content["lldp_rem_sys_name"] in lldpctl_interface["chassis"],
        "lldp_rem_sys_name does not match for {}".format(interface),
    )
    chassis_info = lldpctl_interface["chassis"][entry_content["lldp_rem_sys_name"]]
    port_info = lldpctl_interface["port"]

    # Compare relevant fields between LLDP_ENTRY_TABLE and lldpctl output
    pytest_assert(
        entry_content["lldp_rem_chassis_id"] == chassis_info["id"]["value"],
        "lldp_rem_chassis_id does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_port_id"] == port_info["id"]["value"],
        "lldp_rem_port_id does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_sys_name"]
        == list(lldpctl_interface["chassis"].keys())[0],
        "lldp_rem_sys_name does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_sys_desc"] == chassis_info.get("descr", ""),
        "lldp_rem_sys_desc does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_port_desc"] == port_info.get("descr", ""),
        "lldp_rem_port_desc does not match for {}".format(interface),
    )
    if "," in entry_content["lldp_rem_man_addr"]:
        pytest_assert(
            entry_content["lldp_rem_man_addr"].split(",")
            == chassis_info.get("mgmt-ip", ""),
            "lldp_rem_man_addr does not match for {}, data from DB:{}, data from lldpctl:{}".format(
                interface,
                entry_content["lldp_rem_man_addr"],
                chassis_info.get("mgmt-ip", ""),
            ),
        )
    else:
        pytest_assert(
            entry_content["lldp_rem_man_addr"] == chassis_info.get("mgmt-ip", ""),
            "lldp_rem_man_addr does not match for {}, data from DB:{}, data from lldpctl:{}".format(
                interface,
                entry_content["lldp_rem_man_addr"],
                chassis_info.get("mgmt-ip", ""),
            ),
        )

    supported, enabled = get_lldp_capability_bitmaps(chassis_info.get("capability"))
    for field, expected in (
            ("lldp_rem_sys_cap_supported", supported),
            ("lldp_rem_sys_cap_enabled", enabled)):
        pytest_assert(
            entry_content[field] == expected,
            "{} does not match for {}: DB={!r}, LLDP={!r}".format(
                field, interface, entry_content[field], expected),
        )


def verify_lldp_table(duthost):
    output = duthost.shell("show lldp table")["stdout"]
    if "Total entries displayed" in output:
        return True
    else:
        return False


def verify_each_interface_lldp_content(interface, entry_content, neighbors):
    logger.debug("Interface {}, entry_content:{}".format(interface, entry_content))
    # Match the full neighbor identity, including when a fanout advertises the
    # same system name on multiple remote ports.
    lldpctl_interface = None
    db_sys_name = entry_content.get("lldp_rem_sys_name")
    for candidate in neighbors:
        if not isinstance(candidate, dict):
            continue
        chassis = candidate.get("chassis", {}).get(db_sys_name, {})
        if (chassis.get("id", {}).get("value") == entry_content.get("lldp_rem_chassis_id")
                and candidate.get("port", {}).get("id", {}).get("value") == entry_content.get("lldp_rem_port_id")
                and db_sys_name in candidate.get("chassis", {})):
            lldpctl_interface = candidate
            break
    pytest_assert(
        lldpctl_interface is not None,
        "No matching LLDP neighbor for {}: DB entry {}".format(interface, entry_content),
    )
    assert_lldp_entry_content(interface, entry_content, lldpctl_interface)


def assert_expected_lldp_interfaces(interfaces, expected_interfaces):
    observed = set(interfaces)
    missing = expected_interfaces - observed
    unexpected = observed - expected_interfaces
    pytest_assert(
        not missing and not unexpected,
        "LLDP interface baseline mismatch. Missing: {}. Unexpected: {}".format(
            sorted(missing), sorted(unexpected)),
    )


def wait_for_lldp_convergence(
        duthost, db_instance, expected_interfaces=None, *,
        neighbor_timeout=LLDP_NEIGHBOR_TIMEOUT, db_timeout=LLDP_DB_TIMEOUT,
        interval=LLDP_POLL_INTERVAL, phase="LLDP consistency"):
    """Wait for stable neighbors, then fresh DB agreement, using separate budgets."""
    if expected_interfaces is not None:
        expected_interfaces = frozenset(expected_interfaces)
    last_error = "No LLDP sample collected"
    stable_signature = None
    stable_polls = 0
    matched_entries = {}

    def check_lldp_neighbors():
        nonlocal last_error, stable_signature, stable_polls
        previous_polls = stable_polls
        # A collection failure also breaks the consecutive-success streak.
        stable_polls = 0
        last_error = "Failed to collect LLDP neighbors; see the polling error log"
        interfaces = get_lldpctl_output(duthost)["lldp"]["interface"]
        try:
            signature = _lldp_neighbor_signature(interfaces)
            pytest_assert(signature, "No LLDP neighbors learned")
            if expected_interfaces is not None:
                assert_expected_lldp_interfaces(signature, expected_interfaces)
        except pytest.fail.Exception as error:
            stable_signature = None
            last_error = str(error)
            logger.info("LLDP neighbors are not ready: %s", last_error)
            return False
        stable_polls = previous_polls + 1 if signature == stable_signature else 1
        stable_signature = signature
        last_error = "LLDP neighbors stable for {}/{} consecutive samples".format(stable_polls, LLDP_STABLE_POLLS)
        logger.info(last_error)
        return stable_polls >= LLDP_STABLE_POLLS

    neighbors_ready = wait_until(neighbor_timeout, interval, 0, check_lldp_neighbors)
    pytest_assert(
        neighbors_ready,
        "{}: LLDP neighbor readiness timed out after {}s: {}".format(phase, neighbor_timeout, last_error),
    )
    if expected_interfaces is None:
        # Configuration may describe non-LLDP peers (for example KVM servers).
        # The sync daemon's input is the observed LLDP state, including eth0
        # when it has a neighbor. Do not derive this candidate from the DB.
        expected_interfaces = frozenset(stable_signature)
        logger.info("Observed LLDP baseline candidate: %s", sorted(expected_interfaces))

    def check_lldp_snapshot():
        nonlocal last_error, matched_entries
        last_error = "Failed to collect fresh LLDP/DB data; see the polling error log"
        before = get_lldpctl_output(duthost)["lldp"]["interface"]
        entries = get_lldp_entries(db_instance)
        cli_interfaces = get_show_lldp_table_output(duthost)
        after = get_lldpctl_output(duthost)["lldp"]["interface"]
        try:
            pytest_assert(
                _lldp_neighbor_signature(before) == _lldp_neighbor_signature(after),
                "LLDP neighbors changed while sampling the DB and CLI",
            )
            pytest_assert(entries, "No LLDP_ENTRY_TABLE entries populated")
            assert_expected_lldp_interfaces(entries, expected_interfaces)
            assert_lldp_interfaces(entries, cli_interfaces, after)
            neighbors = _build_lldpctl_lookup_map(after)
            for interface, entry_content in entries.items():
                verify_each_interface_lldp_content(interface, entry_content, neighbors[interface])
        except pytest.fail.Exception as error:
            last_error = str(error)
            logger.info("LLDP snapshot has not converged: %s", last_error)
            return False
        matched_entries = entries
        return True

    # Phase two rechecks the live source as well as the DB. Source changes
    # invalidate a sample but never restart either phase's timeout budget.
    result = wait_until(db_timeout, interval, 0, check_lldp_snapshot)
    pytest_assert(
        result,
        "{}: APPL_DB/LLDP convergence timed out after {}s: {}".format(phase, db_timeout, last_error),
    )
    return matched_entries


# Test case 1: Verify LLDP_ENTRY_TABLE content against lldpctl output
def test_lldp_entry_table_content(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance, capture_and_validate_baseline
):
    """Verify eventual LLDP membership and content consistency, including eth0."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline, phase="Before test: LLDP synchronization")


# Test case 2: Verify LLDP_ENTRY_TABLE after restart syncd and orchagent
# This test deliberately restarts swss/syncd, which cascades to a bgp container
# restart. The memory_utilization fixture's before/after snapshots become
# meaningless across such a restart (bgpd RSS drops to ~0 then warms back up),
# so disable memory monitoring for this test.
@pytest.mark.disable_loganalyzer
@pytest.mark.disable_memory_utilization
def test_lldp_entry_table_after_syncd_orchagent(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance, capture_and_validate_baseline
):
    """Verify all required LLDP ports, including eth0, recover after restarting swss."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if duthost.facts['asic_type'] == "vs":
        pytest.skip("Skip this test case for virtual testbed")
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline, phase="Before test: LLDP synchronization")

    logging.info("Stop and start swss and syncd on DUT")
    # It's found that restart swss container could cause swss service to go down. In most of OC tests
    # pre-test will set feature autorestart to be disabled. This results critical services like swss/syncd
    # will not restart. Use swss service restart here.
    duthost.shell("sudo systemctl reset-failed")
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            duthost.shell("sudo systemctl restart {}".format(asic.get_service_name("swss")))
    else:
        duthost.shell("sudo systemctl restart swss")
    assert wait_until(600, 5, 120, duthost.critical_services_fully_started), \
        "Not all critical services are fully started"

    # Wait for BGP sessions to reach Established state instead of a fixed sleep,
    # to avoid a downstream memory-alarm false positive caused by bgpd warming up
    # in the next test case.
    bgp_neighbors = list(duthost.get_bgp_neighbors().keys())
    pytest_assert(
        wait_until(300, 10, 30, duthost.check_bgp_session_state, bgp_neighbors),
        "BGP sessions did not reach Established state after swss restart",
    )
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline,
        neighbor_timeout=LLDP_RECOVERY_NEIGHBOR_TIMEOUT, phase="After swss restart: recovery")


# Test case 3: Verify LLDP_ENTRY_TABLE after sequential interface flap
def test_lldp_entry_table_after_cont_flap(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    db_instance,
    capture_and_validate_baseline,
    ignore_expected_loganalyzer_exceptions,
):
    """Verify LLDP convergence after each selected front-panel interface flap."""
    max_test_interfaces = 32
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline, phase="Before test: LLDP synchronization")
    testable_interfaces = sorted(capture_and_validate_baseline - {"eth0"})
    if len(testable_interfaces) > max_test_interfaces:
        testable_interfaces = get_day_of_week_distributed_ports_from_buckets(
            testable_interfaces, num_buckets=max_test_interfaces
        )
    logger.info("Using sequential flapping interfaces: {}".format(testable_interfaces))
    asic_interface_map = group_interfaces_by_asic(duthost, testable_interfaces)
    for asic_str, asic_interfaces in asic_interface_map.items():
        for interface in asic_interfaces:
            _shutdown_startup_interface(duthost, interface, asic_str)
            wait_for_lldp_convergence(
                duthost, db_instance, capture_and_validate_baseline,
                phase="After {} flap: recovery".format(interface))


# Test case 4: Verify LLDP_ENTRY_TABLE after all batched interface flap
def test_lldp_entry_table_after_all_batched_flap(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    db_instance,
    capture_and_validate_baseline,
    ignore_expected_loganalyzer_exceptions,
):
    """Require all flapped ports to recover while retaining management checks."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline, phase="Before test: LLDP synchronization")
    testable_interfaces = sorted(capture_and_validate_baseline - {"eth0"})
    logger.info("Using bulk interface flap for {} interfaces".format(len(testable_interfaces)))
    asic_interface_map = group_interfaces_by_asic(duthost, testable_interfaces)
    for asic_str, asic_interfaces in asic_interface_map.items():
        logger.info("Flapping interfaces: {}".format(asic_interfaces))
        # Interface range shutdown/startup is not supported in multi-asic platforms.
        for interface in asic_interfaces:
            _shutdown_startup_interface(duthost, interface, asic_str)
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline,
        neighbor_timeout=LLDP_RECOVERY_NEIGHBOR_TIMEOUT, phase="After batched flap: recovery")

    # Bulk flapping every port tears down and re-establishes BGP on all of them at
    # once, which makes orchagent/swss churn heavily while routes are reprogrammed.
    # Wait for the BGP sessions to reconverge so that swss reclaims the transient
    # memory before the memory_utilization fixture takes its teardown snapshot,
    # avoiding a docker:swss memory-alarm false positive from an unsettled reading.
    bgp_neighbors = list(duthost.get_bgp_neighbors().keys())
    pytest_assert(
        wait_until(300, 10, 30, duthost.check_bgp_session_state, bgp_neighbors),
        "BGP sessions did not re-establish after batched interface flap",
    )


# Test case 5: Verify LLDP_ENTRY_TABLE after LLDP service restart
def test_lldp_entry_table_after_lldp_restart(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance, capture_and_validate_baseline,
    ignore_expected_loganalyzer_exceptions,
):
    """Verify fresh LLDP data after restarting configured host and ASIC services."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline, phase="Before test: LLDP synchronization")

    # Restart the LLDP service
    services = [
        "lldp" if ns is None else duthost.asic_instance(int(ns)).get_service_name("lldp")
        for ns in get_lldp_namespace_ids(duthost)
    ]
    for service in services:
        duthost.shell("sudo systemctl restart {}".format(service))
    result = wait_until(
        60, 2, 20, verify_lldp_table, duthost
    )  # Adjust based on LLDP service restart time
    pytest_assert(result, "no output for show lldp table after restarting lldp")
    for service in services:
        result = duthost.shell(
            "sudo systemctl status {}".format(service)
        )["stdout"]
        pytest_assert(
            "active (running)" in result,
            "LLDP service is not running",
        )
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline,
        neighbor_timeout=LLDP_RECOVERY_NEIGHBOR_TIMEOUT, phase="After LLDP restart: recovery")


# Test case 6: Verify LLDP_ENTRY_TABLE after reboot
@pytest.mark.disable_loganalyzer
def test_lldp_entry_table_after_reboot(
    localhost, duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance, capture_and_validate_baseline
):
    """Verify all required LLDP ports, including eth0, recover after a cold reboot."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline, phase="Before test: LLDP synchronization")

    # reboot
    logging.info("Run cold reboot on DUT")
    reboot(
        duthost,
        localhost,
        reboot_type=REBOOT_TYPE_COLD,
        reboot_helper=None,
        reboot_kwargs=None,
        safe_reboot=True,
        check_intf_up_ports=True
    )

    # Wait till we have all lldp entries in the DB after reboot. It's found in scaling
    # setup this may take some time to happen.
    wait_for_lldp_convergence(
        duthost, db_instance, capture_and_validate_baseline,
        neighbor_timeout=LLDP_RECOVERY_NEIGHBOR_TIMEOUT, phase="After cold reboot: recovery")
