"""Check remote LAG IDs while an observer route holds a reference across owner reboot.

Requires a multi-ASIC VOQ T2 chassis with a supervisor, at least two frontend
linecards, resolved IPv4 PortChannel neighbors, and system-LAG support. Run on
the whole chassis, without concurrent configuration changes. The test cold
reboots one linecard and may reboot the supervisor to recover the chassis.
An unchanged owner SPA fails as an unexercised scenario, not a passing result.
Successful recovery does not turn a detected mismatch into a passing result.
Read errors fail the test without suppressing recovery of confirmed mismatches.
"""

import ipaddress
import json
import logging
import random
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli, SonicDbCli
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot
from tests.common.utilities import wait, wait_until


logger = logging.getLogger(__name__)
pytestmark = [
    pytest.mark.topology("t2"),
    pytest.mark.reboot,
]
ASIC = "ASIC_STATE:SAI_OBJECT_TYPE_"
SPA = "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID"
UNRESOLVED_NEIGHBORS = (None, "", "00:00:00:00:00:00")


def db_rows(db, pattern):
    """Read hash rows without coercing the Redis values."""
    result = db.dump(pattern)
    pytest_assert(isinstance(result, dict), "Malformed {} dump: {}".format(db.database, pattern))
    for key, row in result.items():
        pytest_assert(
            isinstance(row, dict) and isinstance(row.get("value"), dict),
            "Malformed hash: {}".format(key))
    return {key: row["value"] for key, row in result.items()}


def lag_id_mismatches(supervisor, scope, phase):
    """Return confirmed LAG-ID mismatches and per-ASIC read errors."""
    pytest_assert(scope, "Empty LAG-ID check scope")
    allocator = db_rows(SonicDbCli(supervisor, "CHASSIS_APP_DB"), "SYSTEM_LAG_ID_TABLE")
    values = list(allocator.get("SYSTEM_LAG_ID_TABLE", {}).values())
    pytest_assert(
        values and all(isinstance(value, str) and value for value in values),
        "{}: missing or invalid LAG allocator values".format(phase))
    expected = set(values)
    mismatches, errors = {}, {}
    for host, asic in scope:
        location = (host.hostname, asic.namespace or "default")
        try:
            rows = db_rows(AsicDbCli(asic), ASIC + "LAG:")
            values = [row[SPA] for key, row in rows.items() if key.startswith(ASIC + "LAG:")]
            pytest_assert(
                values and all(isinstance(value, str) and value for value in values),
                "Incomplete LAG SPA data: {}/{}".format(*location))
        except (Exception, pytest.fail.Exception) as error:
            logger.exception("LAG IDs %s %s/%s: read failed", phase, *location)
            errors[location] = repr(error)
            continue
        actual = set(values)
        missing, extra = sorted(expected - actual), sorted(actual - expected)
        logger.info("LAG IDs %s %s/%s: expected=%d actual=%d missing=%s extra=%s",
                    phase, *location, len(expected), len(actual), missing, extra)
        if missing or extra:
            mismatches[location] = (missing, extra)
    return mismatches, errors


def lag_oid(asic, alias):
    return SonicDbCli(asic, "COUNTERS_DB").hget_key_value("COUNTERS_LAG_NAME_MAP", shlex.quote(alias))


def lag_id(asic, alias):
    return AsicDbCli(asic).hget_key_value(ASIC + "LAG:" + lag_oid(asic, alias), SPA)


def select_test_lag(scope):
    """Select an up, resolved LAG and an observer on a different physical linecard."""
    frontend = [(host, asic) for host, asic in scope if asic in host.frontend_asics]
    pytest_assert(
        len({host.hostname for host, _ in frontend}) >= 2,
        "Requires frontend ASICs on two distinct physical linecards")
    neighbors = []
    for host, asic in frontend:
        interfaces = asic.show_ip_interface()["ansible_facts"]["ip_interfaces"]
        resolved = db_rows(SonicDbCli(asic, "APPL_DB"), "NEIGH_TABLE:PortChannel")
        for portchannel, interface in interfaces.items():
            peer = interface.get("peer_ipv4")
            neighbor = resolved.get("NEIGH_TABLE:{}:{}".format(portchannel, peer), {})
            if (portchannel.startswith("PortChannel") and interface["admin"] == interface["oper_state"] == "up"
                    and peer and neighbor.get("neigh") not in UNRESOLVED_NEIGHBORS):
                ipaddress.IPv4Address(peer)
                neighbors.append((host, asic, portchannel, peer))
    if not neighbors:
        pytest.skip("No up PortChannel with a resolved IPv4 neighbor")

    rng = random.SystemRandom()
    owner, owner_asic, portchannel, peer = rng.choice(neighbors)
    observer, observer_asic = rng.choice(
        [(host, asic) for host, asic in frontend if host.hostname != owner.hostname])

    owner_config = SonicDbCli(owner_asic, "CONFIG_DB")
    alias = "|".join((
        owner_config.hget_key_value("DEVICE_METADATA|localhost", "hostname"),
        owner_config.hget_key_value("DEVICE_METADATA|localhost", "asic_name"),
        portchannel,
    ))
    observer_config = SonicDbCli(observer_asic, "CONFIG_DB")
    inbands = {key.split("|")[1] for key in observer_config.get_keys("VOQ_INBAND_INTERFACE|*")}
    pytest_assert(len(inbands) == 1, "Requires one observer inband interface")
    inband = next(iter(inbands))
    neighbor = SonicDbCli(observer_asic, "APPL_DB").hget_all("NEIGH_TABLE:{}:{}".format(inband, peer))
    pytest_assert(neighbor.get("neigh") not in UNRESOLVED_NEIGHBORS, "Unresolved remote neighbor")
    original_lag_id = lag_id(owner_asic, portchannel)
    pytest_assert(
        lag_id(observer_asic, alias) == original_lag_id,
        "Selected remote LAG does not match its owner")
    prefix = unused_prefix(observer_asic)
    route_fields = {"nexthop": peer, "ifname": inband}

    logger.info("Owner %s/%s %s peer=%s; observer %s/%s remote=%s",
                owner.hostname, owner_asic.namespace, portchannel, peer,
                observer.hostname, observer_asic.namespace, alias)
    return (owner, owner_asic, observer, observer_asic,
            portchannel, peer, alias, original_lag_id, prefix, route_fields)


def asic_routes(asic, prefix):
    rows = db_rows(AsicDbCli(asic), ASIC + "ROUTE_ENTRY:*" + prefix.split("/")[0])
    return {key: fields for key, fields in rows.items()
            if key.startswith(ASIC + "ROUTE_ENTRY:") and json.loads(key.split(":", 2)[2])["dest"] == prefix}


def route_intent(asic, prefix):
    """Check other producers, including static routes not yet installed in the RIB."""
    static = SonicDbCli(asic, "CONFIG_DB").get_keys(
        shlex.quote("STATIC_ROUTE|*" + prefix), raise_error_when_not_found=False)
    rib = json.loads(asic.run_vtysh('-c "show ip route {} json"'.format(prefix))["stdout"])
    pytest_assert(isinstance(rib, dict), "Malformed FRR route response")
    running_config = asic.run_vtysh('-c "show running-config"')["stdout"]
    address = prefix.split("/")[0]
    configured = any(
        line.strip().startswith("ip route ") and
        any(token in (prefix, address) for token in line.split()[2:])
        for line in running_config.splitlines())
    return bool(static or prefix in rib or configured)


def route_in_use(asic, prefix):
    return bool(db_rows(SonicDbCli(asic, "APPL_DB"), "ROUTE_TABLE:*" + prefix)
                or asic_routes(asic, prefix) or route_intent(asic, prefix))


def unused_prefix(asic):
    prefixes = ["{}.{}/32".format(network, host)
                for network in ("192.0.2", "198.51.100", "203.0.113") for host in range(1, 255)]
    random.SystemRandom().shuffle(prefixes)
    for prefix in prefixes:
        if not route_in_use(asic, prefix):
            return prefix
    raise pytest.fail.Exception("No unused RFC 5737 TEST-NET /32 available")


def publish_route(observer, observer_asic, prefix, route_fields, operation):
    """Use swssconfig's normal APPL_DB route producer without writing ASIC_DB directly."""
    payload = [{"ROUTE_TABLE:" + prefix: route_fields, "OP": operation}]
    result = observer.shell(
        "docker exec -i {} swssconfig /dev/stdin".format(shlex.quote(observer_asic.get_docker_name("swss"))),
        stdin=json.dumps(payload))
    pytest_assert(result["rc"] == 0, "Route {} failed: {}".format(operation, result))


def assert_holder(observer_asic, prefix, route_fields, peer, alias):
    """Prove route -> direct IP next hop -> port RIF -> alias-mapped remote LAG."""
    app = db_rows(SonicDbCli(observer_asic, "APPL_DB"), "ROUTE_TABLE:" + prefix)
    pytest_assert(app.get("ROUTE_TABLE:" + prefix) == route_fields, "Test route missing or changed")
    routes = asic_routes(observer_asic, prefix)
    pytest_assert(len(routes) == 1, "Expected one installed test route")
    key, fields = next(iter(routes.items()))
    db = AsicDbCli(observer_asic)

    nh = db.hget_all(ASIC + "NEXT_HOP:" + fields["SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID"])
    pytest_assert(
        nh["SAI_NEXT_HOP_ATTR_TYPE"] == "SAI_NEXT_HOP_TYPE_IP",
        "Holder is not a direct IP next hop")
    pytest_assert(nh["SAI_NEXT_HOP_ATTR_IP"] == peer, "Wrong holder next hop")
    rif = db.hget_all(ASIC + "ROUTER_INTERFACE:" + nh["SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID"])
    pytest_assert(
        rif["SAI_ROUTER_INTERFACE_ATTR_TYPE"] == "SAI_ROUTER_INTERFACE_TYPE_PORT",
        "Wrong RIF type")
    pytest_assert(
        rif["SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID"] == json.loads(key.split(":", 2)[2])["vr"],
        "Route and remote RIF belong to different VRs")
    pytest_assert(
        rif["SAI_ROUTER_INTERFACE_ATTR_PORT_ID"] == lag_oid(observer_asic, alias),
        "Holder RIF is not on the selected owner's remote LAG")
    pytest_assert(lag_id(observer_asic, alias), "Missing remote LAG SPA")
    return True


def route_absent(asic, prefix):
    return (not db_rows(SonicDbCli(asic, "APPL_DB"), "ROUTE_TABLE:*" + prefix)
            and not asic_routes(asic, prefix))


def remove_holder(observer, observer_asic, prefix, route_fields):
    current = db_rows(SonicDbCli(observer_asic, "APPL_DB"), "ROUTE_TABLE:" + prefix).get("ROUTE_TABLE:" + prefix)
    if current is None:
        logger.info("Test route %s is already absent; skipping DEL", prefix)
    else:
        pytest_assert(
            current == route_fields and not route_intent(observer_asic, prefix),
            "Route ownership changed; refusing DEL of {}".format(prefix))
        publish_route(observer, observer_asic, prefix, route_fields, "DEL")
    pytest_assert(
        wait_until(90, 3, 0, route_absent, observer_asic, prefix),
        "Test route was not removed from APPL_DB and ASIC_DB: {}".format(prefix))


def owner_ready(owner_asic, portchannel, supervisor, alias):
    interface = owner_asic.show_ip_interface()["ansible_facts"]["ip_interfaces"][portchannel]
    chassis_db = SonicDbCli(supervisor, "CHASSIS_APP_DB")
    published = chassis_db.hget_key_value(shlex.quote("SYSTEM_LAG_TABLE|" + alias), "lag_id")
    allocated = chassis_db.hget_key_value("SYSTEM_LAG_ID_TABLE", shlex.quote(alias))
    return (interface["admin"] == interface["oper_state"] == "up"
            and lag_id(owner_asic, portchannel) == published == allocated)


def bgp_baseline(scope):
    """Save pre-disruption peers so an empty post-reboot BGP table cannot pass."""
    neighbors = {}
    for name, host in {host.hostname: host for host, _ in scope}.items():
        neighbors[name] = host.get_bgp_neighbors_per_asic(state="all")
        pytest_assert(any(neighbors[name].values()), "Missing baseline BGP peers: " + name)
        pytest_assert(
            host.check_bgp_session_state_all_asics(neighbors[name]),
            "Baseline BGP sessions are not established: " + name)
    return neighbors


def recover_chassis(supervisor, localhost, scope, neighbors):
    """Reboot the supervisor, allow linecards to settle, then verify chassis health."""
    reboot(supervisor, localhost, reboot_type="cold", safe_reboot=True)
    wait(600, "Allow the whole chassis to stabilize after supervisor reboot")
    cards = {host.hostname: host for host, _ in scope}
    for host in [supervisor] + list(cards.values()):
        pytest_assert(
            wait_until(600, 10, 0, host.critical_services_fully_started),
            "Critical services did not recover: " + host.hostname)
        wait_critical_processes(host)
        if host.hostname in neighbors:
            pytest_assert(
                wait_until(300, 10, 0, host.check_bgp_session_state_all_asics, neighbors[host.hostname]),
                "BGP did not recover: " + host.hostname)
    mismatches, read_errors = lag_id_mismatches(supervisor, scope, "after-recovery")
    pytest_assert(
        not mismatches and not read_errors,
        "LAG-ID check failed after chassis recovery: mismatches: {}; read errors: {}".format(mismatches, read_errors))


def cleanup_test_route_and_recover_on_lag_mismatch(
        supervisor, localhost, scope, neighbors, observer, observer_asic, prefix, route_fields):
    """Recover confirmed mismatches while retaining cleanup and read errors."""
    errors = []
    try:
        remove_holder(observer, observer_asic, prefix, route_fields)
    except (Exception, pytest.fail.Exception) as error:
        logger.exception("Test route cleanup failed")
        errors.append("Route cleanup failed: {!r}".format(error))

    try:
        mismatches, read_errors = lag_id_mismatches(supervisor, scope, "after-cleanup")
    except (Exception, pytest.fail.Exception) as error:
        logger.exception("Post-cleanup LAG-ID check incomplete")
        errors.append("Post-cleanup LAG-ID check incomplete: {!r}".format(error))
    else:
        if read_errors:
            errors.append("Post-cleanup LAG-ID check incomplete: {}".format(read_errors))
        if mismatches:
            errors.append("Post-cleanup LAG-ID mismatch: {}".format(mismatches))
            logger.warning("Recovering the chassis through supervisor %s: %s", supervisor.hostname, mismatches)
            try:
                recover_chassis(supervisor, localhost, scope, neighbors)
                pytest_assert(
                    wait_until(90, 3, 0, route_absent, observer_asic, prefix),
                    "Route still present after chassis recovery: " + prefix)
            except (Exception, pytest.fail.Exception) as error:
                logger.exception("Chassis recovery failed")
                errors.append("Chassis recovery failed: {!r}".format(error))
            else:
                errors.append("Chassis recovered through supervisor reboot; mismatch verdict preserved")
    pytest_assert(not errors, "; ".join(errors))


def test_remote_lag_held_reference(duthosts, localhost):
    """Keep a remote LAG reference through owner reboot and verify LAG-ID consistency."""
    if not duthosts.supervisor_nodes or len(duthosts.frontend_nodes) < 2:
        pytest.skip("Requires a supervisor and at least two physical frontend linecards")
    if not all(host.is_multi_asic and host.facts.get("switch_type") == "voq"
               for host in duthosts.frontend_nodes):
        pytest.skip("Requires multi-ASIC VOQ linecards")
    supervisor = duthosts.supervisor_nodes[0]
    scope = [(host, asic) for host in duthosts.frontend_nodes for asic in host.asics]
    mismatches, read_errors = lag_id_mismatches(supervisor, scope, "baseline")
    pytest_assert(
        not mismatches and not read_errors,
        "Baseline LAG-ID check failed: mismatches: {}; read errors: {}".format(mismatches, read_errors))

    (owner, owner_asic, observer, observer_asic,
     portchannel, peer, alias, original_lag_id, prefix, route_fields) = select_test_lag(scope)
    neighbors = bgp_baseline(scope)
    pytest_assert(not route_in_use(observer_asic, prefix), "Prefix became owned before SET: " + prefix)
    logger.info("Holding route %s via %s on %s/%s",
                prefix, peer, observer.hostname, observer_asic.namespace)

    try:
        publish_route(observer, observer_asic, prefix, route_fields, "SET")
        pytest_assert(
            wait_until(90, 3, 0, assert_holder, observer_asic, prefix, route_fields, peer, alias),
            "Holder was not installed on the selected remote LAG")

        reboot(owner, localhost, reboot_type="cold", safe_reboot=True, wait_for_bgp=True)
        pytest_assert(
            wait_until(300, 10, 0, owner.check_bgp_session_state_all_asics, neighbors[owner.hostname]),
            "Owner BGP peers did not return")
        pytest_assert(
            wait_until(180, 5, 0, owner_ready, owner_asic, portchannel, supervisor, alias),
            "Owner PortChannel/LAG did not return")
        wait(30, "Allow owner LAG replication to settle")
        pytest_assert(
            lag_id(owner_asic, portchannel) != original_lag_id,
            "Owner reused its original SPA {}; LAG-ID reallocation scenario was not exercised".format(original_lag_id))
        mismatches, read_errors = lag_id_mismatches(supervisor, scope, "after-reboot")
        pytest_assert(
            not mismatches and not read_errors,
            "LAG-ID check failed after owner reboot: mismatches: {}; read errors: {}".format(mismatches, read_errors))
        assert_holder(observer_asic, prefix, route_fields, peer, alias)
    finally:
        cleanup_test_route_and_recover_on_lag_mismatch(
            supervisor, localhost, scope, neighbors, observer, observer_asic, prefix, route_fields)
