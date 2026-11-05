"""Basic cpoutil hardware checks, following the scope of test_sfputil.py.

Tests select their DUT explicitly and use connected CPO ports from the testbed
connection graph. Commands and public output checks stay together. The DUT
helper removes identity data before any command output reaches Ansible.
All cpoutil queries and control readbacks use default text output.
"""
from contextlib import contextmanager
import hashlib
import json
import logging
import math
from pathlib import Path
import shlex

import pytest

from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("any"), pytest.mark.device_type("physical"),
              pytest.mark.usefixtures("preserve_device_state")]


def numbers(value):
    if isinstance(value, (list, tuple)):
        return [int(item) for item in value]
    return [int(item.strip()) for item in str(value).split(",") if item.strip()]


def read_port_config(duthost):
    """Keep only test inputs; omit descriptions/aliases from assertion locals."""
    result = duthost.command("sonic-cfggen -d --var-json PORT", verbose=False)
    return {port: {key: value for key, value in entry.items() if key in ("lanes", "index", "subport", "dom_polling")}
            for port, entry in json.loads(result["stdout"]).items()}


def configured_cpo_ports(duthost):
    """Resolve current PORT lanes against cpo.json, without consulting CLI map.

    Topology interface names can describe parent ports before breakout. Match
    the configured OE bank lane range, not the old parent interface name.
    """
    path = "/usr/share/sonic/device/{}/cpo.json".format(duthost.facts["platform"])
    topology = json.loads(duthost.command("cat " + shlex.quote(path), verbose=False)["stdout"])
    devices = {name.upper(): device for name, device in topology["devices"].items()}
    declared = {}
    for interface in topology["interfaces"].values():
        links = {devices[link["device_id"].upper()]["device_type"]: link
                 for link in interface["associated_devices"]}
        oe, els = links["optical_engine"], links["external_laser_source"]
        name, bank = oe["device_id"].upper(), int(oe.get("bank", 0))
        lanes = numbers(devices[name]["asic_lanes"])
        banks = int(devices[name].get("max_banks", 1))
        assert banks > 0 and len(lanes) % banks == 0 and 0 <= bank < banks, "Invalid configured OE bank"
        width = len(lanes) // banks
        record = {"oe": {"id": name, "bank": bank, "lanes": lanes[bank * width:(bank + 1) * width]},
                  "els": {"id": els["device_id"].upper()}}
        key = (name, bank)
        assert key not in declared or declared[key] == record, "Ambiguous configured OE/ELS association"
        declared[key] = record
    result = {}
    for port, config in read_port_config(duthost).items():
        lanes = set(numbers(config["lanes"]))
        matches = [record for record in declared.values() if lanes and lanes <= set(record["oe"]["lanes"])]
        assert len(matches) <= 1, "PORT lanes match multiple configured OE banks: " + port
        if matches:
            result[port] = matches[0]
    return result


def run_cpoutil(duthost, arguments, expected_rc=0, optional=False):
    """Execute the visible command in one transport step; return safe output."""
    script = (Path(__file__).parent / "files/cpo_runner.py").read_text(encoding="utf-8")
    command = "sudo python3 -c {} {}".format(shlex.quote(script), shlex.quote(json.dumps(shlex.split(arguments))))
    outer = duthost.command(command, module_ignore_errors=True, verbose=False)
    assert outer["rc"] == 0, "DUT output helper failed; raw output suppressed"
    try:
        result = json.loads(outer["stdout"])
    except ValueError:
        pytest.fail("DUT output helper returned invalid JSON; raw output suppressed")
    logger.info("cpoutil %s: rc=%s", arguments, result["rc"])
    if optional and result["rc"] == 1 and "not implemented" in result["stderr"]:
        pytest.skip("Platform explicitly does not implement this operation")
    if expected_rc is not None:
        assert result["rc"] == expected_rc, "cpoutil returned {}, expected {}: {}".format(
            result["rc"], expected_rc, result["stderr"])
    assert "traceback" not in result["stderr"], "CLI traceback suppressed"
    return result


def container_snapshot(duthost):
    ids = duthost.command("docker ps -q", verbose=False)["stdout"].split()
    if not ids:
        return {}
    result = duthost.command("docker inspect " + " ".join(shlex.quote(item) for item in ids), verbose=False)
    return {item["Name"]: (item["Id"], item["State"]["StartedAt"], item["RestartCount"])
            for item in json.loads(result["stdout"])}


@pytest.fixture(scope="module")
def preserve_device_state(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Explicit module marker checks PORT/container state once around the suite."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    before_ports = hashlib.sha256(json.dumps(json.loads(duthost.command(
        "sonic-cfggen -d --var-json PORT", verbose=False)["stdout"]), sort_keys=True).encode()).hexdigest()
    containers = container_snapshot(duthost)
    yield
    after_ports = hashlib.sha256(json.dumps(json.loads(duthost.command(
        "sonic-cfggen -d --var-json PORT", verbose=False)["stdout"]), sort_keys=True).encode()).hexdigest()
    assert after_ports == before_ports, "PORT configuration changed"
    assert container_snapshot(duthost) == containers, "Container identity/start time/restart count changed"


@pytest.fixture(scope="module")
def connected_cpo_ports(duthosts, enum_rand_one_per_hwsku_frontend_hostname, conn_graph_facts):
    """Return port names only; the fixture neither selects controls nor probes hardware."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if int(duthost.facts.get("num_asic", 1)) != 1:
        pytest.skip("This basic suite currently uses the single-ASIC host PORT table")
    path = "/usr/share/sonic/device/{}/cpo.json".format(duthost.facts["platform"])
    if not duthost.stat(path=path, verbose=False)["stat"]["exists"]:
        pytest.skip("Platform has no cpo.json")
    topology = json.loads(duthost.command("cat " + shlex.quote(path), verbose=False)["stdout"])
    ports = read_port_config(duthost)
    connections = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})
    oe_lanes = [set(numbers(device["asic_lanes"])) for device in topology["devices"].values()
                if device["device_type"] == "optical_engine"]
    selected = sorted(port for port in connections if port in ports and numbers(ports[port]["lanes"])
                      and any(set(numbers(ports[port]["lanes"])) <= lanes for lanes in oe_lanes))
    if not selected:
        pytest.skip("Connection graph has no connected CPO ports")
    if any(len(numbers(ports[port]["index"])) != 1 for port in selected):
        pytest.skip("Ganged CPO ports require member-aware controls")
    logger.info("Connected CPO ports selected from connection graph: %s", selected)
    return selected


def wait_for_state(duthost, command, expected, timeout=30):
    """Poll a bulk query for the requested subset of resource/port states."""
    def matches():
        result = run_cpoutil(duthost, command, expected_rc=None)
        if result["rc"] != 0:
            return False
        records = result["table"]["records"]
        return all(key in records and records[key] == value for key, value in expected.items())
    assert wait_until(timeout, 2, 0, matches), "CPO state did not converge: " + command


def interfaces_have_state(duthost, ports, state):
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    return all(status[port]["oper_state"] == state for port in ports)


def check_connected_recovery(duthost, connected_ports, originally_up):
    """Require presence and recovery of links which were up before the action."""
    def present():
        result = run_cpoutil(duthost, "show interface presence", expected_rc=None)
        if result["rc"] != 0:
            return False
        records = result["table"]["records"]
        return all(records.get(port, {}).get("present") is True for port in connected_ports)
    assert wait_until(60, 2, 0, present), "Connected CPO interface is absent after the action"
    assert wait_until(180, 5, 0, interfaces_have_state, duthost, originally_up, "up"), \
        "Previously up connected links did not recover"


@contextmanager
def isolated_interfaces(duthost, ports):
    """Quiesce shared ports, then restore DOM/admin settings and original up links."""
    baseline = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    config = read_port_config(duthost)
    originally_up = [port for port in ports if baseline[port]["oper_state"] == "up"]
    physical_ports = {index for port in ports for index in numbers(config[port]["index"])}
    # DOM polling belongs to the unsplit/primary subport, not every breakout
    # child. The standard config CLI rejects subport > 1. Find owners in all
    # PORT entries, even when only a secondary child is affected/connected.
    dom_ports = sorted(port for port, entry in config.items()
                       if str(entry.get("subport", "0")) in ("0", "1")
                       and physical_ports.intersection(numbers(entry["index"])))
    covered = {index for port in dom_ports for index in numbers(config[port]["index"])}
    assert physical_ports <= covered, "DOM polling owner is missing for an affected physical port"
    dom_attempted, admin_attempted = [], []
    errors = []
    try:
        for port in dom_ports:
            dom_attempted.append(port)
            result = duthost.command("sudo config interface transceiver dom {} disable".format(port),
                                     module_ignore_errors=True, verbose=False)
            assert result["rc"] == 0, "Could not disable DOM polling for " + port
        for port in ports:
            if baseline[port]["admin_state"] != "up":
                continue
            admin_attempted.append(port)
            result = duthost.command("sudo config interface shutdown " + port,
                                     module_ignore_errors=True, verbose=False)
            assert result["rc"] == 0, "Could not shut down shared port: " + port
        assert wait_until(60, 2, 0, interfaces_have_state, duthost, ports, "down")
        yield
    finally:
        # Restore only attempted changes; a preparation failure must not
        # restart untouched ports. Keep DOM disabled until admin restoration.
        for port in admin_attempted:
            try:
                if duthost.command("sudo config interface startup " + port,
                                   module_ignore_errors=True, verbose=False)["rc"] != 0:
                    errors.append(port)
            except Exception:
                errors.append(port)
        for port in dom_attempted:
            key = shlex.quote("PORT|" + port)
            if "dom_polling" in config[port]:
                dom = "sonic-db-cli CONFIG_DB HSET {} dom_polling {}".format(
                    key, shlex.quote(config[port]["dom_polling"]))
            else:
                dom = "sonic-db-cli CONFIG_DB HDEL {} dom_polling".format(key)
            try:
                if duthost.command(dom, module_ignore_errors=True, verbose=False)["rc"] != 0:
                    errors.append(port)
            except Exception:
                errors.append(port)
        assert not errors, "Shared interface restoration failed for: {}".format(sorted(set(errors)))
        assert wait_until(180, 5, 0, interfaces_have_state, duthost, originally_up, "up"), \
            "Original links did not recover"


def test_cpoutil_map(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check map command success, common columns and connected-port rows only."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    table = run_cpoutil(duthost, "show interface map")["table"]
    assert table["headers"] == ["Interface", "OE", "OE Lanes", "ELS", "ELS Lasers"]
    assert set(connected_cpo_ports) <= set(table["resources"]), "Connected CPO port missing from map output"


def test_cpoutil_presence(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Every connected CPO interface must be present; absence is a failure."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    records = run_cpoutil(duthost, "show interface presence")["table"]["records"]
    for port in connected_cpo_ports:
        assert records[port]["present"] is True, "Connected CPO port is absent: " + port


def test_cpoutil_dom(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check DOM structure and read status without asserting identity values."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    records = run_cpoutil(duthost, "show interface dom")["dom"]
    for port in connected_cpo_ports:
        record = records[port]
        assert record["present"] is True, "DOM reports an absent port: " + port
        assert not record["read_errors"], "DOM read failed for " + port
        assert record["sections"] == ["oe", "els"], "DOM must display OE and ELS sections"
        for endpoint in ("oe", "els"):
            assert record["fields"][endpoint] > 0, "DOM endpoint has no displayed fields: " + endpoint
            assert record["monitors"][endpoint] and record["thresholds"][endpoint], \
                "DOM monitor/threshold headings are missing: " + endpoint


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_endpoint_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Read basic module state, temperature and low-power mode for OE or ELS."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = configured_cpo_ports(duthost)
    expected = {mapping[port][target]["id"].lower() for port in connected_cpo_ports}
    state_heading = "Module State" if target == "oe" else "Status"
    queries = (("status", state_heading), ("temperature", "Temperature (C)"), ("lpmode", "Low-power Mode"))
    for command, heading in queries:
        table = run_cpoutil(duthost, "show {} {}".format(target, command), optional=command == "lpmode")["table"]
        assert table["headers"] == [target.upper(), heading]
        records = table["records"]
        assert expected <= set(records)
        for name in expected:
            value = records[name]
            if command == "status":
                # The filter returns cell validity, never arbitrary status text.
                assert value is True, "Module state is empty or N/A: " + name
            elif command == "temperature":
                assert not isinstance(value, bool) and math.isfinite(value)
            else:
                assert isinstance(value, bool)


def test_cpoutil_application(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check Application display fields and exact logical-port lanes, including breakout."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ports = read_port_config(duthost)
    path = "/usr/share/sonic/device/{}/cpo.json".format(duthost.facts["platform"])
    topology = json.loads(duthost.command("cat " + shlex.quote(path), verbose=False)["stdout"])
    devices = {name.upper(): device for name, device in topology["devices"].items()}
    mapping = configured_cpo_ports(duthost)
    expected_lanes_by_port = {}
    for port in connected_cpo_ports:
        # Derive bank-local lane positions from topology and active PORT lanes,
        # independently of the Application response. A sibling's same-size
        # lane set, or the complete parent bank, must not pass for a subport.
        oe = mapping[port]["oe"]
        device = devices[oe["id"]]
        device_lanes = numbers(device["asic_lanes"])
        banks = int(device.get("max_banks", 1))
        assert banks > 0 and len(device_lanes) % banks == 0
        assert type(oe["bank"]) is int and 0 <= oe["bank"] < banks
        width = len(device_lanes) // banks
        bank_lanes = device_lanes[oe["bank"] * width:(oe["bank"] + 1) * width]
        port_lanes = set(numbers(ports[port]["lanes"]))
        assert port_lanes and port_lanes <= set(bank_lanes), "PORT lanes do not belong to the mapped OE bank"
        expected_lanes = {index for index, lane in enumerate(bank_lanes) if lane in port_lanes}
        expected_lanes_by_port[port] = expected_lanes
    tables = run_cpoutil(duthost, "show interface speed application", optional=True)["table"]["tables"]
    assert len(tables) == 1
    table = tables[0]
    assert table["headers"] == ["Interface", "Lane", "Configured Application", "Active Application"]
    for port in connected_cpo_ports:
        rows = [row for row in table["lane_rows"] if row["port"] == port]
        assert {row["lane"] for row in rows} == expected_lanes_by_port[port] \
            and len(rows) == len(expected_lanes_by_port[port]), "Application table lanes do not match PORT"
        assert all(row["populated"] for row in rows), "Application table has an empty configured/active cell"
        assert all(row["valid_display"] for row in rows), "Application AppSel/Host/Media display is malformed"


def test_cpoutil_tx_disable_query(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check boolean Tx flags and the common lane table for connected ports."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ports = read_port_config(duthost)
    table = run_cpoutil(duthost, "show interface tx-disable", optional=True)["table"]
    assert table["headers"] == ["Interface", "Lane", "Tx Disable Status"]
    records = table["records"]
    for port in connected_cpo_ports:
        assert len(records[port]) == len(numbers(ports[port]["lanes"])), "TX lane count does not match PORT"
        assert all(isinstance(value, bool) for value in records[port].values())


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_eeprom_read(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Sanity only: rc=0, correct target heading and at least one data row."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = configured_cpo_ports(duthost)
    names = sorted({mapping[port][target]["id"] for port in connected_cpo_ports})
    # Read each shared endpoint once; the CLI selects its declared pages.
    # No range/bank matrix or EEPROM content comparison belongs in this check.
    for name in names:
        index = int(name[len(target):])
        result = run_cpoutil(duthost, "read-eeprom {} -i {}".format(target, index))["eeprom"]
        assert result["headings"] == ["EEPROM hexdump for " + name], "EEPROM target heading is incorrect"
        assert result["has_data"], "EEPROM dump contains no data rows for " + name
    # Every connected port still exercises its interface entry point, even
    # when several breakout siblings share the same physical endpoint.
    for port in connected_cpo_ports:
        name = mapping[port][target]["id"]
        result = run_cpoutil(duthost, "read-eeprom interface -p {} --{}".format(port, target))["eeprom"]
        assert result["headings"] == ["EEPROM hexdump for port {} ({})".format(port, name)], \
            "EEPROM interface heading is incorrect"
        assert result["has_data"], "EEPROM dump contains no data rows for " + port


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_low_power(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Like sfputil lpmode: invert/read back, restore, then check presence/links.

    Keep interface admin settings and DOM polling unchanged. Reset isolation
    is not needed for this test and would flap ports even for an unsupported setter.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = configured_cpo_ports(duthost)
    names = sorted({mapping[port][target]["id"].lower() for port in connected_cpo_ports})
    query = "show {} lpmode".format(target)
    records = run_cpoutil(duthost, query, optional=True)["table"]["records"]
    originals = {name: records[name] for name in names}
    assert all(type(value) is bool for value in originals.values()), "Invalid original low-power state"
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    originally_up = [port for port in connected_cpo_ports if status[port]["oper_state"] == "up"]
    attempted, tested, skipped = [], [], {}
    try:
        # Finish all writes before checking the inverted configuration.
        for name in names:
            mode = "full" if originals[name] else "low"
            attempted.append(name)  # A failed setter may already have changed hardware.
            result = run_cpoutil(duthost, "config {} lpmode {} {}".format(target, name, mode), expected_rc=None)
            if result["rc"] == 1 and "not implemented" in result["stderr"]:
                wait_for_state(duthost, query, {name: originals[name]})
                attempted.remove(name)
                skipped[name] = "Low-power setter is not implemented"
                continue
            assert result["rc"] == 0, "Invert low-power failed for " + name
            tested.append(name)
        if tested:
            wait_for_state(duthost, query, {name: not originals[name] for name in tested})
    finally:
        # Attempt every restoration even if one setter or readback fails.
        errors = []
        for name in attempted:
            try:
                mode = "low" if originals[name] else "full"
                run_cpoutil(duthost, "config {} lpmode {} {}".format(target, name, mode))
            except Exception:
                errors.append(name)
        for name in attempted:
            try:
                wait_for_state(duthost, query, {name: originals[name]})
            except Exception:
                errors.append(name)
        assert not errors, "Low-power restoration failed for: {}".format(errors)
    wait_for_state(duthost, query, originals)
    check_connected_recovery(duthost, connected_cpo_ports, originally_up)
    logger.info("%s low-power coverage: tested=%s, skipped=%s", target, tested, skipped)
    if not tested:
        pytest.skip("No supported {} low-power endpoints: {}".format(target, skipped))


def test_cpoutil_tx_disable(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Snapshot all shared OE banks, invert them together, then restore original TX."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = configured_cpo_ports(duthost)
    # The CLI controls an OE bank, which can contain several breakout subports.
    # Use topology, not physical PORT index, to avoid duplicate/conflicting writes.
    banks = {(mapping[port]["oe"]["id"], mapping[port]["oe"]["bank"]) for port in connected_cpo_ports}
    query = "show interface tx-disable"
    records = run_cpoutil(duthost, query, optional=True)["table"]["records"]
    groups, originals, skipped = {}, {}, {}
    for bank in sorted(banks):
        siblings = sorted(port for port, entry in mapping.items()
                          if (entry["oe"]["id"], entry["oe"]["bank"]) == bank)
        values = [value for port in siblings for value in records[port].values()]
        assert values and all(type(value) is bool for value in values), "Invalid original TX state"
        # This command accepts one boolean for the entire bank, not a lane mask.
        # Mixed states cannot be restored exactly; do not overwrite them.
        if len(set(values)) != 1:
            skipped[str(bank)] = "Mixed lane states cannot be inverted/restored by the bank-wide setter"
            continue
        representative = siblings[0]
        groups[representative] = siblings
        originals.update({port: records[port] for port in siblings})
    if not groups:
        pytest.skip("No restorable OE banks for TX: {}".format(skipped))
    affected = sorted(originals)
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    originally_up = [port for port in connected_cpo_ports if status[port]["oper_state"] == "up"]
    attempted, tested = [], []
    with isolated_interfaces(duthost, affected):
        try:
            for port, siblings in groups.items():
                original = next(iter(originals[port].values()))
                attempted.append(port)
                result = run_cpoutil(duthost, "config interface tx-disable -p {} {}".format(
                    port, str(not original).lower()), expected_rc=None)
                if result["rc"] == 1 and "not implemented" in result["stderr"]:
                    attempted.remove(port)
                    skipped[port] = "Tx-disable setter is not implemented"
                    wait_for_state(duthost, query, {name: originals[name] for name in siblings})
                    continue
                assert result["rc"] == 0, "Invert TX failed for " + port
                tested.append(port)
            inverted = {name: {lane: not value for lane, value in originals[name].items()}
                        for port in tested for name in groups[port]}
            if inverted:
                wait_for_state(duthost, query, inverted)
        finally:
            errors = []
            for port in attempted:
                try:
                    original = next(iter(originals[port].values()))
                    run_cpoutil(duthost, "config interface tx-disable -p {} {}".format(port, str(original).lower()))
                except Exception:
                    errors.append(port)
            for port in attempted:
                try:
                    wait_for_state(duthost, query, {name: originals[name] for name in groups[port]})
                except Exception:
                    errors.append(port)
            assert not errors, "TX restoration failed for: {}".format(errors)
    wait_for_state(duthost, query, originals)
    check_connected_recovery(duthost, connected_cpo_ports, originally_up)
    logger.info("Tx-disable coverage: tested=%s, skipped=%s", tested, skipped)
    if not tested:
        pytest.skip("No supported TX setters: {}".format(skipped))


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_reset(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Like sfputil: successful reset, readable/present module and recovered links.

    Application/TX may legitimately reinitialize; they are not reset snapshots.
    This checks the CLI recovery contract, not electrical reset-pulse evidence.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = configured_cpo_ports(duthost)
    names = sorted({mapping[port][target]["id"].lower() for port in connected_cpo_ports})
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    originally_up = [port for port in connected_cpo_ports if status[port]["oper_state"] == "up"]
    tested, skipped = [], {}
    for name in names:
        affected = sorted(port for port, entry in mapping.items() if entry[target]["id"].lower() == name)
        query = "show {} status {}".format(target, name)
        with isolated_interfaces(duthost, affected):
            result = run_cpoutil(duthost, "config {} reset {}".format(target, name), expected_rc=None)
            unsupported = result["rc"] == 1 and "not implemented" in result["stderr"]
            assert unsupported or result["rc"] == 0, "Reset failed for {}: {}".format(name, result["stderr"])
            if not unsupported:
                def readable():
                    result = run_cpoutil(duthost, query, expected_rc=None)
                    if result["rc"] != 0:
                        return False
                    return result["table"]["records"].get(name) is True
                assert wait_until(60, 2, 0, readable), "Module did not become readable after reset: " + name
                # sfputil also checks presence after the reset wait. Do not
                # require a platform-specific module state or a visible down edge.
                check_connected_recovery(duthost, [port for port in connected_cpo_ports if port in affected], [])
        # Decide skip only after cleanup and presence/link recovery checks.
        # An unsupported command must not hide restoration or connection errors.
        check_connected_recovery(duthost, connected_cpo_ports, originally_up)
        if unsupported:
            skipped[name] = "Reset is not implemented"
            continue
        tested.append(name)
    logger.info("%s reset coverage: tested=%s, skipped=%s", target, tested, skipped)
    if not tested:
        pytest.skip("No supported {} reset endpoints: {}".format(target, skipped))


def test_cpoutil_lane_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check the two public lane tables for all connected CPO interfaces."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tables = run_cpoutil(duthost, "show interface lane-status", optional=True)["table"]["tables"]
    assert [table["headers"] for table in tables] == [
        ["Interface", "Lane", "Data Path State"],
        ["Interface", "ELS", "Laser", "ELS Lane State", "Shared"],
    ], "Expected only the OE datapath and ELS lane tables"
    for table in tables:
        assert set(connected_cpo_ports) <= set(table["resources"]), "Connected CPO port missing from lane table"
