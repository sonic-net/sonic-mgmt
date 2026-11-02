"""Basic cpoutil hardware checks, following the scope of test_sfputil.py.

Tests select their DUT explicitly and use connected CPO ports from the testbed
connection graph. Commands and public output checks stay together. The DUT
helper removes identity data before any command output reaches Ansible.
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
    return {port: {key: value for key, value in entry.items() if key in ("lanes", "index", "dom_polling")}
            for port, entry in json.loads(result["stdout"]).items()}


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
    """Poll one JSON query for a requested or restored state."""
    def matches():
        result = run_cpoutil(duthost, command + " --json", expected_rc=None)
        return result["rc"] == 0 and json.loads(result["stdout"]) == expected
    assert wait_until(timeout, 2, 0, matches), "CPO state did not converge: " + command


def interfaces_have_state(duthost, ports, state):
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    return all(status[port]["oper_state"] == state for port in ports)


@contextmanager
def isolated_interfaces(duthost, ports):
    """Quiesce shared ports, then restore DOM/admin settings and original up links."""
    baseline = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    config = read_port_config(duthost)
    originally_up = [port for port in ports if baseline[port]["oper_state"] == "up"]
    errors = []
    try:
        for port in ports:
            result = duthost.command("sudo config interface transceiver dom {} disable".format(port),
                                     module_ignore_errors=True, verbose=False)
            assert result["rc"] == 0, "Could not disable DOM polling"
            result = duthost.command("sudo config interface shutdown " + port,
                                     module_ignore_errors=True, verbose=False)
            assert result["rc"] == 0, "Could not shut down shared port"
        assert wait_until(60, 2, 0, interfaces_have_state, duthost, ports, "down")
        yield
    finally:
        # Attempt restoration for every shared port, even if one command fails.
        for port in ports:
            key = shlex.quote("PORT|" + port)
            if "dom_polling" in config[port]:
                dom = "sonic-db-cli CONFIG_DB HSET {} dom_polling {}".format(
                    key, shlex.quote(config[port]["dom_polling"]))
            else:
                dom = "sonic-db-cli CONFIG_DB HDEL {} dom_polling".format(key)
            mode = "startup" if baseline[port]["admin_state"] == "up" else "shutdown"
            for command in (dom, "sudo config interface {} {}".format(mode, port)):
                try:
                    if duthost.command(command, module_ignore_errors=True, verbose=False)["rc"] != 0:
                        errors.append(port)
                except Exception:
                    errors.append(port)
        assert not errors, "Shared interface restoration failed for: {}".format(sorted(set(errors)))
        assert wait_until(180, 5, 0, interfaces_have_state, duthost, originally_up, "up"), \
            "Original links did not recover"


def test_cpoutil_map(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check public mapping fields against PORT lanes and the configured topology."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ports = read_port_config(duthost)
    path = "/usr/share/sonic/device/{}/cpo.json".format(duthost.facts["platform"])
    topology = json.loads(duthost.command("cat " + shlex.quote(path), verbose=False)["stdout"])
    devices = {name.upper(): device for name, device in topology["devices"].items()}
    # Build the declared OE-bank/ELS pairs independently of the CLI response.
    declared_pairs = set()
    for entry in topology["interfaces"].values():
        links = {devices[item["device_id"].upper()]["device_type"]: item for item in entry["associated_devices"]}
        oe_link = links["optical_engine"]
        els_link = links["external_laser_source"]
        declared_pairs.add((oe_link["device_id"].upper(), int(oe_link.get("bank", 0)), els_link["device_id"].upper()))
    records = json.loads(run_cpoutil(duthost, "show interface map --json")["stdout"])
    for port in connected_cpo_ports:
        oe, els = records[port]["oe"], records[port]["els"]
        assert devices[oe["id"]]["device_type"] == "optical_engine"
        assert devices[els["id"]]["device_type"] == "external_laser_source"
        assert set(oe["lanes"]) == set(numbers(ports[port]["lanes"]))
        assert type(oe["bank"]) is int and 0 <= oe["bank"] < int(devices[oe["id"]].get("max_banks", 1))
        assert set(oe["lanes"]) <= set(numbers(devices[oe["id"]]["asic_lanes"]))
        device_lanes = numbers(devices[oe["id"]]["asic_lanes"])
        width = len(device_lanes) // int(devices[oe["id"]].get("max_banks", 1))
        bank_lanes = device_lanes[oe["bank"] * width:(oe["bank"] + 1) * width]
        assert set(oe["lanes"]) <= set(bank_lanes), "Interface lanes do not belong to the declared OE bank"
        assert (oe["id"], oe["bank"], els["id"]) in declared_pairs, "OE/ELS association does not match topology"
        assert els["lasers"] is None or (isinstance(els["lasers"], list)
                                         and all(type(laser) is int and laser >= 0 for laser in els["lasers"]))
    table = run_cpoutil(duthost, "show interface map")["table"]
    assert {"Interface", "OE", "OE Lanes", "ELS", "ELS Lasers"} <= set(table["headers"])
    assert set(connected_cpo_ports) <= set(table["resources"])
    # Validate all connected ports in bulk, then one representative selector.
    port = connected_cpo_ports[0]
    assert json.loads(run_cpoutil(duthost, "show interface map -p " + port + " --json")["stdout"]) == {
        port: records[port]}


def test_cpoutil_presence(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Connected CPO interfaces are present and identify their mapped ELS."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = json.loads(run_cpoutil(duthost, "show interface map --json")["stdout"])
    records = json.loads(run_cpoutil(duthost, "show interface presence --json")["stdout"])
    for port in connected_cpo_ports:
        assert records[port]["present"] is True, "Connected CPO port is absent: " + port
        assert records[port]["els"] == mapping[port]["els"]["id"]
    table = run_cpoutil(duthost, "show interface presence")["table"]
    assert {"Interface", "ELS", "Presence"} <= set(table["headers"])
    assert set(connected_cpo_ports) <= set(table["resources"])
    port = connected_cpo_ports[0]
    assert json.loads(run_cpoutil(duthost, "show interface presence -p " + port + " --json")["stdout"]) == {
        port: records[port]}


def test_cpoutil_dom(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check DOM structure and read status without asserting identity values."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    records = json.loads(run_cpoutil(duthost, "show interface dom --json")["stdout"])
    for port in connected_cpo_ports:
        record = records[port]
        assert record["present"] is True
        assert not record.get("read_errors"), "DOM read failed for " + port
        for endpoint in ("oe", "els"):
            for section in ("info", "dom", "thresholds"):
                assert isinstance(record[endpoint][section], dict)
                if section != "thresholds":
                    assert record[endpoint][section], "DOM section is empty: " + section
    port = connected_cpo_ports[0]
    table = run_cpoutil(duthost, "show interface dom -p " + port)["dom"]
    assert table[port]["present"] is True
    assert set(table[port]["sections"]) == {"oe", "els"}


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_endpoint_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Read basic module state, temperature and low-power mode for OE or ELS."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = json.loads(run_cpoutil(duthost, "show interface map --json")["stdout"])
    expected = {mapping[port][target]["id"].lower() for port in connected_cpo_ports}
    queries = (("status", "Module State"), ("temperature", "Temperature (C)"), ("lpmode", "Low-power Mode"))
    for command, heading in queries:
        query = "show {} {}".format(target, command)
        records = json.loads(run_cpoutil(duthost, query + " --json", optional=command == "lpmode")["stdout"])
        assert expected <= set(records)
        for name in expected:
            value = records[name]
            if command == "status":
                assert isinstance(value, str) and value and value != "N/A"
            elif command == "temperature":
                assert not isinstance(value, bool) and math.isfinite(float(value))
            else:
                assert isinstance(value, bool)
        table = run_cpoutil(duthost, query)["table"]
        assert {target.upper(), heading} <= set(table["headers"])
        assert {name.upper() for name in expected} <= set(table["resources"])
        name = sorted(expected)[0]
        assert json.loads(run_cpoutil(duthost, query + " " + name + " --json")["stdout"]) == {name: records[name]}


def test_cpoutil_application(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check public Host/Media application fields and per-interface lane counts."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ports = read_port_config(duthost)
    records = json.loads(run_cpoutil(duthost, "show interface speed application --json", optional=True)["stdout"])
    for port in connected_cpo_ports:
        advertisements = records[port]["Application Advertisement"]
        assert isinstance(advertisements, dict) and advertisements
        for application in advertisements.values():
            assert isinstance(application, dict)
            assert {"host_electrical_interface_id", "module_media_interface_id"} <= set(application)
        for field in ("Application Select Controls", "Active Application Control Set"):
            assert isinstance(records[port][field], dict)
            assert len(records[port][field]) == len(numbers(ports[port]["lanes"]))
    table = run_cpoutil(duthost, "show interface speed application")["table"]
    assert {"Interface", "Lane", "Configured Application", "Active Application"} <= set(table["headers"])
    assert set(connected_cpo_ports) <= set(table["resources"])


def test_cpoutil_tx_disable_query(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check boolean Tx flags and the common lane table for connected ports."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ports = read_port_config(duthost)
    records = json.loads(run_cpoutil(duthost, "show interface tx-disable --json", optional=True)["stdout"])
    for port in connected_cpo_ports:
        assert isinstance(records[port], dict) and len(records[port]) == len(numbers(ports[port]["lanes"]))
        assert all(isinstance(value, bool) for value in records[port].values())
    table = run_cpoutil(duthost, "show interface tx-disable")["table"]
    assert {"Interface", "Lane", "Tx Disable Status"} <= set(table["headers"])
    assert set(connected_cpo_ports) <= set(table["resources"])


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_eeprom_read(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Read one selected endpoint and its interface alias; transport no raw bytes."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    port = connected_cpo_ports[0]
    mapping = json.loads(run_cpoutil(duthost, "show interface map -p " + port + " --json")["stdout"])[port]
    name = mapping[target]["id"]
    direct = run_cpoutil(duthost, "read-eeprom {} -i {}".format(target, int(name[len(target):])))["eeprom"]
    assert direct["headings"] == ["EEPROM hexdump for " + name]
    assert direct["size"] > 0
    indirect = run_cpoutil(duthost, "read-eeprom interface -p {} --{}".format(port, target))["eeprom"]
    assert indirect["headings"] == ["EEPROM hexdump for port {} ({})".format(port, name)]
    assert indirect["size"] > 0


def test_cpoutil_basic_arguments(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Small CLI smoke check; exhaustive parser/fault matrices are outside this suite."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    help_text = run_cpoutil(duthost, "--help")["stdout"]
    assert "Usage:" in help_text and "Commands:" in help_text
    assert all(command in help_text for command in ("show", "config", "read-eeprom", "write-eeprom"))
    mapping = json.loads(run_cpoutil(duthost, "show interface map -p " + connected_cpo_ports[0] + " --json")["stdout"])
    index = int(mapping[connected_cpo_ports[0]]["oe"]["id"][2:])
    for options in ("--page 0", "--offset 0", "--page 0 --offset 0"):
        result = run_cpoutil(duthost, "read-eeprom oe -i {} {}".format(index, options), expected_rc=1)
        assert "must be supplied together" in result["stderr"]
    result = run_cpoutil(duthost, "read-eeprom oe -i {} --page".format(index), expected_rc=2)
    assert "requires an argument" in result["stderr"]


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_low_power(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Toggle one OE/ELS, verify readback and restore the original power mode."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = json.loads(run_cpoutil(duthost, "show interface map --json")["stdout"])
    name = mapping[connected_cpo_ports[0]][target]["id"].lower()
    affected = sorted(port for port, entry in mapping.items() if entry[target]["id"].lower() == name)
    query = "show {} lpmode {}".format(target, name)
    original = json.loads(run_cpoutil(duthost, query + " --json", optional=True)["stdout"])
    assert isinstance(original[name], bool)
    if original[name]:
        pytest.skip("Restoration requires an initially full-power endpoint")
    unsupported = False
    with isolated_interfaces(duthost, affected):
        try:
            result = run_cpoutil(duthost, "config {} lpmode {} low".format(target, name), expected_rc=None)
            unsupported = result["rc"] == 1 and "not implemented" in result["stderr"]
            if unsupported:
                wait_for_state(duthost, query, original)
            else:
                assert result["rc"] == 0, result["stderr"]
                wait_for_state(duthost, query, {name: True})
        finally:
            if not unsupported:
                run_cpoutil(duthost, "config {} lpmode {} full".format(target, name))
                wait_for_state(duthost, query, original)
        if unsupported:
            pytest.skip("Platform explicitly does not implement the low-power setter")
    wait_for_state(duthost, query, original)


def test_cpoutil_tx_disable(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Toggle a physical port and restore TX for all of its mapped logical ports."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    port = connected_cpo_ports[0]
    config = read_port_config(duthost)
    mapping = json.loads(run_cpoutil(duthost, "show interface map --json")["stdout"])
    affected = sorted(name for name in mapping
                      if set(numbers(config[name]["index"])) & set(numbers(config[port]["index"])))
    # The setter acts on a physical port, including unconnected logical siblings.
    originals = {}
    for name in affected:
        result = run_cpoutil(duthost, "show interface tx-disable -p " + name + " --json", optional=True)
        originals[name] = json.loads(result["stdout"])
    states = [value for name in affected for value in originals[name][name].values()]
    if not states or any(value is not False for value in states):
        pytest.skip("Restoration requires uniformly enabled TX on all physical-port lanes")
    unsupported = False
    with isolated_interfaces(duthost, affected):
        try:
            result = run_cpoutil(duthost, "config interface tx-disable -p " + port + " true", expected_rc=None)
            unsupported = result["rc"] == 1 and "not implemented" in result["stderr"]
            if not unsupported:
                assert result["rc"] == 0, result["stderr"]
            for name in affected:
                if unsupported:
                    expected = originals[name]
                else:
                    expected = {name: {lane: True for lane in originals[name][name]}}
                wait_for_state(duthost, "show interface tx-disable -p " + name, expected)
        finally:
            if not unsupported:
                run_cpoutil(duthost, "config interface tx-disable -p " + port + " false")
                for name in affected:
                    wait_for_state(duthost, "show interface tx-disable -p " + name, originals[name])
        if unsupported:
            pytest.skip("Platform explicitly does not implement Tx-disable")
    for name in affected:
        wait_for_state(duthost, "show interface tx-disable -p " + name, originals[name])


@pytest.mark.parametrize("target", ("oe", "els"))
def test_cpoutil_reset(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports, target):
    """Reset one shared OE/ELS and check power, presence, Application and TX recovery."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mapping = json.loads(run_cpoutil(duthost, "show interface map --json")["stdout"])
    name = mapping[connected_cpo_ports[0]][target]["id"].lower()
    affected = sorted(port for port, entry in mapping.items() if entry[target]["id"].lower() == name)
    query = "show {} lpmode {}".format(target, name)
    original = json.loads(run_cpoutil(duthost, query + " --json", optional=True)["stdout"])
    if original[name] is not False:
        pytest.skip("Reset recovery requires an initially full-power endpoint")
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    if any(status[port]["admin_state"] != "up" for port in affected):
        pytest.skip("Reset recovery requires all shared ports admin-up for reprovisioning")
    before_presence = json.loads(run_cpoutil(duthost, "show interface presence --json")["stdout"])
    # A shared endpoint can reset several interfaces; save each interface's state.
    before = {}
    for port in affected:
        before[port] = {}
        for command in ("speed application", "tx-disable"):
            result = run_cpoutil(duthost, "show interface {} -p {} --json".format(command, port), optional=True)
            before[port][command] = json.loads(result["stdout"])
    unsupported = False
    with isolated_interfaces(duthost, affected):
        try:
            result = run_cpoutil(duthost, "config {} reset {}".format(target, name), expected_rc=None)
            unsupported = result["rc"] == 1 and "not implemented" in result["stderr"]
            assert unsupported or result["rc"] == 0, result["stderr"]
        finally:
            if not unsupported:
                assert wait_until(60, 2, 0, lambda: run_cpoutil(
                    duthost, query + " --json", expected_rc=None)["rc"] == 0)
                run_cpoutil(duthost, "config {} lpmode {} full".format(target, name))
                wait_for_state(duthost, query, original)
        if unsupported:
            pytest.skip("Platform explicitly does not implement reset")
    wait_for_state(duthost, query, original)
    presence = json.loads(run_cpoutil(duthost, "show interface presence --json")["stdout"])
    for port in affected:
        assert presence[port] == before_presence[port]
        for command in before[port]:
            wait_for_state(duthost, "show interface {} -p {}".format(command, port), before[port][command], timeout=60)


def test_cpoutil_lane_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname, connected_cpo_ports):
    """Check the OE datapath and ELS lane tables for connected CPO interfaces."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    expected_headers = [
        ["Interface", "Lane", "Data Path State"],
        ["Interface", "ELS", "Laser", "ELS Lane State", "Shared"],
    ]
    # Only OE datapath and ELS lane tables belong here, not ELS module status.
    # Check connected ports in bulk, then one representative port selector.
    for selected_port in (None, connected_cpo_ports[0]):
        command = "show interface lane-status"
        if selected_port is not None:
            command += " -p " + selected_port
        tables = run_cpoutil(duthost, command, optional=True)["table"]["tables"]
        assert [table["headers"] for table in tables] == expected_headers, \
            "Expected only the OE datapath and ELS lane tables"
        for table in tables:
            if selected_port is None:
                assert set(connected_cpo_ports) <= set(table["resources"]), "Connected CPO port missing from lane table"
            else:
                assert set(table["resources"]) == {selected_port}, "Lane table contains an unexpected port"
