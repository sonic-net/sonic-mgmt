"""Exercise the common cpoutil against CPO platform hardware.

See docs/testplan/cpoutil.md for requirements, dependencies and run options.
"""
from contextlib import contextmanager
import json
import logging
import math
from pathlib import Path
import re
import shlex

import pytest

from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("any"), pytest.mark.device_type("physical")]

INTERFACE_SHOW = ("map", "presence", "dom", "lpmode", "tx-disable", "speed application", "lane-status")
ENDPOINT_SHOW = ("status", "temperature", "lpmode")
ERROR_RC = 3


def run(dut, arguments, rc=0):
    command = "sudo cpoutil " + arguments
    result = dut.command(command, module_ignore_errors=True)
    logger.info("%s\nrc=%s\n%s\n%s", command, result.get("rc"),
                result.get("stdout", ""), result.get("stderr", ""))
    if rc is not None:
        assert result["rc"] == rc, "{}: {}".format(command, result)
    assert "Traceback" not in result.get("stderr", "") + result.get("stdout", ""), result
    return result


def json_output(dut, arguments, optional=False):
    result = run(dut, arguments + " --json", rc=None)
    if optional and is_unsupported(result):
        pytest.skip("{}: {}".format(arguments, result.get("stderr", "")))
    assert result["rc"] == 0, result
    records = json.loads(result["stdout"])
    assert isinstance(records, dict) and records, result
    return records


def is_unsupported(result):
    # Do not turn EEPROM failures, malformed JSON or missing APIs into a skip.
    return result["rc"] == ERROR_RC and "not implemented" in result.get("stderr", "").lower()


def integers(value):
    if isinstance(value, (list, tuple)):
        return [int(item) for item in value]
    return [int(item.strip()) for item in str(value).split(",") if item.strip()]


def expected_mapping(topology, ports):
    """Build an oracle from ASIC lane ownership, without importing cpoutil.

    The bank slice defines the full parent port. Active lanes select breakout
    children. Empty precise laser maps must not imply sequential wiring.
    """
    devices = topology["devices"]
    parents = []
    for name, entry in topology["interfaces"].items():
        associations = entry["associated_devices"]
        oe = next(item for item in associations if devices[item["device_id"]]["device_type"] == "optical_engine")
        els = next(item for item in associations
                   if devices[item["device_id"]]["device_type"] == "external_laser_source")
        device = devices[oe["device_id"]]
        lanes = integers(device["asic_lanes"])
        banks = int(device.get("max_banks", 1))
        assert lanes and len(lanes) % banks == 0, device
        width = len(lanes) // banks
        bank = int(oe["bank"])
        parent_lanes = lanes[bank * width:(bank + 1) * width]
        parents.append((name, oe, els, parent_lanes))

    expected = {}
    for port, config in ports.items():
        lanes = set(integers(config["lanes"]))
        matches = [entry for entry in parents if lanes and lanes <= set(entry[3])]
        assert len(matches) <= 1, "Ambiguous CPO lane ownership for {}".format(port)
        if not matches:
            continue
        parent, oe, els, parent_lanes = matches[0]
        els_device = devices[els["device_id"]]
        precise = els_device.get("laser_to_asic_lane_mapping", {})
        if precise:
            lasers = sorted(int(laser) - 1 for laser, wired in precise.items() if lanes.intersection(integers(wired)))
            covered = {lane for wired in precise.values() for lane in integers(wired)}
            assert lanes <= covered, "Incomplete ELS laser wiring for {}".format(port)
        elif lanes == set(parent_lanes):
            lasers = topology.get("platform_data", {}).get("interfaces", {}).get(parent, {}).get("laser_ids", [])
        else:
            fallback = topology.get("platform_data", {}).get("interfaces", {}).get(parent, {}).get("laser_ids", [])
            lasers = None if fallback else []
        els_record = {"id": els["device_id"].upper(), "lasers": lasers}
        if els.get("bank") not in (None, "N/A"):
            els_record["bank"] = int(els["bank"])
        expected[port] = {
            "oe": {"id": oe["device_id"].upper(), "bank": int(oe["bank"]),
                   "lanes": [lane for lane in parent_lanes if lane in lanes]},
            "els": els_record,
        }
    return expected


def probe(dut, ports):
    indices = sorted({index for entry in ports.values() for index in integers(entry["index"])})
    script = (Path(__file__).parent / "files" / "cpo_probe.py").read_text()
    command = "sudo python3 -c {} {}".format(shlex.quote(script), shlex.quote(json.dumps(indices)))
    result = dut.command(command, module_ignore_errors=True)
    assert result["rc"] == 0, result
    return json.loads(result["stdout"])


def service_snapshot(dut):
    names = dut.command("docker ps --format '{{.Names}}'")["stdout"].splitlines()
    result = dut.command("docker inspect " + " ".join(shlex.quote(name) for name in names))
    return {item["Name"]: (item["Id"], item["State"]["StartedAt"], item["RestartCount"])
            for item in json.loads(result["stdout"])}


@pytest.fixture(scope="module")
def cpo_environment(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if int(dut.facts.get("num_asic", 1)) != 1:
        pytest.skip("cpoutil currently loads the host PORT table; multi-ASIC namespace support is not covered")
    platform = dut.facts["platform"]
    path = "/usr/share/sonic/device/{}/cpo.json".format(platform)
    if not dut.stat(path=path)["stat"]["exists"]:
        pytest.skip("Platform has no cpo.json")
    topology = json.loads(dut.command("cat " + shlex.quote(path))["stdout"])
    ports = json.loads(dut.command("sonic-cfggen -d --var-json PORT")["stdout"])
    mapping = expected_mapping(topology, ports)
    assert mapping, "CPO topology did not resolve any active PORT entries"
    run(dut, "--help")  # A missing CLI on a CPO image is a failure.
    cpo_ports = {port: ports[port] for port in mapping}
    objects = probe(dut, cpo_ports)
    for port, config in cpo_ports.items():
        indices = integers(config["index"])
        if len(indices) != 1:
            pytest.skip("Ganged CPO ports need member-aware assertions: {}".format(port))
        assert objects[str(indices[0])] is not None, "Missing chassis CPO object for {}".format(port)
    # Every active CPO interface is queried, including unconnected/absent ones.
    logger.info("CPO ports: %s", sorted(mapping))
    return {"dut": dut, "ports": ports, "mapping": mapping, "objects": objects, "topology": topology}


@pytest.fixture(autouse=True)
def preserve_state(cpo_environment):
    dut = cpo_environment["dut"]
    before_ports = json.loads(dut.command("sonic-cfggen -d --var-json PORT")["stdout"])
    before_services = service_snapshot(dut)
    yield
    assert json.loads(dut.command("sonic-cfggen -d --var-json PORT")["stdout"]) == before_ports
    assert service_snapshot(dut) == before_services, "Container identity/start time/restart count changed"


def resources(environment, target):
    if target == "interface":
        return sorted(environment["mapping"])
    return sorted({entry[target]["id"].lower() for entry in environment["mapping"].values()})


def check_record(command, value, mapping=None):
    if command == "presence":
        assert isinstance(value["present"], bool), value
        assert value["els"] == mapping["els"]["id"], value
    elif command == "map":
        assert value == mapping
    elif command == "lpmode":
        assert isinstance(value, bool), value
    elif command == "temperature":
        assert not isinstance(value, bool) and math.isfinite(float(value)), value
    elif command == "status":
        assert isinstance(value, str) and value and value != "N/A", value
    elif command == "dom":
        assert isinstance(value["present"], bool), value
        for endpoint in ("oe", "els"):
            if value["present"]:
                for section in ("info", "dom", "thresholds"):
                    assert isinstance(value[endpoint][section], dict) and value[endpoint][section], value
            else:
                assert value[endpoint] == {}, value
        assert not value.get("read_errors"), value
    elif command == "tx-disable":
        assert len(value) == len(mapping["oe"]["lanes"]), value
        assert all(isinstance(item, bool) for item in value.values()), value
    elif command == "speed application":
        assert isinstance(value["Application Advertisement"], dict) and value["Application Advertisement"], value
        for section in ("Application Select Controls", "Active Application Control Set"):
            assert len(value[section]) == len(mapping["oe"]["lanes"]), value
    elif command == "lane-status":
        assert len(value["Data Path State Indicator"]) == len(mapping["oe"]["lanes"]), value
        assert value["ELS"] == mapping["els"]["id"], value
        assert value["ELS Lasers"] == mapping["els"]["lasers"], value
        assert isinstance(value["ELS Status"], dict) and value["ELS Status"], value


@pytest.mark.parametrize("command", INTERFACE_SHOW)
def test_interface_queries(cpo_environment, command):
    """Validate every active interface in bulk JSON and individual JSON/table queries."""
    env = cpo_environment
    dut = env["dut"]
    bulk = json_output(dut, "show interface " + command, optional=command == "lpmode")
    assert set(bulk) == set(env["mapping"]), bulk
    table = run(dut, "show interface " + command)["stdout"]
    for port, mapping in env["mapping"].items():
        assert port in table
        selected = json_output(dut, "show interface {} {}".format(command, port))
        assert set(selected) == {port}, selected
        check_record(command, bulk[port], mapping)
        check_record(command, selected[port], mapping)
        assert port in run(dut, "show interface {} {}".format(command, port))["stdout"]
        if command in ("map", "presence"):
            assert selected[port] == bulk[port]
        if command == "presence":
            index = integers(env["ports"][port]["index"])[0]
            assert selected[port]["present"] == env["objects"][str(index)]["presence"]["value"]
        elif command == "lpmode":
            index = integers(env["ports"][port]["index"])[0]
            assert selected[port] == env["objects"][str(index)]["lpmode"]["value"]


@pytest.mark.parametrize("target", ("oe", "els"))
@pytest.mark.parametrize("command", ENDPOINT_SHOW)
def test_endpoint_queries(cpo_environment, target, command):
    """Check de-duplicated OE/ELS inventory, single selectors and table/JSON output."""
    dut = cpo_environment["dut"]
    expected = resources(cpo_environment, target)
    bulk = json_output(dut, "show {} {}".format(target, command), optional=command == "lpmode")
    assert set(bulk) == set(expected), bulk
    table = run(dut, "show {} {}".format(target, command))["stdout"].lower()
    for name in expected:
        assert name in table
        single = json_output(dut, "show {} {} {}".format(target, command, name))
        assert set(single) == {name}, single
        check_record(command, bulk[name])
        check_record(command, single[name])
        assert name in run(dut, "show {} {} {}".format(target, command, name))["stdout"].lower()
        if command == "lpmode":
            port = next(port for port, entry in cpo_environment["mapping"].items()
                        if entry[target]["id"].lower() == name)
            index = integers(cpo_environment["ports"][port]["index"])[0]
            assert single[name] == cpo_environment["objects"][str(index)][target + "_lpmode"]["value"]


def parse_hexdump(output, size):
    data = []
    for line in output.splitlines():
        match = re.match(r"^\s*[0-9a-fA-F]{8}\s+([^|]+)\|", line)
        if match:
            data.extend(int(byte, 16) for byte in match.group(1).split())
    assert len(data) == size, "Expected {} bytes, got {}: {}".format(size, data, output)
    return data


@pytest.mark.parametrize("target", ("oe", "els"))
def test_eeprom_reads(cpo_environment, target):
    """Compare stable identifier bytes through direct and mapped interface paths."""
    dut = cpo_environment["dut"]
    for port, mapping in cpo_environment["mapping"].items():
        name = mapping[target]["id"]
        ranges = [(0, 0, 0)]
        if target == "oe":
            # Page 10h is banked: select the local bank, including banks above zero.
            ranges.append((mapping["oe"]["bank"], 0x10, 128))
        elif cpo_environment["topology"].get("platform_data", {}).get("cpo_eeprom_mode") == "joint":
            # Joint-memory ELS identity lives at B0/B4, separate from OE lower memory.
            extension = cpo_environment["topology"]["platform_data"]["devices"][name]
            ranges.append((0, 0xB0 + int(extension["base_page"]), 128))
        for bank, page, offset in ranges:
            args = "-n {} -o {} -s 4".format(page, offset)
            direct = run(dut, "read-eeprom {} -i {} -b {} {}".format(
                target, int(name[len(target):]), bank, args))
            indirect = run(dut, "read-eeprom interface {} --{} {}".format(port, target, args))
            assert parse_hexdump(direct["stdout"], 4) == parse_hexdump(indirect["stdout"], 4)


@pytest.mark.parametrize("target", ("oe", "els"))
def test_eeprom_full_dump(cpo_environment, target):
    """Full dumps include every unique endpoint, not one duplicate per interface."""
    result = run(cpo_environment["dut"], "read-eeprom " + target)["stdout"]
    for name in resources(cpo_environment, target):
        assert re.search(r"EEPROM hexdump for {}\b".format(name), result, re.IGNORECASE), result


@pytest.mark.parametrize("arguments,diagnostic", (
    ("show interface presence __invalid_cpo_port__", "invalid"),
    ("show oe temperature -1", "-1"), ("show els temperature -1", "-1"),
    ("config interface tx-disable __invalid_cpo_port__ enable", "invalid value"),
    ("config oe lpmode -1 invalid", "invalid"), ("config els lpmode -1 invalid", "invalid"),
    ("read-eeprom oe -i {oe} -n 0 -o 0 -s 0", "size must be greater than zero"),
    ("read-eeprom oe -i {oe} -n 0 -o 255 -s 2", "crosses the cmis page boundary"),
    ("read-eeprom oe -i {oe} -n 256 -o 128 -s 1", "page must be between"),
    ("read-eeprom oe -i {oe} -b 1 -n 0 -o 0 -s 1", "does not use bank selection"),
    ("read-eeprom els -i {els} -n 1 -o 0 -s 1", "valid range: 80h-ffh"),
    ("read-eeprom oe -i {oe} -n 0", "must be supplied together"),
    ("write-eeprom oe -i {oe} -n 0 -o 0 -d zz", "hex"),
    ("write-eeprom els -i {els} -n 0 -o 0 -d 1", "hex"),
    ("show oe input-power", "no such command"), ("show els output-power", "no such command"),
    ("show els presence", "no such command"),
    ("config oe tx-disable 0 true", "no such command"), ("config els tx-disable 0 true", "no such command"),
))
def test_invalid_arguments(cpo_environment, arguments, diagnostic):
    """Rejected inputs and removed commands must return the CLI's documented error code."""
    arguments = arguments.format(oe=int(resources(cpo_environment, "oe")[0][2:]),
                                 els=int(resources(cpo_environment, "els")[0][3:]))
    result = run(cpo_environment["dut"], arguments, rc=ERROR_RC)
    assert diagnostic in result.get("stderr", "").lower(), result


def test_sfp_coexistence(cpo_environment):
    """Ordinary SFP ports are absent from CPO output and are directed to sfputil."""
    dut = cpo_environment["dut"]
    ordinary = set(cpo_environment["ports"]) - set(cpo_environment["mapping"])
    if not ordinary:
        pytest.skip("No ordinary SFP ports on this DUT")
    for port in sorted(ordinary):
        result = run(dut, "show interface presence " + port, rc=ERROR_RC)
        assert "sfputil" in result["stderr"], result


@pytest.mark.parametrize("query", ("interface map", "oe temperature"))
def test_concurrent_queries(cpo_environment, query):
    """Independent read processes return complete, parseable mapping output."""
    dut = cpo_environment["dut"]
    # One Ansible shell call avoids concurrent use of the same Ansible host object.
    command = "sudo python3 -c " + shlex.quote(
        "import concurrent.futures,json,subprocess; "
        "pool=concurrent.futures.ThreadPoolExecutor(max_workers=4); "
        "jobs=[pool.submit(subprocess.run,['cpoutil','show']+" + repr(query.split()) + "+['--json'],"
        "capture_output=True,text=True) for _ in range(4)]; "
        "print(json.dumps([{'rc':j.result().returncode,'stdout':j.result().stdout,"
        "'stderr':j.result().stderr} for j in jobs])); pool.shutdown()")
    result = dut.command(command)
    for item in json.loads(result["stdout"]):
        assert item["rc"] == 0, item
        records = json.loads(item["stdout"])
        if query == "interface map":
            assert records == cpo_environment["mapping"]
        else:
            assert set(records) == set(resources(cpo_environment, "oe")), records
            for value in records.values():
                check_record("temperature", value)


def affected_ports(environment, target, selector, command):
    mapping = environment["mapping"]
    if target != "interface":
        return sorted(port for port, entry in mapping.items() if entry[target]["id"].lower() == selector)
    if command == "tx-disable":
        indices = set(integers(environment["ports"][selector]["index"]))
        return sorted(port for port in mapping
                      if indices.intersection(integers(environment["ports"][port]["index"])))
    oe = mapping[selector]["oe"]["id"]
    return sorted(port for port, entry in mapping.items() if entry["oe"]["id"] == oe)


def interfaces_up(dut, ports):
    status = dut.show_interface(command="status")["ansible_facts"]["int_status"]
    return all(status[port]["oper_state"] == "up" for port in ports)


@contextmanager
def isolated_ports(environment, ports):
    """Quiesce every shared port and restore admin/DOM settings even on failure."""
    dut = environment["dut"]
    baseline = dut.show_interface(command="status")["ansible_facts"]["int_status"]
    config = json.loads(dut.command("sonic-cfggen -d --var-json PORT")["stdout"])
    originally_up = [port for port in ports if baseline[port]["oper_state"] == "up"]
    restore_errors = []
    try:
        for port in ports:
            result = dut.command("sudo config interface transceiver dom {} disable".format(port),
                                 module_ignore_errors=True)
            assert result["rc"] == 0, result
            result = dut.command("sudo config interface shutdown " + port, module_ignore_errors=True)
            assert result["rc"] == 0, result
        assert wait_until(60, 2, 0, lambda: all(
            dut.show_interface(command="status")["ansible_facts"]["int_status"][port]["oper_state"] == "down"
            for port in ports)), "Shared interfaces did not shut down"
        yield
    finally:
        # Attempt every restoration, collecting failures rather than stopping at the first.
        for port in ports:
            mode = "startup" if baseline[port]["admin_state"] == "up" else "shutdown"
            commands = ["sudo config interface {} {}".format(mode, port)]
            key = shlex.quote("PORT|" + port)
            if "dom_polling" in config[port]:
                commands.append("sonic-db-cli CONFIG_DB HSET {} dom_polling {}".format(
                    key, shlex.quote(config[port]["dom_polling"])))
            else:
                commands.append("sonic-db-cli CONFIG_DB HDEL {} dom_polling".format(key))
            for command in commands:
                try:
                    result = dut.command(command, module_ignore_errors=True)
                    if result["rc"] != 0:
                        restore_errors.append(result)
                except Exception as exc:
                    restore_errors.append(str(exc))
        assert not restore_errors, "Interface restoration failed: {}".format(restore_errors)
        assert wait_until(180, 5, 0, interfaces_up, dut, originally_up), "Original links did not recover"


def matches_json(dut, arguments, expected):
    result = run(dut, arguments + " --json", rc=None)
    return result["rc"] == 0 and json.loads(result["stdout"]) == expected


@pytest.mark.parametrize("target", ("interface", "oe", "els"))
def test_low_power_control(cpo_environment, request, target):
    """Toggle one controller/endpoint, check readback and restore its original state."""
    if not request.config.getoption("--cpo-disruptive"):
        pytest.skip("Use --cpo-disruptive to test shared hardware controls")
    env = cpo_environment
    dut = env["dut"]
    selector = resources(env, target)[0]
    query = "show {} lpmode {}".format(target, selector)
    original = json_output(dut, query, optional=True)
    old = original[selector]
    assert isinstance(old, bool), original
    if old:
        pytest.skip("Reprovisioning can clear an initial low-power state; use an initially full-power controller")
    command = "config {} lpmode {} ".format(target, selector)
    with isolated_ports(env, affected_ports(env, target, selector, "lpmode")):
        attempted = False
        unsupported = False
        try:
            attempted = True
            result = run(dut, command + ("full" if old else "low"), rc=None)
            unsupported = is_unsupported(result)
            if unsupported:
                assert json_output(dut, query) == original, "Unsupported setter changed state"
            else:
                assert result["rc"] == 0, result
                assert wait_until(30, 2, 0, matches_json, dut, query, {selector: not old}), result
        finally:
            if attempted and not unsupported:
                run(dut, command + ("low" if old else "full"))
                assert wait_until(30, 2, 0, matches_json, dut, query, original), "Low-power restore failed"
        if unsupported:
            pytest.skip("Platform explicitly does not implement the low-power setter")
    assert wait_until(30, 2, 0, matches_json, dut, query, original), "Power mode changed during reprovisioning"


def test_tx_disable_control(cpo_environment, request):
    """Toggle a uniformly configured physical port and restore its original Tx state."""
    if not request.config.getoption("--cpo-disruptive"):
        pytest.skip("Use --cpo-disruptive to test Tx-disable")
    env = cpo_environment
    dut = env["dut"]
    port = resources(env, "interface")[0]
    query = "show interface tx-disable " + port
    original = json_output(dut, query)
    # The setter acts on the whole physical port. Include every breakout sibling.
    affected = affected_ports(env, "interface", port, "tx-disable")
    originals = {name: json_output(dut, "show interface tx-disable " + name) for name in affected}
    states = {value for record in originals.values() for lanes in record.values() for value in lanes.values()}
    if len(states) != 1 or not all(isinstance(value, bool) for value in states):
        pytest.skip("Whole-port Tx setter cannot restore a mixed per-lane state")
    old = states.pop()
    command = "config interface tx-disable {} ".format(port)
    with isolated_ports(env, affected):
        unsupported = False
        try:
            result = run(dut, command + str(not old).lower(), rc=None)
            unsupported = is_unsupported(result)
            if unsupported:
                assert json_output(dut, query) == original
            else:
                assert result["rc"] == 0, result
                for name, record in originals.items():
                    expected = {name: {lane: not old for lane in record[name]}}
                    assert wait_until(30, 2, 0, matches_json, dut, "show interface tx-disable " + name, expected)
        finally:
            if not unsupported:
                run(dut, command + str(old).lower())
                for name, record in originals.items():
                    assert wait_until(30, 2, 0, matches_json, dut, "show interface tx-disable " + name, record)
        if unsupported:
            pytest.skip("Platform explicitly does not implement Tx-disable")


@pytest.mark.parametrize("target", ("interface", "oe", "els"))
def test_reset_control(cpo_environment, request, target):
    """Reset one shared controller, restore power mode, admin-toggle and recover original links."""
    if not request.config.getoption("--cpo-disruptive"):
        pytest.skip("Use --cpo-disruptive to test reset")
    env = cpo_environment
    dut = env["dut"]
    selector = resources(env, target)[0]
    query = "show {} lpmode {}".format(target, selector)
    original = json_output(dut, query, optional=True)
    affected = affected_ports(env, target, selector, "reset")
    if original[selector]:
        pytest.skip("Reset recovery requires an initially full-power controller")
    status = dut.show_interface(command="status")["ansible_facts"]["int_status"]
    if any(status[port]["admin_state"] != "up" for port in affected):
        pytest.skip("Reset recovery requires all affected ports admin-up for xcvrd reprovisioning")
    before = {port: {command: json_output(dut, "show interface {} {}".format(command, port))
                     for command in ("speed application", "tx-disable")} for port in affected}
    with isolated_ports(env, affected):
        unsupported = False
        try:
            result = run(dut, "config {} reset {}".format(target, selector), rc=None)
            unsupported = is_unsupported(result)
            if unsupported:
                assert json_output(dut, query) == original, "Unsupported reset changed power mode"
            else:
                assert result["rc"] == 0, result
        finally:
            if not unsupported:
                # Successful reset may reset CMIS state even if the command later fails.
                assert wait_until(60, 2, 0, lambda: run(dut, query, rc=None)["rc"] == 0)
                mode = "low" if original[selector] else "full"
                run(dut, "config {} lpmode {} {}".format(target, selector, mode))
                assert wait_until(30, 2, 0, matches_json, dut, query, original)
        if unsupported:
            pytest.skip("Platform explicitly does not implement reset")
    presence = json_output(dut, "show interface presence")
    assert wait_until(30, 2, 0, matches_json, dut, query, original), "Reset power mode did not recover"
    for port in affected:
        index = integers(env["ports"][port]["index"])[0]
        assert presence[port]["present"] == env["objects"][str(index)]["presence"]["value"]
        for command, record in before[port].items():
            assert wait_until(60, 2, 0, matches_json, dut, "show interface {} {}".format(command, port), record), \
                "Reset did not restore {} for {}".format(command, port)


@pytest.mark.parametrize("access", ("endpoint", "interface"))
def test_eeprom_write(cpo_environment, request, access):
    """Write an approved scratch range, verify it, and restore the saved bytes in finally."""
    location = request.config.getoption("--cpo-eeprom-write")
    if not location:
        pytest.skip("Supply --cpo-eeprom-write with a platform-approved scratch range")
    assert request.config.getoption("--cpo-disruptive"), "EEPROM writes also require --cpo-disruptive"
    location = json.loads(location)
    assert set(location) == {"target", "index", "bank", "page", "offset", "data"}, location
    target = location["target"]
    assert target in ("oe", "els"), location
    for key in ("index", "bank", "page", "offset"):
        assert type(location[key]) is int and location[key] >= 0, location
    data = bytes.fromhex(location["data"])
    assert data and location["offset"] + len(data) <= 256, location
    assert location["bank"] <= 255 and location["page"] <= 255, location
    assert location["page"] == 0 or location["offset"] >= 128, location
    selector = target + str(location["index"])
    assert selector in resources(cpo_environment, target), location
    dut = cpo_environment["dut"]
    address = "{} -i {} -b {} -n {} -o {}".format(
        target, location["index"], location["bank"], location["page"], location["offset"])
    read = "read-eeprom {} -s {}".format(address, len(data))
    write = "write-eeprom {} -d ".format(address)
    if access == "interface":
        banked = location["page"] >= 0x10 and not 0x9F <= location["page"] <= 0xAF
        candidates = [port for port, entry in cpo_environment["mapping"].items()
                      if entry[target]["id"].lower() == selector
                      and (entry["oe"]["bank"] if target == "oe" and banked else 0) == location["bank"]]
        if not candidates:
            pytest.skip("Approved scratch range has no matching interface/bank alias")
        write = "write-eeprom interface {} --{} -n {} -o {} -d ".format(
            sorted(candidates)[0], target, location["page"], location["offset"])
    restore = "write-eeprom {} -d ".format(address)
    with isolated_ports(cpo_environment, affected_ports(cpo_environment, target, selector, "eeprom")):
        original = parse_hexdump(run(dut, read)["stdout"], len(data))
        assert list(data) != original, "Choose a test pattern different from the saved bytes"
        try:
            run(dut, write + data.hex())
            assert parse_hexdump(run(dut, read)["stdout"], len(data)) == list(data)
        finally:
            run(dut, restore + bytes(original).hex())
            assert parse_hexdump(run(dut, read)["stdout"], len(data)) == original, "EEPROM restore failed"
