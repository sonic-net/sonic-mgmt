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
from .argument_cases import ARGUMENT_CASES, HELP_COMMANDS, LEAF_COMMANDS


logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("any"), pytest.mark.device_type("physical")]

INTERFACE_SHOW = ("map", "presence", "dom", "tx-disable", "speed application", "lane-status")
ENDPOINT_SHOW = ("status", "temperature", "lpmode")
ERROR_RC = 3


def runner_request(dut, payload):
    script = (Path(__file__).parent / "files" / "cpo_runner.py").read_text(encoding="utf-8")
    command = "sudo python3 -c {} {}".format(shlex.quote(script), shlex.quote(json.dumps(payload)))
    outer = dut.command(command, module_ignore_errors=True, verbose=False)
    assert outer["rc"] == 0, "DUT runner failed; raw command output suppressed"
    try:
        return json.loads(outer["stdout"])
    except ValueError:
        pytest.fail("DUT runner returned invalid JSON; raw command output suppressed")


def run(dut, arguments, rc=0, privileged=True):
    result = runner_request(dut, {"args": shlex.split(arguments), "privileged": privileged})
    # The DUT runner projects/redacts identity data before it reaches Ansible.
    logger.info("cpoutil %s: rc=%s", shlex.split(arguments)[:3], result.get("rc"))
    if rc is not None:
        assert result["rc"] == rc, "cpoutil failed: {}".format(result.get("stderr", ""))
    assert "traceback" not in result.get("stderr", "").lower(), "CLI traceback suppressed"
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
    result = dut.command(command, module_ignore_errors=True, verbose=False)
    assert result["rc"] == 0, "Platform probe failed; raw output suppressed"
    return json.loads(result["stdout"])


def service_snapshot(dut):
    # Avoid Docker Go templates: Ansible would parse their braces as Jinja.
    container_ids = dut.command("docker ps -q", verbose=False)["stdout"].splitlines()
    if not container_ids:
        return {}
    result = dut.command("docker inspect " + " ".join(shlex.quote(item) for item in container_ids), verbose=False)
    return {item["Name"]: (item["Id"], item["State"]["StartedAt"], item["RestartCount"])
            for item in json.loads(result["stdout"])}


@pytest.fixture(scope="module")
def cpo_environment(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if int(dut.facts.get("num_asic", 1)) != 1:
        pytest.skip("cpoutil currently loads the host PORT table; multi-ASIC namespace support is not covered")
    platform = dut.facts["platform"]
    path = "/usr/share/sonic/device/{}/cpo.json".format(platform)
    if not dut.stat(path=path, verbose=False)["stat"]["exists"]:
        pytest.skip("Platform has no cpo.json")
    topology = json.loads(dut.command("cat " + shlex.quote(path), verbose=False)["stdout"])
    ports = json.loads(dut.command("sonic-cfggen -d --var-json PORT", verbose=False)["stdout"])
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
    before_ports = json.loads(dut.command("sonic-cfggen -d --var-json PORT", verbose=False)["stdout"])
    before_services = service_snapshot(dut)
    yield
    assert json.loads(dut.command("sonic-cfggen -d --var-json PORT", verbose=False)["stdout"]) == before_ports
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
                    assert isinstance(value[endpoint][section], dict), "DOM section must be a dictionary"
                    if section != "thresholds":
                        assert value[endpoint][section], "DOM info/monitor section must not be empty"
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
    bulk = json_output(dut, "show interface " + command, optional=command == "tx-disable")
    assert set(bulk) == set(env["mapping"]), bulk
    table = run(dut, "show interface " + command)["stdout"]
    for port, mapping in env["mapping"].items():
        assert port in table
        selected = json_output(dut, "show interface {} -p {}".format(command, port))
        assert set(selected) == {port}, selected
        check_record(command, bulk[port], mapping)
        check_record(command, selected[port], mapping)
        assert port in run(dut, "show interface {} --port {}".format(command, port))["stdout"]
        if command in ("map", "presence"):
            assert selected[port] == bulk[port]
        if command == "presence":
            index = integers(env["ports"][port]["index"])[0]
            assert selected[port]["present"] == env["objects"][str(index)]["presence"]["value"]
        elif command == "tx-disable":
            index = integers(env["ports"][port]["index"])[0]
            values = env["objects"][str(index)]["tx_disable"]["value"]
            oe = env["topology"]["devices"][mapping["oe"]["id"]]
            width = len(integers(oe["asic_lanes"])) // int(oe.get("max_banks", 1))
            bank = mapping["oe"]["bank"]
            parent_lanes = integers(oe["asic_lanes"])[bank * width:(bank + 1) * width]
            if isinstance(values, dict):
                values = [value for _, value in sorted(values.items(), key=lambda item: int(
                    re.search(r"\d+$", str(item[0])).group()))]
            expected = {"lane{:02d}".format(lane): values[lane] for lane, asic_lane in enumerate(parent_lanes)
                        if asic_lane in mapping["oe"]["lanes"]}
            assert selected[port] == expected


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


def eeprom_pages(environment, port, target):
    index = integers(environment["ports"][port]["index"])[0]
    return environment["objects"][str(index)][target + "_pages"]


def eeprom_ranges(environment, port, target):
    """Select valid ranges from the actual endpoint map, never assume an ELS page-zero alias."""
    mapping = environment["mapping"][port]
    pages = eeprom_pages(environment, port, target)
    ranges = []
    if any(page["page"] == 0 and page["lower"] for page in pages):
        ranges.append((0, 0, 0))
    if target == "oe" and any(page["page"] == 0x10 and not page["lower"] for page in pages):
        ranges.append((mapping["oe"]["bank"], 0x10, 128))
    else:
        upper = sorted(page["page"] for page in pages if not page["lower"])
        if upper:
            bank = mapping["oe"]["bank"] if target == "oe" and upper[0] >= 0x10 else 0
            ranges.append((bank, upper[0], 128))
    assert ranges, "Endpoint map exposes no readable test range"
    return ranges


@pytest.mark.parametrize("target", ("oe", "els"))
@pytest.mark.parametrize("syntax", ("short-decimal", "long-hex"))
def test_eeprom_reads(cpo_environment, target, syntax):
    """Compare declared ranges through endpoint/interface paths without returning their bytes."""
    dut = cpo_environment["dut"]
    for port, mapping in cpo_environment["mapping"].items():
        name = mapping[target]["id"]
        for bank, page, offset in eeprom_ranges(cpo_environment, port, target):
            args = "-n {} -o {} -s 4".format(page, offset) if syntax == "short-decimal" else (
                "--page {} --offset {} --size 4".format(hex(page), hex(offset)))
            direct = run(dut, "read-eeprom {} --index {} --bank {} {}".format(
                target, int(name[len(target):]), bank, args))
            indirect = run(dut, "read-eeprom interface -p {} --{} {}".format(port, target, args))
            assert direct["eeprom"]["size"] == indirect["eeprom"]["size"] == 4
            assert direct["eeprom"]["sha256"] == indirect["eeprom"]["sha256"], "EEPROM paths disagree"


@pytest.mark.parametrize("target", ("oe", "els", "all"))
def test_eeprom_full_dump(cpo_environment, target):
    """Full dumps include every unique endpoint, not one duplicate per interface."""
    result = run(cpo_environment["dut"], "read-eeprom" + (" " + target if target != "all" else ""))
    expected = resources(cpo_environment, target) if target != "all" else (
        resources(cpo_environment, "oe") + resources(cpo_environment, "els"))
    names = [heading.removeprefix("EEPROM hexdump for ").lower() for heading in result["eeprom"]["headings"]]
    assert sorted(names) == sorted(expected), "EEPROM dump inventory mismatch"
    assert result["eeprom"]["size"] > 0


@pytest.mark.parametrize("target", ("oe", "els"))
@pytest.mark.parametrize("access", ("endpoint", "interface"))
def test_selected_eeprom_full_dump(cpo_environment, target, access):
    """Omitting all three range fields is a valid single-resource/interface full dump."""
    env = cpo_environment
    port = resources(env, "interface")[0]
    name = env["mapping"][port][target]["id"]
    arguments = "read-eeprom {} -i {}".format(target, int(name[len(target):])) if access == "endpoint" else (
        "read-eeprom interface --port {} --{}".format(port, target))
    result = run(env["dut"], arguments)
    assert result["eeprom"]["size"] > 0
    assert len(result["eeprom"]["headings"]) == 1
    expected = name if access == "endpoint" else "port {} ({})".format(port, name)
    assert result["eeprom"]["headings"][0] == "EEPROM hexdump for " + expected


@pytest.mark.parametrize("case", ARGUMENT_CASES, ids=lambda case: case[0])
def test_argument_matrix(cpo_environment, case):
    """Exercise missing fields, bad values and invalid combinations across every leaf command."""
    _, arguments, diagnostic, _ = case
    values = {"port": resources(cpo_environment, "interface")[0],
              "oe": int(resources(cpo_environment, "oe")[0][2:]),
              "els": int(resources(cpo_environment, "els")[0][3:])}
    result = run(cpo_environment["dut"], arguments.format(**values), rc=ERROR_RC)
    assert diagnostic in result["stderr"], "Incorrect argument-error category"


@pytest.mark.parametrize("command", HELP_COMMANDS, ids=lambda command: command or "root")
def test_command_help(cpo_environment, command):
    """Every group and leaf publishes help without changing hardware."""
    assert "Usage:" in run(cpo_environment["dut"], (command + " --help").strip())["stdout"]


FAULT_CASES = tuple(("read-eeprom", target, failure) for target in (
    "oe", "els", "interface-oe", "interface-els") for failure in (
        "none", "short", "oserror", "timeout", "unsupported", "attribute")) + tuple(
    ("write-eeprom", target, failure) for target in ("oe", "els", "interface-oe", "interface-els")
    for failure in ("false", "oserror", "timeout", "unsupported", "attribute")) + tuple(
    (operation, target, failure) for operation, target in (
        ("tx-disable", "interface"), ("lpmode", "oe"), ("reset", "oe"), ("lpmode", "els"), ("reset", "els"))
    for failure in ("false", "oserror", "timeout", "unsupported")) + (("tx-disable", "interface", "partial"),)


@pytest.mark.parametrize("case", FAULT_CASES, ids=lambda case: "-".join(case))
def test_simulated_io_failures(cpo_environment, case):
    """Installed CLI reports synthetic failures without a real platform/EEPROM write."""
    operation, target, failure = case
    script = (Path(__file__).parent / "files" / "cpo_faults.py").read_text(encoding="utf-8")
    payload = {"operation": operation, "target": target, "failure": failure}
    command = "sudo python3 -c {} {}".format(shlex.quote(script), shlex.quote(json.dumps(payload)))
    outer = cpo_environment["dut"].command(command, module_ignore_errors=True, verbose=False)
    assert outer["rc"] == 0, "Synthetic-fault helper failed; raw output suppressed"
    result = json.loads(outer["stdout"])
    assert result["rc"] == ERROR_RC and not result["traceback"], "Fault escaped CLI error handling"
    if operation == "read-eeprom":
        assert result["reads"] == 1 and result["writes"] == result["controls"] == 0
    elif operation == "write-eeprom":
        assert result["writes"] == 1 and result["reads"] == result["controls"] == 0
    else:
        assert result["controls"] == (2 if failure == "partial" else 1)
        assert result["reads"] == result["writes"] == 0
    assert result["unsupported"] if failure == "unsupported" and operation not in (
        "read-eeprom", "write-eeprom") else result["failed"]
    if failure == "partial":
        assert result["partial"], "Partial completion was not identified"


@pytest.mark.parametrize("arguments,diagnostic", (
    ("show oe temperature -1", "-1"), ("show els temperature -1", "-1"),
    ("read-eeprom oe -i {oe} -b 1 -n 0 -o 0 -s 1", "does not use bank selection"),
    ("show oe input-power", "no such command"), ("show els output-power", "no such command"),
    ("show els presence", "no such command"),
    ("config oe tx-disable 0 true", "no such command"), ("config els tx-disable 0 true", "no such command"),
    ("show interface lpmode", "no such command"),
    ("config interface lpmode -p __invalid_cpo_port__ low", "no such command"),
    ("config interface reset -p __invalid_cpo_port__", "no such command"),
))
def test_invalid_arguments(cpo_environment, arguments, diagnostic):
    """Rejected inputs and removed commands must return the CLI's documented error code."""
    arguments = arguments.format(oe=int(resources(cpo_environment, "oe")[0][2:]),
                                 els=int(resources(cpo_environment, "els")[0][3:]))
    result = run(cpo_environment["dut"], arguments, rc=ERROR_RC)
    assert diagnostic in result.get("stderr", "").lower(), result


@pytest.mark.parametrize("target", ("oe", "els"))
@pytest.mark.parametrize("operation", ("read-eeprom", "write-eeprom"))
def test_undeclared_eeprom_page(cpo_environment, target, operation):
    """Both read and write reject an address outside the endpoint's memory map."""
    env = cpo_environment
    selector = resources(env, target)[0]
    port = next(port for port, entry in env["mapping"].items() if entry[target]["id"].lower() == selector)
    declared = {page["page"] for page in eeprom_pages(env, port, target)}
    page = next((page for page in range(255, -1, -1) if page not in declared), None)
    if page is None:
        pytest.skip("Endpoint declares every possible page")
    args = "{} {} -i {} -n {} -o 128 ".format(operation, target, int(selector[len(target):]), page)
    result = run(env["dut"], args + ("-s 1" if operation == "read-eeprom" else "-d ff"), rc=ERROR_RC)
    assert "not declared" in result["stderr"], "Undeclared page must be rejected before hardware access"


@pytest.mark.parametrize("arguments,expected_rc", (("--help", 0),) + tuple(
    (command, 1) for command in LEAF_COMMANDS + ("read-eeprom",)))
def test_root_privileges(cpo_environment, arguments, expected_rc):
    """Top-level help is public; hardware commands reject an unprivileged user."""
    result = run(cpo_environment["dut"], arguments, rc=expected_rc, privileged=False)
    if expected_rc:
        assert "root privileges are required" in result["stderr"]
    else:
        assert "Usage:" in result["stdout"]


def test_sfp_coexistence(cpo_environment):
    """Ordinary SFP ports are absent from CPO output and are directed to sfputil."""
    dut = cpo_environment["dut"]
    ordinary = set(cpo_environment["ports"]) - set(cpo_environment["mapping"])
    if not ordinary:
        pytest.skip("No ordinary SFP ports on this DUT")
    for port in sorted(ordinary):
        result = run(dut, "show interface presence -p " + port, rc=ERROR_RC)
        assert "sfputil" in result["stderr"], result


@pytest.mark.parametrize("query", ("interface map", "oe temperature"))
def test_concurrent_queries(cpo_environment, query):
    """Independent read processes return complete, parseable mapping output."""
    dut = cpo_environment["dut"]
    # One transport call avoids concurrent use of an Ansible host object; each
    # CLI process still passes through DUT-side output projection.
    result = runner_request(dut, {"concurrent": ["show"] + query.split() + ["--json"]})
    assert len(result["jobs"]) == 4
    for item in result["jobs"]:
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
    assert command == "tx-disable", "Only Tx-disable is available at interface scope"
    indices = set(integers(environment["ports"][selector]["index"]))
    return sorted(port for port in mapping
                  if indices.intersection(integers(environment["ports"][port]["index"])))


def interfaces_up(dut, ports):
    status = dut.show_interface(command="status")["ansible_facts"]["int_status"]
    return all(status[port]["oper_state"] == "up" for port in ports)


@contextmanager
def isolated_ports(environment, ports):
    """Quiesce every shared port and restore admin/DOM settings even on failure."""
    dut = environment["dut"]
    baseline = dut.show_interface(command="status")["ansible_facts"]["int_status"]
    config = json.loads(dut.command("sonic-cfggen -d --var-json PORT", verbose=False)["stdout"])
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


@pytest.mark.parametrize("target", ("oe", "els"))
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
    query = "show interface tx-disable -p " + port
    original = json_output(dut, query, optional=True)
    # The setter acts on the whole physical port. Include every breakout sibling.
    affected = affected_ports(env, "interface", port, "tx-disable")
    originals = {name: json_output(dut, "show interface tx-disable -p " + name) for name in affected}
    states = {value for record in originals.values() for lanes in record.values() for value in lanes.values()}
    if len(states) != 1 or not all(isinstance(value, bool) for value in states):
        pytest.skip("Whole-port Tx setter cannot restore a mixed per-lane state")
    old = states.pop()
    if old:
        pytest.skip("Reprovisioning can enable TX; use an initially enabled physical port")
    command = "config interface tx-disable -p {} ".format(port)
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
                    assert wait_until(30, 2, 0, matches_json, dut, "show interface tx-disable -p " + name, expected)
        finally:
            if not unsupported:
                run(dut, command + str(old).lower())
                for name, record in originals.items():
                    assert wait_until(30, 2, 0, matches_json, dut, "show interface tx-disable -p " + name, record)
        if unsupported:
            pytest.skip("Platform explicitly does not implement Tx-disable")
    for name, record in originals.items():
        assert wait_until(30, 2, 0, matches_json, dut, "show interface tx-disable -p " + name, record), \
            "Tx-disable state changed during reprovisioning"


@pytest.mark.parametrize("target", ("oe", "els"))
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
    before = {port: {command: json_output(
                        dut, "show interface {} -p {}".format(command, port), optional=command == "tx-disable")
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
            assert wait_until(60, 2, 0, matches_json, dut, "show interface {} -p {}".format(command, port), record), \
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
    # A single DUT-side transaction keeps saved bytes out of controller logs and
    # pytest locals, and restores them even if write/readback fails.
    alias = None
    if access == "interface":
        banked = location["page"] >= 0x10 and not 0x9F <= location["page"] <= 0xAF
        candidates = [port for port, entry in cpo_environment["mapping"].items()
                      if entry[target]["id"].lower() == selector
                      and (entry["oe"]["bank"] if target == "oe" and banked else 0) == location["bank"]]
        if not candidates:
            pytest.skip("Approved scratch range has no matching interface/bank alias")
        alias = sorted(candidates)[0]
    port = next(port for port, entry in cpo_environment["mapping"].items()
                if entry[target]["id"].lower() == selector)
    pages = eeprom_pages(cpo_environment, port, target)
    selected = [page for page in pages if page["page"] == location["page"]]
    assert selected, "Approved scratch page is not declared by the endpoint"
    assert location["offset"] >= 128 or any(page["lower"] for page in selected), "Scratch lower half unavailable"
    assert location["offset"] + len(data) <= 128 or any(not page["lower"] for page in selected), \
        "Scratch upper half unavailable"
    with isolated_ports(cpo_environment, affected_ports(cpo_environment, target, selector, "eeprom")):
        result = runner_request(dut, {"scratch": location, "port": alias})
        assert result["rc"] == 0 and result["readback"] and result["restored"], \
            "Scratch operation failed; retained private recovery file: {}".format(result.get("recovery_file"))
