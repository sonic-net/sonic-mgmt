import re
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401


console_lines = list(map(str, range(1, 49)))


@pytest.fixture(scope="module", autouse=True)
def skip_if_os_not_support(duthost):
    not_support_os_versions = ['201803', '201807', '201811', '201911']
    dut_os_version = duthost.os_version
    if any(os_version in dut_os_version for os_version in not_support_os_versions):
        pytest.skip("Skip test due to the console switch feature is not supported on {}".format(dut_os_version))
    yield


@pytest.fixture(scope="module", autouse=True)
def skip_if_console_feature_disabled(console_facts):
    if not console_facts['enabled']:
        pytest.skip("Skip test due to the console switch feature is not enabled for current DUT.")
    yield


@pytest.fixture(scope='module')
def setup_c0(request, duthost, tbinfo):
    # Verify console lines are configured as expected
    # we have a console_facts fixture but it's probably better to run it every time it's called
    topo_console_intfs = tbinfo["topo"]["properties"]["topology"]["console_interfaces"]
    dut_console_config = duthost.console_facts()["ansible_facts"]["console_facts"]["lines"]
    for topo_console_intf in topo_console_intfs:
        line_number, baud_rate, flow_control = topo_console_intf.split(".")
        dut_line_config = dut_console_config[line_number]
        if dut_line_config["baud_rate"] != int(baud_rate):
            pytest.fail("Baud rate mismatch for line {}: expect {}, got {}".format(line_number, baud_rate,
                                                                                   dut_line_config["baud_rate"]))
        if dut_line_config["flow_control"] != bool(int(flow_control)):
            pytest.fail("Flow control mismatch for line {}: expect {}, got {}".format(line_number,
                                                                                      bool(int(flow_control)),
                                                                                      dut_line_config["flow_control"]))

    if tbinfo["topo"]["name"] == "c0":
        fanouthosts = request.getfixturevalue("fanouthosts")
        console_fanouts = list(filter(lambda fh: fh.get_fanout_os() == 'sonic' and fh.is_console_switch(),
                                      fanouthosts.values()))
        if len(console_fanouts) != 1:
            pytest.fail("Test requires exactly one console switch fanout device (could be dut itself)")
        console_fanout = console_fanouts[0].host
    elif tbinfo["topo"]["name"] == "c0-lo":
        console_fanout = duthost
    else:
        pytest.fail("Test requires c0 or c0-lo topology")

    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    if len(console_facts["lines"]) != len(console_lines):
        pytest.fail("C0 topo test requires DUT with 48 console lines configured, got {}"
                    .format(len(console_facts["lines"])))

    return duthost, console_fanout


@pytest.fixture(scope='module')
def console_facts(duthost):
    return duthost.console_facts()['ansible_facts']['console_facts']


@pytest.fixture(scope="module")
def cleanup_modules(setup_c0):
    '''
    Reset all console lines before and after the script runs. Sometime socat or
    other programs can leave the lines inaccessible.
    '''
    duthost, console_fanout = setup_c0
    duthost.shell("rmmod nim_async_lite; rmmod tty_async; modprobe nim_async_lite ", module_ignore_errors=True)
    duthost.shell("sudo killall socat", module_ignore_errors=True)

    if console_fanout != duthost:
        console_fanout.shell("rmmod nim_async_lite; rmmod tty_async; modprobe nim_async_lite ",
                             module_ignore_errors=True)
        console_fanout.shell("sudo killall socat", module_ignore_errors=True)

    yield
    duthost.shell("sudo killall socat", module_ignore_errors=True)
    duthost.shell("rmmod nim_async_lite; rmmod tty_async; modprobe nim_async_lite ", module_ignore_errors=True)

    if console_fanout != duthost:
        console_fanout.shell("sudo killall socat", module_ignore_errors=True)
        console_fanout.shell("rmmod nim_async_lite; rmmod tty_async; modprobe nim_async_lite ",
                             module_ignore_errors=True)


def _get_serial_device_prefix(host):
    """
    Try to read platform udevprefix.conf to determine serial device prefix.
    Falls back to /dev/ttyUSB if it cannot be determined (non-SONiC host, missing file, etc.).
    """
    script = r"""
from sonic_py_common import device_info
import os

platform_path, _ = device_info.get_paths_to_platform_and_hwsku_dirs()
config_file = os.path.join(platform_path, "udevprefix.conf")

if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        device_prefix = "/dev/" + f.readline().rstrip()
else:
    raise FileNotFoundError("udevprefix.conf not found")

print(device_prefix)
""".strip()

    cmd = "python3 << 'EOF'\n{}\nEOF".format(script)
    res = host.shell(cmd, module_ignore_errors=True)
    prefix = (res.get("stdout") or "").strip()
    if res.get("rc") != 0 or not prefix:
        return "/dev/ttyUSB"
    return prefix


def _console_dev(host, port_idx):
    """
    Return the console device path for a given line/port index.
    """
    try:
        # Prefer platform helper when available (SonicHost)
        return host._get_serial_device_path(int(port_idx))
    except Exception:
        return "{}{}".format(_get_serial_device_prefix(host), port_idx)


def _get_tty_driver_name(host, device_prefix):
    """
    Resolve the /proc/tty/driver/<name> file to use for a given /dev prefix.
    """
    drivers = host.shell("cat /proc/tty/drivers", module_ignore_errors=True).get("stdout") or ""
    for line in drivers.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == device_prefix:
            return parts[0]
    raise AssertionError("Failed to resolve tty driver for device prefix {} on {}"
                         .format(device_prefix, getattr(host, "hostname", host)))


def get_driver_stats(host, port_idx):
    """
    Parse /proc/tty/driver/<name> to get tx/rx counters for a console line.
    """
    device_path = _console_dev(host, str(port_idx))
    device_prefix = re.sub(r'\d+$', '', device_path)
    driver_name = _get_tty_driver_name(host, device_prefix)
    out = host.shell("cat /proc/tty/driver/{} | grep '^{}:'".format(driver_name, port_idx),
                     module_ignore_errors=True).get("stdout", "").strip()
    if not out:
        raise AssertionError("No driver stats found for port {} on {}".format(port_idx, host))
    tx_match = re.search(r'tx:(\d+)', out)
    rx_match = re.search(r'rx:(\d+)', out)
    if not tx_match or not rx_match:
        raise AssertionError("Failed to parse tx/rx from driver stats on {}: {}".format(host, out))
    return {
        "tx": int(tx_match.group(1)),
        "rx": int(rx_match.group(1))
    }
