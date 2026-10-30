import re
import shlex
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from tests.common.helpers.console_helper import generate_random_string


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
def setup_c0(request, duthost, tbinfo, conn_graph_facts):    # noqa: F811
    # Verify the DUT's wired console lines (from *_serial_links.csv via
    # conn_graph_facts) match the DUT's configured baud rate / flow control.
    dut_serial_links = conn_graph_facts.get('device_serial_link', {}).get(duthost.hostname, {})
    if not dut_serial_links:
        pytest.fail(
            "No serial links found for DUT '{}' in *_serial_links.csv".format(duthost.hostname))

    dut_console_config = duthost.console_facts()["ansible_facts"]["console_facts"]["lines"]
    for line_number, link in dut_serial_links.items():
        if line_number not in dut_console_config:
            pytest.fail(
                "Line {} is wired to DUT '{}' in *_serial_links.csv but is not configured on the DUT"
                .format(line_number, duthost.hostname))
        dut_line_config = dut_console_config[line_number]
        expected_baud = int(link.get("baud_rate", "9600"))
        expected_flow = bool(int(link.get("flow_control", "0")))
        if dut_line_config["baud_rate"] != expected_baud:
            pytest.fail("Baud rate mismatch for line {}: expect {}, got {}".format(
                line_number, expected_baud, dut_line_config["baud_rate"]))
        if dut_line_config["flow_control"] != expected_flow:
            pytest.fail("Flow control mismatch for line {}: expect {}, got {}".format(
                line_number, expected_flow, dut_line_config["flow_control"]))

    if tbinfo["topo"]["name"] == "c0":
        fanouthosts = request.getfixturevalue("fanouthosts")
        console_fanouts = list(filter(lambda fh: fh.get_fanout_os() == 'sonic' and fh.is_console_switch(),
                                      fanouthosts.values()))
        if len(console_fanouts) != 1:
            pytest.fail("Test requires exactly one console switch fanout device (could be dut itself)")
        console_fanout = console_fanouts[0].host
    elif tbinfo["topo"]["name"] == "c0-lo":
        # Loopback: exercise console path on the DUT without a separate fanout.
        console_fanout = duthost
    else:
        pytest.fail("Test requires c0 or c0-lo topology")

    return duthost, console_fanout


@pytest.fixture(scope='module')
def console_facts(duthost):
    return duthost.console_facts()['ansible_facts']['console_facts']


@pytest.fixture(scope="module")
def cleanup_modules(setup_c0):
    """
    Best-effort cleanup for console tests: kill stray socat on DUT and fanout, and reload
    nim_async_lite/tty_async where present (ignored on images without those modules).
    """
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


def _get_tty_driver_name(host, port_idx):
    """
    Resolve the /proc/tty/driver/<name> file to use for a given /dev prefix.

    Returns:
        tuple: (driver_name, driver_port_id)
            driver_name - first column in /proc/tty/drivers for the matched driver.
            driver_port_id - str minor/index after the matched devfs prefix in readlink output
                (e.g. /dev/ttyCO0 -> "0"); used for lines in /proc/tty/driver/<driver_name>.
    """
    device_path = (host.shell("readlink -f {}{}".format(host.get_serial_device_prefix(), port_idx)).get("stdout")
                   or "").strip()
    drivers = host.shell("cat /proc/tty/drivers", module_ignore_errors=True).get("stdout") or ""
    # Column 2 is the driver's devfs prefix (e.g. /dev/ttyCO); readlink returns the full node (e.g. /dev/ttyCO0).
    # Match by longest prefix so /dev/ttyCO beats the generic /dev/tty line.
    best_name = None
    best_prefix = None
    best_len = -1
    for line in drivers.splitlines():
        parts = line.split()
        if len(parts) >= 2 and device_path.startswith(parts[1]):
            plen = len(parts[1])
            if plen > best_len:
                best_len = plen
                best_name = parts[0]
                best_prefix = parts[1]
    if best_name and best_prefix is not None:
        remainder = device_path[len(best_prefix):]
        if remainder.isdigit():
            driver_port_id = remainder
        else:
            driver_port_id = str(port_idx)
        return best_name, driver_port_id
    raise AssertionError("Failed to resolve tty driver for device path {} on {}"
                         .format(device_path, getattr(host, "hostname", host)))


def get_driver_stats(host, port_idx):
    """
    Parse /proc/tty/driver/<name> for tx/rx counters for a logical console line.

    Resolves the driver and driver line index from readlink + /proc/tty/drivers (see _get_tty_driver_name).
    """
    driver_name, driver_port_id = _get_tty_driver_name(host, port_idx)
    out = host.shell("cat /proc/tty/driver/{} | grep '^{}:'".format(driver_name, driver_port_id),
                     module_ignore_errors=True).get("stdout", "").strip()
    if not out:
        raise AssertionError(
            "No driver stats for logical line {} (driver {} line {}) on {}".format(
                port_idx, driver_name, driver_port_id, host))
    tx_match = re.search(r'tx:(\d+)', out)
    rx_match = re.search(r'rx:(\d+)', out)
    if not tx_match or not rx_match:
        raise AssertionError("Failed to parse tx/rx from driver stats on {}: {}".format(host, out))
    return {
        "tx": int(tx_match.group(1)),
        "rx": int(rx_match.group(1))
    }


def build_chunked_text_data(host, total_mb, chunk_size, seed="ABC",
                            data_path="/tmp/sonic-mgmt-flow-control-data.txt"):
    """
    Build a text payload on host sized to `total_mb` bytes.
    The repeated chunk is created using shared `generate_random_string`.
    """
    total_bytes = max(1, int(total_mb * 1024 * 1024))
    chunk_bytes = max(1, int(chunk_size))

    chunk_text = generate_random_string(chunk_bytes)
    if seed:
        chunk_text = (seed + chunk_text)[:chunk_bytes]

    cmd = "yes {} | tr -d '\\n' | head -c {} > {}".format(
        shlex.quote(chunk_text),
        total_bytes,
        shlex.quote(data_path)
    )
    host.shell("bash -lc {}".format(shlex.quote(cmd)))
    return data_path
