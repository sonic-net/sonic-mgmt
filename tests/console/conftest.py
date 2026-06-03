import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401


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
        console_fanout = duthost
    else:
        pytest.fail("Test requires c0 or c0-lo topology")

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
