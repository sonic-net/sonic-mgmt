import pytest
import time
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.console_helper import assert_expect_text, create_ssh_client, ensure_console_session_up


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.disable_memory_utilization
]

BOOT_TYPE = {
    "armhf-nokia_ixs7215_52x-r0": "UBoot-ONIE",
    "x86_64-arista_720dt_48s": "ABoot"
}
pass_config_test = True


def is_sonic_console(conn_graph_facts, dut_hostname):
    return conn_graph_facts['device_console_info'][dut_hostname].get("Os", "") == "sonic"


def get_expected_baud_rate(duthost):
    DEFAULT_BAUDRATE = 9600
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    return hostvars.get('console_baudrate', DEFAULT_BAUDRATE)


def test_console_baud_rate_config(duthost):
    expected_baud_rate = get_expected_baud_rate(duthost)
    res = duthost.shell("cat /proc/cmdline | grep -Eo 'console=ttyS[0-9]+,[0-9]+' | cut -d ',' -f2")
    pytest_require(res["stdout"] != "", "Cannot get baud rate")
    if res["stdout"] != str(expected_baud_rate):
        global pass_config_test
        pass_config_test = False
        pytest.fail("Device baud rate is {}, expected {}".format(res["stdout"], expected_baud_rate))


@pytest.fixture(scope="module")
def console_client_setup_teardown(duthost, conn_graph_facts, creds):
    pytest_assert(pass_config_test, "Fail due to failure in test_console_baud_rate_config.")
    dut_hostname = duthost.hostname
    if "ManagementIp" not in conn_graph_facts['device_console_info'][dut_hostname]:
        pytest.skip("Console port does not exist in console_links.csv file. Skipping {}".format(dut_hostname))
    console_host = conn_graph_facts['device_console_info'][dut_hostname]['ManagementIp']
    if "/" in console_host:
        console_host = console_host.split("/")[0]
    console_type = conn_graph_facts['device_console_link'][dut_hostname]["ConsolePort"]["type"]
    pytest_require(console_type == "ssh", "Unsupported console type: {}".format(console_type))
    pytest_require(is_sonic_console(conn_graph_facts, dut_hostname), "Unsupport non-sonic console swith.")
    console_port = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['peerport']
    console_user = creds['console_user']['console_ssh']
    console_passwords = creds['console_password']['console_ssh']

    client = None
    for console_password in console_passwords:
        try:
            client = create_ssh_client(console_host, "{}:{}".format(console_user, console_port), console_password)
            ensure_console_session_up(client, console_port)
        except Exception:
            client = None
        else:
            break

    pytest_assert(client is not None, "Cannot connect to console device")
    client.sendline()
    yield client, console_port

    if client is not None:
        time.sleep(2)
        client.terminate()


@pytest.fixture(scope="module")
def boot_connect_teardown(console_client_setup_teardown):
    yield
    client, _ = console_client_setup_teardown
    if client is not None:
        client.sendline("reboot")
        # Wait DUT to reboot
        time.sleep(120)


def run_aboot_test(client, console_port):
    assert_expect_text(client, "Press Control-C now to enter Aboot shell", console_port, timeout_sec=120)
    client.sendcontrol("c")
    assert_expect_text(client, "Aboot#", console_port, timeout_sec=2)


def run_uboot_onie_test(client, console_port):
    assert_expect_text(client, "Hit any key to stop autoboot", console_port, timeout_sec=180)
    client.sendline()
    assert_expect_text(client, "Marvell>>", console_port, timeout_sec=2)
    client.sendline("run onie_bootcmd")
    assert_expect_text(client, "Please press Enter to activate this console", console_port, timeout_sec=60)
    client.sendline()
    assert_expect_text(client, "ONIE:/ #", console_port, timeout_sec=60)


def test_baud_rate_sonic_connect(console_client_setup_teardown):
    client, console_port = console_client_setup_teardown
    assert_expect_text(client, "login:", console_port, timeout_sec=1)


def test_baud_rate_boot_connect(duthost, console_client_setup_teardown, boot_connect_teardown):
    client, console_port = console_client_setup_teardown
    platform = duthost.facts["platform"]
    pytest_require(platform in BOOT_TYPE, "Unsupported platform: {}".format(platform))
    duthost.shell("sudo reboot", module_async=True)
    if BOOT_TYPE[platform] == "ABoot":
        run_aboot_test(client, console_port)
    elif BOOT_TYPE[platform] == "UBoot-ONIE":
        run_uboot_onie_test(client, console_port)
