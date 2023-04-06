import pytest
import time
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.console_helper import assert_expect_text, create_ssh_client, ensure_console_session_up


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

BAUD_RATE_MAP = {
    "default": "9600"
}
BOOT_TYPE = {
    "armhf-nokia_ixs7215_52x-r0": "UBoot-ONIE",
    "x86_64-arista_720dt_48s": "ABoot"
}
pass_config_test = True


def is_sonic_console(conn_graph_facts, dut_hostname):
    return conn_graph_facts['device_console_info'][dut_hostname]["Os"] == "sonic"


def test_console_baud_rate_config(duthost):
    global pass_config_test
    pass_config_test = False
    platform = duthost.facts["platform"]
    expected_baud_rate = BAUD_RATE_MAP[platform] if platform in BAUD_RATE_MAP else BAUD_RATE_MAP["default"]
    res = duthost.shell("cat /proc/cmdline | grep -Eo 'console=ttyS[0-9]+,[0-9]+' | cut -d ',' -f2",
                        module_ignore_errors=True)
    pytest_assert(res["rc"] == 0 and res["stdout"] == expected_baud_rate, "Baud rate {} is unexpected!"
                  .format(res["stdout"]))
    pass_config_test = True


@pytest.fixture(scope="module")
def console_client_setup_teardown(duthost, conn_graph_facts, creds):
    pytest_assert(pass_config_test, "Fail due to failure in test_console_baud_rate_config.")
    dut_hostname = duthost.hostname
    console_host = conn_graph_facts['device_console_info'][dut_hostname]['ManagementIp']
    pytest_require(is_sonic_console(conn_graph_facts, dut_hostname), "Unsupport non-sonic console swith.")
    console_port = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['peerport']
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    client = None
    try:
        client = create_ssh_client(console_host, "{}:{}".format(dutuser, console_port), dutpass)
    except Exception as err:
        pytest.fail("Not connect console ssh, error: {}".format(err))

    ensure_console_session_up(client, console_port)
    client.sendline()
    assert_expect_text(client, "login:", console_port, timeout_sec=1)
    client.sendline(dutuser)
    client.sendline(dutpass)
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
    assert_expect_text(client, "Last login:", console_port, timeout_sec=5)


def test_baud_rate_boot_connect(duthost, console_client_setup_teardown, boot_connect_teardown):
    client, console_port = console_client_setup_teardown
    platform = duthost.facts["platform"]
    pytest_require(platform in BOOT_TYPE, "Unsupported platform: {}".format(platform))
    client.sendline("sudo reboot")
    if BOOT_TYPE[platform] == "ABoot":
        run_aboot_test(client, console_port)
    elif BOOT_TYPE[platform] == "UBoot-ONIE":
        run_uboot_onie_test(client, console_port)
