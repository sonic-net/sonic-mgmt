import time
import logging
import pytest
from tests.vxlan.vnet_monitor_utils import add_vnet_ping_task, remove_vnet_ping_task
from tests.vxlan.vnet_monitor_utils import verity_vnet_monitor_state, block_reply_for_vip, unblock_reply_for_vip
from tests.vxlan.vnet_monitor_utils import setup_info, setup_vnet_ping_responder # noqa F401
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t1")
]

# T0_lo, VIP
IPV4_TEST_DATA = [
    ("10.0.0.1", "20.0.0.1/32"),
    ("10.0.0.2", "20.0.0.2/24"),
    ("10.0.0.3", "20.0.0.3")
]

# T0_lo, VIP
# T0 Loopback is always IPv4
IPV6_TEST_DATA = [
    ("10.0.0.1", "fc01::1/128"),
    ("10.0.0.2", "fc01::2/64"),
    ("10.0.0.3", "fc01::3")
]


@pytest.fixture(params=["ipv4", "ipv6"])
def ipver(request):
    return request.param


@pytest.fixture(scope='module', autouse=True)
def check_vnet_monitor_feature(rand_selected_dut):
    feature_status, ret = rand_selected_dut.get_feature_status()
    KEY = 'vnet-monitor'
    if not ret or KEY not in feature_status or feature_status[KEY] != "enabled":
        pytest.skip('{} feature is not enabled on DUT'.format(KEY))


def wait_vnet_ping_state(duthost, t0_lo, vip, state):
    """
    Wait for vnet ping state to be as expected.
    """
    TIMEOUT = 10
    pytest_assert(
            wait_until(TIMEOUT, 1, 0, verity_vnet_monitor_state, duthost, t0_lo, vip, state),
            "State of t0 {} vip {} is not {}".format(t0_lo, vip, state)
        )


def test_vnet_monitor(rand_selected_dut, ptfhost, ipver, setup_vnet_ping_responder): # noqa F401
    """
    Test basic functionality of vnet monitor.
    """

    if ipver == "ipv4":
        test_data = IPV4_TEST_DATA
    else:
        test_data = IPV6_TEST_DATA

    # Initialize state should be up
    for t0_lo, vip in test_data:
        add_vnet_ping_task(rand_selected_dut, t0_lo, vip)
        wait_vnet_ping_state(rand_selected_dut, t0_lo, vip, "up")

    # Block each VIP and verify state is down
    for i in range(len(test_data)):
        t0_lo, vip = test_data[i]
        block_reply_for_vip(ptfhost, vip)
        # The one we blocked should be down
        wait_vnet_ping_state(rand_selected_dut, t0_lo, vip, "down")

        # Others should be up
        for other_t0_lo, other_vip in test_data[:i] + test_data[i+1:]:
            verity_vnet_monitor_state(rand_selected_dut, other_t0_lo, other_vip, "up")

        unblock_reply_for_vip(ptfhost, vip)
        # The one we unblocked should be up after unblocking
        wait_vnet_ping_state(rand_selected_dut, t0_lo, vip, "up")

    # Remove all tasks
    for t0_lo, vip in test_data:
        remove_vnet_ping_task(rand_selected_dut, t0_lo, vip)


def _wait_portchannel_up(duthost, portchannel):
    def _check_lag_status():
        cmd = "show interface portchannel | grep {}".format(portchannel)
        return '(Up)' in duthost.shell(cmd)['stdout']

    if not wait_until(300, 10, 30, _check_lag_status):
        pytest.fail("PortChannel didn't startup")
    # Wait another 60 seconds for routes announcement
    time.sleep(60)


def test_vnet_monitor_with_intf_toggle(rand_selected_dut, ipver, setup_info, setup_vnet_ping_responder): # noqa F401
    """
    Test vnet monitor with interface toggle.
    Steps:
    1. Shutdown a portchannel interface
    2. Restart vnet_monitor service with 1 portchannel shutdown
    3. Startup the portchannel interface shutdown in step 1
    4. Send vnet_ping via the portchannel interface being toggled (with static route)
    5. Verify vnet_ping state is up
    """
    test_ips = None
    try:
        # Shutdown a portchannel on DUT
        portchannel_to_toggle = setup_info['portchannel']
        cmd = "config interface shutdown {}".format(portchannel_to_toggle)
        rand_selected_dut.shell(cmd)
        # Restart vnet_monitor service
        rand_selected_dut.shell("sudo systemctl unmask vnet-monitor")
        rand_selected_dut.shell("sudo systemctl restart vnet-monitor")
        # Startup the portchannel
        cmd = "config interface startup {}".format(portchannel_to_toggle)
        rand_selected_dut.shell(cmd)
        _wait_portchannel_up(rand_selected_dut, portchannel_to_toggle)
        # Configure static route
        if ipver == "ipv4":
            test_ips = IPV4_TEST_DATA[0]
        else:
            test_ips = IPV6_TEST_DATA[0]
        # As the T0 Loopback address is always IPV4, so we only need to add static route for IPV4
        cmd = "ip route add {} nexthop via {}".format(IPV4_TEST_DATA[0][0], setup_info['portchannel_ipv4_neigh'])
        rand_selected_dut.shell(cmd)
        # Add vnet ping task
        add_vnet_ping_task(rand_selected_dut, test_ips[0], test_ips[1])
        # Verify state is up
        wait_vnet_ping_state(rand_selected_dut, test_ips[0], test_ips[1], "up")
    finally:
        # Remove static routes
        cmd = "ip route del {}".format(IPV4_TEST_DATA[0][0])
        rand_selected_dut.shell(cmd, module_ignore_errors=True)
        # Startup the portchannel
        cmd = "config interface startup {}".format(portchannel_to_toggle)
        if test_ips:
            remove_vnet_ping_task(rand_selected_dut, test_ips[0], test_ips[1])


def test_no_fd_leak_at_link_flap(rand_selected_dut, setup_info): # noqa F401
    """
    This test is to verify no file descriptor leak when link flaps.
    """
    # Get the PID of vnet_monitor process
    pid = rand_selected_dut.shell("pgrep vnet_monitor.py")['stdout']
    pytest_assert(pid != "", "vnet_monitor process not found")
    # Get the open fd count of vnet_monitor process
    cmd_get_fd = "ls -l /proc/{}/fd | wc -l".format(pid)
    fd_count_base = rand_selected_dut.shell(cmd_get_fd)['stdout']
    # Toggle the portchannel intensively
    portchannel_to_toggle = setup_info['portchannel']
    TOGGLE_COUNT = 20
    for i in range(TOGGLE_COUNT):
        cmd = "config interface shutdown {}".format(portchannel_to_toggle)
        rand_selected_dut.shell(cmd)
        time.sleep(1)
        cmd = "config interface startup {}".format(portchannel_to_toggle)
        rand_selected_dut.shell(cmd)
        time.sleep(1)

    def _fd_leak_detected():
        MARGIN = 5
        # Get the open fd count of vnet_monitor process after port flapping
        fd_count_after = rand_selected_dut.shell(cmd_get_fd)['stdout']
        return int(fd_count_after) - int(fd_count_base) <= MARGIN

    pytest_assert(wait_until(300, 10, 5, _fd_leak_detected), "File descriptor leak detected")
