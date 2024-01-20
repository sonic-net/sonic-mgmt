"""
Fault insertion tests for platform.
"""
import time
import logging
import pytest
import re
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.cisco.common.utils import skip_if_sim


pytestmark = [
    pytest.mark.topology('t2')
]

RP_SWITCH_MGMT_PORT = '28'
LC_SWITCH_ETH1_PORT = '10'

def test_eth_switch_monitor(duthosts, enum_rand_one_per_hwsku_hostname, skip_if_sim):
    """
    @summary: Check ethswitch monitoring service
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command("systemctl status platform-ethswitch.service")
    logging.info(result)

    assert "active (running)" in str(result), "Ethernet switch monitor service is not running"


def test_eth_switch_appDemo(duthosts, enum_rand_one_per_hwsku_hostname, skip_if_sim):
    """
    @summary: Check ethswitch appdemo process
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command("ps -C appDemo")
    logging.info(result)

    assert "appDemo" in str(result), "Appdemo process is not running"


def test_eth_switch_cli(duthosts, enum_rand_one_per_hwsku_hostname, skip_if_sim):
    """
    @summary: Check the ethernet switch CLI
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_supervisor_node():
        port = RP_SWITCH_MGMT_PORT
    else:
        port = LC_SWITCH_ETH1_PORT

    result = duthost.command("show platform eth-switch interfaces status ethernet 0/{}".format(port));
    logging.info(result)

    assert "Up" in str(result), "Failed to get link state in CLI"


def test_eth_switch_monitor_midplane_fault(duthosts, enum_rand_one_per_hwsku_hostname, skip_if_sim):
    """
    @summary: Inject an fault on midplane link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("Not supported on RP")

    result = duthost.command("ifconfig eth1-midplane down")
    logging.info(result)

    result = duthost.command("ifconfig eth1-midplane")
    assert "UP" not in str(result), "Failed to down eth1-midplane"

    time.sleep(130)

    result = duthost.command("ifconfig eth1-midplane")
    print(result)
    assert "UP" in str(result), "Ethernet switch service failed to recover eth1-midplane"


def test_eth_switch_monitor_eth0_fault(duthosts, localhost, enum_rand_one_per_hwsku_hostname, skip_if_sim):
    """
    @summary: Inject an fault on eth0 link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("Not supported on RP")

    result = duthost.command("ifconfig eth0 down")
    logging.info(result)

    # SSH will drop and will be available after recovery
    wait_for_startup(duthost, localhost, 0, 60)

    result = duthost.command("ifconfig eth0")
    assert "UP" in str(result), "Ethernet switch service failed to recover eth0"


def test_eth_switch_inject_link_error(duthosts, localhost, enum_rand_one_per_hwsku_hostname, skip_if_sim):
    """
    @summary: Inject link errors and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("Not supported on RP")
    else:
        port = LC_SWITCH_ETH1_PORT

    result = duthost.command("mkdir -p /tmp/rx_err_pkt_test_inject/0")
    logging.info(result)

    try:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='eth_switch_inject')
        loganalyzer.expect_regex = []

        #grep for rx err pkt: alarm raised at
        loganalyzer.expect_regex.append("rx err pkt: alarm raised at")

        with loganalyzer:
            result = duthost.command("touch /tmp/rx_err_pkt_test_inject/0/{}".format(port))
            time.sleep(130)

    except LogAnalyzerError:
        pytest.fail("Not found alarm message for Rx error packets.")

    try:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='eth_switch_inject')
        loganalyzer.expect_regex = []

        # grep for rx err pkt: alarm cleared at
        loganalyzer.expect_regex.append("rx err pkt: alarm cleared")

        with loganalyzer:
            result = duthost.command("rm /tmp/rx_err_pkt_test_inject/0/{}".format(port))
            time.sleep(90)

    except LogAnalyzerError:
        pytest.fail("Not found clear alarm message for Rx error packets.")

