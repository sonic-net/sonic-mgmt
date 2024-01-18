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


pytestmark = [
    pytest.mark.topology('t2')
]


class CheckEnvironment:
    _is_sim = None

    @staticmethod
    def is_sim(duthost):
        return False
        if CheckEnvironment._is_sim is None:
            result = duthost.shell("dmidecode | grep QEMU")['stdout']
            if result:
                CheckEnvironment._is_sim = True
                logging.info("In simulation env")
            else:
                CheckEnvironment._is_sim = False
                logging.info("In hardware env")
        return CheckEnvironment._is_sim


def test_eth_switch_monitor(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Check ethswitch monitoring service
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Not supported in SIM")

    result = duthost.command("systemctl status platform-ethswitch.service")
    logging.info(result)

    assert "active (running)" in str(result), "Etherner switch monitor service is not running"


def test_eth_switch_appDemo(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Check ethswitch appdemo process
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Not supported in SIM")

    result = duthost.command("ps -C appDemo")
    logging.info(result)

    assert "appDemo" in str(result), "Appdemo process is not running"


def test_eth_switch_cli(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an fault on midplane link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Not supported in SIM")

    if duthost.is_supervisor_node():
        port = "28"
    else:
        port = "10"

    result = duthost.command("show platform eth-switch interfaces status ethernet 0/{}".format(port));
    logging.info(result)

    assert "Up" in str(result), "Failed to get link state in CLI"


def test_eth_switch_monitor_midplane_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an fault on midplane link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Not supported in SIM")

    result = duthost.command("ifconfig eth1-midplane down")
    logging.info(result)

    result = duthost.command("ifconfig eth1-midplane")
    assert "UP" not in str(result), "Failed to down eth1-midplane"

    time.sleep(130)

    result = duthost.command("ifconfig eth1-midplane")
    print(result)
    assert "UP" in str(result), "Ethernet switch service failed to recover eth1-midplane"


def test_eth_switch_monitor_eth0_fault(duthosts, localhost, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an fault on eth0 link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Not supported in SIM")

    result = duthost.command("ifconfig eth0 down")
    logging.info(result)

    # SSH will drop and will be available after recovery
    wait_for_startup(duthost, localhost, 0, 60)

    result = duthost.command("ifconfig eth0")
    assert "UP" in str(result), "Ethernet switch service failed to recover eth0"


def test_eth_switch_inject_link_error(duthosts, localhost, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an fault on eth0 link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if CheckEnvironment.is_sim(duthost):
        pytest.skip("Not supported in SIM")

    if duthost.is_supervisor_node():
        port = "28"
    else:
        port = "10"

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

