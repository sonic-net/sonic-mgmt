"""
Tests for voq watchdog
"""

import logging
import pytest
import time

from tests.common.fixtures.duthost_utils import dut_qos_maps            # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory # noqa F401
from tests.common.helpers.assertions import pytest_assert
from .qos_base import QosBase

logger = logging.getLogger(__name__)
pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t2')
]

PTF_FILE_DIR = 'ptftests'
VOQ_WATCHDOG_TIMEOUT_SECONDS = 60
SAI_LOG_TO_CHECK = ["HARDWARE_WATCHDOG", "soft_reset"]
SDK_LOG_TO_CHECK = ["VOQ Appears to be stuck"]
SAI_LOG = "/var/log/sai.log"
SDK_LOG = "/var/log/syslog"
PKT_SIZE = 1024
PKT_COUNT = 1000


def init_log_check(duthost):
    pre_offsets = []
    for logfile in [SAI_LOG, SDK_LOG]:
        offset_cmd = "stat -c %s {}".format(logfile)
        pre_offsets.append(int(duthost.shell(offset_cmd)["stdout"]))
    return pre_offsets


def verify_log(duthost, pre_offsets, voq_watchdog_enable=True):
    found_list = []
    for pre_offset, logfile, str_to_check in zip(pre_offsets, [SAI_LOG, SDK_LOG],
                                                 [SAI_LOG_TO_CHECK, SDK_LOG_TO_CHECK]):
        egrep_str = '|'.join(str_to_check)
        check_cmd = "tail -c +{} {} | egrep '{}' | grep -v 'ansible' || true".format(pre_offset + 1, logfile, egrep_str)
        result = duthost.shell(check_cmd)
        logging.debug("Log for {}: {}".format(egrep_str, result["stdout"]))
        for string in str_to_check:
            if string in result["stdout"]:
                found_list.append(True)
            else:
                found_list.append(False)
    if voq_watchdog_enable:
        pytest_assert(all(found is True for found in found_list),
                      "VOQ watchdog trigger not detected")
    else:
        pytest_assert(all(found is False for found in found_list),
                      "unexpected VOQ watchdog trigger")


class TestVoqWatchdog(QosBase):
    def testVoqWatchdog(self, get_src_dst_asic_and_duts, dutConfig, dutTestParams, ptfhost):
        """
        Verify voq watchdog is functional by default
        tx disable, send traffic, sleep 60 seconds, verify soft_reset is triggered
        """

        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        pre_offsets = init_log_check(dst_dut)

        # tx disable
        dst_port_id = dutConfig["testPorts"]["dst_port_id"]
        tx_disable_cmd = "sudo config platform cisco interface {} tx disable"
        if "lagMembers" in dutConfig["dutPorts"][dst_port_id]:
            for port in dutConfig["dutPorts"][dst_port_id]["lagMembers"]:
                dst_dut.command(tx_disable_cmd.format(port))
        else:
            dst_dut.command(tx_disable_cmd.format(dutConfig["dutPorts"][dst_port_id]["portName"]))

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({
            "dst_port_id": dst_port_id,
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "dscp": 8,
            "pkt_size": PKT_SIZE,
            "pkt_count": PKT_COUNT,
        })

        # send traffic
        self.runPtf(
            ptfhost,
            PTF_FILE_DIR,
            testCase="basic_traffic.SimpleUdpTraffic",
            testParams=testParams
        )

        time.sleep(VOQ_WATCHDOG_TIMEOUT_SECONDS + 10)

        # check log
        verify_log(dst_dut, pre_offsets)

        # tx enable
        tx_disable_cmd = "sudo config platform cisco interface {} tx enable"
        if "lagMembers" in dutConfig["dutPorts"][dst_port_id]:
            for port in dutConfig["dutPorts"][dst_port_id]["lagMembers"]:
                dst_dut.command(tx_disable_cmd.format(port))
        else:
            dst_dut.command(tx_disable_cmd.format(dutConfig["dutPorts"][dst_port_id]["portName"]))

    def testVoqWatchdogDisable(self, get_src_dst_asic_and_duts, dutConfig, dutTestParams, ptfhost,
                               function_scope_disable_voq_watchdog):
        """
        disable voq watchdog
        tx disable, send traffic, sleep 60 seconds, verify no soft_reset in sai.log
        """
        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        pre_offsets = init_log_check(dst_dut)

        # tx disable
        dst_port_id = dutConfig["testPorts"]["dst_port_id"]
        tx_disable_cmd = "sudo config platform cisco interface {} tx disable"
        if "lagMembers" in dutConfig["dutPorts"][dst_port_id]:
            for port in dutConfig["dutPorts"][dst_port_id]["lagMembers"]:
                dst_dut.command(tx_disable_cmd.format(port))
        else:
            dst_dut.command(tx_disable_cmd.format(dutConfig["dutPorts"][dst_port_id]["portName"]))

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({
            "dst_port_id": dst_port_id,
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "dscp": 8,
            "pkt_size": PKT_SIZE,
            "pkt_count": PKT_COUNT,
        })

        # send traffic
        self.runPtf(
            ptfhost,
            PTF_FILE_DIR,
            testCase="basic_traffic.SimpleUdpTraffic",
            testParams=testParams
        )
        time.sleep(VOQ_WATCHDOG_TIMEOUT_SECONDS)

        # check log
        verify_log(dst_dut, pre_offsets, False)

        # tx enable
        tx_disable_cmd = "sudo config platform cisco interface {} tx enable"
        if "lagMembers" in dutConfig["dutPorts"][dst_port_id]:
            for port in dutConfig["dutPorts"][dst_port_id]["lagMembers"]:
                dst_dut.command(tx_disable_cmd.format(port))
        else:
            dst_dut.command(tx_disable_cmd.format(dutConfig["dutPorts"][dst_port_id]["portName"]))
