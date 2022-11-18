import pytest

import logging
import ipaddress

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-pub', 'wan-pub-cisco'),
    pytest.mark.device_type('vs')
]

TEST_DIR = "/tmp/lagtests/"
ATTR_PORT_NOT_BEHIND_LAG = "port_not_behind_lag"


def setup_dut_lag(duthost, dut_lag):
    duthost.shell("config interface ip add {} {}".format(dut_lag["pc"], dut_lag["ip"]))


def setup_ptf_lag(ptfhost, ptf_lag):
    logger.info("########### Setup for lag testing ###########")
    copy_ptftests_directory(ptfhost)
    ptfhost.shell("ip address add {} dev {}".format(ptf_lag["ip"], ptf_lag["port_list"][0]))
    ptfhost.shell("mkdir -p {}".format(TEST_DIR))
    test_files = ["lag_test.py", "acs_base_test.py", "router_utils.py"]
    for test_file in test_files:
        src = "../ansible/roles/test/files/acstests/%s" % test_file
        dst = TEST_DIR + test_file
        ptfhost.copy(src=src, dest=dst)


def ptf_dut_teardown(duthost, ptfhost, dut_lag, ptf_lag):
    """
    Setup and teardown of ptf and dut

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
    """
    duthost.shell("config interface ip remove {} {}".format(dut_lag["pc"], dut_lag["ip"]))
    ptfhost.shell("ip address del {} dev {}".format(ptf_lag["ip"], ptf_lag["port_list"][0]))
    ptfhost.file(path=TEST_DIR, state="absent")


def test_lag_member_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    """
    Test ports' status of members in a lag
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    port_channels_data = asichost.get_portchannels_and_members_in_ns(tbinfo)

    for portchannel in port_channels_data:
        logging.info('Trying to get PortChannel: {} for test'.format(portchannel))
        cmd = "ip a | grep 'master {}' | cut -d : -f 2".format(portchannel)
        members_from_cli_query = duthost.shell(cmd)['stdout'].split('\n')

        port_channel_status = duthost.get_port_channel_status(portchannel)
        memebers_from_teamd_query = port_channel_status["ports"].keys()
        pytest_assert(
                        len(members_from_cli_query) == len(memebers_from_teamd_query),
                        "Missing ports in {}".format(portchannel)
                    )
        for port in members_from_cli_query:
            pytest_assert(port.strip() in memebers_from_teamd_query), "Missing port {}".format(port)


def test_lag_member_traffic(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost):
    """
    Test traffic about ports in a lag

    Test steps:
        1.) Setup DUT and PTF
        2.) Send ICMP request packet from port behind lag in PTF to port behind lag in DUT,
            and then verify receive ICMP reply packet in PTF lag
        3.) Send ICMP request packet from port behind lag in PTF to port not behind lag in PTF,
            and then verify receive the packet in port not behind lag
        4.) Send ICMP request packet from port not behind lag in PTF to port behind lag in PTF,
            and then verify recieve the packet in port behind lag
    """
    dut_lag = None
    ptf_lag = None

    try:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        portchannel_itfs = cfg_facts["PORTCHANNEL_INTERFACE"]

        pytest_require(len(portchannel_itfs.items()) > 0, "We need a port channel.")
        portchannel = portchannel_itfs.keys()[0]
        dut_lag = {
            'pc': portchannel,
            "id": 109,
            "ip": "192.168.9.1/24"
        }
        setup_dut_lag(duthost, dut_lag)

        portchannel_members = cfg_facts["PORTCHANNEL_MEMBER"][portchannel]
        port_index_map = cfg_facts["port_index_map"]
        port_list = []
        for port, _ in portchannel_members.items():
            port_list.append("eth{}".format(port_index_map[port]))

        ptf_lag = {
            'port_list': port_list,
            'ip': "{}/24".format(str(ipaddress.ip_address(str(dut_lag['ip'].split("/")[0])) + 1))
        }
        setup_ptf_lag(ptfhost, ptf_lag)

        aux_port = None
        for port, _ in cfg_facts['PORT'].items():
            if (port not in portchannel_members.keys()):
                aux_port = "eth{}".format(port_index_map[port])
                break

        """
        Run lag member traffic test

        Args:
            duthost: DUT host object
            dut_vlan: vlan information in dut
            ptf_lag_map: information about lag in ptf
            ptfhost: PTF host object
        """
        params = {
            "dut_mac": duthost.facts["router_mac"],
            "dut_vlan": dut_lag,
            "ptf_lag": ptf_lag,
            ATTR_PORT_NOT_BEHIND_LAG: aux_port
        }

        ptf_runner(ptfhost, TEST_DIR, "lag_test.LagMemberTrafficTest", "/root/ptftests", params=params)
    finally:
        ptf_dut_teardown(duthost, ptfhost, dut_lag, ptf_lag)
