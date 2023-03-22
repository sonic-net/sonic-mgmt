import pytest

import logging
import ipaddress
import traceback
import sys

from tests.common.utilities import wait
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-pub', 'wan-4link'),
    pytest.mark.device_type('vs')
]

if sys.version_info.major >= 3:
    unicode = str

TEST_DIR = "/tmp/lagtests/"
PTF_LAG_NAME = "bond1"
ATTR_PORT_NOT_BEHIND_LAG = "port_not_behind_lag"
DUT_LAYER2_BR = "br1"


def setup_dut_lag(duthost, dut_lag, ptf_non_lag_port):
    duthost.shell("config portchannel member del {} {}".format(ptf_non_lag_port["pc"], ptf_non_lag_port["pc_member"]))

    duthost.shell("ip link add name {} type bridge".format(DUT_LAYER2_BR))
    duthost.shell("ip address add dev {} {}".format(DUT_LAYER2_BR, dut_lag["ip"]))
    duthost.shell("ip link set {} master {}".format(dut_lag["pc"], DUT_LAYER2_BR))
    duthost.shell("ip link set {} master {}".format(ptf_non_lag_port["pc_member"], DUT_LAYER2_BR))
    duthost.shell("ip link set {} up".format(DUT_LAYER2_BR))


def setup_ptf_lag(ptfhost, ptf_lag, ptf_non_lag_port):
    logger.info("########### Setup for lag testing ###########")
    ptfhost.create_lag(PTF_LAG_NAME, ptf_lag["ip"], "802.3ad")
    for port in ptf_lag["port_list"]:
        ptfhost.add_intf_to_lag(PTF_LAG_NAME, port)
    ptfhost.startup_lag(PTF_LAG_NAME)

    ptfhost.add_ip_to_dev(ptf_non_lag_port["port_name"], ptf_non_lag_port['ip'])
    ptfhost.ptf_nn_agent()

    ptfhost.shell("mkdir -p {}".format(TEST_DIR))
    test_files = ["lag_test.py", "acs_base_test.py", "router_utils.py"]
    for test_file in test_files:
        src = "../ansible/roles/test/files/acstests/%s" % test_file
        dst = TEST_DIR + test_file
        ptfhost.copy(src=src, dest=dst)


def ptf_dut_teardown(duthost, ptfhost, dut_lag, ptf_lag, ptf_non_lag_port):
    """
    Setup and teardown of ptf and dut

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
    """
    duthost.shell("ip link set {} nomaster".format(dut_lag["pc"]))
    duthost.shell("ip link set {} nomaster".format(ptf_non_lag_port["pc_member"]))
    duthost.shell("ip address del dev {} {}".format(DUT_LAYER2_BR, dut_lag["ip"]))
    duthost.shell("ip link delete dev {} type bridge".format(DUT_LAYER2_BR))
    duthost.shell("config portchannel member add {} {}".format(ptf_non_lag_port["pc"], ptf_non_lag_port["pc_member"]))

    ptfhost.set_dev_no_master(PTF_LAG_NAME)
    for ptf_lag_member in ptf_lag["port_list"]:
        ptfhost.set_dev_no_master(ptf_lag_member)
        ptfhost.set_dev_up_or_down(ptf_lag_member, True)

    ptfhost.shell("ip link del {}".format(PTF_LAG_NAME))
    ptfhost.shell("ip addr del {} dev {}".format(ptf_non_lag_port['ip'], ptf_non_lag_port["port_name"]))
    ptfhost.ptf_nn_agent()
    ptfhost.file(path=TEST_DIR, state="absent")


def nbrhosts_itf_up_or_down(nbrhosts, nei_lag_ports, action):
    for nbr in nei_lag_ports:
        hostname = nbr.split(':')[0]
        itf = nbr.split(':')[1]
        for nbr_hostname, nbrhost in list(nbrhosts.items()):
            if nbr_hostname != hostname:
                continue
            if action == 'down':
                nbrhost['host'].shutdown(itf)
            elif action == 'up':
                nbrhost['host'].no_shutdown(itf)


def test_ping_from_neighbor(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts):
    """
    Issue ping from neighbors to DUT via LACP, verify IPv4/v6 connectivity.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    dut_ports = cfg_facts["PORT"]
    portchannel_itfs = cfg_facts["PORTCHANNEL_INTERFACE"]
    for portchannel, ip_list in list(portchannel_itfs.items()):
        portchannel_members = list(cfg_facts["PORTCHANNEL_MEMBER"][portchannel].keys())
        hostname = dut_ports[portchannel_members[0]]['description'].split(':')[0]
        for nbr_hostname, nbrhost in list(nbrhosts.items()):
            if nbr_hostname != hostname:
                continue
            for ip in ip_list:
                ip = ip.split('/')[0]
                pytest_assert(nbrhost['host'].ping_dest(ip), "{} ping port channel {} failed".format(nbr_hostname, ip))


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
        memebers_from_teamd_query = list(port_channel_status["ports"].keys())
        pytest_assert(
                        len(members_from_cli_query) == len(memebers_from_teamd_query),
                        "Missing ports in {}".format(portchannel)
                    )
        for port in members_from_cli_query:
            pytest_assert(port.strip() in memebers_from_teamd_query), "Missing port {}".format(port)


def test_lag_member_traffic(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts, ptfhost):
    #                         #
    #  BR on DUT  # .1     .2 #   PTF   #
    #  - LACP/ALG # <-------> #  LACP   #
    #             #        .3 #         #
    # - EthernetXX# <-------> #  EthXX  #
    #                         #
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
    nei_lag_ports = []
    ptf_lag = None
    ptf_non_lag_port = None

    try:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        portchannel_itfs = cfg_facts["PORTCHANNEL_INTERFACE"]

        pytest_require(len(list(portchannel_itfs.items())) > 1, "We need two port channels.")
        portchannel = list(portchannel_itfs.keys())[0]
        dut_lag = {
            'pc': portchannel,
            "id": 109,
            "ip": "192.168.9.1/24",
        }

        portchannel_members = cfg_facts["PORTCHANNEL_MEMBER"][portchannel]
        dut_ports = cfg_facts["PORT"]
        port_index_map = cfg_facts["port_index_map"]
        port_list = []
        for port, _ in list(portchannel_members.items()):
            port_list.append("eth{}".format(port_index_map[port]))
            nei_lag_ports.append(dut_ports[port]['description'])

        pytest_assert(len(port_list) == len(nei_lag_ports), "Neighbor LACP configuration is not correct.")

        ptf_lag = {
            'port_list': port_list,
            'ip': "{}/24".format(unicode(ipaddress.ip_address(str(dut_lag['ip'].split("/")[0])) + 1))
        }

        aux_port_idx = None
        aux_port = None
        pc_member = None
        aux_portchannel = list(portchannel_itfs.keys())[1]
        for port, _ in list(cfg_facts["PORTCHANNEL_MEMBER"][aux_portchannel].items()):
            if (port not in list(portchannel_members.keys())):
                pc_member = port
                aux_port_idx = port_index_map[port]
                aux_port = "eth{}".format(aux_port_idx)
                break

        ptf_non_lag_port = {
            'pc': aux_portchannel,
            'pc_member': pc_member,
            'port_id': aux_port_idx,
            'port_name': aux_port,
            'ip': "{}/24".format(unicode(ipaddress.ip_address(str(dut_lag['ip'].split("/")[0])) + 2))
        }
        # Shutdown neighbor interfaces to disable existing LACP and connect to PTF LACP.
        nbrhosts_itf_up_or_down(nbrhosts, nei_lag_ports, 'down')
        setup_dut_lag(duthost, dut_lag, ptf_non_lag_port)
        setup_ptf_lag(ptfhost, ptf_lag, ptf_non_lag_port)
        wait(10)

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
            ATTR_PORT_NOT_BEHIND_LAG: ptf_non_lag_port
        }
        ptf_runner(ptfhost, TEST_DIR, "lag_test.LagMemberTrafficTest", "/root/ptftests", params=params)
    except Exception:
        logger.error(traceback.format_exc())
    finally:
        nbrhosts_itf_up_or_down(nbrhosts, nei_lag_ports, 'up')
        ptf_dut_teardown(duthost, ptfhost, dut_lag, ptf_lag, ptf_non_lag_port)
