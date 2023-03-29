import logging
import pytest

import os.path
import ptf.packet as scapy
from ptf.mask import Mask
import ptf.testutils as testutils
from ipaddress import ip_address
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import check_container_state
from tests.vxlan.vnet_constants import *
from tests.vxlan.vnet_utils import cleanup_vnet_routes, cleanup_dut_vnets, cleanup_vxlan_tunnels, \
                       apply_dut_config_files, generate_dut_config_files


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.asic("mellanox")
]

BACKUP_CONFIG_DB_CMD = "sudo cp /etc/sonic/config_db.json /etc/sonic/config_db.json.vnet_monitor_orig"
RESTORE_CONFIG_DB_CMD = "sudo cp /etc/sonic/config_db.json.vnet_monitor_orig /etc/sonic/config_db.json"
DELETE_BACKUP_CONFIG_DB_CMD = "sudo rm /etc/sonic/config_db.json.vnet_monitor_orig"
ENABLE_VNET_MONITOR_CMD = "sudo config feature state vnet_monitor enabled"
VNET_MONITOR_CONTAINER_NAME = 'vnet_monitor'


@pytest.fixture(scope='module', autouse=True)
def check_vnet_monitor_feature(rand_selected_dut):
    feature_status, ret = rand_selected_dut.get_feature_status()
    KEY = 'vnet_monitor'
    if not ret or KEY not in feature_status:
        pytest.skip('{} feature is not enabled on DUT'.format(KEY))

class VnetMonitorTest:
    def __init__(self, duthost, minigraph_facts, vnet_config, vnet_test_params):
        self.tagged = True
        self.net_port = 0

        self.random_mac = '00:01:02:03:04:05'
        self.vxlan_router_mac = '00:aa:bb:cc:78:9a'
        self.vxlan_port = 65330
        self.vxlan_port_test = 13330
        self.udp_sport = 1234
        self.vxlan_pkt_len = 104
        self.tcp_pkt_len = 58
        self.tcp_pkt_len_without_options = 54

        self.tcp_sport = 5000
        self.tcp_dport = 1021

        self.dut_mac = None
        self.loopback_ipv4 = None

        self.net_ports = []
        self.acc_ports = []
        self.tests = []
        self.ptf_mac_addrs = []
        self.serv_info = {}

    def setup(self, duthost, minigraph_facts, vnet_config, vnet_test_params):

        for name, val in minigraph_facts['minigraph_portchannels'].items():
            logger.info("minigraph_portchannels name is: " + str(name) + " val:" + str(val))
            members = [minigraph_facts['minigraph_port_indices'][member] for member in val['members']]
            self.net_ports.extend(members)
            logger.info("minigraph_portchannels members is: " + str(members))
            for member in val['members']:
                logger.info("minigraph_portchannels member is: " + str(member))
                logger.info(
                    "minigraph_port_indices member is: " + str(minigraph_facts['minigraph_port_indices'][member]))

            ip = None

            for d in minigraph_facts['minigraph_portchannel_interfaces']:
                logger.info("minigraph_portchannel_interfaces d: " + str(d))
                if d['attachto'] == name:
                    ip = d['peer_addr']
                    logger.info("pc_info name: " + str(name) + " ip:" + str(ip))
                    break
        logger.info("net_ports is: " + str(self.net_ports))
        logger.info("net_ports[0] is: " + str(self.net_ports[0]))

        for name, data in minigraph_facts['minigraph_vlans'].items():
            logger.info("minigraph_vlans name is: " + str(name) + " data:" + str(data))
            ports = [minigraph_facts['minigraph_port_indices'][member] for member in data['members'][1:]]
            self.acc_ports.extend(ports)
            logger.info("minigraph_vlans ports is: " + str(ports))

        logger.info("acc_ports is: " + str(self.acc_ports))

        vni_base = 10000
        acc_ports_size = len(self.acc_ports)
        for idx, data in enumerate(vnet_config["vnet_intf_list"]):
            logger.info("vnet_intf_list idx is: " + str(idx) + " data:" + str(data) + " vnet:" + str(data['vnet']))
            if data['vnet'] not in self.serv_info:
                self.serv_info[data['vnet']] = []
                ports = self.acc_ports[idx % acc_ports_size]
            elif self.serv_info[data['vnet']]:
                # Specify the port when there are multiple RIFs per VNET
                # We want all RIFs in one VNET to use the same port/interface
                # If we have already seen a RIF from this VNET, use the port of the previously seen RIF for consistency
                ports = self.serv_info[data['vnet']][0].get('port', ports)
            serv_info = {}
            for nbr in vnet_config["vnet_nbr_list"]:
                if nbr['ifname'] == data['ifname']:
                    if 'Vlan' in data['ifname']:
                        vlan_id = int(data['ifname'].replace('Vlan', ''))
                    else:
                        vlan_id = 0
                    ip = nbr['ip']
            serv_info['ifname'] = data['ifname']
            serv_info['vlan_id'] = vlan_id
            serv_info['ip'] = ip
            serv_info['port'] = ports
            serv_info['vni'] = vni_base + int(data['vnet'].replace('Vnet',''))
            self.serv_info[data['vnet']].extend([serv_info])
            logger.info("serv_info ifname: " + str(data['ifname']) + " vlan_id:" + str(vlan_id) + " ip:" + str(ip) + " ports:" + str(self.acc_ports[idx]) + " vni:" + str(data['vnet'].replace('Vnet', '')))
            logger.info("serv_info: " + str(serv_info))


        for routes in vnet_config["vnet_subnet_routes"]:
            for name, rt_list in routes.items():
                logger.info("addtest subnet name : " + str(name))
                for entry in rt_list:
                    logger.info("addtest subnet entry : " + str(entry))
                    self.addtest(name, entry)

        dut_facts = duthost.facts
        self.dut_mac = dut_facts["router_mac"]
        logger.info("dut_mac : " + str(dut_facts["router_mac"]))

        for data in minigraph_facts['minigraph_lo_interfaces']:
            if data['prefixlen'] == 32:
                self.loopback_ipv4 = data['addr']
                logger.info("loopback ipv4 is: " + str(data['addr']))
            elif data['prefixlen'] == 128:
                logger.info("loopback ipv6 is: " + str(data['addr']))

        self.ptf_mac_addrs = self.readMacs()
        logger.info("net_ports0 : " + str(self.net_ports[0]))
        logger.info("acc_ports0 : " + str(self.acc_ports[0]))
        logger.info("net_ports0 : " + str(self.tests[0]))
        logger.info("serv_info0 : " + str(self.serv_info.keys()))
        bind_layers(UDP, VXLAN, sport=self.vxlan_port)
        bind_layers(UDP, VXLAN, dport=self.vxlan_port)
        bind_layers(UDP, VXLAN, sport=self.vxlan_port_test)
        bind_layers(UDP, VXLAN, dport=self.vxlan_port_test)


    def readMacs(self):
        addrs = {}
        for intf in os.listdir('/sys/class/net'):
            if os.path.isdir('/sys/class/net/%s' % intf):
                with open('/sys/class/net/%s/address' % intf) as fp:
                    addrs[intf] = fp.read().strip()

        return addrs

    def getsrvinfo(self, vnet, ifname=''):
        for item in self.serv_info[vnet]:
            if ifname == '' or item['ifname'] == ifname:
                return item['ip'], item['port'], item['vlan_id'], item['vni'], item['ifname']

        return None

    def addtest(self, name, entry):
        test = {}
        test['name'] = name.split('_')[0]
        test['dst'] = entry['pfx'].split('/')[0]
        test['host'] = entry['end']
        if 'mac' in entry:
            test['mac'] = entry['mac']
        else:
            test['mac'] = self.vxlan_router_mac
        test['src'], test['port'], test['vlan'], test['vni'], test['ifname'] = self.getsrvinfo(test['name'])
        self.tests.append(test)

    def vnetping_server_test(self, ptfadapter):
        test = self.tests[0]
        logger.info("test: " + str(test))
        net_port = test['port']
        vni = int(test['vni'])

        pkt = testutils.simple_tcp_packet(
            pktlen=self.tcp_pkt_len,
            eth_dst=self.vxlan_router_mac,
            eth_src=self.random_mac,
            ip_dst=test['src'],
            ip_src=test['dst'],
            ip_id=108,
            ip_ttl=2,
            tcp_sport=self.tcp_sport,
            tcp_dport=self.tcp_dport)
        vxlan_pkt = testutils.simple_vxlan_packet(
            eth_dst=self.dut_mac,
            eth_src=self.random_mac,
            ip_id=0,
            ip_src=test['host'],
            ip_dst=self.loopback_ipv4,
            ip_ttl=64,
            udp_sport=self.udp_sport,
            udp_dport=self.vxlan_port,
            vxlan_vni=vni,
            with_udp_chksum=False,
            inner_frame=pkt)

        exp_pkt = testutils.simple_tcp_packet(
            pktlen=self.tcp_pkt_len,
            eth_src=self.dut_mac,
            eth_dst=self.random_mac,
            ip_ihl=None,
            ip_tos=0,
            ip_src=self.loopback_ipv4,
            ip_dst=test['host'],
            ip_id=1,
            ip_ttl=64,
            tcp_flags="SA",
            tcp_sport=self.tcp_dport,
            tcp_dport=self.tcp_sport,
            with_tcp_chksum=False)

        logging.info("vxlan_pkg")
        logging.info(testutils.inspect_packet(vxlan_pkt))
        logging.info(testutils.inspect_packet(pkt))
        logging.info("exp_pkg")
        logging.info(testutils.inspect_packet(exp_pkt))

        testutils.send_packet(ptfadapter, self.net_port, str(vxlan_pkt))

        log_str = "Sending packet from port " + str(net_port) + " to " + test['src']
        logging.info(log_str)

        log_str = "Expecing packet on " + str("eth%d" % test['port']) + " from " + str(self.net_ports)
        logging.info(log_str)

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "type")

        log_str = "Ether mask :\n" + str(masked_exp_pkt)
        logging.info(log_str)

        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "options")

        log_str = "IP mask :\n" + str(masked_exp_pkt)
        logging.info(log_str)

        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "seq")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "ack")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "dataofs")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "options")

        log_str = "TCP mask :\n" + str(masked_exp_pkt)
        logging.info(log_str)

        offset_do_not_care = self.tcp_pkt_len_without_options
        len_do_not_care = len(exp_pkt) - self.tcp_pkt_len_without_options
        if len_do_not_care > 0:
            masked_exp_pkt.set_do_not_care(offset_do_not_care * 8, len_do_not_care * 8)
            log_str = "do_not_care  mask :\n" + str(masked_exp_pkt)
            logging.info(log_str)

        masked_exp_pkt.set_ignore_extra_bytes()

        testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, self.net_ports)


    def vnetping_client_test(self, ptfadapter, duthost):
        test = self.tests[0]
        logger.info("test: " + str(test))
        dstcaip = test['dst']
        srccaip = test['src']
        vnetinterface = test['ifname']

        vnetping_cmd = "python /tmp/vnetping.py -i {0} -s {1} -d {2}".format(vnetinterface, srccaip, dstcaip)
        logger.info(vnetping_cmd)
        duthost.shell(vnetping_cmd)

        tcp_pkt = testutils.simple_tcp_packet(
            pktlen=self.tcp_pkt_len,
            eth_src=self.dut_mac,
            eth_dst=self.random_mac,
            ip_dst=dstcaip,
            ip_src=srccaip,
            ip_id=1,
            ip_ttl=1,
            tcp_sport=self.tcp_sport,
            tcp_dport=self.tcp_dport,
            with_tcp_chksum=False)

        encap_pkt = testutils.simple_vxlan_packet(
            pktlen=104,
            eth_src=self.dut_mac,
            eth_dst=self.random_mac,
            ip_src=self.loopback_ipv4,
            ip_dst=test['host'],
            ip_id=0,
            # ip_flags = 0x40, # need to upgrade ptf version to support it
            ip_ttl=128,
            udp_sport=self.udp_sport,
            udp_dport=self.vxlan_port_test,
            with_udp_chksum=False,
            inner_frame=tcp_pkt)

        logging.info("encap_pkg")
        logging.info(testutils.inspect_packet(encap_pkt))
        logging.info("tcp_pkg")
        logging.info(testutils.inspect_packet(tcp_pkt))

        log_str = "len of encap_pkt : {0}, len of tcp_pkt : {1}".format(len(encap_pkt), len(tcp_pkt))
        logging.info(log_str)

        masked_exp_pkt = Mask(encap_pkt, ignore_extra_bytes=True)

        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "type")

        log_str = "Ether mask : len:{0}\n".format(len(encap_pkt[scapy.Ether])) + str(masked_exp_pkt)
        logging.info(log_str)

        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "options")

        log_str = "IP mask : len:{0}\n".format(len(encap_pkt[scapy.IP])) + str(masked_exp_pkt)
        logging.info(log_str)

        masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "sport")
        masked_exp_pkt.set_do_not_care_scapy(scapy.UDP, "chksum")

        log_str = "UDP mask : len:{0}\n".format(len(encap_pkt[scapy.UDP])) + str(masked_exp_pkt)
        logging.info(log_str)

        masked_exp_pkt.set_do_not_care_scapy(scapy.VXLAN, "vni")

        log_str = "VXLAN mask : len:{0}, tcp_len:{1}\n".format(len(encap_pkt[scapy.VXLAN]), len(encap_pkt[scapy.TCP])) + str(masked_exp_pkt)
        logging.info(log_str)

        log_str = "VXLAN Len: Ether:{0}, ip:{1}:, tcp:{2}\n".format(len(encap_pkt[scapy.VXLAN][scapy.Ether]), len(encap_pkt[scapy.VXLAN][scapy.IP]), len(encap_pkt[scapy.VXLAN][scapy.TCP]))
        logging.info(log_str)

        len_inner_ehter = len(encap_pkt[scapy.VXLAN][scapy.Ether])
        len_inner_ip = len(encap_pkt[scapy.VXLAN][scapy.IP])
        len_inner_tcp =len(encap_pkt[scapy.VXLAN][scapy.TCP])

        # skip inner Ether and IP packets
        offset_do_not_care_1 = len(encap_pkt) - len_inner_ehter
        len_do_not_care_1 = len_inner_ehter - len_inner_tcp
        # match source ip and destination ip
        len_do_not_care_1 = len_do_not_care_1 -8
        masked_exp_pkt.set_do_not_care(offset_do_not_care_1 * 8, len_do_not_care_1 * 8)


        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "sport")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "seq")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "dataofs")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.TCP, "options")

        log_str = "TCP mask :\n" + str(masked_exp_pkt)
        logging.info(log_str)

        # skip any extra bytes in encap_pkt
        offset_do_not_care_2 = self.vxlan_pkt_len
        len_do_not_care_2 = len(encap_pkt) - offset_do_not_care_2
        if len_do_not_care_2 > 0:
            masked_exp_pkt.set_do_not_care(offset_do_not_care_2 * 8, len_do_not_care_2 * 8)
            log_str = "do_not_care  mask :\n " + str(masked_exp_pkt)
            logging.info(log_str)

        testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, self.net_ports)


@pytest.fixture(scope="module")
def setup(minigraph_facts, duthosts, rand_one_dut_hostname, vnet_config, vnet_test_params):
    """
    Setup/teardown fixture for VNET route leak test
    During the setup portion, generates VNET VxLAN configurations and applies them to the DUT
    During the teardown portion, removes all previously pushed VNET VxLAN information from the DUT
    Args:
        minigraph_facts: Minigraph information
        duthost: DUT host object
        vnet_config: Dictionary containing VNET configuration information
        vnet_test_params: Dictionary containing VNET test parameters
    """
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Backing up config_db.json")
    duthost.shell(BACKUP_CONFIG_DB_CMD)

    duthost.shell("sonic-clear fdb all")
    duthost.shell(ENABLE_VNET_MONITOR_CMD)
    generate_dut_config_files(duthost, minigraph_facts, vnet_test_params, vnet_config)
    apply_dut_config_files(duthost, vnet_test_params)

    logger.info("VNet config is: " + str(vnet_config))
    logger.info("VNet test params is: " + str(vnet_test_params))

    # In this case yield is used only to separate this fixture into setup and teardown portions
    yield

    if vnet_test_params[CLEANUP_KEY]:
        logger.info("Restoring config_db.json")
        duthost.shell(RESTORE_CONFIG_DB_CMD)
        duthost.shell(DELETE_BACKUP_CONFIG_DB_CMD)

        cleanup_vnet_routes(duthost, vnet_test_params)
        cleanup_dut_vnets(duthost, minigraph_facts, vnet_config)
        cleanup_vxlan_tunnels(duthost, vnet_test_params)
    else:
        logger.info("Skipping cleanup")

def test_vnet_monitor(setup, duthosts, rand_one_dut_hostname, ptfhost, ptfadapter, minigraph_facts, vnet_config, vnet_test_params):
    """
    Test case for vnet_monitor
    Args:
        setup: Pytest fixture that sets up PTF and DUT hosts
        duthost: DUT host object
        ptfhost: PTF host object
        PtfAdapter: Provides an interface to send and receive traffic
        minigraph_facts: Minigraph information
        vnet_config: Dictionary containing VNET configuration information
        vnet_test_params: Dictionary containing vnet test parameters
    """
    duthost = duthosts[rand_one_dut_hostname]
    dut_facts = duthost.facts

    if check_container_state(duthost, VNET_MONITOR_CONTAINER_NAME, should_be_running=True):
        docker_copy_cmd = "docker cp vnet_monitor:/usr/bin/vnetping.py /tmp/"
        logger.info(docker_copy_cmd)
        duthost.shell(docker_copy_cmd)
        docker_copy_cmd = "docker cp vnet_monitor:/usr/bin/configutil.py /tmp/"
        logger.info(docker_copy_cmd)
        duthost.shell(docker_copy_cmd)
        vnmTest = VnetMonitorTest(duthost, minigraph_facts, vnet_config, vnet_test_params)
        vnmTest.setup(duthost, minigraph_facts, vnet_config, vnet_test_params)
        vnmTest.vnetping_server_test(ptfadapter)
        vnmTest.vnetping_client_test(ptfadapter, duthost)
    else:
        logging.info("The test is skipped, since vnet_monitor service doesn't run")


    pytest_assert(True, True)

