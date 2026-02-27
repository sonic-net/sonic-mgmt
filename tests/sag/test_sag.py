import pytest
import os
import sys
import logging
import time
import inspect
from socket import AF_INET, AF_INET6
from tests.common.errors import RunAnsibleModuleFail
from tests.common.config_reload import config_reload
from ipaddress import IPv4Interface, IPv6Interface

pytestmark = [
    pytest.mark.topology('ptf'),
    pytest.mark.device_type('vs')
]

# global test config
VLAN_1 = 100
VLAN_2 = 200
dut_ip = ""

class DutHelper():

    def __init__(self, duthost):
        self.duthost = duthost

    def del_redis_interface_ip(self, key):
        self.duthost.shell("redis-cli -n 4 hdel \"{}\" NULL".format(key))

    def del_vlan(self, vlanid):
        self.duthost.shell("config vlan del {}".format(vlanid))

    def add_vlan(self, vlanid):
        self.duthost.shell("config vlan add {}".format(vlanid))

    def add_vlan_member(self, vlanid, portName):
        self.duthost.shell("config vlan member add -u {} {}".format(vlanid, portName))

    def add_sag_mac(self, mac):
        self.duthost.shell("config static-anycast-gateway mac_address add {}".format(mac))

    def del_sag_mac(self, mac):
        self.duthost.shell("config static-anycast-gateway mac_address del {}".format(mac))

    def set_enable_sag(self, vlanid, enable):
        enable_str = "enable" if enable == True else "disable"
        self.duthost.shell("config vlan static-anycast-gateway {} {}".format(enable_str, vlanid))

    def add_interface_ip(self, interface, ip):
        self.duthost.shell("config interface ip add {} {}".format(interface, ip))

    def remove_interface_ip(self, interface, ip):
        self.duthost.shell("config interface ip remove {} {}".format(interface, ip))

    def save_config(self):
        self.duthost.shell("config save -y")

    def reset_config(self):
        self.duthost.shell('config load_minigraph -y')

    def get_configDB_keys(self, pattern):
        res = self.duthost.shell("redis-cli -n 4 --csv keys \"{}\"".format(pattern))
        result = []
        if len(res['stdout_lines']) > 0:
            result = [eval(a) for a in res['stdout_lines'][0].split(",")]
        return result

    def is_vlan_cfg_exist(self, vlan_id):
        res = self.duthost.shell("redis-cli -n 4 keys \"*VLAN|Vlan{}\"".format(vlan_id))
        result = []
        if len(res['stdout_lines']) > 0:
            return True
        else:
            return False

class PtfHelper():

    def __init__(self, ptfhost):
        self.ptfhost = ptfhost

    def add_netns(self, name):
        self.ptfhost.shell("ip netns add {}".format(name))

    def del_netns(self, name):
        self.ptfhost.shell("ip netns del {}".format(name))

    def set_netns_ip(self, ns, dev, ip):
        self.ptfhost.shell("ip link set {} netns {}".format(dev, ns))
        self.ptfhost.shell("ip netns exec {} ip address add {} dev {}".format(ns, ip, dev))
        self.ptfhost.shell("ip netns exec {} ip link set dev {} up".format(ns, dev))

    def unset_netns_device(self, ns, dev):
        self.ptfhost.shell("ip netns exec {} ip link set {} netns 1".format(ns, dev))

    def set_netns_default_gw(self, ns, ip):
        self.ptfhost.shell("ip netns exec {} ip route add default via {}".format(ns, ip))

    def set_iface_up(self, iface):
        self.ptfhost.shell("ip link set {} up".format(iface))

    def list_netns(self):
        return self.ptfhost.shell("ip netns list")['stdout_lines']

    def list_netns_device(self, ns):
        return self.ptfhost.shell("ip netns exec {} ip -br link show".format(ns))['stdout_lines']

    def remove_device_from_netns(self, device, ns):
        self.ptfhost.shell("ip netns exec {} ip link set {} netns 1".format(ns, device))
        self.ptfhost.shell("ip link set {} up ".format(device))

    def del_netns(self, ns):
        self.ptfhost.shell("ip netns del {}".format(ns))

    def flush_ptf_arp_ping(self, ns, ip):
        self.ptfhost.shell("ip netns exec {} ip neigh flush all".format(ns))
        # to resolve arp, don't check return code
        time.sleep(0.5)
        self.ptfhost.shell("ip netns exec {} ping -c 1 {}".format(ns, ip), module_ignore_errors=True)
        time.sleep(1)
        self.ptfhost.shell("ip netns exec {} ping -c 1 {}".format(ns, ip))

    def get_ptf_netns_neighbor(self, ns, ip):
        res = self.ptfhost.shell("ip netns exec {} ip neigh show {}".format(ns, ip))
        result = res['stdout_lines']
        if len(result) == 0:
            return ""

        # e.g.
        # 1.1.1.253 dev eth0  FAILED
        # 1.1.1.254 dev eth0 lladdr 80:a2:35:d2:4c:b5 STALE
        result_splited = result[0].split()
        if len(result_splited) < 6:
            return ""
        else:
            return result_splited[4]

@pytest.fixture(name='dut_helper', scope='module')
def fixture_dut_helper(duthost):
    return DutHelper(duthost)

@pytest.fixture(name='ptf_helper', scope='module')
def fixture_ptf_helper(ptfhost):
    return PtfHelper(ptfhost)


@pytest.fixture(scope="module", autouse=True)
def setup_dut_env(duthost, dut_helper):
    dut_portName = []
    dut_port_ip = {}

    # get dut portName
    logging.info("get the first and the second port name of dut")
    dut_ports = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']['minigraph_ports'].keys()
    dut_ports_splited_tuple = [(int(item[len("Ethernet"):]), item) for item in dut_ports]
    dut_ports_tuple_sorted = sorted(dut_ports_splited_tuple)
    assert len(dut_ports_tuple_sorted) >= 2
    dut_portName = [dut_ports_tuple_sorted[0][1], dut_ports_tuple_sorted[1][1]]
    logging.info("get port name: {}, {}".format(dut_portName[0], dut_portName[1]))

    # get dut ip
    global dut_ip
    dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']
    logging.info("get dut ip: {}".format(dut_ip))

    # clear the port IP in dut
    logging.info("remove the original IP config of the first and the second port")
    for portName in dut_portName:
        dut_port_ip[portName] = dut_helper.get_configDB_keys("INTERFACE|{}|*".format(portName))
        dut_port_ip[portName].extend(dut_helper.get_configDB_keys("INTERFACE|{}".format(portName)))
        for key in dut_port_ip[portName]:
            logging.info("remove {} from redis".format(key))
            dut_helper.del_redis_interface_ip(key)

    # Clear Vlan first, avoid creation failure
    if dut_helper.is_vlan_cfg_exist(VLAN_1):
        dut_helper.del_vlan(VLAN_1)

    if dut_helper.is_vlan_cfg_exist(VLAN_2):
        dut_helper.del_vlan(VLAN_2)

    # Create Vlan for test
    logging.info("create VLANs for test")
    dut_helper.add_vlan(VLAN_1)
    dut_helper.add_vlan(VLAN_2)

    # Add Vlan member
    logging.info("add VLAN member")
    dut_helper.add_vlan_member(VLAN_1, dut_portName[0])
    dut_helper.add_vlan_member(VLAN_2, dut_portName[1])

    # Save config
    dut_helper.save_config()

    yield

    # Reset config
    dut_helper.reset_config()
    dut_helper.save_config()

# Clear network namespace config in ptf container
@pytest.fixture(scope="module", autouse=True)
def clear_ptf_netns(ptf_helper):
    logging.info("remove network namespaces from ptf")
    for ns in ptf_helper.list_netns():
        for device in ptf_helper.list_netns_device(ns):
            # e.g. "eth1@if4         DOWN           98:03:9b:2a:e6:c0 <BROADCAST,MULTICAST>"
            dev_name = device.split()[0].split("@")[0]
            if dev_name == "lo":
                continue
            logging.info("remove dev {} from netns {}".format(dev_name, ns))
            ptf_helper.remove_device_from_netns(dev_name, ns)
        logging.info("delete network namespace {}".format(ns))
        ptf_helper.del_netns(ns)

TEST_DATA = {
    "IPv4": (IPv4Interface(u'1.1.1.1/24'), IPv4Interface(u"2.2.2.2/24"), IPv4Interface(u"1.1.1.254/24"), IPv4Interface(u"2.2.2.254/24"), "00:11:22:33:44:55"),
    "IPv6": (IPv6Interface(u"2001:1000::1/64"), IPv6Interface(u"2001:1001::1/64"), IPv6Interface(u"2001:1000::fe/64"), IPv6Interface(u"2001:1001::fe/64"), "00:11:22:33:44:55")
}

class Test_SAG:
    @pytest.fixture(scope="class", params=["IPv4", "IPv6"])
    def env_cfg(self, request):
        yield TEST_DATA[request.param]

    @pytest.fixture(scope="class", autouse=True)
    def setup_ptf(self, env_cfg, ptf_helper):
        (host1, host2, dut1, dut2, sag_mac) = env_cfg

        # create netns
        ptf_helper.add_netns("ns1")
        ptf_helper.add_netns("ns2")

        # set IP and let device up
        ptf_helper.set_netns_ip("ns1", "eth0", str(host1))
        ptf_helper.set_netns_ip("ns2", "eth1", str(host2))
        ptf_helper.set_netns_default_gw("ns1", str(dut1.ip))
        ptf_helper.set_netns_default_gw("ns2", str(dut2.ip))

        yield

        # set device from netns to host
        ptf_helper.unset_netns_device("ns1", "eth0")
        ptf_helper.unset_netns_device("ns2", "eth1")

        # force interface up
        ptf_helper.set_iface_up("eth0")
        ptf_helper.set_iface_up("eth1")

        # delete netns
        ptf_helper.del_netns("ns1")
        ptf_helper.del_netns("ns2")

    @pytest.fixture(scope="class", autouse=True)
    def setup_dut(self, env_cfg, dut_helper):
        (host1, host2, dut1, dut2, sag_mac) = env_cfg

        vlan_str = "Vlan" + str(VLAN_1)
        dut_helper.add_sag_mac(sag_mac)
        dut_helper.add_interface_ip(vlan_str, str(dut1))
        dut_helper.set_enable_sag(VLAN_1, True)

        # wait for activate
        time.sleep(3)

        # config the second vlan for routing
        vlan2_str = "Vlan" + str(VLAN_2)
        dut_helper.add_interface_ip(vlan2_str, str(dut2))

        # save config
        dut_helper.save_config()

        yield

        vlan_str = "Vlan" + str(VLAN_1)

        dut_helper.set_enable_sag(VLAN_1, False)
        dut_helper.remove_interface_ip(vlan_str, str(dut1))
        dut_helper.del_sag_mac(sag_mac)
        dut_helper.remove_interface_ip("Vlan"+str(VLAN_2), str(dut2))

        # save config
        dut_helper.save_config()

    def test_sag_ping(self, ptf_helper, env_cfg):
        (host1, host2, dut1, dut2, sag_mac) = env_cfg
        ptf_helper.flush_ptf_arp_ping("ns1", str(dut1.ip))
        assert sag_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

    def test_sag_route(self, ptf_helper, env_cfg):
        (host1, host2, dut1, dut2, sag_mac) = env_cfg

        ptf_helper.flush_ptf_arp_ping("ns2", str(dut2.ip))
        ptf_helper.flush_ptf_arp_ping("ns1", str(host2.ip))
        assert sag_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

    def test_sag_change_enable_field(self, dut_helper, ptf_helper, env_cfg):
        (host1, host2, dut1, dut2, sag_mac) = env_cfg
        logging.info("disable VLAN{} static-anycast-gateway".format(VLAN_1))
        dut_helper.set_enable_sag(VLAN_1, False)

        ptf_helper.flush_ptf_arp_ping("ns1", str(dut1.ip))
        assert sag_mac != ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        ptf_helper.flush_ptf_arp_ping("ns1", str(host2.ip))
        assert sag_mac != ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        logging.info("enable VLAN{} static-anycast-gateway".format(VLAN_1))
        dut_helper.set_enable_sag(VLAN_1, True)

        ptf_helper.flush_ptf_arp_ping("ns1", str(dut1.ip))
        assert sag_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        ptf_helper.flush_ptf_arp_ping("ns1", str(host2.ip))
        assert sag_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

    def test_sag_change_sag_mac(self, ptf_helper, dut_helper, env_cfg):
        (host1, host2, dut1, dut2, sag_mac) = env_cfg
        # ping with original SAG_MAC address
        ptf_helper.flush_ptf_arp_ping("ns1", str(dut1.ip))
        assert sag_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        # route with original SAG_MAC address
        ptf_helper.flush_ptf_arp_ping("ns1", str(host2.ip))
        assert sag_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        # change SAG address
        new_mac = "00:11:22:33:44:77"
        dut_helper.del_sag_mac(sag_mac)
        dut_helper.add_sag_mac(new_mac)

        # ping with new SAG address
        ptf_helper.flush_ptf_arp_ping("ns1", str(dut1.ip))
        assert new_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        # route with new SAG address
        ptf_helper.flush_ptf_arp_ping("ns1", str(host2.ip))
        assert new_mac == ptf_helper.get_ptf_netns_neighbor("ns1", str(dut1.ip))

        # Rollback SAG address
        logging.info("rollback SAG address")
        dut_helper.del_sag_mac(new_mac)
        dut_helper.add_sag_mac(sag_mac)

    def test_sag_ping_after_reload(self, duthost, ptf_helper, env_cfg):
        config_reload(duthost, wait=180)
        self.test_sag_ping(ptf_helper, env_cfg)