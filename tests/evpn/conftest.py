import pytest
import logging
import inspect
import json
import random

from collections import namedtuple
from ipaddress import IPv4Interface
from tests.common.utilities import wait_until
from tests.common.utilities import wait
from tests.common.helpers.assertions import pytest_assert as pt_assert

import ptf.testutils as testutils
import ptf.packet as scapy
import ptf.mask as mask


CMD_TEMPLATE = "=== %s cmd: %s ===\n%s"
DUT_VTEP_IP = "10.1.0.32"
T0_VLAN_INDEX_RANGE = range(1, 25)  # 1-24
DUT_PORT_NAME_LIST = {}

NUM_CONTINUOUS_PKT_COUNT = 20

# Type define
VTEP_Param = namedtuple("VTEP_Param", "if_index, ip_ptf, ip_dut, as_number_ptf, gobgp_port")
PCH_Param = namedtuple("Portchannel_Param", "member_index_list, dut_pch_name, ptf_pch_name, es_mac, es_id")
PCH_Param.__new__.__defaults__ = (None,) * len(PCH_Param._fields)

evpn_neighbor_list = [
    # index, ip_ptf, ip_dut, as_number, gobgp_port
    VTEP_Param(1, IPv4Interface(u"10.0.0.65/31"), IPv4Interface(u"10.0.0.64/31"), "65200", "50051"),
    VTEP_Param(4, IPv4Interface(u"10.0.0.71/31"), IPv4Interface(u"10.0.0.70/31"), "65300", "50052"),
]

@pytest.fixture(scope="module", autouse=True)
def setup_check_topo(tbinfo):
    if tbinfo['topo']['type'] in ['t1', 'ptf']:
        pytest.skip('Unsupported topology')


@pytest.fixture(scope="module", autouse=True)
def get_dut_indices_port(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    dut_indices_port = {id: port for port, id in mg_facts['minigraph_port_indices'].items()}
    # must use update function to avoid the dict address changed, and the dict address imported by other file is the origin one.
    DUT_PORT_NAME_LIST.update(dut_indices_port)


@pytest.fixture(scope="module", autouse=True)
def ptf_intf_setup_recover(ptfhost, ptfadapter):
    # remove existing IPs from PTF host
    ptfhost.script('scripts/remove_ip.sh')
    # set unique MACs to PTF interfaces
    ptfhost.script('scripts/change_mac.sh')
    # reinitialize data plane due to above changes on PTF interfaces
    ptfadapter.reinit({'qlen': 10000})
    yield
    cmd_list = []
    for i in range(32):
        cmd_list.append("ip link set eth{} up".format(i))
    ptfhost.shell_cmds(cmds=cmd_list, module_ignore_errors=True)


class EVPN_ENV:
    # _instance = None

    ptf_pch_mac_offset = 0
    vtep_param_list = [
        VTEP_Param(if_index=1,
                   ip_ptf=IPv4Interface(u"10.0.0.65/31"),
                   ip_dut=IPv4Interface(u"10.0.0.64/31"),
                   as_number_ptf="65200",
                   gobgp_port="50051"),
    ]

    def __init__(self, duthost, ptfhost, ptfadapter):
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.ptfadapter = ptfadapter
        self.ptf_helper = self.PtfHelper(self)
        self.dut_helper = self.DutHelper(self)
        self.gobgp_helper = self.GobgpHelper(self)
        self.frr_helper = self.VtyshFrrHelper(self)
        self.pkt_helper = self.PacketHelper(self)
        self.vtep_if = "vtep-1000"

    def check_interface_status(self, ifname, is_present):
        cmd = "ip -j link show {}".format(ifname)
        result = self.duthost.shell(cmd, module_ignore_errors=True)
        return ((result["rc"] == 0) == is_present)

    def setup_dut_base(self, input_list=None):
        if input_list == None:
            input_list = self.vtep_param_list

        try:
            self.dut_helper.add_vxlan(vtep_ip=DUT_VTEP_IP, vlanid="1000", vni="10000")
            pt_assert(wait_until(10, 2, self.check_interface_status, self.vtep_if, True))
            for item in input_list:
                self.dut_helper.set_ip(iface=item.if_index, ip_mask=str(item.ip_dut))
                self.frr_helper.set_neighbor(neighbor_ip=str(item.ip_ptf.ip), as_number=item.as_number_ptf)
            self.frr_helper.set_advertise_all_vni()


        except Exception as e:
            self.teardown_dut_base()
            pytest.fail(e)

    def teardown_dut_base(self, input_list=None):
        if input_list == None:
            input_list = self.vtep_param_list

        for item in input_list:
            self.frr_helper.unset_neighbor(neighbor_ip=str(item.ip_ptf.ip), as_number=item.as_number_ptf)
            self.dut_helper.unset_ip(iface=item.if_index, ip_mask=str(item.ip_dut))
        self.frr_helper.unset_advertise_all_vni()
        self.dut_helper.del_vxlan(vlanid="1000", vni="10000")
        pt_assert(wait_until(10, 2, self.check_interface_status, self.vtep_if, False))

    def setup_ptf_base(self, input_list=None):
        if input_list == None:
            input_list = self.vtep_param_list

        for item in input_list:
            ifname = "eth{}".format(item.if_index)
            ip_ptf = item.ip_ptf
            as_number = item.as_number_ptf
            gobgp_port = item.gobgp_port

            self.ptf_helper.copy_gobgp_config(as_number=as_number, ip=str(ip_ptf.ip))
            self.ptf_helper.set_ip(ifname=ifname, ip_mask=str(ip_ptf))
            self.gobgp_helper.start(as_number=as_number, gobgp_port=gobgp_port)

        try:
            gobgp_port_list = [item.gobgp_port for item in input_list]
            pt_assert(wait_until(30, 5, self.gobgp_helper.check_gobgpd_present_status, gobgp_port_list))

            for item in input_list:
                ip_neighbor = item.ip_dut
                gobgp_port = item.gobgp_port
                self.gobgp_helper.add_neighbor(neighbor_ip=str(ip_neighbor.ip), gobgp_port=gobgp_port)

            pt_assert(wait_until(100, 10, self.gobgp_helper.check_gobgpd_neighbor, gobgp_port_list), "gobgp neighbor cannot establish")

        except Exception as e:
            self.teardown_ptf_base()
            pytest.fail(e)

    def teardown_ptf_base(self, input_list=None):
        if input_list == None:
            input_list = self.vtep_param_list

        for item in input_list:
            ifname = "eth{}".format(item.if_index)
            ip_ptf = item.ip_ptf
            self.ptf_helper.unset_ip(ifname=ifname, ip_mask=str(ip_ptf))
        self.gobgp_helper.stop_all()

    def create_portchannels_and_start(self, pch_param_list, ptf_netns_name=None, remove_vlan=True):
        for item in pch_param_list:
            dut_pch_name = item.dut_pch_name
            ptf_pch_name = item.ptf_pch_name

            dut_pch_member_index_list = []
            ptf_pch_member_list = []
            for port_index in item.member_index_list:
                dut_pch_member_index_list.append(port_index)
                ptf_pch_member_list.append("eth{}".format(port_index))

            # base: "00:aa:bb:cc:dd:01"
            ptf_pch_mac = "00:aa:bb:cc:dd:{:02x}".format(0x01+self.ptf_pch_mac_offset)
            self.ptf_pch_mac_offset += 1

            self.ptf_helper.start_portchannel(pch_name=ptf_pch_name, hwaddr=ptf_pch_mac, member_list=ptf_pch_member_list, netns_name=ptf_netns_name)
            self.dut_helper.add_portchannel(pch_name=dut_pch_name, member_list=dut_pch_member_index_list, remove_vlan=remove_vlan)
            self.ptf_helper.set_link_up(ptf_pch_name, ptf_netns_name)

    def remove_portchannel(self, pch_param_list, ptf_netns_name=None):
        for item in pch_param_list:
            dut_pch_name = item.dut_pch_name
            ptf_pch_name = item.ptf_pch_name
            dut_pch_member_index_list = []
            ptf_pch_member_list = []
            for port_index in item.member_index_list:
                dut_pch_member_index_list.append(port_index)
                ptf_pch_member_list.append("eth{}".format(port_index))
            self.ptf_helper.set_link_down(ptf_pch_name, ptf_netns_name)  # if it has be down, it do not cause error.
            self.dut_helper.del_portchannel(pch_name=dut_pch_name, member_list=dut_pch_member_index_list)
            self.ptf_helper.stop_portchannel(pch_name=ptf_pch_name, member_list=ptf_pch_member_list, netns_name=ptf_netns_name)
    # PTF related command
    class PtfHelper():
        def __init__(self, outer):
            self.outer = outer
            self.name = "ptf"
            self.showCmd = True
            self.cmd_list = []

        def _exec(self, cmd, ignore_errors=False):
            if self.showCmd:
                logging.info(CMD_TEMPLATE, self.name, inspect.currentframe().f_back.f_code.co_name, cmd)
            if ignore_errors:
                self.outer.ptfhost.shell(cmd, module_ignore_errors=True)
            else:
                self.outer.ptfhost.shell(cmd)

        def copy_gobgp_config(self, as_number, ip):
            extra_vars = {
                "as_number": as_number,
                "ip_address": ip
            }
            self.outer.ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
            self.outer.ptfhost.template(src='./evpn/gobgpd_conf.j2', dest='/root/gobgpd_AS{}.conf'.format(as_number))

        def set_ip(self, ifname, ip_mask, netns_name=None):
            if netns_name != None:
                cmd = "ip netns exec {} ip address add {} dev {} || echo 0 ;".format(netns_name, ip_mask, ifname)
            else:
                cmd = "ip address add {} dev {} || echo 0 ;".format(ip_mask, ifname)
            self._exec(cmd)

        def unset_ip(self, ifname, ip_mask, netns_name=None):
            if netns_name != None:
                cmd = "ip netns exec {} ip address del {} dev {}".format(netns_name, ip_mask, ifname)
            else:
                cmd = "ip address del {} dev {} || echo 0 ;".format(ip_mask, ifname)
            self._exec(cmd)

        def get_index_mac(self, index):
            return self.outer.ptfadapter.dataplane.ports[(0, index)].mac()

        def set_link_up(self, ifname, netns_name=None):
            if netns_name != None:
                cmd = "ip netns exec {} ip link set {} up".format(netns_name, ifname)
            else:
                cmd = "ip link set {} up".format(ifname)
            self._exec(cmd)

        def set_link_down(self, ifname, netns_name=None):
            if netns_name != None:
                cmd = "ip netns exec {} ip link set {} down".format(netns_name, ifname)
            else:
                cmd = "ip link set {} down".format(ifname)
            self._exec(cmd)

        def cmd_ptf_portchannel_start(self, pch_name, hwaddr, member_list):
            content = {
                "device": "",
                "hwaddr": "",
                "runner": {
                    "name": "lacp",
                    "active": True,
                    "fast_rate": True,
                    "agg_select_policy": "lacp_prio_stable",
                    "tx_hash": ["eth", "ipv4", "ipv6"]
                },
                "link_watch": {"name": "ethtool"},
                "ports": {
                }
            }
            content["device"] = pch_name
            content["hwaddr"] = hwaddr
            for member in member_list:
                content["ports"][member] = {}

            config_str = json.dumps(content)
            cmd = "teamd -t {} -c '{}' -g -d".format(pch_name, config_str)
            return cmd

        def get_netns_list(self):
            return self.outer.ptfhost.shell("ip netns ls")['stdout_lines']

        def start_portchannel(self, pch_name, hwaddr, member_list, netns_name=None):
            cmd_to_create_pch = self.cmd_ptf_portchannel_start(pch_name=pch_name, hwaddr=hwaddr, member_list=member_list)

            cmd_list = []
            # add netns
            if netns_name != None and netns_name not in self.get_netns_list():
                cmd_list.append('ip netns add {}'.format(netns_name))

            # shutdown port for portchannel member
            for member in member_list:
                cmd_list.append('ip link set {} down'.format(member))
                if netns_name != None:
                    cmd_list.append("ip link set {} netns {}".format(member, netns_name))

            # start portchannel
            if netns_name != None:
                cmd_list.append("ip netns exec {} {}".format(netns_name, cmd_to_create_pch))
            else:
                cmd_list.append(cmd_to_create_pch)

            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def stop_portchannel(self, pch_name, member_list, netns_name=None):
            cmd_list = []
            if netns_name != None:
                cmd_list.append('ip netns exec {} ip link set {} down'.format(netns_name, pch_name))
            else:
                cmd_list.append('ip link set {} down'.format(pch_name))
            cmd_list.append('teamd -t {} -k'.format(pch_name))
            for member in member_list:
                if netns_name != None:
                    cmd_list.append('ip netns exec {} ip link set {} netns 1'.format(netns_name, member))
                cmd_list.append('ip link set {} up'.format(member))
            cmd = "\n".join(cmd_list)
            self._exec(cmd, ignore_errors=True)

        def restart_ptf_nn_agent(self):
            cmd_list = []
            cmd_list.append('supervisorctl restart ptf_nn_agent')

            cmd = "\n".join(cmd_list)
            self._exec(cmd)
            wait(10)

    # PTF gobgp related command
    class GobgpHelper():
        def __init__(self, outer):
            self.outer = outer
            self.name = "gobgp"
            self.showCmd = True
            self.cmd_list = []

        def _exec(self, cmd, ignore_errors=False, chdir=None):

            if self.showCmd:
                logging.info(CMD_TEMPLATE, self.name, inspect.currentframe().f_back.f_code.co_name, cmd)
            if ignore_errors:
                self.outer.ptfhost.shell(cmd, module_ignore_errors=True)
            elif chdir != None:
                self.outer.ptfhost.shell(cmd, chdir=chdir)
            else:
                self.outer.ptfhost.shell(cmd)

        def start(self, as_number, gobgp_port):
            cmd = "nohup gobgpd -f ./gobgpd_AS{}.conf -p --api-hosts=:{} > /dev/null 2>&1 & sleep 1".format(
                as_number, gobgp_port)
            self._exec(cmd, chdir="/root")

        def stop_all(self):
            cmd = "killall gobgpd"
            self._exec(cmd, ignore_errors=True)

        def add_neighbor(self, neighbor_ip, gobgp_port="50051"):
            cmd_list = []
            cmd_list.append("gobgp -p {} neighbor add {} as 65100 family ipv4-unicast,ipv6-unicast,l2vpn-evpn".format(
                gobgp_port, neighbor_ip))
            cmd = "\n".join(cmd_list)
            self._exec(cmd, ignore_errors=True)

        def check_gobgpd_present_status(self, gobgp_port_list=["50051"]):
            res = self.outer.ptfhost.shell("ps -xo cmd | grep gobgpd")
            for gobgp_port in gobgp_port_list:
                found = False
                for line in res["stdout_lines"]:
                    if "--api-hosts=:{}".format(gobgp_port) in line:
                        found = True
                        break
                if not found:
                    logging.error("gobgp port:{} is not start.".format(gobgp_port))
                    return False
            return True

        def check_gobgpd_neighbor(self, gobgp_port_list=["50051"]):
            all_establ = False
            not_establ_list = []
            for gobgp_port in gobgp_port_list:
                res = self.outer.ptfhost.shell("gobgp -p {} neighbor".format(gobgp_port))
                if 'Establ' not in res['stdout']:
                    not_establ_list.append(gobgp_port)
            logging.info("[check][gobgp], not established gobgp port:{}".format(not_establ_list))
            if len(not_establ_list) == 0:
                all_establ = True

            return all_establ

        def add_type2(self, mac, ip, es_info=None, as_ptf="65200", vni="10000", vtep_ip="10.0.0.65", gobgp_port="50051"):
            ip = ip if ip is not None else "0.0.0.0"
            if es_info != None:
                es_mac = es_info[0]
                es_id = es_info[1]
                cmd = "gobgp -p {port} global rib -a evpn add macadv {mac} {ip} esi MAC {es_mac} {es_id} etag 0 label {vni} rd {vtep_ip}:2 rt {as_number}:{vni} encap vxlan".format(
                    port=gobgp_port,
                    mac=mac,
                    ip=ip,
                    es_mac=es_mac,
                    es_id=es_id,
                    vtep_ip=vtep_ip,
                    as_number=as_ptf,
                    vni=vni)
            else:
                cmd = "gobgp -p {port} global rib -a evpn add macadv {mac} {ip} etag 0 label {vni} rd {vtep_ip}:2 rt {as_number}:{vni} encap vxlan".format(
                    port=gobgp_port,
                    mac=mac,
                    ip=ip,
                    vtep_ip=vtep_ip,
                    as_number=as_ptf,
                    vni=vni)
            self._exec(cmd)

        def del_type2(self, mac, ip, es_info, as_ptf="65200", vni="10000", vtep_ip="10.0.0.65", gobgp_port="50051"):
            ip = ip if ip is not None else "0.0.0.0"
            if es_info != None:
                es_mac = es_info[0]
                es_id = es_info[1]
                cmd = "gobgp -p {port} global rib -a evpn del macadv {mac} {ip} esi MAC {es_mac} {es_id} etag 0 label {vni} rd {vtep_ip}:2 rt {as_number}:{vni} encap vxlan".format(
                    port=gobgp_port,
                    mac=mac,
                    ip=ip,
                    es_mac=es_mac,
                    es_id=es_id,
                    vtep_ip=vtep_ip,
                    as_number=as_ptf,
                    vni=vni)
            else:
                cmd = "gobgp -p {port} global rib -a evpn del macadv {mac} {ip} etag 0 label {vni} rd {vtep_ip}:2 rt {as_number}:{vni} encap vxlan".format(
                    port=gobgp_port,
                    mac=mac,
                    ip=ip,
                    vtep_ip=vtep_ip,
                    as_number=as_ptf,
                    vni=vni)
            self._exec(cmd)

        def add_type3(self, as_ptf="65200", vni="10000", vtep_ip="10.0.0.65", gobgp_port="50051", rd="2"):
            cmd = "gobgp -p {port} global rib -a evpn add multicast {vtep_ip} etag 0 rd {vtep_ip}:{rd} rt {as_number}:{vni} encap vxlan pmsi ingress-repl {vni} {vtep_ip}".format(
                port=gobgp_port,
                vtep_ip=vtep_ip,
                as_number=as_ptf,
                rd=rd,
                vni=vni)
            self._exec(cmd)

        def del_type3(self, as_ptf="65200", vni="10000", vtep_ip="10.0.0.65", gobgp_port="50051", rd="2"):
            cmd = "gobgp -p {port} global rib -a evpn del multicast {vtep_ip} etag 0 rd {vtep_ip}:{rd} rt {as_number}:{vni} encap vxlan pmsi ingress-repl {vni} {vtep_ip}".format(
                port=gobgp_port,
                vtep_ip=vtep_ip,
                as_number=as_ptf,
                rd=rd,
                vni=vni)
            self._exec(cmd)

    # DUT related command
    class DutHelper():
        def __init__(self, outer):
            self.outer = outer
            self.name = "dut"
            self.showCmd = True
            self.cmd_list = []

        def _exec(self, cmd, ignore_errors=False):
            if self.showCmd:
                logging.info(CMD_TEMPLATE, self.name, inspect.currentframe().f_back.f_code.co_name, cmd)
            if ignore_errors:
                self.outer.duthost.shell(cmd, module_ignore_errors=True)
            else:
                self.outer.duthost.shell(cmd)

        def add_vxlan(self, vtep_ip, vlanid, vni):
            cmd_list = []
            cmd_list.append("config vxlan add vtep {}".format(vtep_ip))
            cmd_list.append("config vxlan evpn_nvo add evpnnvo1 vtep")
            cmd_list.append("config vxlan map add vtep {} {}".format(vlanid, vni))

            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def del_vxlan(self, vlanid, vni):
            cmd_list = []
            cmd_list.append("config vxlan map del vtep {} {}".format(vlanid, vni))
            cmd_list.append("config vxlan evpn_nvo del evpnnvo1")
            cmd_list.append("config vxlan del vtep")

            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def set_ip(self, iface, ip_mask, secondary=False, flag_vlan=True):
            cmd_list = []
            extra_str = ""
            if secondary:
                extra_str = "--secondary"
            if type(iface) == int:
                ifname = DUT_PORT_NAME_LIST[iface]
                if iface in T0_VLAN_INDEX_RANGE and flag_vlan:
                    cmd_list.append("config vlan member del 1000 {}".format(ifname))
                cmd_list.append("config interface ip add {} '{}' {}".format(ifname, ip_mask, extra_str))
            else:
                ifname = str(iface)
                cmd_list.append("config interface ip add {} '{}' {}".format(ifname, ip_mask, extra_str))
            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def unset_ip(self, iface, ip_mask, secondary=False, flag_vlan=True):
            cmd_list = []
            extra_str = ""
            if secondary:
                extra_str = "--secondary"
            if type(iface) == int:
                ifname = DUT_PORT_NAME_LIST[iface]
                cmd_list.append("config interface ip remove {} '{}' {}".format(ifname, ip_mask, extra_str))
                if iface in T0_VLAN_INDEX_RANGE and flag_vlan:
                    cmd_list.append("config vlan member add 1000 {} -u".format(ifname))
            else:
                ifname = str(iface)
                cmd_list.append("config interface ip remove {} '{}' {}".format(ifname, ip_mask, extra_str))
            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def get_all_iface_mac(self):
            cmd = 'ip -j link show | jq ".[] | {(.ifname): .address}" | jq -s add'
            result_shell = self.outer.duthost.shell(cmd)
            result_json = json.loads(result_shell['stdout'])
            return result_json

        def get_iface_mac(self, iface_name):
            all_iface_mac = self.get_all_iface_mac()
            if iface_name in all_iface_mac:
                return all_iface_mac[iface_name]

        def get_index_mac(self, index):
            iface_name = DUT_PORT_NAME_LIST[index]
            return self.get_iface_mac(iface_name)

        def add_portchannel(self, pch_name, member_list, remove_vlan=True):
            cmd_list = []
            cmd_list.append("config portchannel add {}".format(pch_name))
            for port_index in member_list:
                ifname = DUT_PORT_NAME_LIST[port_index]
                if port_index in T0_VLAN_INDEX_RANGE and remove_vlan is True:
                    cmd_list.append("config vlan member del 1000 {}".format(ifname))
                cmd_list.append("config portchannel member add {} {}".format(pch_name, ifname))

            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def del_portchannel(self, pch_name, member_list):
            cmd_list = []
            for port_index in member_list:
                ifname = DUT_PORT_NAME_LIST[port_index]
                cmd_list.append("config portchannel member del {} {}".format(pch_name, ifname))
                if port_index in T0_VLAN_INDEX_RANGE:
                    cmd_list.append("config vlan member add 1000 {} -u".format(ifname))
            cmd_list.append("config portchannel del {}".format(pch_name))

            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def add_portchannel_to_vlan(self, pch_name, vlanid=1000, untagged=False):
            extra = ""
            if untagged:
                extra = "-u"
            cmd = "config vlan member add {} {} {}".format(vlanid, pch_name, extra)
            self._exec(cmd)

        def del_portchannel_from_vlan(self, pch_name, vlanid=1000):
            cmd = "config vlan member del {} {}".format(vlanid, pch_name)
            self._exec(cmd)

    # DUT vtysh related command
    class VtyshFrrHelper():
        def __init__(self, outer):
            self.outer = outer
            self.name = "vtysh"
            self.showCmd = True
            self.cmd_list = []

        def _exec(self, cmd, ignore_errors=False):
            if self.showCmd:
                logging.info(CMD_TEMPLATE, self.name, inspect.currentframe().f_back.f_code.co_name, cmd)
            if ignore_errors:
                self.outer.duthost.shell(cmd, module_ignore_errors=True)
            else:
                self.outer.duthost.shell(cmd)

        def set_advertise_all_vni(self):
            cmd = "vtysh -c 'configure terminal' -c 'router bgp 65100' -c 'address-family l2vpn evpn' -c 'advertise-all-vni'"
            self._exec(cmd)

        def unset_advertise_all_vni(self):
            cmd = "vtysh -c 'configure terminal' -c 'router bgp 65100' -c 'address-family l2vpn evpn' -c 'no advertise-all-vni'"
            self._exec(cmd)

        def set_neighbor(self, neighbor_ip, as_number):
            cmd_list = []
            cmd_list.append("vtysh -c 'configure terminal' -c 'router bgp 65100' -c 'neighbor {} remote-as {}'".format(neighbor_ip, as_number))
            cmd_list.append("vtysh -c 'configure terminal' -c 'router bgp 65100' -c 'address-family l2vpn evpn' -c 'neighbor {} activate'".format(neighbor_ip))
            cmd = "\n".join(cmd_list)
            self._exec(cmd)

        def unset_neighbor(self, neighbor_ip, as_number):
            cmd_list = []
            cmd_list.append("vtysh -c 'configure terminal' -c 'router bgp 65100' -c 'address-family l2vpn evpn' -c 'no neighbor {} activate'".format(neighbor_ip))
            cmd_list.append("vtysh -c 'configure terminal' -c 'router bgp 65100' -c 'no neighbor {} remote-as {}'".format(neighbor_ip, as_number))
            cmd = "\n".join(cmd_list)
            self._exec(cmd)

    class PacketHelper():
        def __init__(self, outer):
            self.outer = outer
            self.name = "pkt"

        def compose_expected_vxlan_packet(self, outer_da, outer_sa, outer_dip, outer_sip, vni, pkt, GPE_flag=False):
            exp_pkt = testutils.simple_vxlan_packet(
                eth_dst=outer_da,
                eth_src=outer_sa,
                ip_dst=outer_dip,
                ip_src=outer_sip,
                vxlan_vni=vni,
                inner_frame=pkt,
            )
            if GPE_flag:
                exp_pkt["Ethernet"]["IP"]["UDP"]["VXLAN"].flags = 0x0a
            exp_pkt = mask.Mask(exp_pkt)
            exp_pkt.set_do_not_care_scapy(scapy.UDP, 'sport')
            exp_pkt.set_do_not_care_scapy(scapy.UDP, 'chksum')
            exp_pkt.set_do_not_care_scapy(scapy.IP, 'ttl')
            exp_pkt.set_do_not_care_scapy(scapy.IP, 'chksum')
            exp_pkt.set_do_not_care_scapy(scapy.IP, 'id')
            return exp_pkt

        def create_vxlan_packet(self, outer_da, outer_sa, outer_dip, outer_sip, vni, inner_da, inner_dip, inner_sa="00:11:22:33:55:66", inner_sip="192.168.0.44", is_inner_vlan=False, vlan_id=1):
            out_ether = scapy.Ether(dst=outer_da, src=outer_sa)
            out_ip = scapy.IP(dst=outer_dip, src=outer_sip)
            out_udp = scapy.UDP(dport=4789, sport=random.randint(49152, 65535 - NUM_CONTINUOUS_PKT_COUNT))
            vxlan = scapy.VXLAN(vni=vni)

            ether = scapy.Ether(dst=inner_da, src=inner_sa)
            dot1q = scapy.Dot1Q(vlan=vlan_id)
            ip = scapy.IP(dst=inner_dip, src=inner_sip)
            udp = scapy.UDP(dport=22222, sport=11111)

            # minimum packet for untagged
            payload = "\0" * (64-4-len(ether / ip / udp))

            packet_vxlan = out_ether / out_ip / out_udp / vxlan / ether / ip / udp / payload
            if is_inner_vlan:
                packet_inner = ether / dot1q / ip / udp / payload
            else:
                packet_inner = ether / ip / udp / payload
            return packet_vxlan, packet_inner

        def verify_packet_count(self, pkt, port_id):
            test = self.outer.ptfadapter
            device, port = testutils.port_to_tuple(port_id)
            logging.debug("Checking for pkt on device %d, port %d", device, port)
            result = testutils.dp_poll(test, device_number=device, port_number=port,
                                       exp_pkt=pkt)
            if isinstance(result, test.dataplane.PollSuccess):
                return(1, result.packet)

            return(0, None)

        def verify_decap_receive_packet(self, send_port, access_port_list, pkt_send, pkt_expected):
            test = self.outer.ptfadapter
            hit_map = {}
            for each in access_port_list:
                hit_map[each] = 0

            for i in range(0, NUM_CONTINUOUS_PKT_COUNT):
                pkt_send['UDP'].sport = pkt_send['UDP'].sport + 1
                test.dataplane.flush()
                testutils.send(test, send_port, pkt_send)
                logging.debug("send packet #{}".format(i))
                index, _ = testutils.verify_packet_any_port(test, pkt_expected, access_port_list)
                hit_map[access_port_list[index]] += 1
                logging.debug("Received in port index: {}".format(access_port_list[index]))

            # check whether each port receives at lease one packet
            for each in hit_map:
                pt_assert(hit_map[each] > 0)
            # check all sended packet is all received
            pt_assert(sum(hit_map.values()) == NUM_CONTINUOUS_PKT_COUNT)


@pytest.fixture(scope="module")
def evpn_env(duthost, ptfhost, ptfadapter):
    instance = EVPN_ENV(duthost, ptfhost, ptfadapter)
    yield instance

# available parameters : one_neighbor , all_neighbors
@pytest.fixture(scope="class", params=["one_neighbor"])
def neighbor_size(request):
    yield request.param

# available parameters : normal_port , with_portchannel
@pytest.fixture(scope="class", params=["normal_port"])
def access_ports_type(request):
    yield request.param

