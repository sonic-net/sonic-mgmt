from contextlib import contextmanager
from netaddr import IPNetwork
from .qos_fixtures import lossless_prio_dscp_map, leaf_fanouts      # noqa: F401
from tests.common.cisco_data import is_cisco_device, copy_set_voq_watchdog_script_cisco_8000, run_dshell_command
import re
import os
import json
import logging
import requests

logger = logging.getLogger(__name__)

PFC_GEN_FILE = 'pfc_gen.py'
PFC_GEN_LOCAL_PATH = '../../ansible/roles/test/files/helpers/pfc_gen.py'
PFC_GEN_REMOTE_PATH = '~/pfc_gen.py'
WITHDRAW = 'withdraw'
ANNOUNCE = 'announce'


def atoi(text):
    return int(text) if text.isdigit() else text


def natural_keys(text):
    return [atoi(c) for c in re.split(r'(\d+)', text)]


def ansible_stdout_to_str(ansible_stdout):
    """
    @Summary: The stdout of Ansible host is essentially a list of unicode characters.
              This function converts it to a string.
    @param ansible_stdout: stdout of Ansible
    @return: Return a string
    """
    result = ""
    for x in ansible_stdout:
        result += x
    return result


def get_phy_intfs(host_ans):
    """
    @Summary: Get the physical interfaces (e.g., EthernetX) of a DUT
    @param host_ans: Ansible host instance of this DUT
    @return: Return the list of active interfaces
    """
    intf_facts = host_ans.interface_facts(
    )['ansible_facts']['ansible_interface_facts']
    phy_intfs = [k for k in list(intf_facts.keys())
                 if k.startswith('Ethernet') and "." not in k]
    return phy_intfs


def get_active_intfs(host_ans):
    """
    @Summary: Get the active interfaces of a DUT
    @param host_ans: Ansible host instance of this DUT
    @return: Return the list of active interfaces
    """
    int_status = host_ans.show_interface(command="status")[
        'ansible_facts']['int_status']
    active_intfs = []

    for intf in int_status:
        if int_status[intf]['admin_state'] == 'up' and \
           int_status[intf]['oper_state'] == 'up':
            active_intfs.append(intf)

    return active_intfs


def get_addrs_in_subnet(subnet, n):
    """
    @Summary: Get N IP addresses in a subnet
    @param subnet: IPv4 subnet, e.g., '192.168.1.1/24'
    @param n: # of IP addresses to get
    @return: Retuen n IPv4 addresses in this subnet in a list
    """
    ip_addr = subnet.split('/')[0]
    ip_addrs = [str(x) for x in list(IPNetwork(subnet))]
    ip_addrs.remove(ip_addr)

    """ Try to avoid network and broadcast addresses """
    if len(ip_addrs) >= n + 2:
        del ip_addrs[0]
        del ip_addrs[-1]

    return ip_addrs[:n]


def start_pause(host_ans, pkt_gen_path, intf, pkt_count, pause_duration, pause_priority):
    """
    @Summary: Start priority-based/global flow control pause storm on an interface of a leaf fanout switch
    @param host_ans: Ansible host instance of this leaf fanout
    @param pkt_gen_path: path of packet generator
    @param intf: interface to send packets
    @param pkt_count: # of pause frames to send
    @pause_duration: pause time duration
    @pause_priority: priority to pause (None means global pause)
    """
    """ global pause """
    if pause_priority is None:
        cmd = "nohup sudo python %s -i %s -g -t %d -n %d </dev/null >/dev/null 2>&1 &" % (
            pkt_gen_path, intf, pause_duration, pkt_count)

    else:
        cmd = "nohup sudo python %s -i %s -p %d -t %d -n %d </dev/null >/dev/null 2>&1 &" % (
            pkt_gen_path, intf, 2**pause_priority, pause_duration, pkt_count)

    print(cmd)
    host_ans.host.shell(cmd)


def stop_pause(host_ans, pkt_gen_path):
    """
    @Summary: Stop priority-based/global flow control pause storm on a leaf fanout switch
    @param host_ans: Ansible host instance of this leaf fanout
    @param pkt_gen_path: path of packet generator
    """
    cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (pkt_gen_path)
    host_ans.host.shell(cmd)


def get_all_vlans(host_ans):
    """
    @Summary: Get all vlans active on a DUT from the device's minigraph facts
    @param host_ans: Ansible host instance of the device
    @return: Dictionary, mapping dictionaries representing each vlan's values to the vlan name
    """
    mg_facts = host_ans.minigraph_facts(
        host=host_ans.hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']

    return mg_vlans


def get_active_vlan_members(host_ans, vlan):
    """
    @Summary: Get all the active physical interfaces enslaved to a Vlan
    @param host_ans: Ansible host instance of the device
    @param vlan: Dictionary containing a single vlan's `name`, `members` and `vlanid`
    @return: Return the list of active physical interfaces
    """
    """ Get all the Vlan memebrs """
    vlan_members = vlan['members']
    vlan_id = None
    if 'type' in vlan and vlan['type'] is not None \
            and 'Tagged' in vlan['type']:
        vlan_id = vlan['vlanid']

    """ Filter inactive Vlan members """
    active_intfs = get_active_intfs(host_ans)
    vlan_members = [x for x in vlan_members if x in active_intfs]

    return vlan_members, vlan_id


def get_vlan_subnet(host_ans, vlan):
    """
    @Summary: Get Vlan subnet of a T0 device
    @param host_ans: Ansible host instance of the device
    @param vlan: Dictionary containing a single vlan's `name`, `members` and `vlanid`
    @return: Return Vlan subnet, e.g., "192.168.1.1/24"
    """
    mg_facts = host_ans.minigraph_facts(
        host=host_ans.hostname)['ansible_facts']

    mg_vlan_intfs = mg_facts['minigraph_vlan_interfaces']
    vlan_intf = [curr_intf for curr_intf in mg_vlan_intfs if curr_intf['attachto'] == vlan['name']][0]
    vlan_subnet = ansible_stdout_to_str(vlan_intf['subnet'])
    return vlan_subnet


def setup_testbed(fanouthosts, ptfhost, leaf_fanouts):      # noqa: F811
    """
    @Summary: Set up the testbed
    @param leaf_fanouts: Leaf fanout switches
    """

    """ Copy the PFC generator to leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = fanouthosts[peer_device]
        cmd = "sudo kill -9 $(pgrep -f %s) </dev/null >/dev/null 2>&1 &" % (PFC_GEN_FILE)
        peerdev_ans.host.shell(cmd)
        file_src = os.path.join(os.path.dirname(__file__), PFC_GEN_LOCAL_PATH)
        peerdev_ans.host.copy(
            src=file_src, dest=PFC_GEN_REMOTE_PATH, force=True)

    """ Stop PFC storm at the leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = fanouthosts[peer_device]
        stop_pause(peerdev_ans, PFC_GEN_FILE)


def get_max_priority(testbed_type):
    """
    Returns the maximum priority supported by a testbed type

    Args:
        testbed_type(string): testbed topology

    Returns:
        max_prio(string): Maximum priority that is applicable based on testbed type
    """
    if 'backend' in testbed_type:
        return 8
    else:
        return 64


def dutBufferConfig(duthost, dut_asic=None):
    bufferConfig = {}
    try:
        ns_spec = ""
        if dut_asic is not None:
            ns = dut_asic.get_asic_namespace()
            if ns is not None:
                # multi-asic support
                ns_spec = " -n " + ns
        bufferConfig['BUFFER_POOL'] = json.loads(duthost.shell(
            'sonic-cfggen -d --var-json "BUFFER_POOL"' + ns_spec)['stdout'])
        bufferConfig['BUFFER_PROFILE'] = json.loads(duthost.shell(
            'sonic-cfggen -d --var-json "BUFFER_PROFILE"' + ns_spec)['stdout'])
        bufferConfig['BUFFER_QUEUE'] = json.loads(duthost.shell(
            'sonic-cfggen -d --var-json "BUFFER_QUEUE"' + ns_spec)['stdout'])
        bufferConfig['BUFFER_PG'] = json.loads(duthost.shell(
            'sonic-cfggen -d --var-json "BUFFER_PG"' + ns_spec)['stdout'])
    except Exception as err:
        logger.info(err)
    return bufferConfig


def voq_watchdog_enabled(get_src_dst_asic_and_duts):
    dst_dut = get_src_dst_asic_and_duts['dst_dut']
    if not is_cisco_device(dst_dut):
        return False
    namespace_option = "-n asic0" if dst_dut.facts.get("modular_chassis") else ""
    show_command = "show platform npu global {}".format(namespace_option)
    result = run_dshell_command(dst_dut, show_command)
    pattern = r"voq_watchdog_enabled +: +True"
    match = re.search(pattern, result["stdout"])
    return match


def modify_voq_watchdog(duthosts, get_src_dst_asic_and_duts, enable):
    # Skip if voq watchdog is not enabled.
    if not voq_watchdog_enabled(get_src_dst_asic_and_duts):
        logger.info("voq_watchdog is not enabled, skipping modify voq watchdog")
        return

    dst_dut = get_src_dst_asic_and_duts['dst_dut']
    dst_asic = get_src_dst_asic_and_duts['dst_asic']
    dut_list = [dst_dut]
    asic_index_list = [dst_asic.asic_index]

    if not get_src_dst_asic_and_duts["single_asic_test"]:
        src_dut = get_src_dst_asic_and_duts['src_dut']
        src_asic = get_src_dst_asic_and_duts['src_asic']
        dut_list.append(src_dut)
        asic_index_list.append(src_asic.asic_index)
        # fabric card asics
        for rp_dut in duthosts.supervisor_nodes:
            for asic in rp_dut.asics:
                dut_list.append(rp_dut)
                asic_index_list.append(asic.asic_index)

    # Modify voq watchdog.
    for (dut, asic_index) in zip(dut_list, asic_index_list):
        copy_set_voq_watchdog_script_cisco_8000(
            dut=dut,
            asic=asic_index,
            enable=enable)
        cmd_opt = "-n asic{}".format(asic_index)
        if not dst_dut.sonichost.is_multi_asic:
            cmd_opt = ""
        dut.shell("sudo show platform npu script {} -s set_voq_watchdog.py".format(cmd_opt))


@contextmanager
def disable_voq_watchdog(duthosts, get_src_dst_asic_and_duts):
    # Disable voq watchdog.
    modify_voq_watchdog(duthosts, get_src_dst_asic_and_duts, enable=False)
    yield
    # Enable voq watchdog.
    modify_voq_watchdog(duthosts, get_src_dst_asic_and_duts, enable=True)


def get_upstream_vm_offset(nbrhosts, tbinfo):
    """
    Get ports offset of exabgp port
    """
    port_offset_list = []
    if 't0' in tbinfo['topo']['type']:
        vm_filter = 'T1'
    elif 't1' in tbinfo['topo']['type']:
        vm_filter = 'T2'
    vm_name_list = [vm_name for vm_name in nbrhosts.keys() if vm_name.endswith(vm_filter)]
    for vm_name in vm_name_list:
        port_offset = tbinfo['topo']['properties']['topology']['VMs'][vm_name]['vm_offset']
        port_offset_list.append((port_offset))
    return port_offset_list


def get_upstream_exabgp_port(nbrhosts, tbinfo, exabgp_base_port):
    """
    Get exabgp port and ptf receive port
    """
    port_offset_list = get_upstream_vm_offset(nbrhosts, tbinfo)
    return [_ + exabgp_base_port for _ in port_offset_list]


def install_route_from_exabgp(operation, ptfip, route, port):
    """
    Install or withdraw ip route by exabgp
    """
    route_data = [route]
    url = "http://{}:{}".format(ptfip, port)
    command = "{} attribute next-hop self nlri {}".format(operation, ' '.join(route_data))
    data = {"command": command}
    logger.info("url: {}".format(url))
    logger.info("command: {}".format(data))
    r = requests.post(url, data=data, timeout=90)
    assert r.status_code == 200


def announce_route(ptfip, route, port, action=ANNOUNCE):
    """
    Announce or withdraw ipv4 or ipv6 route
    """
    logger.info("\n========================== announce_route -- {} ==========================".format(action))
    logger.info(" action:{}\n ptfip:{}\n route:{}\n port:{}".format(action, ptfip, route, port))
    install_route_from_exabgp(action, ptfip, route, port)
    logger.info("\n--------------------------------------------------------------------------------")
