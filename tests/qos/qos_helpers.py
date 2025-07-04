from netaddr import IPNetwork
from .qos_fixtures import lossless_prio_dscp_map, leaf_fanouts      # noqa: F401
import re
import os
import json
import logging

logger = logging.getLogger(__name__)


PFC_GEN_FILE = 'pfc_gen.py'
PFC_GEN_LOCAL_PATH = '../../ansible/roles/test/files/helpers/pfc_gen.py'
PFC_GEN_REMOTE_PATH = '~/pfc_gen.py'


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


def eos_to_linux_intf(eos_intf_name, hwsku=None):
    """
    @Summary: Map EOS's interface name to Linux's interface name
    @param eos_intf_name: Interface name in EOS
    @return: Return the interface name in Linux
    """
    if hwsku == "MLNX-OS":
        linux_intf_name = eos_intf_name.replace(
            "ernet 1/", "sl1p").replace("/", "sp")
    elif hwsku and "Nokia" in hwsku:
        linux_intf_name = eos_intf_name
    else:
        linux_intf_name = eos_intf_name.replace(
            'Ethernet', 'et').replace('/', '_')
    return linux_intf_name


def nxos_to_linux_intf(nxos_intf_name):
    """
        @Summary: Map NxOS's interface name to Linux's interface name
        @param nxos_intf_name: Interface name in NXOS
        @return: Return the interface name in Linux
    """
    return nxos_intf_name.replace('Ethernet', 'Eth').replace('/', '-')


def sonic_to_linux_intf(sonic_intf_name):
    """
    @Summary: Map SONiC's interface name to Linux's interface name
    @param sonic_intf_name: Interface name in SONiC
    @return: Return the interface name in Linux
    """
    return sonic_intf_name


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
