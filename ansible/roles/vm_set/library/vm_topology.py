#!/usr/bin/python

import datetime
import logging
import hashlib
import json
import re
import subprocess
import shlex
import time
import traceback

import docker

from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: vm_topology
version_added: "0.1"
author: Pavel Shirshov (pavelsh@microsoft.com)
short_description: Create a custom virtual topology for vm_sets
description:
    - With cmd: 'create' the module:
      - creates a bridges for every VM name in vm_names which will be used for back plane connections
      - creates len(vm_names)*max_fp_num ovs bridges with name template "br-{{ vm_name }}-{{ 0..max_fp_num-1 }}" which will be used by FP port of VMs
    - With cmd: 'destroy' the module:
      - destroys ovs bridges which were created with 'create' cmd
    - With cmd: 'bind' the module:
      - inserts mgmt interface inside of the docker container with name "ptf_{{vm_set_name}}"
      - assigns ip address and default route to the mgmt interface
      - inserts physical vlans into the docker container to represent endhosts
      - binds internal interfaces of the docker container to corresponding VM ports
      - connects interfaces "Ethernet9" of every VM in current vm set to each other
      - connect dut fp ports to bridges representing vm set fp ports
      - connect dut mgmt ports to mgmt bridge (option)
    - with cmd: 'renumber' the module:
      - disconnect vlan interface to bridges representing vm set fp ports
      - inserts mgmt interface inside of the docker container with name "ptf_{{vm_set_name}}"
      - assigns ip address and default route to the mgmt interface
      - inserts physical vlans into the docker container to represent endhosts
      - binds internal interfaces of the docker container to corresponding VM ports
    - With cmd: 'unbind' the module:
      - destroys everything what was created with command 'bind'
    - With cmd: 'connect-vms' the module:
      - disconnect all VM ports from the DUT
    - With cmd: 'disconnect-vms' the module:
      - reconnect all VM ports to the DUT


Parameters:
    - cmd: One of the commands: 'create', 'bind', 'renumber', 'unbind', 'destroy', 'connect-vms', 'disconnect-vms'
    - vm_set_name: name of the current vm set. It will be used for generation of interface names
    - topo: dictionary with VMs topology. Check vars/topo_*.yml for details
    - vm_names: list of VMs represented on a current host
    - vm_base: which VM consider the first VM in the current vm set
    - ptf_mgmt_ip_addr: ip address with prefixlen for the injected docker container
    - ptf_mgmt_ipv6_addr: ipv6 address with prefixlen for the injected docker container
    - ptf_mgmt_ip_gw: default gateway for the injected docker container
    - ptf_mgmt_ipv6_gw: default ipv6 gateway for the injected docker container
    - ptf_bp_ip_addr: ipv6 address with prefixlen for the injected docker container
    - ptf_bp_ipv6_addr: ipv6 address with prefixlen for the injected docker container
    - mgmt_bridge: a bridge which is used as mgmt bridge on the host
    - duts_fp_ports: duts front panel ports
    - duts_mgmt_port: duts mgmt port
    - duts_name: duts names
    - fp_mtu: MTU for FP ports
'''

EXAMPLES = '''
- name: Create VMs network
  vm_network:
    cmd:          'create'
    vm_names:     "{{ VM_hosts }}"
    fp_mtu:       "{{ fp_mtu_size }}"

- name: Bind topology {{ topo }} to VMs. base vm = {{ VM_base }}
  vm_topology:
    cmd: "bind"
    vm_set_name: "{{ vm_set_name }}"
    topo: "{{ topology }}"
    vm_names: "{{ VM_hosts }}"
    vm_base: "{{ VM_base }}"
    ptf_mgmt_ip_addr: "{{ ptf_ip }}"
    ptf_mgmt_ipv6_addr: "{{ ptf_ipv6 }}"
    ptf_mgmt_ip_gw: "{{ mgmt_gw }}"
    ptf_mgmt_ipv6_gw: "{{ mgmt_gw_v6 }}"
    ptf_bp_ip_addr: "{{ ptf_ip }}"
    ptf_bp_ipv6_addr: "{{ ptf_ip }}"
    mgmt_bridge: "{{ mgmt_bridge }}"
    duts_mgmt_port: "{{ duts_mgmt_port }}"
    duts_fp_ports: "{{ duts_fp_ports }}"
    duts_name: "{{ duts_name }}"
    fp_mtu: "{{ fp_mtu_size }}"
    max_fp_num: "{{ max_fp_num }}

- name: Bind ptf_ip to keysight_api_server
  vm_topology:
    cmd: "bind_keysight_api_server_ip"
    ptf_mgmt_ip_addr: "{{ ptf_ip }}"
    ptf_mgmt_ipv6_addr: "{{ ptf_ipv6 }}"
    ptf_mgmt_ip_gw: "{{ mgmt_gw }}"
    ptf_mgmt_ipv6_gw: "{{ mgmt_gw_v6 | default(None) }}"
    mgmt_bridge: "{{ mgmt_bridge }}"
    vm_names: ""
'''


DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 4
VM_SET_NAME_MAX_LEN = 8  # used in interface names. So restricted
MGMT_PORT_NAME = 'mgmt'
BP_PORT_NAME = 'backplane'
CMD_DEBUG_FNAME = "/tmp/vmtopology.cmds.%s.txt"

OVS_FP_BRIDGE_REGEX = 'br-%s-[0-9]+'
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
OVS_FP_TAP_TEMPLATE = '%s-t%d'
OVS_BP_TAP_TEMPLATE = '%s-back'
INJECTED_INTERFACES_TEMPLATE = 'inje-%s-%d'
MUXY_INTERFACES_TEMPLATE = 'muxy-%s-%d'
MUXY_BRIDGE_TEMPLATE = 'mbr-%s-%d'
PTF_NAME_TEMPLATE = 'ptf_%s'
PTF_MGMT_IF_TEMPLATE = 'ptf-%s-m'
PTF_BP_IF_TEMPLATE = 'ptf-%s-b'
ROOT_BACK_BR_TEMPLATE = 'br-b-%s'
PTF_FP_IFACE_TEMPLATE = 'eth%d'
RETRIES = 10

VS_CHASSIS_INBAND_BRIDGE_NAME = "br-T2Inband"
VS_CHASSIS_MIDPLANE_BRIDGE_NAME = "br-T2Midplane"

BACKEND_TOR_TYPE = "BackEndToRRouter"
BACKEND_LEAF_TYPE = "BackEndLeafRouter"
SUB_INTERFACE_SEPARATOR = '.'
SUB_INTERFACE_VLAN_ID = '10'


def config_logging():
    curtime = datetime.datetime.now().isoformat()
    logging.basicConfig(filename=CMD_DEBUG_FNAME % curtime,
                        format='%(asctime)s %(levelname)s %(name)s#%(lineno)d: %(message)s',
                        level=logging.DEBUG)


def adaptive_name(template, host, index):
    """
    A helper function for interface/bridge name calculation.
    Since the name of interface must be less than 15 bytes. This util is to adjust the template automatically
    according to the length of vmhost name and port index. The leading characters (inje, muxy, mbr) will be shorten if necessary
    e.g.
    port 21 on vms7-6 -> inje-vms7-6-21
    port 121 on vms21-1 -> inj-vms21-1-121
    port 121 on vms121-1 -> in-vms121-1-121
    """
    MAX_LEN = 15
    host_index_str = '-%s-%d' % (host, index)
    leading_len = MAX_LEN - len(host_index_str)
    leading_characters = template.split('-')[0][:leading_len]
    rendered_name = leading_characters + host_index_str
    return rendered_name


def adaptive_temporary_interface(vm_set_name, interface_name, reserved_space=0):
    """A helper function to calculate temporary interface name for the interface to adapt to the 15-characters name limit."""
    MAX_LEN = 15 - reserved_space
    t_suffix = "_t"
    HASH_LEN = 6
    # the max length is at least as long as the hash string length + suffix length
    if MAX_LEN < HASH_LEN + len(t_suffix):
        raise ValueError("Requested length is too short to get temporary interface name.")
    interface_name_len = len(interface_name)
    ptf_name = PTF_NAME_TEMPLATE % vm_set_name
    if interface_name_len <= MAX_LEN - len(t_suffix) - HASH_LEN:
        t_int_if = hashlib.md5(ptf_name.encode("utf-8")).hexdigest()[0:HASH_LEN] + interface_name + t_suffix
    else:
        t_int_if = hashlib.md5((ptf_name + interface_name).encode("utf-8")).hexdigest()[0:HASH_LEN] + t_suffix
    return t_int_if


class HostInterfaces(object):
    """Data descriptor that supports multi-DUTs interface definition."""

    def __get__(self, obj, objtype):
        return obj._host_interfaces

    def __set__(self, obj, host_interfaces):
        """
        Parse and set host interfaces.

        for single DUT, host interface like [0, 1, 2, ...],
        where the number is the port index starting from 0.

        For multi DUT, host interface like [(0, 1), (0, 2), (1, 1), (1, 2), ...],
        or [[(0, 1, 1), (1, 1, 1)], [(0, 2, 2), (1, 2, 2)]]
        where the tuple is (dut_index, dut_port_index) or (dut_index, dut_port_index, ptf_port_index), both starting
        from 0.

        For dual-tor, host interface look like [[(0, 1), (1, 1)], [(0, 2), (1,2)], ...],
        or [[(0, 1, 1), (1, 1, 1)], [(0, 2, 2), (1, 2, 2)]]
        where one interface consists of multiple ports to DUT.

        Example: [[(0, 2, 2), (1, 2, 2)], ] means that the PTF host interface 2 connects to port2@dut0 and port2@dut1

        Example: [[(0, 1), (1, 1)], ] means the PTF host interface connects to port1@dut0 and port1@dut1.
        """
        if obj._is_multi_duts:
            obj._host_interfaces = []
            for intf in host_interfaces:
                intfs = intf.split(',')
                # re.split('\.|@', s) is to split string 's' by characters '.' or '@' and return a list.
                # The tuple may has 2 or 3 items:
                # (dut_index, dut_port_index) or (dut_index, dut_port_index, ptf_port_index)
                if len(intfs) > 1:
                    obj._host_interfaces.append(
                        [tuple(map(int, re.split(r'\.|@', x.strip()))) for x in intfs])
                else:
                    obj._host_interfaces.append(
                        tuple(map(int, re.split(r'\.|@', intfs[0].strip()))))
        else:
            obj._host_interfaces = host_interfaces


class VMTopology(object):

    host_interfaces = HostInterfaces()

    def __init__(self, vm_names, vm_properties, fp_mtu, max_fp_num, topo):
        self.vm_names = vm_names
        self.vm_properties = vm_properties
        self.fp_mtu = fp_mtu
        self.max_fp_num = max_fp_num
        self.topo = topo
        return

    def init(self, vm_set_name, vm_base, duts_fp_ports, duts_name, ptf_exists=True):
        self.vm_set_name = vm_set_name
        self.duts_name = duts_name

        if ptf_exists:
            self.pid = VMTopology.get_pid(PTF_NAME_TEMPLATE % vm_set_name)
        else:
            self.pid = None

        self.VMs = {}
        if 'VMs' in self.topo:
            self.vm_base = vm_base
            if vm_base in self.vm_names:
                self.vm_base_index = self.vm_names.index(vm_base)
            else:
                raise Exception('VM_base "%s" should be presented in current vm_names: %s' % (vm_base, str(self.vm_names)))
            for k, v in self.topo['VMs'].items():
                if self.vm_base_index + v['vm_offset'] < len(self.vm_names):
                    self.VMs[k] = v

            for hostname, attrs in self.VMs.items():
                vmname = self.vm_names[self.vm_base_index + attrs['vm_offset']]
                vm_bridges = self.get_vm_bridges(vmname)
                if len(attrs['vlans']) > len(vm_bridges):
                    raise Exception("Wrong vlans parameter for hostname %s, vm %s. Too many vlans. Maximum is %d" % (hostname, vmname, len(vm_bridges)))

        self._is_multi_duts = True if len(self.duts_name) > 1 else False
        # For now distinguish a cable topology since it does not contain any vms and there are two ToR's
        self._is_cable = True if len(self.duts_name) > 1 and 'VMs' not in self.topo else False

        if 'host_interfaces' in self.topo:
            self.host_interfaces = self.topo['host_interfaces']
        else:
            self.host_interfaces = []

        if 'disabled_host_interfaces' in self.topo:
            self.disabled_host_interfaces = self.topo['disabled_host_interfaces']
        else:
            self.disabled_host_interfaces = []

        self.duts_fp_ports = duts_fp_ports

        self.injected_fp_ports = self.extract_vm_vlans()

        self.bp_bridge = ROOT_BACK_BR_TEMPLATE % self.vm_set_name

        # if the device is a bt0, build the mapping from interface to vlan id
        if self.dut_type == BACKEND_TOR_TYPE:
            default_vlan_config = self.topo.get("DUT", {}).get("vlan_configs", {}).get("default_vlan_config")
            if not default_vlan_config:
                raise ValueError("Topology has no default vlan config.")
            if default_vlan_config not in self.topo["DUT"]["vlan_configs"]:
                raise ValueError("Topology has no definition for default vlan config %s" % default_vlan_config)
            vlan_config = self.topo["DUT"]["vlan_configs"][default_vlan_config]
            self.vlan_ids = {}
            for vlan in vlan_config.values():
                for intf in vlan["intfs"]:
                    self.vlan_ids[str(intf)] = str(vlan["id"])

    @property
    def dut_type(self):
        """Return the dut_type in vm configuration if present."""
        if not hasattr(self, "_dut_type"):
            for properties in self.vm_properties.values():
                dut_type = properties.get("dut_type")
                if dut_type:
                    self._dut_type = dut_type
                    break
            else:
                self._dut_type = None
        return self._dut_type

    def extract_vm_vlans(self):
        vlans = {}
        for vm, attr in self.VMs.items():
            vlans[vm] = attr['vlans'][:]

        return vlans

    def create_bridges(self):
        for vm in self.vm_names:
            for fp_num in range(self.max_fp_num):
                fp_br_name = adaptive_name(OVS_FP_BRIDGE_TEMPLATE, vm, fp_num)
                self.create_ovs_bridge(fp_br_name, self.fp_mtu)

        if self.topo and 'DUT' in self.topo and 'vs_chassis' in self.topo['DUT']:
            # We have a KVM based virtual chassis, need to create bridge for midplane and inband.
            self.create_ovs_bridge(VS_CHASSIS_INBAND_BRIDGE_NAME, self.fp_mtu)
            self.create_ovs_bridge(VS_CHASSIS_MIDPLANE_BRIDGE_NAME, self.fp_mtu)

    def create_ovs_bridge(self, bridge_name, mtu):
        logging.info('=== Create bridge %s with mtu %d ===' % (bridge_name, mtu))
        VMTopology.cmd('ovs-vsctl --may-exist add-br %s' % bridge_name)

        if mtu != DEFAULT_MTU:
            VMTopology.cmd('ifconfig %s mtu %d' % (bridge_name, mtu))

        VMTopology.cmd('ifconfig %s up' % bridge_name)

    def destroy_bridges(self):
        for vm in self.vm_names:
            for fp_num in range(self.max_fp_num):
                fp_br_name = adaptive_name(OVS_FP_BRIDGE_TEMPLATE, vm, fp_num)
                self.destroy_ovs_bridge(fp_br_name)

        if self.topo and 'DUT' in self.topo and 'vs_chassis' in self.topo['DUT']:
            # In case of KVM based virtual chassis, need to destroy bridge for midplane and inband.
            self.destroy_ovs_bridge(VS_CHASSIS_INBAND_BRIDGE_NAME)
            self.destroy_ovs_bridge(VS_CHASSIS_MIDPLANE_BRIDGE_NAME)

    def destroy_ovs_bridge(self, bridge_name):
        logging.info('=== Destroy bridge %s ===' % bridge_name)
        VMTopology.cmd('ovs-vsctl --if-exists del-br %s' % bridge_name)

    def get_vm_bridges(self, vmname):
        brs = []
        vm_bridge_regx = OVS_FP_BRIDGE_REGEX % vmname
        out = VMTopology.cmd('ifconfig -a', grep_cmd='grep -E %s' % vm_bridge_regx, retry=3)
        for row in out.split('\n'):
            fields = row.split(':')
            if len(fields) > 0:
                brs.append(fields[0])

        return brs

    def add_injected_fp_ports_to_docker(self):
        """
        add injected front panel ports to docker


            PTF (int_if) ----------- injected port (ext_if)

        """
        for vm, vlans in self.injected_fp_ports.items():
            for vlan in vlans:
                (_, _, ptf_index) = VMTopology.parse_vm_vlan_port(vlan)
                ext_if = adaptive_name(INJECTED_INTERFACES_TEMPLATE, self.vm_set_name, ptf_index)
                int_if = PTF_FP_IFACE_TEMPLATE % ptf_index
                properties = self.vm_properties.get(vm, {})
                create_vlan_subintf = properties.get('device_type') in (BACKEND_TOR_TYPE, BACKEND_LEAF_TYPE)
                if create_vlan_subintf:
                    vlan_subintf_sep = properties.get('sub_interface_separator', SUB_INTERFACE_SEPARATOR)
                    vlan_subintf_vlan_id = properties.get('sub_interface_vlan_id', SUB_INTERFACE_VLAN_ID)
                    self.add_veth_if_to_docker(
                        ext_if, int_if,
                        create_vlan_subintf=create_vlan_subintf,
                        sub_interface_separator=vlan_subintf_sep,
                        sub_interface_vlan_id=vlan_subintf_vlan_id
                    )
                else:
                    self.add_veth_if_to_docker(ext_if, int_if)

    def add_mgmt_port_to_docker(self, mgmt_bridge, mgmt_ip, mgmt_gw, mgmt_ipv6_addr=None, mgmt_gw_v6=None, api_server_pid=None):
        if api_server_pid:
            self.pid = api_server_pid
        if VMTopology.intf_not_exists(MGMT_PORT_NAME, self.pid):
            if api_server_pid is None:
                tmp_mgmt_if = hashlib.md5((PTF_NAME_TEMPLATE % self.vm_set_name).encode("utf-8")).hexdigest()[0:6] + MGMT_PORT_NAME
                self.add_br_if_to_docker(mgmt_bridge, PTF_MGMT_IF_TEMPLATE % self.vm_set_name, tmp_mgmt_if)
            else:
                tmp_mgmt_if = hashlib.md5(('apiserver').encode("utf-8")).hexdigest()[0:6] + MGMT_PORT_NAME
                self.add_br_if_to_docker(mgmt_bridge, 'apiserver', tmp_mgmt_if)

            VMTopology.iface_down(tmp_mgmt_if, self.pid)
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, tmp_mgmt_if, MGMT_PORT_NAME))

        VMTopology.iface_up(MGMT_PORT_NAME, self.pid)
        self.add_ip_to_docker_if(MGMT_PORT_NAME, mgmt_ip, mgmt_ipv6_addr=mgmt_ipv6_addr, mgmt_gw=mgmt_gw, mgmt_gw_v6=mgmt_gw_v6, api_server_pid=api_server_pid)

    def add_bp_port_to_docker(self, mgmt_ip, mgmt_ipv6):
        self.add_br_if_to_docker(self.bp_bridge, PTF_BP_IF_TEMPLATE % self.vm_set_name, BP_PORT_NAME)
        self.add_ip_to_docker_if(BP_PORT_NAME, mgmt_ip, mgmt_ipv6)
        VMTopology.iface_disable_txoff(BP_PORT_NAME, self.pid)

    def add_br_if_to_docker(self, bridge, ext_if, int_if):
        logging.info('=== For veth pair, add %s to bridge %s, set %s to PTF docker' % (ext_if, bridge, int_if))
        if VMTopology.intf_not_exists(ext_if):
            VMTopology.cmd("ip link add %s type veth peer name %s" % (ext_if, int_if))

        _, if_to_br = VMTopology.brctl_show(bridge)
        if ext_if not in if_to_br:
            VMTopology.cmd("brctl addif %s %s" % (bridge, ext_if))

        VMTopology.iface_up(ext_if)

        if VMTopology.intf_exists(int_if) and VMTopology.intf_not_exists(int_if, self.pid):
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, int_if))

        VMTopology.iface_up(int_if, self.pid)

    def add_ip_to_docker_if(self, int_if, mgmt_ip_addr, mgmt_ipv6_addr=None, mgmt_gw=None, mgmt_gw_v6=None, api_server_pid=None):
        if api_server_pid:
            self.pid = api_server_pid

        if VMTopology.intf_exists(int_if, self.pid):
            VMTopology.cmd("nsenter -t %s -n ip addr flush dev %s" % (self.pid, int_if))
            VMTopology.cmd("nsenter -t %s -n ip addr add %s dev %s" % (self.pid, mgmt_ip_addr, int_if))
            if mgmt_gw:
                if api_server_pid:
                    VMTopology.cmd("nsenter -t %s -n ip route del default" % (self.pid))
                VMTopology.cmd("nsenter -t %s -n ip route add default via %s dev %s" % (self.pid, mgmt_gw, int_if))
            if mgmt_ipv6_addr:
                VMTopology.cmd("nsenter -t %s -n ip -6 addr flush dev %s" % (self.pid, int_if))
                VMTopology.cmd("nsenter -t %s -n ip -6 addr add %s dev %s" % (self.pid, mgmt_ipv6_addr, int_if))
            if mgmt_ipv6_addr and mgmt_gw_v6:
                VMTopology.cmd("nsenter -t %s -n ip -6 route flush default" % (self.pid))
                VMTopology.cmd("nsenter -t %s -n ip -6 route add default via %s dev %s" % (self.pid, mgmt_gw_v6, int_if))

    def add_dut_if_to_docker(self, iface_name, dut_iface):
        logging.info("=== Add DUT interface %s to PTF docker as %s ===" % (dut_iface, iface_name))
        if VMTopology.intf_exists(dut_iface) \
            and VMTopology.intf_not_exists(dut_iface, self.pid) \
            and VMTopology.intf_not_exists(iface_name, self.pid):
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, dut_iface))

        if VMTopology.intf_exists(dut_iface, self.pid) and VMTopology.intf_not_exists(iface_name, self.pid):
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, dut_iface, iface_name))

        VMTopology.iface_up(iface_name, self.pid)

    def add_dut_vlan_subif_to_docker(self, iface_name, vlan_separator, vlan_id):
        """Create a vlan sub interface for the ptf interface."""
        if VMTopology.intf_not_exists(iface_name, self.pid):
            raise ValueError("Interface %s not present in docker" % iface_name)
        vlan_sub_iface_name = iface_name + vlan_separator + vlan_id
        VMTopology.cmd("nsenter -t %s -n ip link add link %s name %s type vlan id %s" % (self.pid, iface_name, vlan_sub_iface_name, vlan_id))
        VMTopology.cmd("nsenter -t %s -n ip link set %s up" % (self.pid, vlan_sub_iface_name))

    def remove_dut_if_from_docker(self, iface_name, dut_iface):

        if self.pid is None:
            return

        if VMTopology.intf_exists(iface_name, self.pid):
            VMTopology.iface_down(iface_name, self.pid)

            if VMTopology.intf_not_exists(dut_iface, self.pid):
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, iface_name, dut_iface))

        if VMTopology.intf_not_exists(dut_iface) and VMTopology.intf_exists(dut_iface, self.pid):
            VMTopology.cmd("nsenter -t %s -n ip link set netns 1 dev %s" % (self.pid, dut_iface))

    def remove_dut_vlan_subif_from_docker(self, iface_name, vlan_separator, vlan_id):
        """Remove the vlan sub interface created for the ptf interface."""
        if self.pid is None:
            return

        vlan_sub_iface_name = iface_name + vlan_separator + vlan_id
        if VMTopology.intf_exists(vlan_sub_iface_name, self.pid):
            VMTopology.cmd("nsenter -t %s -n ip link del %s" % (self.pid, vlan_sub_iface_name))

    def add_veth_if_to_docker(self, ext_if, int_if, create_vlan_subintf=False, **kwargs):
        """Create vethernet devices (ext_if, int_if) and put int_if into the ptf docker."""
        logging.info('=== Create veth pair %s/%s, set %s to PTF docker namespace ===' % (ext_if, int_if, int_if))
        if create_vlan_subintf:
            try:
                vlan_subintf_sep = kwargs["sub_interface_separator"]
                vlan_subintf_vlan_id = kwargs["sub_interface_vlan_id"]
            except KeyError:
                raise TypeError("Missing arguments for function 'add_veth_if_to_docker'")

        reserved_space = len(vlan_subintf_sep + vlan_subintf_vlan_id) if create_vlan_subintf else 0
        t_int_if = adaptive_temporary_interface(self.vm_set_name, int_if, reserved_space=reserved_space)
        if create_vlan_subintf:
            int_sub_if = int_if + vlan_subintf_sep + vlan_subintf_vlan_id
            t_int_sub_if = t_int_if + vlan_subintf_sep + vlan_subintf_vlan_id

        if VMTopology.intf_exists(t_int_if):
            VMTopology.cmd("ip link del dev %s" % t_int_if)

        if VMTopology.intf_not_exists(ext_if):
            VMTopology.cmd("ip link add %s type veth peer name %s" % (ext_if, t_int_if))
            if create_vlan_subintf:
                VMTopology.cmd("vconfig add %s %s" % (t_int_if, vlan_subintf_vlan_id))

        if self.fp_mtu != DEFAULT_MTU:
            VMTopology.cmd("ip link set dev %s mtu %d" % (ext_if, self.fp_mtu))
            if VMTopology.intf_exists(t_int_if):
                VMTopology.cmd("ip link set dev %s mtu %d" % (t_int_if, self.fp_mtu))
            elif VMTopology.intf_exists(t_int_if, self.pid):
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, t_int_if, self.fp_mtu))
            elif VMTopology.intf_exists(int_if, self.pid):
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_if, self.fp_mtu))
            if create_vlan_subintf:
                if VMTopology.intf_exists(t_int_sub_if):
                    VMTopology.cmd("ip link set dev %s mtu %d" % (t_int_sub_if, self.fp_mtu))
                elif VMTopology.intf_exists(t_int_sub_if, self.pid):
                    VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, t_int_sub_if, self.fp_mtu))
                elif VMTopology.intf_exists(int_sub_if, self.pid):
                    VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_sub_if, self.fp_mtu))

        VMTopology.iface_up(ext_if)

        if VMTopology.intf_exists(t_int_if) \
            and VMTopology.intf_not_exists(t_int_if, self.pid) \
            and VMTopology.intf_not_exists(int_if, self.pid):
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, t_int_if))
        if create_vlan_subintf \
            and VMTopology.intf_exists(t_int_sub_if) \
            and VMTopology.intf_not_exists(t_int_sub_if, self.pid) \
            and VMTopology.intf_not_exists(int_sub_if, self.pid):
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, t_int_sub_if))

        if VMTopology.intf_exists(t_int_if, self.pid) and VMTopology.intf_not_exists(int_if, self.pid):
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_if, int_if))
        if create_vlan_subintf \
            and VMTopology.intf_exists(t_int_sub_if, self.pid) \
            and VMTopology.intf_not_exists(int_sub_if, self.pid):
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_sub_if, int_sub_if))

        VMTopology.iface_up(int_if, self.pid)
        if create_vlan_subintf:
            VMTopology.iface_up(int_sub_if, self.pid)

    def bind_mgmt_port(self, br_name, mgmt_port):
        logging.info('=== Bind mgmt port %s to bridge %s ===' % (mgmt_port, br_name))
        _, if_to_br = VMTopology.brctl_show(br_name)
        if mgmt_port not in if_to_br:
            VMTopology.cmd("brctl addif %s %s" % (br_name, mgmt_port))

    def unbind_mgmt_port(self, mgmt_port):
        _, if_to_br = VMTopology.brctl_show()
        if mgmt_port in if_to_br:
            VMTopology.cmd("brctl delif %s %s" % (if_to_br[mgmt_port], mgmt_port))

    def bind_fp_ports(self, disconnect_vm=False):
        """
        bind dut front panel ports to VMs

                            +----------------------+
                            |     OVS_FP_BRIDGE    |
                 +----+     |                      |
                 | VM +-----+ vm_iface             |      +-----+
                 +----+     |        duts_fp_port  +------+ DUT |
                            |                      |      +-----+
                 +-----+    |                      |
                 | PTF +----+ injected_iface       |
                 +-----+    |                      |
                            +----------------------+

        """
        for attr in self.VMs.values():
            for idx, vlan in enumerate(attr['vlans']):
                br_name = adaptive_name(OVS_FP_BRIDGE_TEMPLATE, self.vm_names[self.vm_base_index + attr['vm_offset']], idx)
                vm_iface = OVS_FP_TAP_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], idx)
                (dut_index, vlan_index, ptf_index) = VMTopology.parse_vm_vlan_port(vlan)
                injected_iface = adaptive_name(INJECTED_INTERFACES_TEMPLATE, self.vm_set_name, ptf_index)
                if len( self.duts_fp_ports[self.duts_name[dut_index]] ) == 0:
                    continue
                self.bind_ovs_ports(br_name, self.duts_fp_ports[self.duts_name[dut_index]][str(vlan_index)], injected_iface, vm_iface, disconnect_vm)

        if self.topo and 'DUT' in self.topo and 'vs_chassis' in self.topo['DUT']:
            # We have a KVM based virtaul chassis, bind the midplane and inband ports
            self.bind_vs_dut_ports(VS_CHASSIS_INBAND_BRIDGE_NAME, self.topo['DUT']['vs_chassis']['inband_port'])
            self.bind_vs_dut_ports(VS_CHASSIS_MIDPLANE_BRIDGE_NAME, self.topo['DUT']['vs_chassis']['midplane_port'])

    def unbind_fp_ports(self):
        for attr in self.VMs.values():
            for vlan_num, vlan in enumerate(attr['vlans']):
                br_name = adaptive_name(OVS_FP_BRIDGE_TEMPLATE, self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
                vm_iface = OVS_FP_TAP_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
                self.unbind_ovs_ports(br_name, vm_iface)

        if self.topo and 'DUT' in self.topo and 'vs_chassis' in self.topo['DUT']:
            # We have a KVM based virtaul chassis, unbind the midplane and inband ports
            self.unbind_vs_dut_ports(VS_CHASSIS_INBAND_BRIDGE_NAME, self.topo['DUT']['vs_chassis']['inband_port'])
            self.unbind_vs_dut_ports(VS_CHASSIS_MIDPLANE_BRIDGE_NAME, self.topo['DUT']['vs_chassis']['midplane_port'])
            # Remove the bridges as well - this is here instead of destroy_bridges as that is called with cmd: 'destroy'
            # is called from 'testbed-cli.sh stop-vms' which takes a server name, an no testbed name, and thus has
            # no topology associated with it.
            self.destroy_ovs_bridge(VS_CHASSIS_INBAND_BRIDGE_NAME)
            self.destroy_ovs_bridge(VS_CHASSIS_MIDPLANE_BRIDGE_NAME)

    def bind_vm_backplane(self):

        if VMTopology.intf_not_exists(self.bp_bridge):
            VMTopology.cmd('brctl addbr %s' % self.bp_bridge)

        VMTopology.iface_up(self.bp_bridge)

        for attr in self.VMs.values():
            vm_name = self.vm_names[self.vm_base_index + attr['vm_offset']]
            bp_port_name = OVS_BP_TAP_TEMPLATE % vm_name

            br_to_ifs, _ = VMTopology.brctl_show()
            if bp_port_name not in br_to_ifs[self.bp_bridge]:
                VMTopology.cmd("brctl addif %s %s" % (self.bp_bridge, bp_port_name))

            VMTopology.iface_up(bp_port_name)

    def unbind_vm_backplane(self):

        if VMTopology.intf_exists(self.bp_bridge):
            VMTopology.iface_down(self.bp_bridge)
            VMTopology.cmd('brctl delbr %s' % self.bp_bridge)

    def bind_vs_dut_ports(self, br_name, dut_ports):
        # dut_ports is a list of port on each DUT that has to be bound together. eg. 30,30,30 - will bind ports
        # 30 of each DUT together into bridge br_name
        # Also for vm, a dut's ports would be of the format <dut_hostname>-<port_num + 1>. So, port '30' on vm with
        # name 'vlab-02' would be 'vlab-02-31'
        br_ports = VMTopology.get_ovs_br_ports(br_name)
        for dut_index, a_port in enumerate(dut_ports):
            dut_name = self.duts_name[dut_index]
            port_name = "{}-{}".format(dut_name, (a_port + 1))
            br = VMTopology.get_ovs_bridge_by_port(port_name)
            if br is not None and br != br_name:
                VMTopology.cmd('ovs-vsctl del-port %s %s' % (br, port_name))

            if port_name not in br_ports:
                VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, port_name))

    def unbind_vs_dut_ports(self, br_name, dut_ports):
        """unbind all ports except the vm port from an ovs bridge"""
        ports = VMTopology.get_ovs_br_ports(br_name)
        for dut_index, a_port in enumerate(dut_ports):
            dut_name = self.duts_name[dut_index]
            port_name = "{}-{}".format(dut_name, (a_port + 1))
            if port_name in ports:
                VMTopology.cmd('ovs-vsctl del-port %s %s' % (br_name, port_name))

    def bind_ovs_ports(self, br_name, dut_iface, injected_iface, vm_iface, disconnect_vm=False):
        """
        bind dut/injected/vm ports under an ovs bridge as follows

                                   +----------------------+
                                   |                      +---- dut_iface
            PTF (injected_iface) --+ OVS bridge (br_name) |
                                   |                      +---- vm_iface
                                   +----------------------+
        """
        br = VMTopology.get_ovs_bridge_by_port(injected_iface)
        if br is not None and br != br_name:
            VMTopology.cmd('ovs-vsctl del-port %s %s' % (br, injected_iface))

        br = VMTopology.get_ovs_bridge_by_port(dut_iface)
        if br is not None and br != br_name:
            VMTopology.cmd('ovs-vsctl del-port %s %s' % (br, dut_iface))

        ports = VMTopology.get_ovs_br_ports(br_name)
        if injected_iface not in ports:
            VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, injected_iface))

        if dut_iface not in ports:
            VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, dut_iface))

        bindings = VMTopology.get_ovs_port_bindings(br_name, [dut_iface])
        dut_iface_id = bindings[dut_iface]
        injected_iface_id = bindings[injected_iface]
        vm_iface_id = bindings[vm_iface]

        # clear old bindings
        VMTopology.cmd('ovs-ofctl del-flows %s' % br_name)

        if disconnect_vm:
            # Drop packets from VM
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=drop" % (br_name, vm_iface_id))
        else:
            # Add flow from a VM to an external iface
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, vm_iface_id, dut_iface_id))

        if disconnect_vm:
            # Add flow from external iface to ptf container
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, dut_iface_id, injected_iface_id))
        else:
            # Add flow from external iface to a VM and a ptf container
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s,%s" % (br_name, dut_iface_id, vm_iface_id, injected_iface_id))

        # Add flow from a ptf container to an external iface
        VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, injected_iface_id, dut_iface_id))

    def unbind_ovs_ports(self, br_name, vm_port):
        """unbind all ports except the vm port from an ovs bridge"""
        ports = VMTopology.get_ovs_br_ports(br_name)

        for port in ports:
            if port != vm_port:
                VMTopology.cmd('ovs-vsctl del-port %s %s' % (br_name, port))

    def unbind_ovs_port(self, br_name, port):
        """unbind a port from an ovs bridge"""
        ports = VMTopology.get_ovs_br_ports(br_name)

        if port in ports:
            VMTopology.cmd('ovs-vsctl del-port %s %s' % (br_name, port))

    def create_muxy_cable(self, host_ifindex, host_if, upper_if, lower_if, active_if_index=0):
        """
        create muxy cable

                          +--------------+
                          |              +----- upper_if
          PTF (host_if) --+  OVS bridge  |
                          |              +----- lower_if
                          +--------------+
        """

        br_name = adaptive_name(MUXY_BRIDGE_TEMPLATE, self.vm_set_name, host_ifindex)

        self.create_ovs_bridge(br_name, self.fp_mtu)

        for intf in [host_if, upper_if, lower_if]:
            br = VMTopology.get_ovs_bridge_by_port(intf)
            if br is not None and br != br_name:
                VMTopology.cmd('ovs-vsctl del-port %s %s' % (br, intf))

        ports = VMTopology.get_ovs_br_ports(br_name)
        for intf in [host_if, upper_if, lower_if]:
            if intf not in ports:
                VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, intf))

        bindings = VMTopology.get_ovs_port_bindings(br_name, [upper_if, lower_if])
        host_if_id = bindings[host_if]
        upper_if_id = bindings[upper_if]
        lower_if_id = bindings[lower_if]

        # clear old bindings
        VMTopology.cmd('ovs-ofctl del-flows %s' % br_name)

        VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s,%s" % (br_name, host_if_id, upper_if_id, lower_if_id))
        if active_if_index == 0:
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, upper_if_id, host_if_id))
        else:
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, lower_if_id, host_if_id))

    def remove_muxy_cable(self, host_ifindex):
        """
        remove muxy cable
        """

        br_name = adaptive_name(MUXY_BRIDGE_TEMPLATE, self.vm_set_name, host_ifindex)

        self.destroy_ovs_bridge(br_name)

    def add_host_ports(self):
        """
        add dut port in the ptf docker

        for non-dual topo, inject the dut port into ptf docker.
        for dual-tor topo, create ovs port and add to ptf docker.
        """
        for i, intf in enumerate(self.host_interfaces):
            if self._is_multi_duts and not self._is_cable:
                if isinstance(intf, list):
                    # create veth link and inject one end into the ptf docker
                    # If host interface index is explicitly specified by "@x" (len(intf[0]==3), use host interface
                    # index specified in topo definition.
                    # Otherwise, it means that host interface does not have "@x" in topo definition, then assume that
                    # there is no gap in sequence of host interfaces.
                    host_ifindex = intf[0][2] if len(intf[0]) == 3 else i
                    muxy_if = adaptive_name(MUXY_INTERFACES_TEMPLATE, self.vm_set_name, host_ifindex)
                    ptf_if = PTF_FP_IFACE_TEMPLATE % host_ifindex
                    self.add_veth_if_to_docker(muxy_if, ptf_if)

                    # create muxy cable
                    upper_tor_if = self.duts_fp_ports[self.duts_name[intf[0][0]]][str(intf[0][1])]
                    lower_tor_if = self.duts_fp_ports[self.duts_name[intf[1][0]]][str(intf[1][1])]
                    self.create_muxy_cable(host_ifindex, muxy_if, upper_tor_if, lower_tor_if)
                else:
                    host_ifindex = intf[2] if len(intf) == 3 else i
                    fp_port = self.duts_fp_ports[self.duts_name[intf[0]]][str(intf[1])]
                    ptf_if = PTF_FP_IFACE_TEMPLATE % host_ifindex
                    self.add_dut_if_to_docker(ptf_if, fp_port)
            elif self._is_multi_duts and self._is_cable:
                # Since there could be multiple ToR's in cable topology, some Ports
                # can be connected to muxcable and some to a DAC cable. But it could
                # be possible that not all ports have cables connected. So for whichever
                # port link is connected and has a vlan associated, inject them to container
                # with the enumeration in topo file
                # essentially mux ports will map to one port and DAC ports will map to different
                # ports in a dualtor setup. Here implicit is taken that
                # interface index is explicitly specified by "@x" format
                host_ifindex = intf[0][2]
                if self.duts_fp_ports[self.duts_name[intf[0][0]]].get(str(intf[0][1])) is not None:
                    fp_port = self.duts_fp_ports[self.duts_name[intf[0][0]]][str(intf[0][1])]
                    ptf_if = PTF_FP_IFACE_TEMPLATE % host_ifindex
                    self.add_dut_if_to_docker(ptf_if, fp_port)

                host_ifindex = intf[1][2]
                if self.duts_fp_ports[self.duts_name[intf[1][0]]].get(str(intf[1][1])) is not None:
                    fp_port = self.duts_fp_ports[self.duts_name[intf[1][0]]][str(intf[1][1])]
                    ptf_if = PTF_FP_IFACE_TEMPLATE % host_ifindex
                    self.add_dut_if_to_docker(ptf_if, fp_port)
            else:
                fp_port = self.duts_fp_ports[self.duts_name[0]][str(intf)]
                ptf_if = PTF_FP_IFACE_TEMPLATE % intf
                self.add_dut_if_to_docker(ptf_if, fp_port)
                # only create sub interface for enabled ports defined in t0-backend
                if self.dut_type == BACKEND_TOR_TYPE and intf not in self.disabled_host_interfaces:
                    vlan_separator = self.topo.get("DUT", {}).get("sub_interface_separator", SUB_INTERFACE_SEPARATOR)
                    vlan_id = self.vlan_ids[str(intf)]
                    self.add_dut_vlan_subif_to_docker(ptf_if, vlan_separator, vlan_id)

    def remove_host_ports(self):
        """
        remove dut port from the ptf docker
        """
        for i, intf in enumerate(self.host_interfaces):
            if self._is_multi_duts:
                if isinstance(intf, list):
                    host_ifindex = intf[0][2] if len(intf[0]) == 3 else i
                    self.remove_muxy_cable(host_ifindex)
                else:
                    host_ifindex = intf[2] if len(intf) == 3 else i
                    self.remove_muxy_cable(host_ifindex)
                    fp_port = self.duts_fp_ports[self.duts_name[intf[0]]][str(intf[1])]
                    ptf_if = PTF_FP_IFACE_TEMPLATE % host_ifindex
                    self.remove_dut_if_from_docker(ptf_if, fp_port)
            else:
                fp_port = self.duts_fp_ports[self.duts_name[0]][str(intf)]
                ptf_if = PTF_FP_IFACE_TEMPLATE % intf
                self.remove_dut_if_from_docker(ptf_if, fp_port)
                if self.dut_type == BACKEND_TOR_TYPE:
                    vlan_separator = self.topo.get("DUT", {}).get("sub_interface_separator", SUB_INTERFACE_SEPARATOR)
                    vlan_id = self.vlan_ids[str(intf)]
                    self.remove_dut_vlan_subif_from_docker(ptf_if, vlan_separator, vlan_id)

    @staticmethod
    def _intf_cmd(intf, pid=None):
        if pid:
            cmdline = 'nsenter -t %s -n ifconfig -a %s' % (pid, intf)
        else:
            cmdline = 'ifconfig -a %s' % intf
        return cmdline

    @staticmethod
    def intf_exists(intf, pid=None):
        """Check if the specified interface exists.

        This function uses command "ifconfig <intf name>" to check the existence of the specified interface. By default
        the command is executed on host. If a pid is specified, this command is executed in the network namespace
        of the specified pid. The meaning is to check if the interface exists in a specific docker.

        Args:
            intf (str): Name of the interface.
            pid (str), optional): Pid of docker. Defaults to None.

        Returns:
            bool: True if the interface exists. Otherwise False.
        """
        cmdline = VMTopology._intf_cmd(intf, pid=pid)

        try:
            VMTopology.cmd(cmdline, retry=3)
            return True
        except:
            return False

    @staticmethod
    def intf_not_exists(intf, pid=None):
        """Check if the specified interface does not exist.

        This function uses command "ifconfig <intf name>" to check the existence of the specified interface. By default
        the command is executed on host. If a pid is specified, this command is executed in the network namespace
        of the specified pid. The meaning is to check if the interface exists in a specific docker.

        Args:
            intf (str): Name of the interface.
            pid (str), optional): Pid of docker. Defaults to None.

        Returns:
            bool: True if the interface does not exist. Otherwise False.
        """
        cmdline = VMTopology._intf_cmd(intf, pid=pid)

        try:
            VMTopology.cmd(cmdline, retry=3, negative=True)
            return True
        except:
            return False

    @staticmethod
    def iface_up(iface_name, pid=None):
        return VMTopology.iface_updown(iface_name, 'up', pid)

    @staticmethod
    def iface_down(iface_name, pid=None):
        return VMTopology.iface_updown(iface_name, 'down', pid)

    @staticmethod
    def iface_updown(iface_name, state, pid):
        if pid is None:
            return VMTopology.cmd('ip link set %s %s' % (iface_name, state))
        else:
            return VMTopology.cmd('nsenter -t %s -n ip link set %s %s' % (pid, iface_name, state))

    @staticmethod
    def iface_disable_txoff(iface_name, pid=None):
        if pid is None:
            return VMTopology.cmd('ethtool -K %s tx off' % (iface_name))
        else:
            return VMTopology.cmd('nsenter -t %s -n ethtool -K %s tx off' % (pid, iface_name))

    @staticmethod
    def cmd(cmdline, grep_cmd=None, retry=1, negative=False):
        """Execute a command and return the output

        Args:
            cmdline (str): The command line to be executed.
            grep_cmd (str, optional): Grep command line. Defaults to None.
            retry (int, optional): Max number of retry if command result is unexpected. Defaults to 1.
            negative (bool, optional): If negative is True, expect the command to fail. Defaults to False.

        Raises:
            Exception: If command result is unexpected after max number of retries, raise an exception.

        Returns:
            str: Output of the command.
        """

        for attempt in range(retry):
            logging.debug('*** CMD: %s, grep: %s, attempt: %d' % (cmdline, grep_cmd, attempt+1))
            process = subprocess.Popen(
                shlex.split(cmdline),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            if grep_cmd:
                process_grep = subprocess.Popen(
                    shlex.split(grep_cmd),
                    stdin=process.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                out, err = process_grep.communicate()
                ret_code = process_grep.returncode
            else:
                out, err = process.communicate()
                ret_code = process.returncode
            out, err = out.decode('utf-8'), err.decode('utf-8')

            msg = {
                'cmd': cmdline,
                'grep_cmd': grep_cmd,
                'ret_code': ret_code,
                'stdout': out.splitlines(),
                'stderr': err.splitlines()
            }
            logging.debug('*** OUTPUT: \n%s' % json.dumps(msg, indent=2))

            if negative:
                if ret_code != 0:
                    # Result is expected, return early
                    return out
                else:
                    # Result is unexpected, need to retry
                    continue
            else:
                if ret_code == 0:
                    # Result is expected, return early
                    return out
                else:
                    # Result is unexpected, need to retry
                    continue

        # Reached max retry, fail with exception
        raise Exception('ret_code=%d, error message="%s". cmd="%s"' % (ret_code, err, cmdline))

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = VMTopology.cmd('ovs-vsctl list-ports %s' % bridge)
        ports = set()
        for port in out.split('\n'):
            if port != "":
                ports.add(port)
        return ports

    @staticmethod
    def get_ovs_bridge_by_port(port):
        try:
            out = VMTopology.cmd('ovs-vsctl port-to-br %s' % port)
        except:
            return None

        bridge = out.rstrip()
        return bridge

    @staticmethod
    def get_ovs_port_bindings(bridge, vlan_iface = []):
        # Vlan interface addition may take few secs to reflect in OVS Command,
        # Let`s retry few times in that case.
        for retries in range(RETRIES):
            out = VMTopology.cmd('ovs-ofctl show %s' % bridge)
            lines = out.split('\n')
            result = {}
            for line in lines:
                matched = re.match(r'^\s+(\S+)\((\S+)\):\s+addr:.+$', line)
                if matched:
                    port_id = matched.group(1)
                    iface_name = matched.group(2)
                    result[iface_name] = port_id
            # Check if we have vlan_iface populated
            if len(vlan_iface) == 0 or all([intf in result for intf in vlan_iface]):
                return result
            time.sleep(2*retries+1)
        # Flow reaches here when vlan_iface not present in result
        raise Exception("Can't find vlan_iface_id")

    @staticmethod
    def get_pid(ptf_name):
        cli = docker.from_env()
        try:
            ctn = cli.containers.get(ptf_name)
        except:
            return None

        return ctn.attrs['State']['Pid']

    @staticmethod
    def brctl_show(bridge=None):
        br_to_ifs = {}
        if_to_br = {}

        cmdline = "brctl show "
        if bridge:
            cmdline += bridge
        try:
            out = VMTopology.cmd(cmdline)
        except:
            logging.error('!!! Failed to run %s' % cmdline)
            return br_to_ifs, if_to_br

        rows = out.split('\n')[1:]
        cur_br = None
        for row in rows:
            if len(row) == 0:
                continue
            terms = row.split()
            if not row[0].isspace():
                cur_br = terms[0]
                br_to_ifs[cur_br] = []
                if len(terms) > 3:
                    br_to_ifs[cur_br].append(terms[3])
                    if_to_br[terms[3]] = cur_br
            else:
                br_to_ifs[cur_br].append(terms[0])
                if_to_br[terms[0]] = cur_br

        return br_to_ifs, if_to_br

    @staticmethod
    def parse_vm_vlan_port(vlan):
        """
        parse vm vlan port

        old format (non multi-dut): vlan_index
        new format (multi-dut):     dut_index.vlan_index@ptf_index

        """
        if isinstance(vlan, int):
            dut_index = 0
            vlan_index = vlan
            ptf_index = vlan
        else:
            m = re.match("(\d+)\.(\d+)@(\d+)", vlan)
            (dut_index, vlan_index, ptf_index) = (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return (dut_index, vlan_index, ptf_index)


def check_topo(topo, is_multi_duts=False):

    def _assert(condition, exctype, msg):
        if not condition:
            raise exctype(msg)

    hostif_exists = False
    vms_exists = False
    all_intfs = set()

    if 'host_interfaces' in topo:
        host_interfaces = topo['host_interfaces']

        _assert(isinstance(host_interfaces, list), TypeError,
                "topo['host_interfaces'] should be a list")

        for host_intf in host_interfaces:
            if is_multi_duts:
                for p in host_intf.split(','):
                    condition = (isinstance(p, str) and
                                 re.match(r"^\d+\.\d+(@\d+)?$", p))
                    _assert(condition, ValueError,
                            "topo['host_interfaces'] should be a "
                            "list of strings of format '<dut>.<dut_intf>' or '<dut>.<dut_intf>,<dut>.<dut_intf>'")
                    _assert(p not in all_intfs, ValueError,
                        "topo['host_interfaces'] double use of host interface: %s" % p)
                    all_intfs.add(p)
            else:
                condition = isinstance(host_intf, int) and host_intf >= 0
                _assert(condition, ValueError,
                        "topo['host_interfaces'] should be a "
                        "list of positive integers")
                _assert(host_intf not in all_intfs, ValueError,
                        "topo['host_interfaces'] double use of host interface: %s" % host_intf)
                all_intfs.add(host_intf)

        hostif_exists = True

    if 'VMs' in topo:
        VMs = topo['VMs']

        _assert(isinstance(VMs, dict), TypeError,
                "topo['VMs'] should be a dictionary")

        for hostname, attrs in VMs.items():
            _assert('vlans' in attrs and isinstance(attrs['vlans'], list),
                    ValueError,
                    "topo['VMs']['%s'] should contain "
                    "'vlans' with a list of vlans" % hostname)

            _assert(('vm_offset' in attrs and
                     isinstance(attrs['vm_offset'], int)),
                    ValueError,
                    "topo['VMs']['%s'] should contain "
                    "'vm_offset' with a number" % hostname)

            for vlan in attrs['vlans']:
                if is_multi_duts:
                    condition = (isinstance(vlan, str) and
                                 re.match(r"^\d+\.\d+(@\d+)?$", vlan))
                    _assert(condition, ValueError,
                            "topo['VMs'][%s]['vlans'] should be "
                            "list of strings of format '<dut>.<vlan>'. vlan=%s" % (hostname, vlan))
                else:
                    _assert(isinstance(vlan, int) and vlan >= 0,
                            ValueError,
                            "topo['VMs'][%s]['vlans'] should contain"
                            " a list with integers. vlan=%s" % (hostname, vlan))
                _assert(vlan not in all_intfs,
                        ValueError,
                        "topo['VMs'][%s]['vlans'] double use "
                        "of vlan: %s" % (hostname, vlan))
                all_intfs.add(vlan)

        vms_exists = True

    return hostif_exists, vms_exists


def check_params(module, params, mode):
    for param in params:
        if param not in module.params:
            raise Exception("Parameter %s is required in %s mode" % (param, mode))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(required=True, choices=['create', 'bind', 'bind_keysight_api_server_ip', 'renumber', 'unbind', 'destroy', "connect-vms", "disconnect-vms"]),
            vm_set_name=dict(required=False, type='str'),
            topo=dict(required=False, type='dict'),
            vm_names=dict(required=True, type='list'),
            vm_base=dict(required=False, type='str'),
            vm_type=dict(required=False, type='str'),
            vm_properties=dict(required=False, type='dict', default={}),
            ptf_mgmt_ip_addr=dict(required=False, type='str'),
            ptf_mgmt_ipv6_addr=dict(required=False, type='str'),
            ptf_mgmt_ip_gw=dict(required=False, type='str'),
            ptf_mgmt_ipv6_gw=dict(required=False, type='str'),
            ptf_bp_ip_addr=dict(required=False, type='str'),
            ptf_bp_ipv6_addr=dict(required=False, type='str'),
            mgmt_bridge=dict(required=False, type='str'),
            duts_fp_ports=dict(required=False, type='dict'),
            duts_mgmt_port=dict(required=False, type='list'),
            duts_name=dict(required=False, type='list'),
            fp_mtu=dict(required=False, type='int', default=DEFAULT_MTU),
            max_fp_num=dict(required=False, type='int', default=NUM_FP_VLANS_PER_FP),
        ),
        supports_check_mode=False)

    cmd = module.params['cmd']
    vm_names = module.params['vm_names']
    fp_mtu = module.params['fp_mtu']
    max_fp_num = module.params['max_fp_num']
    vm_properties = module.params['vm_properties']

    if cmd == 'bind_keysight_api_server_ip':
        vm_names = []

    config_logging()

    try:

        topo = module.params['topo']
        net = VMTopology(vm_names, vm_properties, fp_mtu, max_fp_num, topo)

        if cmd == 'create':
            net.create_bridges()
        elif cmd == 'destroy':
            net.destroy_bridges()
        elif cmd == 'bind':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'ptf_mgmt_ip_addr',
                                  'ptf_mgmt_ipv6_addr',
                                  'ptf_mgmt_ip_gw',
                                  'ptf_mgmt_ipv6_gw',
                                  'ptf_bp_ip_addr',
                                  'ptf_bp_ipv6_addr',
                                  'mgmt_bridge',
                                  'duts_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            duts_fp_ports = module.params['duts_fp_ports']
            duts_name = module.params['duts_name']
            is_multi_duts = True if len(duts_name) > 1 else False

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo, is_multi_duts)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None
            vm_type = module.params['vm_type']

            net.init(vm_set_name, vm_base, duts_fp_ports, duts_name)

            ptf_mgmt_ip_addr = module.params['ptf_mgmt_ip_addr']
            ptf_mgmt_ipv6_addr = module.params['ptf_mgmt_ipv6_addr']
            ptf_mgmt_ip_gw = module.params['ptf_mgmt_ip_gw']
            ptf_mgmt_ipv6_gw = module.params['ptf_mgmt_ipv6_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            # Add management port to PTF docker and configure IP
            net.add_mgmt_port_to_docker(mgmt_bridge, ptf_mgmt_ip_addr, ptf_mgmt_ip_gw, ptf_mgmt_ipv6_addr, ptf_mgmt_ipv6_gw)

            ptf_bp_ip_addr = module.params['ptf_bp_ip_addr']
            ptf_bp_ipv6_addr = module.params['ptf_bp_ipv6_addr']

            if module.params['duts_mgmt_port']:
                for dut_mgmt_port in module.params['duts_mgmt_port']:
                    if dut_mgmt_port != "":
                        # For VS setup
                        net.bind_mgmt_port(mgmt_bridge, dut_mgmt_port)

            if vms_exists:
                net.add_injected_fp_ports_to_docker()
                net.bind_fp_ports()
                if vm_type != "vsonic":
                    net.bind_vm_backplane()
                    net.add_bp_port_to_docker(ptf_bp_ip_addr, ptf_bp_ipv6_addr)

            if hostif_exists:
                net.add_host_ports()
        elif cmd == 'bind_keysight_api_server_ip':
            check_params(module, ['ptf_mgmt_ip_addr',
                                  'ptf_mgmt_ipv6_addr',
                                  'ptf_mgmt_ip_gw',
                                  'ptf_mgmt_ipv6_gw',
                                  'mgmt_bridge'], cmd)

            ptf_mgmt_ip_addr = module.params['ptf_mgmt_ip_addr']
            ptf_mgmt_ipv6_addr = module.params['ptf_mgmt_ipv6_addr']
            ptf_mgmt_ip_gw = module.params['ptf_mgmt_ip_gw']
            ptf_mgmt_ipv6_gw = module.params['ptf_mgmt_ipv6_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            api_server_pid = net.get_pid('apiserver')

            net.add_mgmt_port_to_docker(mgmt_bridge, ptf_mgmt_ip_addr, ptf_mgmt_ip_gw, ptf_mgmt_ipv6_addr, ptf_mgmt_ipv6_gw, api_server_pid)
        elif cmd == 'unbind':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'duts_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            duts_fp_ports = module.params['duts_fp_ports']
            duts_name = module.params['duts_name']
            is_multi_duts = True if len(duts_name) > 1 else False

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo, is_multi_duts)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None
            vm_type = module.params['vm_type']

            net.init(vm_set_name, vm_base, duts_fp_ports, duts_name)

            if module.params['duts_mgmt_port']:
                for dut_mgmt_port in module.params['duts_mgmt_port']:
                    if dut_mgmt_port != "":
                        net.unbind_mgmt_port(dut_mgmt_port)

            if vms_exists:
                if vm_type != "vsonic":
                    net.unbind_vm_backplane()
                net.unbind_fp_ports()

            if hostif_exists:
                net.remove_host_ports()
        elif cmd == 'renumber':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'ptf_mgmt_ip_addr',
                                  'ptf_mgmt_ipv6_addr',
                                  'ptf_mgmt_ip_gw',
                                  'ptf_mgmt_ipv6_gw',
                                  'ptf_bp_ip_addr',
                                  'ptf_bp_ipv6_addr',
                                  'mgmt_bridge',
                                  'duts_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            duts_fp_ports = module.params['duts_fp_ports']
            duts_name = module.params['duts_name']
            is_multi_duts = True if len(duts_name) > 1 else False

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo, is_multi_duts)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, vm_base, duts_fp_ports, duts_name, True)

            ptf_mgmt_ip_addr = module.params['ptf_mgmt_ip_addr']
            ptf_mgmt_ipv6_addr = module.params['ptf_mgmt_ipv6_addr']
            ptf_mgmt_ip_gw = module.params['ptf_mgmt_ip_gw']
            ptf_mgmt_ipv6_gw = module.params['ptf_mgmt_ipv6_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            net.add_mgmt_port_to_docker(mgmt_bridge, ptf_mgmt_ip_addr, ptf_mgmt_ip_gw, ptf_mgmt_ipv6_addr, ptf_mgmt_ipv6_gw)

            ptf_bp_ip_addr = module.params['ptf_bp_ip_addr']
            ptf_bp_ipv6_addr = module.params['ptf_bp_ipv6_addr']

            if vms_exists:
                net.unbind_fp_ports()
                net.add_injected_fp_ports_to_docker()
                net.bind_fp_ports()
                net.add_bp_port_to_docker(ptf_bp_ip_addr, ptf_bp_ipv6_addr)

            if hostif_exists:
                net.add_host_ports()
        elif cmd == 'connect-vms' or cmd == 'disconnect-vms':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'duts_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            duts_fp_ports = module.params['duts_fp_ports']
            duts_name = module.params['duts_name']
            is_multi_duts = True if len(duts_name) > 1 else False

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo, is_multi_duts)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, vm_base, duts_fp_ports, duts_name)

            if vms_exists:
                if cmd == 'connect-vms':
                    net.bind_fp_ports()
                else:
                    net.bind_fp_ports(True)
        else:
            raise Exception("Got wrong cmd: %s. Ansible bug?" % cmd)

    except Exception as error:
        logging.error(traceback.format_exc())
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()
