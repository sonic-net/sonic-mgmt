#!/usr/bin/python

import json
import logging
import subprocess
import shlex
import traceback

import docker

from ansible.module_utils.debug_utils import config_module_logging
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
---
module: csonic_network
version_added: "0.1"
author: Based on ceos_network by Guohan Lu
short_description: Create network interfaces for SONiC virtual switch container
description:
    Creates network interfaces for SONiC docker-sonic-vs container using the two-container model:
    - Base container (net_*_VM*) holds the network namespace
    - SONiC container (sonic_*_VM*) shares the namespace via network_mode=container

    This module creates veth pairs on the host and injects them into the base container's namespace:

    MANAGEMENT INTERFACE:
    - Host: VM0200-m <--> eth0 in container
    - Connected to: management bridge (br-mgmt)
    - Purpose: Management plane access

    FRONT PANEL INTERFACES (sonic_naming=true):
    - Host: VM0100-t0 <--> Ethernet0 in container (vm_offset=0)
    - Host: VM0101-t0 <--> Ethernet4 in container (vm_offset=1)
    - Host: VM0102-t0 <--> Ethernet8 in container (vm_offset=2)
    - Host: VM0103-t0 <--> Ethernet12 in container (vm_offset=3)
    - Connected to: OVS bridges (br-VM0100-0, br-VM0101-0, etc.)
    - Purpose: Data plane ports (vm_offset determines which Ethernet port is created)

    BACKPLANE INTERFACE:
    - Host: VM0200-back <--> eth_bp in container
    - Connected to: Backplane bridge (br-b-vms6-1)
    - Purpose: BGP peering with PTF/ExaBGP for route injection

    KEY DIFFERENCES FROM ceos_network:
    - SONiC uses Ethernet0/4/8/12 instead of eth1/2/3/4
    - Backplane interface named eth_bp instead of eth5
    - Increments by 4 to match SONiC's 100G port lane numbering

    PREREQUISITES:
    - Base container must exist and be running
    - OVS bridges must be created (br-VM*-0, br-VM*-1, etc.)
    - Management bridge must exist (br-mgmt)
    - docker-py Python library must be installed

options:
    name:
        description:
            - Name of the base container that holds the network namespace
            - Format: net_<vm_set_name>_<vm_name>
            - Example: net_sonic-test_VM0200
        required: true
        type: str

    vm_name:
        description:
            - VM identifier used for interface and bridge naming
            - Example: VM0100, VM0101, VM0102, VM0103
            - This is used to generate veth pair names like VM0100-t0, VM0101-t0, VM0100-back
        required: true
        type: str

    mgmt_bridge:
        description:
            - Name of the management bridge on the host
            - Typically: br-mgmt
            - The management interface (eth0) will be connected to this bridge
        required: true
        type: str

    fp_mtu:
        description:
            - MTU size for front panel interfaces
            - Set to 0 to use default MTU
            - Common values: 1500 (default), 9214 (jumbo frames)
        required: false
        type: int
        default: 0

    max_fp_num:
        description:
            - Number of front panel ports to create
            - Creates interfaces 0 through (max_fp_num - 1)
            - Default: 4 (creates Ethernet0, 4, 8, 12)
        required: false
        type: int
        default: 4

    vm_offset:
        description:
            - VM offset index from the topology
            - Determines which internal Ethernet interface to create (0=Ethernet0, 1=Ethernet4, 2=Ethernet8, 3=Ethernet12)
            - All VMs use -t0 naming on host side, but different Ethernet ports internally based on vm_offset
            - Default: 0 (creates Ethernet0)
        required: false
        type: int
        default: 0

    sonic_naming:
        description:
            - Use SONiC Ethernet naming convention (Ethernet0, Ethernet4, etc.)
            - Set to false to use eth1, eth2, eth3, eth4 like cEOS
            - Should almost always be true for SONiC containers
        required: false
        type: bool
        default: true

notes:
    - This module creates interfaces only. You must separately start the SONiC container.
    - The SONiC container must use network_mode pointing to the base container.
    - OVS bridges are created by vm_topology.py, not by this module.
    - Interface names must match SONiC's config_db.json PORT table entries.
'''

EXAMPLES = '''
# Basic usage - Create network for SONiC VM0200
- name: Create SONiC network interfaces
  csonic_network:
    name:           net_sonic-test_VM0200
    vm_name:        VM0200
    mgmt_bridge:    br-mgmt
    fp_mtu:         9214
    max_fp_num:     4
    sonic_naming:   true

# Use in a playbook with variables
- name: Create VMs network
  csonic_network:
    name:           net_{{ vm_set_name }}_{{ vm_name }}
    vm_name:        "{{ vm_name }}"
    fp_mtu:         "{{ fp_mtu_size }}"
    max_fp_num:     "{{ max_fp_num }}"
    mgmt_bridge:    "{{ mgmt_bridge }}"
    sonic_naming:   true

# Create with default MTU
- name: Create SONiC network with defaults
  csonic_network:
    name:           net_sonic-test_VM0200
    vm_name:        VM0200
    mgmt_bridge:    br-mgmt

# Create with legacy eth naming (not recommended for SONiC)
- name: Create with eth naming
  csonic_network:
    name:           net_sonic-test_VM0200
    vm_name:        VM0200
    mgmt_bridge:    br-mgmt
    sonic_naming:   false
  # Creates: eth0 (mgmt), eth1-4 (FP), eth5 (BP)

# Verify interfaces were created
- name: Check interfaces in container
  command: docker exec net_sonic-test_VM0200 ip link show

# Example: Full SONiC container setup workflow
- name: Create base container
  docker_container:
    name: net_sonic-test_VM0200
    image: debian:bookworm
    command: sleep infinity
    state: started

- name: Create network interfaces
  csonic_network:
    name: net_sonic-test_VM0200
    vm_name: VM0200
    mgmt_bridge: br-mgmt
    fp_mtu: 9214

- name: Start SONiC container sharing network
  docker_container:
    name: sonic_sonic-test_VM0200
    image: docker-sonic-vs:latest
    network_mode: "container:net_sonic-test_VM0200"
    privileged: yes
    state: started

# Troubleshooting - Check what was created
- name: List host interfaces
  shell: ip link show | grep VM0200

- name: Check container interfaces
  shell: docker exec net_sonic-test_VM0200 ip link show

- name: Verify OVS bridge connections
  shell: ovs-vsctl list-ports br-VM0200-0
'''


DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 4
VM_SET_NAME_MAX_LEN = 8
CMD_DEBUG_FNAME = "/tmp/csonic_network.cmds.%s.txt"

OVS_FP_BRIDGE_REGEX = r'br-%s-\d+'
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
FP_TAP_TEMPLATE = '%s-t%d'
BP_TAP_TEMPLATE = '%s-back'
MGMT_TAP_TEMPLATE = '%s-m'
TMP_TAP_TEMPLATE = '%s-%d'
INT_TAP_TEMPLATE = 'eth%d'

# SONiC interface naming: Ethernet0, Ethernet4, Ethernet8, Ethernet12...
SONIC_INT_TEMPLATE = 'Ethernet%d'
SONIC_BP_TEMPLATE = 'eth_bp'


class CsonicNetwork(object):
    """This class is for creating SONiC virtual switch network.

    Similar to CeosNetwork, this creates veth pairs and injects them into the SONiC container.
    The key difference is SONiC expects Ethernet0, Ethernet4, Ethernet8 naming convention.
    """

    def __init__(self, ctn_name, vm_name, mgmt_br_name, fp_mtu, max_fp_num, vm_offset=0, sonic_naming=True, bp_bridge=None):
        self.ctn_name = ctn_name
        self.vm_name = vm_name
        self.fp_mtu = fp_mtu
        self.max_fp_num = max_fp_num
        self.vm_offset = vm_offset
        self.mgmt_br_name = mgmt_br_name
        self.sonic_naming = sonic_naming
        self.bp_bridge = bp_bridge

        self.pid = CsonicNetwork.get_pid(self.ctn_name)
        if self.pid is None:
            raise Exception("cannot find pid for %s" % (self.ctn_name))

    def init_network(self):
        """Create SONiC network interfaces

        This creates:
        - One management interface (eth0)
        - ONE front panel interface based on vm_offset (not all interfaces)
        - One backplane interface (eth_bp)
        """
        # Create management link (same as cEOS - eth0)
        mp_name = MGMT_TAP_TEMPLATE % (self.vm_name)
        self.add_veth_if_to_docker(mp_name, TMP_TAP_TEMPLATE % (
            self.vm_name, 0), INT_TAP_TEMPLATE % 0)
        self.add_if_to_bridge(mp_name, self.mgmt_br_name)

        for fp_idx in range(self.max_fp_num):
            fp_name = FP_TAP_TEMPLATE % (self.vm_name, fp_idx)
            fp_br_name = OVS_FP_BRIDGE_TEMPLATE % (self.vm_name, fp_idx)

            if self.sonic_naming:
                int_if_name = SONIC_INT_TEMPLATE % ((self.vm_offset * 4) + fp_idx * 4)
            else:
                int_if_name = INT_TAP_TEMPLATE % (fp_idx + 1)

            self.add_veth_if_to_docker(
                fp_name,
                TMP_TAP_TEMPLATE % (self.vm_name, 1 + fp_idx),
                int_if_name
            )

            self.add_if_to_ovs_bridge(fp_name, fp_br_name)


        # Determine internal interface name
        if self.sonic_naming:
            # SONiC expects: Ethernet0, Ethernet4, Ethernet8, Ethernet12
            # Use vm_offset to determine which Ethernet port to create
            int_if_name = SONIC_INT_TEMPLATE % (self.vm_offset * 4)
        else:
            # Fallback to eth1, eth2, eth3, eth4 (like cEOS)
            int_if_name = INT_TAP_TEMPLATE % (fp_idx + 1)

        self.add_veth_if_to_docker(fp_name, TMP_TAP_TEMPLATE % (
            self.vm_name, 1), int_if_name)
        self.add_if_to_ovs_bridge(fp_name, fp_br_name)

        # Create backplane link
        # Always use index 2 for backplane (management=0, fp=1, bp=2)
        bp_int_name = SONIC_BP_TEMPLATE if self.sonic_naming else INT_TAP_TEMPLATE % (self.max_fp_num + 1)
        bp_name = BP_TAP_TEMPLATE % (self.vm_name)
        self.add_veth_if_to_docker(
            bp_name,
            TMP_TAP_TEMPLATE % (self.vm_name, 2),
            bp_int_name)

        # Connect backplane to bridge if specified
        if self.bp_bridge:
            self.add_if_to_bridge(bp_name, self.bp_bridge)

    def add_veth_if_to_docker(self, ext_if, t_int_if, int_if):
        """Create a pair of veth interfaces and add one of them to namespace of docker.

        Args:
            ext_if (str): External interface of the veth pair. It remains in host.
            t_int_if (str): Name of peer interface of ext_if. It is firstly created in host with ext_if.
                           Then it is added to docker namespace and renamed to int_if.
            int_if (str): Internal interface of the veth pair. It is added to docker namespace.
        """
        logging.info("=== Create veth pair %s and %s. Add %s to docker with Pid %s as %s ===" %
                     (ext_if, t_int_if, t_int_if, self.pid, int_if))

        # Delete existing interface if it exists on host but not in container
        if CsonicNetwork.intf_exists(ext_if) and CsonicNetwork.intf_not_exists(int_if, self.pid):
            CsonicNetwork.cmd("ip link del %s" % ext_if)

        # Create veth pair if external interface doesn't exist
        if CsonicNetwork.intf_not_exists(ext_if):
            CsonicNetwork.cmd("ip link add %s type veth peer name %s" %
                            (ext_if, t_int_if))

        # Set MTU if specified
        if self.fp_mtu != DEFAULT_MTU:
            CsonicNetwork.cmd("ip link set dev %s mtu %d" %
                            (ext_if, self.fp_mtu))
            if CsonicNetwork.intf_exists(t_int_if):
                CsonicNetwork.cmd("ip link set dev %s mtu %d" %
                                (t_int_if, self.fp_mtu))
            elif CsonicNetwork.intf_exists(t_int_if, self.pid):
                CsonicNetwork.cmd("nsenter -t %s -n ip link set dev %s mtu %d" %
                                (self.pid, t_int_if, self.fp_mtu))
            elif CsonicNetwork.intf_exists(int_if, self.pid):
                CsonicNetwork.cmd(
                    "nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_if, self.fp_mtu))

        # Bring up external interface on host
        CsonicNetwork.iface_up(ext_if)

        # Move temporary interface into container namespace
        if CsonicNetwork.intf_exists(t_int_if) \
                and CsonicNetwork.intf_not_exists(t_int_if, self.pid) \
                and CsonicNetwork.intf_not_exists(int_if, self.pid):
            CsonicNetwork.cmd("ip link set netns %s dev %s" %
                            (self.pid, t_int_if))

        # Rename to final name inside container
        if CsonicNetwork.intf_exists(t_int_if, self.pid) and CsonicNetwork.intf_not_exists(int_if, self.pid):
            CsonicNetwork.cmd(
                "nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_if, int_if))

        # Bring up internal interface in container
        CsonicNetwork.iface_up(int_if, self.pid)

    def add_if_to_ovs_bridge(self, intf, bridge):
        """Add interface to OVS bridge

        Args:
            intf (str): Interface name
            bridge (str): OVS bridge name
        """
        logging.info("=== Add interface %s to OVS bridge %s ===" %
                     (intf, bridge))

        ports = CsonicNetwork.get_ovs_br_ports(bridge)
        if intf not in ports:
            # Check if port exists on any other bridge and remove it first
            # This handles the case where a previous run may have added the port to the wrong bridge
            try:
                CsonicNetwork.cmd('ovs-vsctl del-port %s' % intf)
                logging.info("=== Removed interface %s from previous bridge ===" % intf)
            except Exception:
                # Port doesn't exist on any bridge, which is fine
                pass
            CsonicNetwork.cmd('ovs-vsctl add-port %s %s' % (bridge, intf))

    def add_if_to_bridge(self, intf, bridge):
        """Add interface to bridge

        Args:
            intf (str): Interface name
            bridge (str): Bridge name
        """
        logging.info("=== Add interface %s to bridge %s" % (intf, bridge))

        _, if_to_br = CsonicNetwork.brctl_show()

        if intf not in if_to_br:
            CsonicNetwork.cmd("brctl addif %s %s" % (bridge, intf))

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

        Args:
            intf (str): Name of the interface.
            pid (str, optional): Pid of docker. Defaults to None.

        Returns:
            bool: True if the interface exists. Otherwise False.
        """
        cmdline = CsonicNetwork._intf_cmd(intf, pid=pid)

        try:
            CsonicNetwork.cmd(cmdline, retry=3)
            return True
        except Exception:
            return False

    @staticmethod
    def intf_not_exists(intf, pid=None):
        """Check if the specified interface does not exist.

        Args:
            intf (str): Name of the interface.
            pid (str, optional): Pid of docker. Defaults to None.

        Returns:
            bool: True if the interface does not exist. Otherwise False.
        """
        cmdline = CsonicNetwork._intf_cmd(intf, pid=pid)

        try:
            CsonicNetwork.cmd(cmdline, retry=3, negative=True)
            return True
        except Exception:
            return False

    @staticmethod
    def iface_up(iface_name, pid=None):
        return CsonicNetwork.iface_updown(iface_name, 'up', pid)

    @staticmethod
    def iface_down(iface_name, pid=None):
        return CsonicNetwork.iface_updown(iface_name, 'down', pid)

    @staticmethod
    def iface_updown(iface_name, state, pid):
        logging.info('=== Bring %s interface %s, pid: %s ===' %
                     (state, iface_name, str(pid)))
        if pid is None:
            return CsonicNetwork.cmd('ip link set %s %s' % (iface_name, state))
        else:
            return CsonicNetwork.cmd('nsenter -t %s -n ip link set %s %s' % (pid, iface_name, state))

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
            logging.debug('*** CMD: %s, grep: %s, attempt: %d' %
                          (cmdline, grep_cmd, attempt+1))
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
                    return out
                else:
                    continue
            else:
                if ret_code == 0:
                    return out
                else:
                    continue

        msg = 'ret_code=%d, error message: "%s" cmd: "%s"' % \
            (ret_code, err, '%s | %s' %
             (cmdline, grep_cmd) if grep_cmd else cmdline)
        raise Exception(msg)

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = CsonicNetwork.cmd('ovs-vsctl list-ports %s' % bridge)
        ports = set()
        for port in out.split('\n'):
            if port != "":
                ports.add(port)
        return ports

    @staticmethod
    def get_pid(ctn_name):
        cli = docker.from_env()
        try:
            ctn = cli.containers.get(ctn_name)
        except Exception:
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
            out = CsonicNetwork.cmd(cmdline)
        except Exception:
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


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True, type='str'),
            vm_name=dict(required=True, type='str'),
            mgmt_bridge=dict(required=True, type='str'),
            fp_mtu=dict(required=False, type='int', default=DEFAULT_MTU),
            max_fp_num=dict(required=False, type='int', default=NUM_FP_VLANS_PER_FP),
            vm_offset=dict(required=False, type='int', default=0),
            sonic_naming=dict(required=False, type='bool', default=True),
            bp_bridge=dict(required=False, type='str', default=None),
        ),
        supports_check_mode=False)

    name = module.params['name']
    vm_name = module.params['vm_name']
    mgmt_bridge = module.params['mgmt_bridge']
    fp_mtu = module.params['fp_mtu']
    max_fp_num = module.params['max_fp_num']
    vm_offset = module.params['vm_offset']
    sonic_naming = module.params['sonic_naming']
    bp_bridge = module.params['bp_bridge']

    config_module_logging('csonic_net_' + vm_name)

    try:
        cnet = CsonicNetwork(name, vm_name, mgmt_bridge, fp_mtu, max_fp_num, vm_offset, sonic_naming, bp_bridge)
        cnet.init_network()

    except Exception as error:
        logging.error(traceback.format_exc())
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
