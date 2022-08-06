#!/usr/bin/python

import json
import logging
import subprocess
import shlex
import traceback

import docker

from ansible.module_utils.debug_utils import config_module_logging
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: ceos_network
version_added: "0.1"
author: Guohan Lu (gulv@microsoft.com)
short_description: Create network for ceos container
description:
    the module creates follow network interfaces
    - 1 management interface which is added to management bridge
    - n front panel interfaces which are added to front panel bridges
    - 1 back plane interface

Parameters:
    - name: container name
    - mgmt_bridge: a bridge which is used as mgmt bridge on the host
    - fp_mtu: MTU for FP ports
'''

EXAMPLES = '''
- name: Create VMs network
  ceos_network:
    name:        net_{{ vm_set_name }}_{{ vm_name }}
    vm_name:     "{{ vm_name }}"
    fp_mtu:      "{{ fp_mtu_size }}"
    max_fp_num:  "{{ max_fp_num }}"
    mgmt_bridge: "{{ mgmt_bridge }}"
'''


DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 4
VM_SET_NAME_MAX_LEN = 8  # used in interface names. So restricted
CMD_DEBUG_FNAME = "/tmp/ceos_network.cmds.%s.txt"

OVS_FP_BRIDGE_REGEX = 'br-%s-\d+'
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
FP_TAP_TEMPLATE = '%s-t%d'
BP_TAP_TEMPLATE = '%s-back'
MGMT_TAP_TEMPLATE = '%s-m'
TMP_TAP_TEMPLATE = '%s-%d'
INT_TAP_TEMPLATE = 'eth%d'


class CeosNetwork(object):
    """This class is for creating CEOS network.

    This creates veth pairs and add one of the veth interface to the CEOS network docker. The external veth interface
    is added to corresponding bridges.

    """
    def __init__(self, ctn_name, vm_name, mgmt_br_name, fp_mtu, max_fp_num):
        self.ctn_name = ctn_name
        self.vm_name = vm_name
        self.fp_mtu = fp_mtu
        self.max_fp_num = max_fp_num
        self.mgmt_br_name = mgmt_br_name

        self.pid = CeosNetwork.get_pid(self.ctn_name)
        if self.pid is None:
            raise Exception("cannot find pid for %s" % (self.ctn_name))

    def init_network(self):
        """Create CEOS network
        """
        # create mgmt link
        mp_name = MGMT_TAP_TEMPLATE % (self.vm_name)
        self.add_veth_if_to_docker(mp_name, TMP_TAP_TEMPLATE % (self.vm_name, 0), INT_TAP_TEMPLATE % 0)
        self.add_if_to_bridge(mp_name, self.mgmt_br_name)

        # create fp link
        for i in range(self.max_fp_num):
            fp_name = FP_TAP_TEMPLATE % (self.vm_name, i)
            fp_br_name = OVS_FP_BRIDGE_TEMPLATE % (self.vm_name, i)
            self.add_veth_if_to_docker(fp_name, TMP_TAP_TEMPLATE % (self.vm_name, (i + 1)), INT_TAP_TEMPLATE % (i + 1))
            self.add_if_to_ovs_bridge(fp_name, fp_br_name)

        # create backplane
        self.add_veth_if_to_docker(
            BP_TAP_TEMPLATE % (self.vm_name),
            TMP_TAP_TEMPLATE % (self.vm_name, (self.max_fp_num + 1)),
            INT_TAP_TEMPLATE % (self.max_fp_num + 1))

    def add_veth_if_to_docker(self, ext_if, t_int_if, int_if):
        """Create a pair of veth interfaces and add one of them to namespace of docker.

        Args:
            ext_if (str): External interface of the veth pair. It remains in host.
            t_int_if (str): Name of peer interface of ext_if. It is firstly created in host with ext_if. Then it
                is added to docker namespace and renamed to int_if.
            int_if (str): Internal interface of the veth pair. It is added to docker namespace.
        """
        logging.info("=== Create veth pair %s and %s. Add %s to docker with Pid %s as %s ===" %
            (ext_if, t_int_if, t_int_if, self.pid, int_if))

        if CeosNetwork.intf_exists(ext_if) and CeosNetwork.intf_not_exists(int_if, self.pid):
            CeosNetwork.cmd("ip link del %s" % ext_if)

        if CeosNetwork.intf_not_exists(ext_if):
            CeosNetwork.cmd("ip link add %s type veth peer name %s" % (ext_if, t_int_if))

        if self.fp_mtu != DEFAULT_MTU:
            CeosNetwork.cmd("ip link set dev %s mtu %d" % (ext_if, self.fp_mtu))
            if CeosNetwork.intf_exists(t_int_if):
                CeosNetwork.cmd("ip link set dev %s mtu %d" % (t_int_if, self.fp_mtu))
            elif CeosNetwork.intf_exists(t_int_if, self.pid):
                CeosNetwork.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, t_int_if, self.fp_mtu))
            elif CeosNetwork.intf_exists(int_if, self.pid):
                CeosNetwork.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_if, self.fp_mtu))

        CeosNetwork.iface_up(ext_if)

        if CeosNetwork.intf_exists(t_int_if) \
            and CeosNetwork.intf_not_exists(t_int_if, self.pid) \
            and CeosNetwork.intf_not_exists(int_if, self.pid):
            CeosNetwork.cmd("ip link set netns %s dev %s" % (self.pid, t_int_if))

        if CeosNetwork.intf_exists(t_int_if, self.pid) and CeosNetwork.intf_not_exists(int_if, self.pid):
            CeosNetwork.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_if, int_if))

        CeosNetwork.iface_up(int_if, self.pid)

    def add_if_to_ovs_bridge(self, intf, bridge):
        """Add interface to OVS bridge

        Args:
            intf (str): Interface name
            bridge (str): OVS bridge name
        """
        logging.info("=== Add interface %s to OVS bridge %s ===" % (intf, bridge))

        ports = CeosNetwork.get_ovs_br_ports(bridge)
        if intf not in ports:
            CeosNetwork.cmd('ovs-vsctl add-port %s %s' % (bridge, intf))

    def add_if_to_bridge(self, intf, bridge):
        """Add interface to bridge

        Args:
            intf (str): Interface name
            bridge (str): Bridge name
        """
        logging.info("=== Add interface %s to bridge %s" % (intf, bridge))

        _, if_to_br = CeosNetwork.brctl_show()

        if intf not in if_to_br:
            CeosNetwork.cmd("brctl addif %s %s" % (bridge, intf))

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
        cmdline = CeosNetwork._intf_cmd(intf, pid=pid)

        try:
            CeosNetwork.cmd(cmdline, retry=3)
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
        cmdline = CeosNetwork._intf_cmd(intf, pid=pid)

        try:
            CeosNetwork.cmd(cmdline, retry=3, negative=True)
            return True
        except:
            return False

    @staticmethod
    def iface_up(iface_name, pid=None):
        return CeosNetwork.iface_updown(iface_name, 'up', pid)

    @staticmethod
    def iface_down(iface_name, pid=None):
        return CeosNetwork.iface_updown(iface_name, 'down', pid)

    @staticmethod
    def iface_updown(iface_name, state, pid):
        logging.info('=== Bring %s interface %s, pid: %s ===' % (state, iface_name, str(pid)))
        if pid is None:
            return CeosNetwork.cmd('ip link set %s %s' % (iface_name, state))
        else:
            return CeosNetwork.cmd('nsenter -t %s -n ip link set %s %s' % (pid, iface_name, state))

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
        msg = 'ret_code=%d, error message: "%s" cmd: "%s"' % \
            (ret_code, err, '%s | %s' % (cmdline, grep_cmd) if grep_cmd else cmdline)
        raise Exception(msg)

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = CeosNetwork.cmd('ovs-vsctl list-ports %s' % bridge)
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
            out = CeosNetwork.cmd(cmdline)
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

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True, type='str'),
            vm_name=dict(required=True, type='str'),
            mgmt_bridge=dict(required=True, type='str'),
            fp_mtu=dict(required=False, type='int', default=DEFAULT_MTU),
            max_fp_num=dict(required=False, type='int', default=NUM_FP_VLANS_PER_FP),
        ),
        supports_check_mode=False)

    name = module.params['name']
    vm_name = module.params['vm_name']
    mgmt_bridge = module.params['mgmt_bridge']
    fp_mtu = module.params['fp_mtu']
    max_fp_num = module.params['max_fp_num']

    config_module_logging('ceos_net_' + vm_name)

    try:
        cnet = CeosNetwork(name, vm_name, mgmt_bridge, fp_mtu, max_fp_num)

        cnet.init_network()

    except Exception as error:
        logging.error(traceback.format_exc())
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()
