#!/usr/bin/python

import subprocess
import re
import os
import os.path
import re
import docker
from ansible.module_utils.basic import *
import traceback
from pprint import pprint

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
EXCEPTION_DEBUG_FNAME = "/tmp/ceos_network.exception.%s.txt"

OVS_FP_BRIDGE_REGEX = 'br-%s-\d+'
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
FP_TAP_TEMPLATE = '%s-t%d'
BP_TAP_TEMPLATE = '%s-back'
MGMT_TAP_TEMPLATE = '%s-m'
INT_TAP_TEMPLATE = 'eth%d'
RETRIES = 3

cmd_debug_fname = None

class CeosNetwork(object):

    def __init__(self, ctn_name, vm_name, mgmt_br_name, fp_mtu, max_fp_num):
        self.ctn_name = ctn_name
        self.vm_name = vm_name
        self.fp_mtu = fp_mtu
        self.max_fp_num = max_fp_num
        self.mgmt_br_name = mgmt_br_name

        self.pid = CeosNetwork.get_pid(self.ctn_name)
        if self.pid is None:
            raise Exception("canot find pid for %s" % (self.ctn_name))
        self.host_ifaces = CeosNetwork.ifconfig('ifconfig -a')

        return

    def init_network(self):

        # create mgmt link
        mp_name = MGMT_TAP_TEMPLATE % (self.vm_name)
        self.add_veth_if_to_docker(mp_name, INT_TAP_TEMPLATE % 0)
        self.add_if_to_bridge(mp_name, self.mgmt_br_name)

        # create fp link
        for i in range(self.max_fp_num):
            fp_name = FP_TAP_TEMPLATE % (self.vm_name, i)
            fp_br_name = OVS_FP_BRIDGE_TEMPLATE % (self.vm_name, i)
            self.add_veth_if_to_docker(fp_name, INT_TAP_TEMPLATE % (i + 1))
            self.add_if_to_ovs_bridge(fp_name, fp_br_name)

        # create backplane
        self.add_veth_if_to_docker(BP_TAP_TEMPLATE % (self.vm_name), INT_TAP_TEMPLATE % (self.max_fp_num + 1))

        return

    def update(self):
        errmsg = []
        i = 0
        while i < 3:
            try:
                self.host_br_to_ifs, self.host_if_to_br = CeosNetwork.brctl_show()
                self.host_ifaces = CeosNetwork.ifconfig('ifconfig -a')
                if self.pid is not None:
                    self.cntr_ifaces = CeosNetwork.ifconfig('nsenter -t %s -n ifconfig -a' % self.pid)
                else:
                    self.cntr_ifaces = []
                break
            except Exception as error:
                errmsg.append(str(error))
                i += 1

        if i == 3:
            raise Exception("update failed for %d times. %s" % (i, "|".join(errmsg)))

        return

    def add_veth_if_to_docker(self, ext_if, int_if):
        self.update()

        if ext_if in self.host_ifaces and int_if not in self.cntr_ifaces:
            CeosNetwork.cmd("ip link del %s" % ext_if)
            self.update()

        t_int_if = int_if + '_t'
        if ext_if not in self.host_ifaces:
            CeosNetwork.cmd("ip link add %s type veth peer name %s" % (ext_if, t_int_if))
            self.update()

        if self.fp_mtu != DEFAULT_MTU:
            CeosNetwork.cmd("ip link set dev %s mtu %d" % (ext_if, self.fp_mtu))
            if t_int_if in self.host_ifaces:
                CeosNetwork.cmd("ip link set dev %s mtu %d" % (t_int_if, self.fp_mtu))
            elif t_int_if in self.cntr_ifaces:
                CeosNetwork.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, t_int_if, self.fp_mtu))
            elif int_if in self.cntr_ifaces:
                CeosNetwork.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_if, self.fp_mtu))

        CeosNetwork.iface_up(ext_if)

        self.update()

        if t_int_if in self.host_ifaces and t_int_if not in self.cntr_ifaces and int_if not in self.cntr_ifaces:
            CeosNetwork.cmd("ip link set netns %s dev %s" % (self.pid, t_int_if))
            self.update()

        if t_int_if in self.cntr_ifaces and int_if not in self.cntr_ifaces:
            CeosNetwork.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_if, int_if))

        CeosNetwork.iface_up(int_if, self.pid)

        return

    def add_if_to_ovs_bridge(self, intf, bridge):
        """
        add interface to ovs bridge
        """
        ports = CeosNetwork.get_ovs_br_ports(bridge)
        if intf not in ports:
            CeosNetwork.cmd('ovs-vsctl add-port %s %s' % (bridge, intf))

    def add_if_to_bridge(self, intf, bridge):
        self.update()

        if intf not in self.host_if_to_br:
            CeosNetwork.cmd("brctl addif %s %s" % (bridge, intf))

        return

    def remove_if_from_bridge(self, intf, bridge):
        self.update()

        if intf in self.host_if_to_br:
            CeosNetwork.cmd("brctl delif %s %s" % (self.host_if_to_br[intf], intf))

        return

    @staticmethod
    def iface_up(iface_name, pid=None):
        return CeosNetwork.iface_updown(iface_name, 'up', pid)

    @staticmethod
    def iface_down(iface_name, pid=None):
        return CeosNetwork.iface_updown(iface_name, 'down', pid)

    @staticmethod
    def iface_updown(iface_name, state, pid):
        if pid is None:
            return CeosNetwork.cmd('ip link set %s %s' % (iface_name, state))
        else:
            return CeosNetwork.cmd('nsenter -t %s -n ip link set %s %s' % (pid, iface_name, state))

    @staticmethod
    def iface_disable_txoff(iface_name, pid=None):
        if pid is None:
            return CeosNetwork.cmd('ethtool -K %s tx off' % (iface_name))
        else:
            return CeosNetwork.cmd('nsenter -t %s -n ethtool -K %s tx off' % (pid, iface_name))

    @staticmethod
    def cmd(cmdline):
        with open(cmd_debug_fname, 'a') as fp:
            pprint("CMD: %s" % cmdline, fp)
        cmd = cmdline.split(' ')
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        ret_code = process.returncode

        if ret_code != 0:
            raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, cmdline))

        with open(cmd_debug_fname, 'a') as fp:
            pprint("OUTPUT: %s" % stdout, fp)
        return stdout

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = CeosNetwork.cmd('ovs-vsctl list-ports %s' % bridge)
        ports = set()
        for port in out.split('\n'):
            if port != "":
                ports.add(port)
        return ports

    @staticmethod
    def ifconfig(cmdline):
        out = CeosNetwork.cmd(cmdline)

        ifaces = set()

        rows = out.split('\n')
        for row in rows:
            if len(row) == 0:
                continue
            terms = row.split()
            if not row[0].isspace():
                ifaces.add(terms[0].rstrip(':'))

        return ifaces

    @staticmethod
    def get_pid(ctn_name):
        cli = docker.from_env()
        try:
            ctn = cli.containers.get(ctn_name)
        except:
            return None

        return ctn.attrs['State']['Pid']

    @staticmethod
    def brctl_show():
        out = CeosNetwork.cmd("brctl show")

        br_to_ifs = {}
        if_to_br = {}

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

def check_params(module, params, mode):
    for param in params:
        if param not in module.params:
            raise Exception("Parameter %s is required in %s mode" % (param, mode))

    return

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

    curtime = datetime.datetime.now().isoformat()

    global cmd_debug_fname
    cmd_debug_fname = CMD_DEBUG_FNAME % curtime
    exception_debug_fname = EXCEPTION_DEBUG_FNAME % curtime

    try:
        if os.path.exists(cmd_debug_fname) and os.path.isfile(cmd_debug_fname):
            os.remove(cmd_debug_fname)

        cnet = CeosNetwork(name, vm_name, mgmt_bridge, fp_mtu, max_fp_num)

        cnet.init_network()

    except Exception as error:
        with open(exception_debug_fname, 'w') as fp:
            traceback.print_exc(file=fp)
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()

