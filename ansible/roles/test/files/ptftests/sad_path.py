import datetime
import re
import subprocess
import time

from arista import Arista


class PrebootTest(object):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, dut_ssh):
        self.oper_type = oper_type
        self.vm_list = vm_list
        self.portchannel_ports = portchannel_ports
        self.vm_dut_map = vm_dut_map
        self.test_args = test_args
        self.dut_ssh = dut_ssh
        self.fails_vm = set()
        self.fails_dut = set()
        self.log = []
        self.shandle = SadOper(self.oper_type, self.vm_list, self.portchannel_ports, self.vm_dut_map, self.test_args, self.dut_ssh)

    def setup(self):
        if 'bgp' in self.oper_type:
            self.shandle.sad_setup(is_up=False)
        return self.shandle.retreive_test_info(), self.shandle.retreive_logs()

    def verify(self):
        self.shandle.sad_bgp_verify()
        return self.shandle.retreive_logs()

    def revert(self):
        self.shandle.sad_setup()
        return self.shandle.retreive_logs()


class SadPath(object):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args):
        self.oper_type = oper_type
        self.vm_list = vm_list
        self.portchannel_ports = portchannel_ports
        self.vm_dut_map = vm_dut_map
        self.test_args = test_args
        self.neigh_vm = None
        self.neigh_name = None
        self.vm_handle = None
        self.neigh_bgp = None
        self.dut_bgp = None
        self.log = []
        self.fails = dict()
        self.fails['dut'] = set()

    def cmd(self, cmds):
        process = subprocess.Popen(cmds,
                                   shell=False,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def select_vm(self):
        self.vm_list.sort()
        # use the day of the month to select a VM from the list for the sad pass operation
        vm_index = datetime.datetime.now().day % len(self.vm_list)
        self.neigh_vm = self.vm_list.pop(vm_index)

    def get_neigh_name(self):
        for key in self.vm_dut_map.keys():
            if self.vm_dut_map[key]['mgmt_addr'] == self.neigh_vm:
                self.neigh_name = key
                break

    def down_neigh_port(self):
        # extract ptf ports for the selected VM and mark them down
        for port in self.vm_dut_map[self.neigh_name]['ptf_ports']:
            self.portchannel_ports.remove(port)

    def vm_connect(self):
        self.vm_handle = Arista(self.neigh_vm, None, self.test_args)
        self.vm_handle.connect()

    def __del__(self):
        self.vm_disconnect()

    def vm_disconnect(self):
        self.vm_handle.disconnect()

    def setup(self):
        self.select_vm()
        self.get_neigh_name()
        self.down_neigh_port()
        self.vm_connect()
        self.neigh_bgp, self.dut_bgp = self.vm_handle.get_bgp_info()
        self.fails[self.neigh_vm] = set()
        self.log.append('Neighbor AS: %s' % self.neigh_bgp['asn'])
        self.log.append('BGP v4 neighbor: %s' % self.neigh_bgp['v4'])
        self.log.append('BGP v6 neighbor: %s' % self.neigh_bgp['v6'])
        self.log.append('DUT BGP v4: %s' % self.dut_bgp['v4'])
        self.log.append('DUT BGP v6: %s' % self.dut_bgp['v6'])

    def retreive_test_info(self):
        return self.vm_list, self.portchannel_ports, self.neigh_vm

    def retreive_logs(self):
        return self.log, self.fails['dut'], self.fails[self.neigh_vm]


class SadOper(SadPath):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, dut_ssh):
        super(SadOper, self).__init__(oper_type, vm_list, portchannel_ports, vm_dut_map, test_args)
        self.dut_ssh = dut_ssh
        self.dut_needed = None

    def populate_bgp_state(self):
        if self.oper_type == 'neigh_bgp_down':
            self.neigh_bgp['changed_state'] = 'down'
            self.dut_bgp['changed_state'] = 'Active'
            self.dut_needed = None
        elif self.oper_type == 'dut_bgp_down':
            self.neigh_bgp['changed_state'] = 'Active'
            self.dut_bgp['changed_state'] = 'Idle'
            self.dut_needed = self.dut_bgp

    def sad_setup(self, is_up=True):
        self.log = []
        if not is_up:
            self.setup()
            self.populate_bgp_state()
        self.log.append('BGP state change will be for %s' % self.neigh_vm)
        if self.oper_type == 'neigh_bgp_down':
            self.log.append('Changing state of AS %s to shut' % self.neigh_bgp['asn'])
            self.vm_handle.change_bgp_neigh_state(self.neigh_bgp['asn'], is_up=is_up)
        elif self.oper_type == 'dut_bgp_down':
            self.change_bgp_dut_state(is_up=is_up)
        time.sleep(30)

    def change_bgp_dut_state(self, is_up=True):
        state = ['shutdown', 'startup']
        for key in self.neigh_bgp.keys():
            if key not in ['v4', 'v6']:
                continue

            self.log.append('Changing state of BGP peer %s from DUT side to %s' % (self.neigh_bgp[key], state[is_up]))
            stdout, stderr, return_code = self.cmd(['ssh', '-oStrictHostKeyChecking=no', self.dut_ssh, 'sudo config bgp %s neighbor %s' % (state[is_up], self.neigh_bgp[key])])
            if return_code != 0:
                self.fails['dut'].add('State change not successful from DUT side for peer %s' % self.neigh_bgp[key])
                self.fails['dut'].add('Return code: %d' % return_code)
                self.fails['dut'].add('Stderr: %s' % stderr)

    def verify_bgp_dut_state(self, state='Idle'):
        bgp_state = {}
        bgp_state['v4'] = bgp_state['v6'] = False
        for key in self.neigh_bgp.keys():
            if key not in ['v4', 'v6']:
                continue
            self.log.append('Verifying if the DUT side BGP peer %s is %s' % (self.neigh_bgp[key], state))
            stdout, stderr, return_code = self.cmd(['ssh', '-oStrictHostKeyChecking=no', self.dut_ssh, 'show ip bgp neighbor %s' % self.neigh_bgp[key]])
            if return_code == 0:
                for line in stdout.split('\n'):
                    if 'BGP state' in line:
                        curr_state = re.findall('BGP state = (\w+)', line)[0]
                        bgp_state[key] = (curr_state == state)
                        break
            else:
                self.fails['dut'].add('Retreiving BGP info for peer %s from DUT side failed' % self.neigh_bgp[key])
                self.fails['dut'].add('Return code: %d' % return_code)
                self.fails['dut'].add('Stderr: %s' % stderr)
        return bgp_state

    def sad_bgp_verify(self):
        self.log = []
        fails_vm, bgp_state = self.vm_handle.verify_bgp_neigh_state(dut=self.dut_needed, state=self.neigh_bgp['changed_state'])
        self.fails[self.neigh_vm] |= fails_vm
        if bgp_state['v4'] and bgp_state['v6']:
            self.log.append('BGP state down as expected for %s' % self.neigh_vm)
        else:
            self.fails[self.neigh_vm].add('BGP state not down for %s' % self.neigh_vm)
        bgp_state = self.verify_bgp_dut_state(state=self.dut_bgp['changed_state'])
        if bgp_state['v4'] and bgp_state['v6']:
            self.log.append('BGP state down as expected on DUT')
        else:
            self.fails['dut'].add('BGP state not down on DUT')
