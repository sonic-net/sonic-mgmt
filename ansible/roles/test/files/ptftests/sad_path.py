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
        self.shandle.sad_setup(is_up=False)
        return self.shandle.retreive_test_info(), self.shandle.retreive_logs()

    def verify(self, pre_check=True):
        self.shandle.sad_bgp_verify()
        if 'lag' in self.oper_type:
            self.shandle.sad_lag_verify(pre_check=pre_check)
        return self.shandle.retreive_logs()

    def revert(self):
        self.shandle.sad_setup()
        return self.shandle.retreive_logs()


class SadPath(object):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args):
        (self.oper_type, self.cnt) = oper_type.split(':') if ':' in oper_type else (oper_type, 1)
        self.cnt = int(self.cnt)
        self.vm_list = vm_list
        self.portchannel_ports = portchannel_ports
        self.vm_dut_map = vm_dut_map
        self.test_args = test_args
        self.neigh_vms = []
        self.neigh_names = dict()
        self.vm_handles = dict()
        self.neigh_bgps = dict()
        self.dut_bgps = dict()
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
        vm_len = len(self.vm_list)
        # use the day of the month to select start VM from the list for the sad pass operation
        # neigh_vms list will contain cnt number of VMs starting from the start VM. vm_list will have the rest of the VMs
        vm_index = datetime.datetime.now().day % vm_len if vm_len > 0 else 0
        exceed_len = vm_index + self.cnt - vm_len
        if exceed_len <= 0:
            self.neigh_vms.extend(self.vm_list[vm_index:vm_index+self.cnt])
            self.vm_list = self.vm_list[0:vm_index] + self.vm_list[vm_index+self.cnt:]
        else:
            self.neigh_vms.extend(self.vm_list[vm_index:])
            self.neigh_vms.extend(self.vm_list[0:exceed_len])
            self.vm_list = self.vm_list[exceed_len:vm_len - self.cnt]

    def get_neigh_name(self):
        for key in self.vm_dut_map:
            for neigh_vm in self.neigh_vms:
                if self.vm_dut_map[key]['mgmt_addr'] == neigh_vm:
                    self.neigh_names[neigh_vm] = key   # VM address to name mapping
                    break

    def down_neigh_port(self):
        # extract ptf ports for the selected VMs and mark them down
        for neigh_name in self.neigh_names.values():
            for port in self.vm_dut_map[neigh_name]['ptf_ports']:
                self.portchannel_ports.remove(port)

    def vm_connect(self):
        for neigh_vm in self.neigh_vms:
            self.vm_handles[neigh_vm] = Arista(neigh_vm, None, self.test_args)
            self.vm_handles[neigh_vm].connect()

    def __del__(self):
        self.vm_disconnect()

    def vm_disconnect(self):
        for vm in self.vm_handles:
            self.vm_handles[vm].disconnect()

    def setup(self):
        self.select_vm()
        self.get_neigh_name()
        self.down_neigh_port()
        self.vm_connect()
        for vm in self.vm_handles:
            self.neigh_bgps[vm], self.dut_bgps[vm] = self.vm_handles[vm].get_bgp_info()
            self.fails[vm] = set()
            self.log.append('Neighbor AS: %s' % self.neigh_bgps[vm]['asn'])
            self.log.append('BGP v4 neighbor: %s' % self.neigh_bgps[vm]['v4'])
            self.log.append('BGP v6 neighbor: %s' % self.neigh_bgps[vm]['v6'])
            self.log.append('DUT BGP v4: %s' % self.dut_bgps[vm]['v4'])
            self.log.append('DUT BGP v6: %s' % self.dut_bgps[vm]['v6'])

    def retreive_test_info(self):
        return self.vm_list, self.portchannel_ports, self.neigh_vms

    def retreive_logs(self):
        return self.log, self.fails


class SadOper(SadPath):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, dut_ssh):
        super(SadOper, self).__init__(oper_type, vm_list, portchannel_ports, vm_dut_map, test_args)
        self.dut_ssh = dut_ssh
        self.dut_needed = dict()
        self.lag_members_down = dict()
        self.neigh_lag_state = None
        self.po_neigh_map = dict()
        self.msg_prefix = ['Postboot', 'Preboot']

    def populate_bgp_state(self):
        [self.dut_needed.setdefault(vm, self.dut_bgps[vm]) for vm in self.neigh_vms]
        if self.oper_type == 'neigh_bgp_down':
            self.neigh_bgps['changed_state'] = 'down'
            self.dut_bgps['changed_state'] = 'Active'
            [self.dut_needed.update({vm:None}) for vm in self.neigh_vms]
        elif self.oper_type == 'dut_bgp_down':
            self.neigh_bgps['changed_state'] = 'Active'
            self.dut_bgps['changed_state'] = 'Idle'
        elif self.oper_type == 'neigh_lag_down':
            # on the DUT side, bgp states are different pre and post boot. hence passing multiple values
            self.neigh_bgps['changed_state'] = 'Idle'
            self.dut_bgps['changed_state'] = 'Connect,Active,Idle'
        elif self.oper_type == 'dut_lag_down':
            self.neigh_bgps['changed_state'] = 'Idle'
            self.dut_bgps['changed_state'] = 'Active,Connect,Idle'

    def sad_setup(self, is_up=True):
        self.log = []

        if not is_up:
            self.setup()
            self.populate_bgp_state()
            if 'lag' in self.oper_type:
                self.populate_lag_state()

        if 'bgp' in self.oper_type:
            self.log.append('BGP state change will be for %s' % ", ".join(self.neigh_vms))
            if self.oper_type == 'neigh_bgp_down':
                for vm in self.neigh_vms:
                    self.log.append('Changing state of AS %s to shut' % self.neigh_bgps[vm]['asn'])
                    self.vm_handles[vm].change_bgp_neigh_state(self.neigh_bgps[vm]['asn'], is_up=is_up)
            elif self.oper_type == 'dut_bgp_down':
                self.change_bgp_dut_state(is_up=is_up)
            time.sleep(30)

        elif 'lag' in self.oper_type:
            self.log.append('LAG state change will be for %s' % ", ".join(self.neigh_vms))
            if self.oper_type == 'neigh_lag_down':
                for vm in self.neigh_vms:
                    self.log.append('Changing state of LAG %s to shut' % self.vm_dut_map[self.neigh_names[vm]]['neigh_portchannel'])
                    self.vm_handles[vm].change_neigh_lag_state(self.vm_dut_map[self.neigh_names[vm]]['neigh_portchannel'], is_up=is_up)
            elif self.oper_type == 'dut_lag_down':
                self.change_dut_lag_state(is_up=is_up)
            # wait for sometime for lag members state to sync
            time.sleep(120)

    def change_bgp_dut_state(self, is_up=True):
        state = ['shutdown', 'startup']
        for vm in self.neigh_vms:
            for key in self.neigh_bgps[vm].keys():
                if key not in ['v4', 'v6']:
                    continue

                self.log.append('Changing state of BGP peer %s from DUT side to %s' % (self.neigh_bgps[vm][key], state[is_up]))
                stdout, stderr, return_code = self.cmd(['ssh', '-oStrictHostKeyChecking=no', self.dut_ssh, 'sudo config bgp %s neighbor %s' % (state[is_up], self.neigh_bgps[vm][key])])
                if return_code != 0:
                    self.fails['dut'].add('State change not successful from DUT side for peer %s' % self.neigh_bgps[vm][key])
                    self.fails['dut'].add('Return code: %d' % return_code)
                    self.fails['dut'].add('Stderr: %s' % stderr)

    def verify_bgp_dut_state(self, state='Idle'):
        states = state.split(',')
        bgp_state = {}
        for vm in self.neigh_vms:
            bgp_state[vm] = dict()
            bgp_state[vm]['v4'] = bgp_state[vm]['v6'] = False
            for key in self.neigh_bgps[vm].keys():
                if key not in ['v4', 'v6']:
                    continue
                self.log.append('Verifying if the DUT side BGP peer %s is %s' % (self.neigh_bgps[vm][key], states))
                stdout, stderr, return_code = self.cmd(['ssh', '-oStrictHostKeyChecking=no', self.dut_ssh, 'show ip bgp neighbor %s' % self.neigh_bgps[vm][key]])
                if return_code == 0:
                    for line in stdout.split('\n'):
                        if 'BGP state' in line:
                            curr_state = re.findall('BGP state = (\w+)', line)[0]
                            bgp_state[vm][key] = (curr_state in states)
                            break
                else:
                    self.fails['dut'].add('Retreiving BGP info for peer %s from DUT side failed' % self.neigh_bgps[vm][key])
                    self.fails['dut'].add('Return code: %d' % return_code)
                    self.fails['dut'].add('Stderr: %s' % stderr)
        return bgp_state

    def sad_bgp_verify(self):
        self.log = []
        for vm in self.neigh_vms:
            fails_vm, bgp_state = self.vm_handles[vm].verify_bgp_neigh_state(dut=self.dut_needed[vm], state=self.neigh_bgps['changed_state'])
            self.fails[vm] |= fails_vm
            if bgp_state['v4'] and bgp_state['v6']:
                self.log.append('BGP state down as expected for %s' % vm)
            else:
                self.fails[vm].add('BGP state not down for %s' % vm)
        bgp_state = self.verify_bgp_dut_state(state=self.dut_bgps['changed_state'])
        state = True
        for vm in self.neigh_vms:
            state &= bgp_state[vm]['v4'] and bgp_state[vm]['v6']
        if state:
            self.log.append('BGP state down as expected on DUT')
        else:
            self.fails['dut'].add('BGP state not down on DUT')

    def populate_lag_state(self):
        if self.oper_type == 'neigh_lag_down':
            self.neigh_lag_state = 'disabled'
        elif self.oper_type == 'dut_lag_down':
            self.neigh_lag_state = 'notconnect'

        for neigh_name in self.neigh_names.values():
            # build portchannel to down members mapping
            po_name = self.vm_dut_map[neigh_name]['dut_portchannel']
            self.lag_members_down[po_name] = self.vm_dut_map[neigh_name]['dut_ports']

    def change_dut_lag_state(self, is_up=True):
        state = ['shutdown', 'startup']
        for neigh_name in self.neigh_names.values():
            dut_portchannel = self.vm_dut_map[neigh_name]['dut_portchannel']
            if not re.match('(PortChannel|Ethernet)\d+', dut_portchannel): continue
            self.log.append('Changing state of %s from DUT side to %s' % (dut_portchannel, state[is_up]))
            stdout, stderr, return_code = self.cmd(['ssh', '-oStrictHostKeyChecking=no', self.dut_ssh, 'sudo config interface %s %s' % (state[is_up], dut_portchannel)])
            if return_code != 0:
                self.fails['dut'].add('%s: State change not successful from DUT side for %s' % (self.msg_prefix[1 - is_up], dut_portchannel))
                self.fails['dut'].add('%s: Return code: %d' % (self.msg_prefix[1 - is_up], return_code))
                self.fails['dut'].add('%s: Stderr: %s' % (self.msg_prefix[1 - is_up], stderr))
            else:
                self.log.append('%s: State change successful on DUT for %s' % (self.msg_prefix[1 - is_up], dut_portchannel))

    def verify_dut_lag_member_state(self, match, pre_check=True):
        success = True
        po_name = match.group(1)
        lag_memb_output = match.group(2)
        neigh_name = self.po_neigh_map[po_name]
        for member in self.vm_dut_map[neigh_name]['dut_ports']:
            if po_name in self.lag_members_down and member in self.lag_members_down[po_name]:
                search_str = '%s(D)' % member
            else:
                search_str = '%s(S)' % member

            if lag_memb_output.find(search_str) != -1:
                self.log.append('Lag member %s state as expected' % member)
            else:
                success = False
                self.fails['dut'].add('%s: Lag member %s state not as expected' % (self.msg_prefix[pre_check], member))
        return success

    def verify_dut_lag_state(self, pre_check=True):
        # pattern match eg: '0001  PortChannel0001  LACP(A)(Up)  Ethernet0(S) Ethernet4(S)'. extract the portchannel name and members
        pat = re.compile("\s+\d+\s+(\w+\d+)\s+LACP\(A\)\(Dw\)\s+(.*)")

        # get list of down portchannels and build portchannel to neigh mapping
        po_list = []
        for vm in self.neigh_vms:
            po_name = self.vm_dut_map[self.neigh_names[vm]]['dut_portchannel']
            po_list.append(po_name)
            self.po_neigh_map[po_name] = self.neigh_names[vm]

        stdout, stderr, return_code = self.cmd(['ssh', '-oStrictHostKeyChecking=no', self.dut_ssh, 'show interfaces portchannel'])
        if return_code == 0:
            for line in stdout.split('\n'):
                if any(po_name in line for po_name in po_list):
                    is_match = pat.match(line)
                    if is_match and self.verify_dut_lag_member_state(is_match, pre_check=pre_check):
                        self.log.append('Lag state is down as expected on the DUT for %s' % is_match.group(1))
                        self.log.append('Pattern check: %s' % line)
                    else:
                        self.fails['dut'].add('%s: Lag state is not down on the DUT for %s' % (self.msg_prefix[pre_check], is_match.group(1)))
                        self.fails['dut'].add('%s: Obtained: %s' % (self.msg_prefix[pre_check], line))
        else:
            self.fails['dut'].add('%s: Retreiving LAG info from DUT side failed' % self.msg_prefix[pre_check])
            self.fails['dut'].add('%s: Return code: %d' % (self.msg_prefix[pre_check], return_code))
            self.fails['dut'].add('%s: Stderr: %s' % (self.msg_prefix[pre_check], stderr))

    def sad_lag_verify(self, pre_check=True):
        for vm in self.neigh_vms:
            fails_vm, lag_state = self.vm_handles[vm].verify_neigh_lag_state(self.vm_dut_map[self.neigh_names[vm]]['neigh_portchannel'], state=self.neigh_lag_state, pre_check=pre_check)
            self.fails[vm] |= fails_vm
            if lag_state:
                self.log.append('LAG state down as expected for %s' % vm)
            else:
                self.fails[vm].add('%s: LAG state not down for %s' % (self.msg_prefix[pre_check], vm))
        self.log.append('Verifying LAG state on the dut end')
        self.verify_dut_lag_state(pre_check=pre_check)
