import datetime
import ipaddress
import re
import time

from arista import Arista
from device_connection import DeviceConnection


class SadTest(object):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, vlan_ports, ports_per_vlan):
        self.oper_type = oper_type
        self.vm_list = vm_list
        self.portchannel_ports = portchannel_ports
        self.vm_dut_map = vm_dut_map
        self.test_args = test_args
        self.vlan_ports = vlan_ports
        self.ports_per_vlan = ports_per_vlan
        self.fails_vm = set()
        self.fails_dut = set()
        self.log = []
        self.shandle = SadOper(self.oper_type, self.vm_list, self.portchannel_ports, self.vm_dut_map, self.test_args, self.vlan_ports, self.ports_per_vlan)

    def setup(self):
        self.shandle.sad_setup(is_up=False)
        return self.shandle.retreive_test_info(), self.shandle.retreive_logs()

    def route_setup(self):
        self.shandle.modify_routes()
        return self.shandle.retreive_logs()

    def verify(self, pre_check=True, inboot=False):
        if 'vlan' in self.oper_type:
            self.shandle.verify_vlan_port_state(pre_check=pre_check)
        elif 'routing' in self.oper_type:
            self.shandle.verify_route_add(pre_check=pre_check, inboot=inboot)
        else:
            self.shandle.sad_bgp_verify()
            if 'lag' in self.oper_type:
                self.shandle.sad_lag_verify(pre_check=pre_check)
        return self.shandle.retreive_logs()

    def revert(self):
        self.shandle.sad_setup()
        return self.shandle.retreive_logs()


class SadPath(object):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, vlan_ports, ports_per_vlan):
        self.oper_type = ''
        self.memb_cnt = 0
        self.cnt = 1 if 'routing' not in oper_type else len(vm_list)
        self.ip_cnt = 1
        self.vm_list = vm_list
        self.portchannel_ports = portchannel_ports
        self.vm_dut_map = vm_dut_map
        self.test_args = test_args
        self.dut_connection = DeviceConnection(test_args['dut_hostname'], test_args['dut_username'], password=test_args['dut_password'])
        self.vlan_ports = vlan_ports
        self.ports_per_vlan = ports_per_vlan
        self.vlan_if_port = self.test_args['vlan_if_port']
        self.neigh_vms = []
        self.neigh_names = dict()
        self.vm_handles = dict()
        self.neigh_bgps = dict()
        self.dut_bgps = dict()
        self.log = []
        self.fails = dict()
        self.fails['dut'] = set()
        self.tot_memb_cnt = 0
        self.memb_index = 0
        self.if_port = []
        self.down_vlan_info = []
        self.bp_ip = None
        self.bp_ip6 = None
        self.extract_oper_info(oper_type)
        self.extract_nexthops()

    def extract_nexthops(self):
        if self.test_args['nexthop_ips']:
            self.bp_ip = str(self.test_args['nexthop_ips'][0])
            self.bp_ip6 = str(self.test_args['nexthop_ips'][1])

    def extract_oper_info(self, oper_type):
        if oper_type and ':' in oper_type:
            temp = oper_type.split(':')
            self.oper_type = temp[0]
            # get number of VMs where the preboot sad pass oper needs to be done. For vlan_member case,
            # this will be the number of down vlan ports
            if 'routing' not in oper_type:
                self.cnt = int(temp[1])
                if len(temp) > 2:
                    # get the number of lag members in a portchannel that should be brought down
                    self.memb_cnt = int(temp[-1])
            else:
                # for sad operation during reboot, all VMs should be included in the cnt
                self.cnt = len(self.vm_list)
                self.ip_cnt = int(temp[-1])
        else:
            self.oper_type = oper_type

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
            self.vm_list = self.vm_list[exceed_len:exceed_len + vm_len - self.cnt]

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

    def select_member(self):
        # select index of lag member to put down
        if self.tot_memb_cnt != 0:
            self.memb_index = datetime.datetime.now().day % self.tot_memb_cnt

    def select_vlan_ports(self):
        self.if_port = sorted(self.vlan_if_port, key=lambda tup: tup[0])
        vlan_len = len(self.if_port)
        vlan_index = datetime.datetime.now().day % vlan_len if vlan_len > 0 else 0
        exceed_len = vlan_index + self.cnt - vlan_len
        if exceed_len <= 0:
            self.down_vlan_info.extend(self.if_port[vlan_index:vlan_index+self.cnt])
            self.if_port = self.if_port[0:vlan_index] + self.if_port[vlan_index+self.cnt:]
        else:
            self.down_vlan_info.extend(self.if_port[vlan_index:])
            self.down_vlan_info.extend(self.if_port[0:exceed_len])
            self.if_port = self.if_port[exceed_len:exceed_len + vlan_len - self.cnt]

    def down_vlan_ports(self):
        # extract the selected vlan ports and mark them down
        for item in self.down_vlan_info:
            self.vlan_ports = [port for port in self.vlan_ports if port != item[1]]
            for vlan in self.ports_per_vlan:
                self.ports_per_vlan[vlan].remove(item[1])

    def setup(self):
        self.select_vm()
        self.get_neigh_name()
        self.vm_connect()
        # bring down the VM PTF ports only for preboot sad oper
        if 'routing' not in self.oper_type:
            self.down_neigh_port()

        # decide if its all member down or few members down for lag member oper type
        if 'member' in self.oper_type:
            self.tot_memb_cnt = len(self.vm_dut_map[self.neigh_names.values()[0]]['dut_ports'])
            if self.memb_cnt == 0:
                self.memb_cnt = self.tot_memb_cnt
            if self.tot_memb_cnt != self.memb_cnt:
                self.select_member()

        for vm in self.vm_handles:
            self.neigh_bgps[vm], self.dut_bgps[vm] = self.vm_handles[vm].get_bgp_info()
            self.fails[vm] = set()
            self.log.append('Neighbor AS: %s' % self.neigh_bgps[vm]['asn'])
            self.log.append('BGP v4 neighbor: %s' % self.neigh_bgps[vm]['v4'])
            self.log.append('BGP v6 neighbor: %s' % self.neigh_bgps[vm]['v6'])
            self.log.append('DUT BGP v4: %s' % self.dut_bgps[vm]['v4'])
            self.log.append('DUT BGP v6: %s' % self.dut_bgps[vm]['v6'])

    def retreive_test_info(self):
        return self.vm_list, self.portchannel_ports, self.neigh_vms, self.vlan_ports, self.ports_per_vlan

    def retreive_logs(self):
        return self.log, self.fails


class SadOper(SadPath):
    def __init__(self, oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, vlan_ports, ports_per_vlan):
        super(SadOper, self).__init__(oper_type, vm_list, portchannel_ports, vm_dut_map, test_args, vlan_ports, ports_per_vlan)
        self.dut_needed = dict()
        self.lag_members_down = dict()
        self.neigh_lag_members_down = dict()
        self.neigh_lag_state = None
        self.po_neigh_map = dict()
        self.msg_prefix = ['Postboot', 'Preboot']
        self.memb_str = 'member' if 'member' in self.oper_type else ''

    def populate_bgp_state(self):
        [self.dut_needed.setdefault(vm, self.dut_bgps[vm]) for vm in self.neigh_vms]
        if self.oper_type == 'neigh_bgp_down':
            self.neigh_bgps['changed_state'] = 'down'
            self.dut_bgps['changed_state'] = 'Active'
            [self.dut_needed.update({vm:None}) for vm in self.neigh_vms]
        elif self.oper_type == 'dut_bgp_down':
            self.neigh_bgps['changed_state'] = 'Active,OpenSent'
            self.dut_bgps['changed_state'] = 'Idle'
        elif 'neigh_lag' in self.oper_type:
            # on the DUT side, bgp states are different pre and post boot. hence passing multiple values
            self.neigh_bgps['changed_state'] = 'Idle'
            self.dut_bgps['changed_state'] = 'Connect,Active,Idle'
        elif 'dut_lag' in self.oper_type:
            self.neigh_bgps['changed_state'] = 'Idle'
            self.dut_bgps['changed_state'] = 'Active,Connect,Idle'

    def sad_setup(self, is_up=True):
        self.log = []

        if not is_up:
            if 'vlan' in self.oper_type:
                self.select_vlan_ports()
                self.down_vlan_ports()
            else:
                self.setup()
                self.populate_bgp_state()
                if 'lag' in self.oper_type:
                    self.populate_lag_state()

                elif 'routing' in self.oper_type:
                    if self.bp_ip and self.bp_ip6:
                        self.generate_ips()
                        self.build_route_config()
                        neigh_rt_v4_info, ret = self.get_bgp_route_cnt(is_up=is_up)
                        neigh_rt_v6_info, ret1 = self.get_bgp_route_cnt(is_up=is_up, v4=False)
                        if not ret and not ret1:
                            self.build_neigh_rt_map(neigh_rt_v4_info + neigh_rt_v6_info)

        if 'routing' in self.oper_type:
            if self.bp_ip:
                for vm in self.neigh_vms:
                    if not is_up:
                        # Need to add the routes which will be removed during the the boot
                        if 'routing_del' in self.oper_type:
                            self.log.append('Adding %d routes from VM %s' % (2 * self.ip_cnt, vm))
                            self.vm_handles[vm].change_bgp_route(self.route_cfg)
                    else:
                        self.log.append('Removing %d routes from VM %s' % (2 * self.ip_cnt, vm))
                        self.vm_handles[vm].change_bgp_route(self.no_route_cfg)

        elif 'bgp' in self.oper_type:
            self.log.append('BGP state change will be for %s' % ", ".join(self.neigh_vms))
            if self.oper_type == 'neigh_bgp_down':
                for vm in self.neigh_vms:
                    self.log.append('Changing state of AS %s to shut' % self.neigh_bgps[vm]['asn'])
                    self.vm_handles[vm].change_bgp_neigh_state(self.neigh_bgps[vm]['asn'], is_up=is_up)
            elif self.oper_type == 'dut_bgp_down':
                self.change_bgp_dut_state(is_up=is_up)
            time.sleep(30)

        elif 'lag' in self.oper_type:
            self.log.append('LAG %s state change will be for %s' % (self.memb_str, ", ".join(self.neigh_vms)))
            if 'neigh_lag' in self.oper_type:
                for vm in self.neigh_vms:

                    # populate entity to be brought down on neigh end (portchannel/portchannel members)
                    if 'member' in self.oper_type:
                        down_intfs = self.neigh_lag_members_down[self.neigh_names[vm]]
                    else:
                        down_intfs = [self.vm_dut_map[self.neigh_names[vm]]['neigh_portchannel']]

                    self.log.append('Changing state of LAG %s %s to shut' % (self.memb_str, ", ".join(down_intfs)))
                    self.vm_handles[vm].change_neigh_intfs_state(down_intfs, is_up=is_up)

            elif 'dut_lag' in self.oper_type:
                self.change_dut_lag_state(is_up=is_up)

            # wait for sometime for lag members state to sync
            time.sleep(120)

        elif 'vlan' in self.oper_type:
            self.change_vlan_port_state(is_up=is_up)

    def generate_ips(self):
        '''
        Generates the prefixes that will be added to the neighbor
        '''
        self.start_ip_pfx = '123.45.67.0/25'
        self.start_ip6_pfx = '20d0:a808:0:80::/120'
        self.ip_pfx_list = list(ipaddress.ip_network(u'%s' % self.start_ip_pfx).hosts())[0:self.ip_cnt]
        self.ip_pfx_list = [str(ip) for ip in self.ip_pfx_list]
        self.ip6_pfx_list = list(ipaddress.IPv6Network(u'%s' % self.start_ip6_pfx).hosts())[0:self.ip_cnt]
        self.ip6_pfx_list = [str(ip) for ip in self.ip6_pfx_list]

    def build_route_config(self):
        # cmds for adding routes
        self.route_cfg = []
        # cmds for deleting routes
        self.no_route_cfg = []
        for cnt, ip in enumerate(zip(self.ip_pfx_list, self.ip6_pfx_list)):
            # add route cfg
            self.route_cfg.append('ip route %s/32 %s' % (ip[0], self.bp_ip))
            self.route_cfg.append('ipv6 route %s/128 %s' % (ip[1], self.bp_ip6))
            # remove route cfg
            self.no_route_cfg.append('no ip route %s/32 %s' % (ip[0], self.bp_ip))
            self.no_route_cfg.append('no ipv6 route %s/128 %s' % (ip[1], self.bp_ip6))
        self.route_cfg.append('router bgp %s' % self.neigh_bgps[self.neigh_vms[-1]]['asn'])
        self.route_cfg.append('redistribute static')
        self.route_cfg.append('exit')
        self.no_route_cfg.append('router bgp %s' % self.neigh_bgps[self.neigh_vms[-1]]['asn'])
        self.no_route_cfg.append('redistribute static route-map PREPENDAS')
        self.no_route_cfg.append('exit')

    def get_bgp_route_cnt(self, is_up=True, v4=True):
        # extract the neigh ip and current number of routes
        if v4:
            cmd = 'show ip bgp summary | sed \'1,/Neighbor/d;/^$/,$d;/^-/d\' | sed \'s/\s\s*/ /g\' | cut -d\' \' -f 1,10'
        else:
            cmd = 'show ipv6 bgp summary | sed \'1,/Neighbor/d;/^$/,$d;/^-/d\' | sed \'s/\s\s*/ /g\' | cut -d\' \' -f 1,10'

        stdout, stderr, return_code = self.dut_connection.execCommand(cmd)
        if return_code != 0:
            self.fails['dut'].add('%s: Failed to retreive BGP route info from DUT' % self.msg_prefix[1 - is_up])
            self.fails['dut'].add('%s: Return code: %d' % (self.msg_prefix[1 - is_up], return_code))
            self.fails['dut'].add('%s: Stderr: %s' % (self.msg_prefix[1 - is_up], stderr))
        return stdout, return_code

    def build_neigh_rt_map(self, neigh_rt_info):
        # construct neigh to route cnt map
        self.neigh_rt_map = dict()
        for line in neigh_rt_info:
            key, value = line.strip().split(' ')
            self.neigh_rt_map.update({key:value})

    def verify_route_cnt(self, rt_incr, is_up=True, v4=True):
        neigh_rt_info, ret = self.get_bgp_route_cnt(is_up=is_up, v4=v4)
        if not ret:
            for line in neigh_rt_info:
                neigh_ip, rt_cnt = line.strip().split(' ')
                exp_cnt = int(self.neigh_rt_map[neigh_ip]) + rt_incr
                if int(rt_cnt) != exp_cnt:
                    self.fails['dut'].add('%s: Route cnt incorrect for neighbor %s Expected: %d Obtained: %d' % (self.msg_prefix[is_up], neigh_ip, exp_cnt, int(rt_cnt)))
                else:
                    self.log.append('Route cnt as expected for neighbor %s: %d' % (neigh_ip, exp_cnt))

    def verify_route_add(self, pre_check=True, inboot=True):
        self.log = []
        rt_incr = 0
        if (pre_check and 'routing_del' in self.oper_type) or (inboot and 'routing_add' in self.oper_type):
            rt_incr = self.ip_cnt
        # verify ipv4 and ipv6 route cnts
        self.verify_route_cnt(rt_incr, is_up=pre_check)
        self.verify_route_cnt(rt_incr, is_up=pre_check, v4=False)

    def modify_routes(self):
        self.log = []
        if self.bp_ip:
            for vm in self.neigh_vms:
                if 'routing_add' in self.oper_type:
                    self.log.append('Adding %d routes from VM %s' % (2 * self.ip_cnt, vm))
                    self.vm_handles[vm].change_bgp_route(self.route_cfg)
                else:
                    self.log.append('Removing %d routes from VM %s' % (2 * self.ip_cnt, vm))
                    self.vm_handles[vm].change_bgp_route(self.no_route_cfg)

    def change_vlan_port_state(self, is_up=True):
        state = ['shutdown', 'startup']

        for intf, port in self.down_vlan_info:
            if not re.match('Ethernet\d+', intf): continue
            self.log.append('Changing state of %s from DUT side to %s' % (intf, state[is_up]))
            stdout, stderr, return_code = self.dut_connection.execCommand('sudo config interface %s %s' % (state[is_up], intf))
            if return_code != 0:
                self.fails['dut'].add('%s: State change not successful from DUT side for %s' % (self.msg_prefix[1 - is_up], intf))
                self.fails['dut'].add('%s: Return code: %d' % (self.msg_prefix[1 - is_up], return_code))
                self.fails['dut'].add('%s: Stderr: %s' % (self.msg_prefix[1 - is_up], stderr))
            else:
                self.log.append('State change successful on DUT for %s' % intf)

    def verify_vlan_port_state(self, state='down', pre_check=True):
        self.log = []
        # pattern match "Ethernet252  177,178,179,180      40G   9100  Ethernet64/1  routed    down     down  QSFP28         off"
        # extract the admin status
        pat = re.compile('(\S+\s+){7}%s' % state)
        for intf, port in self.down_vlan_info:
            stdout, stderr, return_code = self.dut_connection.execCommand('show interfaces status %s' % intf)
            if return_code == 0:
                for line in stdout:
                    if intf in line:
                        is_match = pat.match(line.strip())
                        if is_match:
                            self.log.append('Interface state is down as expected on the DUT for %s' % intf)
                            self.log.append('Pattern check: %s' % line)
                            break

                        else:
                            self.fails['dut'].add('%s: Interface state is not down on the DUT for %s' % (self.msg_prefix[pre_check], intf))
                            self.fails['dut'].add('%s: Obtained: %s' % (self.msg_prefix[pre_check], line))
            else:
                self.fails['dut'].add('%s: Retreiving interface %s info from DUT side failed' % (self.msg_prefix[pre_check], intf))
                self.fails['dut'].add('%s: Return code: %d' % (self.msg_prefix[pre_check], return_code))
                self.fails['dut'].add('%s: Stderr: %s' % (self.msg_prefix[pre_check], stderr))

    def change_bgp_dut_state(self, is_up=True):
        state = ['shutdown', 'startup']
        for vm in self.neigh_vms:
            for key in self.neigh_bgps[vm].keys():
                if key not in ['v4', 'v6']:
                    continue

                self.log.append('Changing state of BGP peer %s from DUT side to %s' % (self.neigh_bgps[vm][key], state[is_up]))
                stdout, stderr, return_code = self.dut_connection.execCommand('sudo config bgp %s neighbor %s' % (state[is_up], self.neigh_bgps[vm][key]))
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
                if key == 'v4':
                    cmd = "show ip bgp neighbors"
                else:
                    cmd = "show ipv6 bgp neighbors"
                stdout, stderr, return_code = self.dut_connection.execCommand(cmd+' %s' % self.neigh_bgps[vm][key])
                if return_code == 0:
                    for line in stdout:
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

    def populate_lag_member_down(self, neigh_name):
        po_name = self.vm_dut_map[neigh_name]['dut_portchannel']
        # build DUT portchannel to down members mapping and neigh name to down members mapping
        # if only single member is down, extract the member and convert it into list otherwise assign the list directly
        if self.tot_memb_cnt != self.memb_cnt:
            self.lag_members_down[po_name] = [self.vm_dut_map[neigh_name]['dut_ports'][self.memb_index]]
            self.neigh_lag_members_down[neigh_name] = [self.vm_dut_map[neigh_name]['neigh_ports'][self.memb_index]]
        else:
            self.lag_members_down[po_name] = self.vm_dut_map[neigh_name]['dut_ports']
            self.neigh_lag_members_down[neigh_name] = self.vm_dut_map[neigh_name]['neigh_ports']

    def populate_lag_state(self):
        if 'neigh_lag' in self.oper_type:
            self.neigh_lag_state = 'disabled,notconnect'
        elif 'dut_lag' in self.oper_type:
            self.neigh_lag_state = 'notconnect'

        for neigh_name in self.neigh_names.values():
            self.populate_lag_member_down(neigh_name)

    def change_dut_lag_state(self, is_up=True):
        state = ['shutdown', 'startup']
        for neigh_name in self.neigh_names.values():
            dut_portchannel = self.vm_dut_map[neigh_name]['dut_portchannel']

            # populate the entity that needs to be brought down (portchannel or portchannel member)
            if 'member' in self.oper_type:
                down_intfs = self.lag_members_down[dut_portchannel]
            else:
                down_intfs = [dut_portchannel]

            for intf in down_intfs:
                if not re.match('(PortChannel|Ethernet)\d+', intf): continue
                self.log.append('Changing state of %s from DUT side to %s' % (intf, state[is_up]))
                stdout, stderr, return_code = self.dut_connection.execCommand('sudo config interface %s %s' % (state[is_up], intf))
                if return_code != 0:
                    self.fails['dut'].add('%s: State change not successful from DUT side for %s' % (self.msg_prefix[1 - is_up], intf))
                    self.fails['dut'].add('%s: Return code: %d' % (self.msg_prefix[1 - is_up], return_code))
                    self.fails['dut'].add('%s: Stderr: %s' % (self.msg_prefix[1 - is_up], stderr))
                else:
                    self.log.append('State change successful on DUT for %s' % intf)

    def verify_dut_lag_member_state(self, match, pre_check=True):
        success = True
        po_name = match.group(1)
        lag_memb_output = match.group(2)
        neigh_name = self.po_neigh_map[po_name]
        for member in self.vm_dut_map[neigh_name]['dut_ports']:
            # default state for the lag member
            search_str = '%s(S)' % member

            if po_name in self.lag_members_down:
                 if member in self.lag_members_down[po_name]:
                     search_str = '%s(D)' % member
                 # single member case. state of non down member of the down portchannel
                 elif self.tot_memb_cnt != self.memb_cnt:
                     search_str = '%s(S*)' % member

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

        stdout, stderr, return_code = self.dut_connection.execCommand('show interfaces portchannel')
        if return_code == 0:
            for line in stdout:
                for po_name in po_list:
                    if po_name in line:
                        is_match = pat.match(line)
                        if is_match and self.verify_dut_lag_member_state(is_match, pre_check=pre_check):
                            self.log.append('Lag state is down as expected on the DUT for %s' % po_name)
                            self.log.append('Pattern check: %s' % line)
                        else:
                            self.fails['dut'].add('%s: Lag state is not down on the DUT for %s' % (self.msg_prefix[pre_check], po_name))
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
