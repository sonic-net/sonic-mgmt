#!/usr/bin/python

DOCUMENTATION = '''
module:  bgp_route
version_added:  "2.0"
short_description: Retrieve BGP routing information from Quagga
description:
    - Retrieve BGP routing information from Quagga, using the VTYSH command line
    - module argument is the property of "SHOW IP BGP"
    - Current supported parsing commands:
        * show ip bgp 100.0.0.1  ### show ip bgp prefix info
        * show ip bgp neighbor 10.0.0.1 adv   ### show ip bgp neighbor address advertised routes
    - Retrieved facts will be inserted into the 'bgp_rt'  or 'bgp_rt_neiadv'
'''

EXAMPLES = '''
- name: Get BGP route information
  bgp_route: show_cmd='100.0.0.1'

- name: Get BGP route information
  bgp_route: show_cmd='neighbor 10.0.0.1 advert'
'''

SAMPLE_COMMAND_DATA = '''
vtysh -c "show ip bgp 192.168.10.1"
 BGP routing table entry for 192.168.10.1/32
 Paths: (8 available, best #8, table Default-IP-Routing-Table)
 Advertised to non peer-group peers:
   10.0.0.1 10.0.0.5 10.0.0.13 10.0.0.17 10.0.0.21 10.0.0.25 10.0.0.29 10.0.0.51 10.0.0.53 10.0.0.55 10.0.0.57 10.0.0.59 10.0.0.61 10.0.0.63
   65200 62011 65501
   10.0.0.17 from 10.0.0.17 (100.1.0.9)
      Origin incomplete, localpref 100, valid, external, multipath
      Last update: Fri Sep 22 06:33:44 2017

   65200 62011 65501
   10.0.0.25 from 10.0.0.25 (100.1.0.13)
      Origin incomplete, localpref 100, valid, external, multipath
      Last update: Fri Sep 22 06:33:42 2017

   65200 62011 65501
   10.0.0.13 from 10.0.0.13 (100.1.0.7)
      Origin incomplete, localpref 100, valid, external, multipath
      Last update: Fri Sep 22 06:33:40 2017

   65200 62011 65501
   10.0.0.1 from 10.0.0.1 (100.1.0.1)
      Origin incomplete, localpref 100, valid, external, multipath
      Last update: Fri Sep 22 06:33:39 2017

    65200 62011 65501
    10.0.0.29 from 10.0.0.29 (100.1.0.15)
       Origin incomplete, localpref 100, valid, external, multipath
       Last update: Fri Sep 22 06:33:39 2017

    65200 62011 65501
    10.0.0.5 from 10.0.0.5 (100.1.0.3)
       Origin incomplete, localpref 100, valid, external, multipath
       Last update: Fri Sep 22 06:33:39 2017

    65200 62011 65501
    10.0.0.21 from 10.0.0.21 (100.1.0.11)
       Origin incomplete, localpref 100, valid, external, multipath
       Last update: Fri Sep 22 06:33:37 2017

    65200 62011 65501
    10.0.0.9 from 10.0.0.9 (100.1.0.5)
       Origin incomplete, localpref 100, valid, external, multipath, best
       Last update: Fri Sep 22 06:33:37 2017



 vtysh -c "show ip bgp neighbor 10.0.0.35 adv" 

  BGP table version is 0, local router ID is 10.1.0.32
  Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
              i internal, r RIB-failure, S Stale, R Removed
  Origin codes: i - IGP, e - EGP, ? - incomplete

      Network          Next Hop            Metric LocPrf Weight Path
   *> 10.1.0.32/32     10.0.0.34                 0         32768 i
   *> 100.1.0.3/32     10.0.0.34                              0 65200 i
   *> 100.1.0.5/32     10.0.0.34                              0 65200 i
   *> 100.1.0.7/32     10.0.0.34                              0 65200 i
   *> 100.1.0.9/32     10.0.0.34                              0 65200 i
   *> 100.1.0.11/32    10.0.0.34                              0 65200 i
   *> 100.1.0.13/32    10.0.0.34                              0 65200 i
   *> 100.1.0.15/32    10.0.0.34                              0 65200 i
   *> 100.1.0.17/32    10.0.0.34                              0 64001 i
   *> 192.168.10.97/32 10.0.0.34                              0 65200 62011 65507 ?
   *> 192.168.10.112/32
                       10.0.0.34                              0 65200 62011 65508 ?
   *> 192.168.10.113/32
                       10.0.0.34                              0 65200 62011 65508 ?
   *> 192.168.10.128/32
                       10.0.0.34                              0 65200 62011 65509 ?
   *> 192.168.10.129/32
                       10.0.0.34                              0 65200 62011 65509 ?
   *> 192.168.10.144/32
                       10.0.0.34                              0 65200 62011 65510 ?

'''


class BgpRoutes(object):
    '''
        parsing bgp routing information
    '''
    def __init__(self):
        self.facts = defaultdict(dict)
        return

    def get_facts(self):
        return self.facts

    def parse_bgp_rt_adv(self, cmd, cmd_result):
        '''
        parse BGP routing facts of neighbor advertised routes
        '''
        regex_neighbor = re.compile('nei.*\s([0-9a-fA-F.:]+)\s.*')
        regix_iprange = re.compile('[0-9a-fA-F.:]+\/\d+')
        if regex_neighbor.match(cmd):
            neighbor = regex_neighbor.match(cmd).group(1)
        else:
            raise Exception('cannot find neighbor in "show ip  bgp ' + cmd + '"')
        self.facts['bgp_rt_neiadv']['neighbor'] = neighbor
        ### so far parsing by fixed length table
        ### will improve this if find better way to parse it
        header_position = [0, 3, 20, 40, 47, 54, 61]
        header = 'Network          Next Hop            Metric LocPrf Weight Path'
        result_lines = cmd_result.split('\n')
        table_start = False
        while len(result_lines) != 0:
            line = result_lines.pop(0)
            if not table_start:
                if header in line:
                    table_start = True
                    continue
            else:
                if not re.match('^\*', line):
                    continue
                entry = {}
                if len(line) > 30:   ## route entry in one line
                    prefix = line[header_position[1]:header_position[2]].strip()
                else:    ### route entry in two lines
                    prefix = line[header_position[1]:30].strip()
                    line = result_lines.pop(0)
                entry['next_hop'] = line[header_position[2]:header_position[3]].strip()
                paths = line[header_position[6]:].strip()
                entry['paths'] = re.findall('[0-9]+', paths)
                self.facts['bgp_rt_neiadv'][prefix] = entry


    def parse_bgp_rt_prefix(self, prefix, cmd_result):
        '''
        parse BGP facts for specific prefix
        '''
        regex_prefix_header = re.compile('BGP routing table entry for ')
        regex_prefix_avail_paths = re.compile('Paths:\s+\((\d+)\s+available')
        prefix_temp_line1 = 'Advertised to non peer-group peers:'
        regex_prefix_prop2 = re.compile('^[0-9a-fA-F.:\s]+$')
        regex_prefix_paths = re.compile('^[0-9\s]+$')
        regex_prefix_path_line1 = re.compile('.* from .*\([0-9a-fA-F.:]+\)')
        regex_prefix_path_line2 = re.compile('\s+Origin')
        regex_prefix_path_line3 = re.compile('\s+Last update:')
        cmd_err1 = 'Unknown command'
        cmd_err2 = 'Network not in table'
        self.facts['bgp_rt'] = defaultdict(dict)
        #self.facts[prefix]['line'] = []
        if cmd_err1 in cmd_result or cmd_err2 in cmd_result:
            self.facts['bgp_rt'][prefix]['found'] = False
            return
        result_lines = cmd_result.split('\n')
        ## search_state = ['header', 'path_prop', 'prefix_prop1', 'prefix_prop2', 'paths', 'path_l1', 'path_l2', 'path_l2', 'path_l3', 'err' ]
        state = 'header'
        self.facts['bgp_rt'][prefix]['paths'] = []
        while len(result_lines) != 0:
            line = result_lines.pop(0)
            #self.facts[prefix]['line'].append(line)
            if line == '':
                continue
            if state == 'header':
                if regex_prefix_header.match(line) and (prefix not in line):
                    self.facts['bgp_rt'][prefix]['found'] = False
                    return
                if regex_prefix_header.match(line) and prefix in line:
                    self.facts['bgp_rt'][prefix]['found'] = True
                    state = 'path_prop'
                else:
                    state = 'err'
            elif state == 'path_prop':
                find_path = regex_prefix_avail_paths.match(line)
                if find_path:
                    path_num = find_path.group(1)
                    self.facts['bgp_rt'][prefix]['path_num'] = path_num
                    state = 'path_prefix_prop1'
                else:
                    state = 'err'
            elif  state == 'path_prefix_prop1':
                state = 'path_prefix_prop2'
            elif  state == 'path_prefix_prop2':
                if regex_prefix_prop2.match(line):
                    state = 'paths'
                else:
                    state = 'err'
            elif state == 'paths':
                if regex_prefix_paths.match(line):
                    path = line.strip()
                    self.facts['bgp_rt'][prefix]['paths'].append(path)
                    state = 'path_l1'
                else:
                    state = 'err'
            elif state == 'path_l1':
                if regex_prefix_path_line1.match(line):
                    state = 'path_l2'
                else:
                    state = 'err'
            elif state == 'path_l2':
                if regex_prefix_path_line2.match(line):
                    state = 'path_l3'
                else:
                    state = 'err'
            elif state == 'path_l3':
                if regex_prefix_path_line3.match(line):
                    state = 'paths'
                else:
                    state = 'err'
            elif state == 'err':
                raise Exception("cannot parse bgp prefix info correctly" + str(self.facts))


def collect_data(module, command=None):
   """
       Collect bgp information by reading output of 'vtysh' command line tool
   """
   rc, out, err = module.run_command('vtysh -c "show ip bgp ' + command + '"',
                                        executable='/bin/bash', use_unsafe_shell=True)
   return (rc, out, err)


def main():
    module = AnsibleModule(
            argument_spec=dict(
               show_cmd=dict(required=False, default=''),
                ),
            supports_check_mode=False
            )
    m_args = module.params
    show_cmd = m_args['show_cmd']
    try:
        bgproute = BgpRoutes()
        regex_ip = re.compile('[0-9a-fA-F.:]+')
        if show_cmd == '':
            raise Exception("parsing 'show ip bgp' full prefix table not implemented yet")
        if show_cmd and 'nei' in show_cmd:
            if 'adv' not in show_cmd :
                raise Exception('No support parsing this command " show ip(v6) bgp %s " yet' % show_cmd)
            else:
                (rc, out, err) = collect_data(module, show_cmd)
                bgproute.parse_bgp_rt_adv(show_cmd, out)
        elif show_cmd and regex_ip.match(show_cmd):
            if netaddr.valid_ipv4 or netaddr.valid_ipv6:
                (rc, out, err) = collect_data(module, show_cmd)
                bgproute.parse_bgp_rt_prefix(show_cmd, out)
            else :
                raise Exception('No support of this command "show ip(v6) bgp %s " yet ' % show_cmd)
        results = bgproute.get_facts()
        module.exit_json(ansible_facts=results)
    except Exception as e:
        fail_msg = "cannot correctly parse BGP Routing facts! \n"
        fail_msg += str(e)
        module.fail_json(msg=fail_msg)
    return

from ansible.module_utils.basic import *
from collections  import defaultdict
import netaddr
if __name__ == "__main__":
    main()
