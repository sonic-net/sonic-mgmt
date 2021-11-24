#!/usr/bin/python

DOCUMENTATION = '''
module:  bgp_route
version_added:  "2.0"
short_description: Retrieve BGP routing information from Quagga
description:
    - Retrieve BGP routing information from Quagga, using the VTYSH command line
    - module argument is the property of "SHOW IP BGP"
    - This is not full implementation of all "show ip bgp" fact retrieving, there are many options for this command.
      This is the first stage. If we need more info in the future, will continue working on this module.
      Currently supported parsing commands:
        * show ip bgp 100.0.0.1  ### show ip bgp prefix info
        * show ip bgp neighbor 10.0.0.1 adv   ### show ip bgp neighbor nei_address advertised routes
    - Retrieved facts will be inserted into the 'bgp_route'  or 'bgp_route_neiadv'
Options:
    - option-name: prefix
      description: bgp prefix to be retrieved from show ip bgp
      required: False
      Default: None

    - option-name: neighbor
      description: restirct retrieving routing information from bgp neighbor
                   bgp neighbor address is expected to follow this option
      required: False
      Default: None

    - option-name: direction
      required: False (if neighbor is presented, then direction is required)
      description: to restict retrieving bgp neighbor advertise or received routes
      Choice:  [adv | rec]
'''

EXAMPLES = '''
- name: Get BGP route information
  bgp_route: prefix='100.0.0.1/28'

- name: Get neighbor BGP advertise route information
  bgp_route: neighbor='10.0.0.1' direction='adv'
'''

RETURN = '''
    return: ansible_facts
        - ansible_facts.bgp_route:  "show ip bgp prefix" result
          bgp_route:
            "10.0.100.0/26": {"found": true,
                              "path_num": "2",
                              "aspath": ["64001 64700", "64003 64700"]
                             }
        - ansible_facts.bgp_route_neiadv:
          "bgp_route_neiadv": {"192.10.0.0/24":
                                   {"next_hop": "10.0.0.20",
                                     "aspath": ["65200", "62101", "65516"],
                                     "origin": ?,
                                     "weight": 0
                                   },
                               "192.168.99.81/32":
                                   {"next_hop": "10.0.0.20",
                                    "aspath": ["65200", "62100", "65506"],
                                    "origin": i,
                                    "weight": 0
                                   }
                              }
'''

SAMPLE_COMMAND_DATA = '''
* vtysh -c "show ip bgp 192.168.10.1"
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


*  vtysh -c "show ip bgp neighbor 10.0.0.35 adv"

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


### TODO: Not fully tested ipv6 route entries parsing option, need continue working on ipv6 specific commands###
import json

class BgpRoutes(object):
    '''
        parsing bgp routing information
    '''
    def __init__(self, neighbor=None, direction=None, prefix=None):
        self.facts = defaultdict(dict)
        self.neighbor = neighbor
        self.direction = direction
        self.prefix = prefix
        return

    def get_facts(self):
        return self.facts

    def parse_bgp_route_adv_json(self, cmd_result):
        '''
        parse BGP routing facts of neighbor advertised routes in json format
        '''

        self.facts['bgp_route_neiadv']['neighbor'] = self.neighbor

        res = json.loads(cmd_result)

        for k, rt in res['advertisedRoutes'].items():
            entry = dict()
            entry['nexthop'] = rt['nextHop']
            entry['origin']  = rt['bgpOriginCode']
            entry['weigh']   = rt['weight']
            entry['aspath']  = rt['path'].split()
            self.facts['bgp_route_neiadv']["{}/{}".format(rt['addrPrefix'], rt['prefixLen'])] = entry

    def parse_bgp_route_adv(self, cmd_result):
        '''
        parse BGP routing facts of neighbor advertised routes
        '''
        self.facts['bgp_route_neiadv']['neighbor'] = self.neighbor
        ### so far parsing prefix, nexthop and aspath, origin and weight
        header = 'Metric LocPrf Weight Path'
        result_lines = cmd_result.split('\n')
        table_start = False
        re_aspath = re.compile('.*\s{2,}(\d+)\s((\d+\s)+)?([ie\?])$')
        while len(result_lines) != 0:
            line = result_lines.pop(0)
            if not table_start:
                if header in line:
                    table_start = True
                    continue
            else:
                ## only parse valid route entry, ignore if it's not marked as valid
                if not re.match('^\*', line):
                    continue
                entry = dict()
                fields = line.strip().split()
                prefix = fields[1]
                if len(fields) > 2:    ### route entry in one line
                    nexthop = fields[2]
                else:                  ### route entry in two lines
                    line = result_lines.pop(0)
                    nexthop = line.strip().split()[0]
                m = re_aspath.match(line)
                if m:
                    weight = m.group(1)
                    aspath = m.group(2)
                    origin = m.group(4)
                    if aspath:
                        entry['aspath'] = aspath.split()
                    else:
                        entry['aspath'] = []
                    entry['nexthop'] = nexthop
                    entry['origin'] = origin
                    entry['weight'] = weight
                self.facts['bgp_route_neiadv'][prefix] = entry


    def parse_bgp_route_prefix_json(self, cmd_result):
        """
        parse BGP facts for specific prefix in json format
        """

        prefix = self.prefix
        self.facts['bgp_route'] = defaultdict(dict)

        p = json.loads(cmd_result)

        if 'prefix' not in p:
            self.facts['bgp_route'][prefix]['found'] = False
            return

        self.facts['bgp_route'][prefix]['found'] = True
        self.facts['bgp_route'][prefix]['aspath'] = []
        self.facts['bgp_route'][prefix]['path_num'] = len(p['paths'])
        for path in p['paths']:
            self.facts['bgp_route'][prefix]['aspath'].append(path['aspath']['string'])

    def parse_bgp_route_prefix(self, cmd_result):
        '''
        parse BGP facts for specific prefix
        '''
        # BGP route preix line parsing state
        # search_state = [HEADER, PATH_PROPERTIES, PEER_GROUP_HEADER, PEER_GROUPS, PREFIX_PATHS, PREFIX_PATHS_FROM, PREFIX_PATH_ORIGIN, PREFIX_PATH_TIMESTAMP, ERR]
        HEADER  = 1
        PATH_PROPERTIES = 2
        PEER_GROUP_HEADER = 3
        PEER_GROUPS = 4
        PREFIX_PATHS = 5
        PREFIX_PATHS_FROM = 6
        PREFIX_PATH_ORIGIN = 7
        PREFIX_PATH_TIMESTAMP = 8
        ERR = 9
        # line content pattern
        prefix = self.prefix
        regex_prefix_header = re.compile('BGP routing table entry for ')
        regex_prefix_avail_paths = re.compile('Paths:\s+\((\d+)\s+available')
        prefix_peer_group_header = 'Advertised to non peer-group peers:'
        regex_prefix_peers = re.compile('^[0-9a-fA-F.:\s]+$')
        regex_prefix_paths = re.compile('^[0-9\s]+$|Local')
        regex_prefix_path_p1_from = re.compile('.* from .*\([0-9a-fA-F.:]+\)')
        regex_prefix_path_p2_origin = re.compile('\s+Origin')
        regex_prefix_path_p3_timestamp = re.compile('\s+Last update:')
        regex_prefix_path_p3_community = re.compile('\s+Community:')
        cmd_err1 = 'Unknown command'
        cmd_err2 = 'Network not in table'

        self.facts['bgp_route'] = defaultdict(dict)
        if cmd_err1 in cmd_result or cmd_err2 in cmd_result:
            self.facts['bgp_route'][prefix]['found'] = False
            return

        result_lines = cmd_result.split('\n')
        state = HEADER
        self.facts['bgp_route'][prefix]['aspath'] = []
        while len(result_lines) != 0:
            line = result_lines.pop(0)
            if line == '':
                continue
            if state == HEADER:
                if regex_prefix_header.match(line) and (prefix not in line):
                    self.facts['bgp_route'][prefix]['found'] = False
                    return
                if regex_prefix_header.match(line) and prefix in line:
                    self.facts['bgp_route'][prefix]['found'] = True
                    state = PATH_PROPERTIES
                else:
                    state = ERR
            elif state == PATH_PROPERTIES:
                find_path = regex_prefix_avail_paths.match(line)
                if find_path:
                    path_num = find_path.group(1)
                    self.facts['bgp_route'][prefix]['path_num'] = path_num
                    state = PEER_GROUP_HEADER
                else:
                    state = ERR
            elif  state == PEER_GROUP_HEADER:
                state = PEER_GROUPS
            elif  state == PEER_GROUPS:
                if regex_prefix_peers.match(line):
                    state = PREFIX_PATHS
                else:
                    state = ERR
            elif state == PREFIX_PATHS:
                if regex_prefix_paths.match(line):
                    path = line.strip()
                    self.facts['bgp_route'][prefix]['aspath'].append(path)
                    state = PREFIX_PATHS_FROM
                else:
                    state = ERR
            elif state == PREFIX_PATHS_FROM:
                if regex_prefix_path_p1_from.match(line):
                    state = PREFIX_PATH_ORIGIN
                else:
                    state = ERR
            elif state == PREFIX_PATH_ORIGIN:
                if regex_prefix_path_p2_origin.match(line):
                    state = PREFIX_PATH_TIMESTAMP
                else:
                    state = ERR
            elif state == PREFIX_PATH_TIMESTAMP:
                if regex_prefix_path_p3_timestamp.match(line):
                    state = PREFIX_PATHS
                elif regex_prefix_path_p3_community.match(line):
                    continue
                else:
                    state = ERR
            elif state == ERR:
                raise Exception("cannot parse bgp prefix info correctly " + str(state) + str(self.facts))


def main():
    module = AnsibleModule(
            argument_spec=dict(
                neighbor=dict(required=False, default=None),
                direction=dict(required=False, choices=['adv', 'rec']),
                prefix=dict(required=False, default=None)
                ),
            supports_check_mode=False
            )
    is_frr = False
    use_json = ""

    m_args = module.params
    neighbor = m_args['neighbor']
    direction = m_args['direction']
    prefix = m_args['prefix']
    regex_ip = re.compile('[0-9a-fA-F.:]+')
    regex_iprange = re.compile('[0-9a-fA-F.:]+\/\d+')
    regex_ipv4 = re.compile('[12][0-9]{0,2}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/?\d+?')
    if neighbor == None and direction == None and prefix == None:
        module.fail_json(msg="No support of parsing 'show ip bgp' full prefix table yet")
        return
    if neighbor and ((not netaddr.valid_ipv4(neighbor)) and (not netaddr.valid_ipv6(neighbor))):
        err_message = "Invalid neighbor address %s ??" % neighbor
        module.fail_json(msg=err_message)
        return
    if (neighbor and not direction) or (neighbor and 'adv' not in direction.lower()):
        err_message = 'No support of parsing this command " show ip(v6) bgp neighbor %s %s" yet' % (neighbor, direction)
        module.fail_json(msg=err_message)
        return
    try:
        bgproute = BgpRoutes(neighbor, direction, prefix)

        command = "docker exec -i bgp vtysh -c 'show version'"
        rc, out, err = module.run_command(command)
        if rc != 0:
            err_message = "command %s failed rc=%d, out=%s, err=%s" %(command, rc, out, err)
            module.fail_json(msg=err_message)
            return
        if "FRRouting" in out:
            is_frr = True
            use_json = "json"

        if prefix:
            if regex_ipv4.match(prefix):
                command = "docker exec -i bgp vtysh -c 'show ip bgp {} {}'".format(str(prefix), use_json)
            else:
                command = "docker exec -i bgp vtysh -c 'show ipv6 bgp {} {}'".format(str(prefix), use_json)
            rc, out, err = module.run_command(command)
            if rc != 0:
                err_message = "command %s failed rc=%d, out=%s, err=%s" %(command, rc, out, err)
                module.fail_json(msg=err_message)
                return
            if is_frr:
                bgproute.parse_bgp_route_prefix_json(out)
            else:
                bgproute.parse_bgp_route_prefix(out)

        elif neighbor:
            if netaddr.valid_ipv4(neighbor):
                command = "docker exec -i bgp vtysh -c 'show ip bgp neighbor {} {} {}'".format(str(neighbor), str(direction), use_json)
            else:
                command = "docker exec -i bgp vtysh -c 'show ipv6 bgp neighbor {] {} {}'".format(str(neighbor), str(direction), use_json)
            rc, out, err = module.run_command(command)
            if rc !=  0:
                err_message = "command %s failed rc=%d, out=%s, err=%s" %(command, rc, out, err)
                module.fail_json(msg=err_message)
                return
            if is_frr:
                bgproute.parse_bgp_route_adv_json(out)
            else:
                bgproute.parse_bgp_route_adv(out)

        results = bgproute.get_facts()
        module.exit_json(ansible_facts=results)
    except Exception as e:
        fail_msg = "cannot correctly parse BGP Routing facts!\n"
        fail_msg += str(e)
        module.fail_json(msg=fail_msg)
    return


from ansible.module_utils.basic import *
from collections  import defaultdict
import netaddr
if __name__ == "__main__":
    main()
