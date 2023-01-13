#!/usr/bin/python

import re
from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
module:  isis_facts
version_added:  "1.0"
short_description: Retrieve ISIS information from FRRouting
description:
    - Retrieve BGP routing information from FRRouting, using the VTYSH command line
    - This is the first stage. If we need more info in the future, will continue working on this module.
      Currently supported parsing commands:
        * show isis neighbor detail
        * show isis database
        * show isis route
        * show isis hostname
    - Retrieved facts will be inserted into the 'isis_facts'
'''

EXAMPLES = '''
- name: Get ISIS information
  isis_facts:
'''

RETURN = '''
    return: ansible_facts
        - ansible_facts.isis_facts:
          "isis_facts": {
                "database": {
                        "test": {
                            "vlab-03.00-00": {
                                "chksum": "0x756a     ",
                                "holdtime": "681",
                                "local": false,
                                "pdulen": "155   ",
                                "seqnum": "0x0000008e  "
                            }
                        }
                },
                "hostname": {
                    "1002.5000.0105": "vlab-03"
                },
                "neighbors": {
                    "test": {
                        "vlab-03": {
                            "expires": 28,
                            "interface": "PortChannel1",
                            "level": "2",
                            "state": "Up"
                        }
                    }
                },
                "route": {
                    "test": {
                        "ipv4": {
                            "200.1.0.30/32": {
                                "interface": "PortChannel1",
                                "metric": 30,
                                "nexthop": "10.0.1.57"
                            }
                        },
                        "ipv6": {
                            "2064:100::1d/128": {
                                "interface": "PortChannel101",
                                "metric": 20,
                                "nexthop": "fe80::10ee:deff:fe10:d1"
                            },
                        }
                    }
                }
            }
'''

SAMPLE_COMMAND_DATA = '''
* vtysh -c "show ip bgp 192.168.10.1"
   Area test:
    vlab-03
        Interface: PortChannel1, Level: 2, State: Up, Expires in 29s
        Adjacency flaps: 1, Last: 1d9h22m9s ago
        Circuit type: L2, Speaks: IPv4, IPv6
        SNPA: 2020.2020.2020
        Area Address(es):
        49.0002
        IPv4 Address(es):
        10.0.1.57
        IPv6 Address(es):
        fe80::5054:ff:fe04:63fd
        Global IPv6 Address(es):
        fc00:1::71
    Area 1:

*   vtysh -c "show isis database"
    Area test:
    IS-IS Level-2 link-state database:
    LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL
    ARISTA02T1.00-00          336   0x000000a6  0x590f     571    0/0/0
    vlab-01.00-00        *    173   0x00000091  0xa3e3    1115    0/0/0
    vlab-03.00-00             155   0x00000091  0x6f6d     882    0/0/0
        3 LSPs

*   vtysh -c "show isis route"
    Area test:
    IS-IS L2 IPv4 routing table:

    Prefix         Metric    Interface       Nexthop    Label(s)
    --------------------------------------------------------------
    1.1.1.0/30     20        PortChannel101  10.0.0.57  -
    10.0.0.56/31   20        PortChannel101  10.0.0.57  -


    IS-IS L2 IPv6 routing table:

    Prefix                                       Metric    Interface       Nexthop                  Label(s)
    ----------------------------------------------------------------------------------------------------------
    2064:100::1d/128                             20        PortChannel101  fe80::10ee:deff:fe10:d1  -
    2064:100::1e/128                             16777235  PortChannel1    fe80::5054:ff:fe04:63fd  -
    fc00:2:3::30/126                             30        PortChannel1    fe80::5054:ff:fe04:63fd  -

    Area 1:

*   vtysh -c "show isis hostname"
    vrf     : default
    Level  System ID      Dynamic Hostname
    2      1002.5000.0052 ARISTA02T1
    2      1002.5000.0105 vlab-03
        * 1002.5000.0100 vlab-01
'''


class IsisModule(object):
    '''
        parsing ISIS facts information
    '''
    def __init__(self, module, vty_cmd):
        self.facts = defaultdict(dict)
        self.module = module
        self.vty_cmd = vty_cmd
        return

    def collect_data(self, command_str):
        """
            Collect isis information by reading output of 'vtysh' command line tool
        """
        docker_cmd = '{} "show isis {}" '.format(self.vty_cmd, command_str)
        try:
            rc, self.out, err = self.module.run_command(docker_cmd, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(msg=str(e))

        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, self.out, err))
        return

    def _parse_areas(self, lines, callback):
        regex_area = re.compile(r'Area (.*):')
        areas = {}
        try:
            area = ''
            for line in lines:
                if regex_area.match(line):
                    area = regex_area.match(line).group(1)
                    areas[area] = []
                elif area:
                    areas[area].append(line)
            for key, item in areas.items():
                areas[key] = callback(item)
        except Exception as e:
            self.module.fail_json(msg=str(e))
        return areas

    def _parse_neighbors_per_area(self, nbrs_items):
        regex_nbr = re.compile(r'\s{1}(\S+)')
        regex_nbr_state = re.compile(r'\s{4}Interface: (\w+), Level: ([12]), State: ([a-zA-Z]+), Expires in (\d+)s')
        neighbors = {}
        nbr = ''
        for line in nbrs_items:
            if regex_nbr.match(line):
                nbr = regex_nbr.match(line).group(1).strip()
                neighbors[nbr] = {}
            elif regex_nbr_state.match(line) and nbr:
                neighbors[nbr]['interface'] = regex_nbr_state.match(line).group(1)
                neighbors[nbr]['level'] = regex_nbr_state.match(line).group(2)
                neighbors[nbr]['state'] = regex_nbr_state.match(line).group(3)
                neighbors[nbr]['expires'] = int(regex_nbr_state.match(line).group(4))
        return neighbors

    def _parse_db_per_area(self, db_items):
        regex_lsp = \
            re.compile(r'(\S{1,14}.[0-9]{2}-[0-9]{2}\b)(\s+\*?\s+)(\d+\s+)(0x[0-9a-f]{8}\s+)(0x[0-9a-f]{4}\s+)(\d+)')
        datebase = {}
        for line in db_items:
            match = regex_lsp.match(line)
            if match:
                datebase[match.group(1)] = {
                    'pdulen': match.group(3),
                    'seqnum': match.group(4),
                    'chksum': match.group(5),
                    'holdtime': match.group(6),
                    'local': True if match.group(2).strip().rstrip() == '*' else False,
                    }
        return datebase

    def _parse_route_per_area(self, route_items):
        routes = {'ipv4': {}, 'ipv6': {}}
        reg = r'(\s{1}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)(\s+\d+\s+)(\S+\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        regex_v4route = re.compile(reg)
        regex_v6route = re.compile(r'(\s{1}[0-9a-fA-F:]+\/\d+)(\s+\d+\s+)(\S+\s+)([0-9a-fA-F:\-]+)')
        for line in [item for item in route_items if item.strip()]:
            match = regex_v4route.match(line)
            if match:
                routes['ipv4'][match.group(1).strip()] = {
                        'metric': int(match.group(2).strip().rstrip()),
                        'interface': match.group(3).strip(),
                        'nexthop': match.group(4)
                    }
                continue
            match = regex_v6route.match(line)
            if match:
                routes['ipv6'][match.group(1).strip()] = {
                        'metric': int(match.group(2).strip().rstrip()),
                        'interface': match.group(3).strip(),
                        'nexthop': match.group(4)
                    }
                continue
        return routes

    def parse_neighbors(self):
        self.facts['neighbors'] = self._parse_areas(self.out.split('\n'), self._parse_neighbors_per_area)
        return

    def parse_database(self):
        self.facts['database'] = self._parse_areas(self.out.split('\n'), self._parse_db_per_area)
        return

    def parse_route(self):
        self.facts['route'] = self._parse_areas(self.out.split('\n'), self._parse_route_per_area)
        return

    def parse_hostname(self):
        regex_hostname = re.compile(r'(\s*[2\*]\s+)(\d{4}.\d{4}.\d{4}\s+)(\S+)')
        split_output = self.out.split('\n')
        hostnames = {}
        for line in split_output:
            match = regex_hostname.match(line)
            if match:
                hostnames[match.group(2).rstrip()] = match.group(3)
        self.facts['hostname'] = hostnames
        return

    def run(self):
        self.collect_data("neighbor detail")
        self.parse_neighbors()

        self.collect_data("database")
        self.parse_database()

        self.collect_data("route")
        self.parse_route()

        self.collect_data("hostname")
        self.parse_hostname()

        self.module.exit_json(ansible_facts={'isis_facts': self.facts})


def main():
    module = AnsibleModule(argument_spec=dict(), supports_check_mode=False)

    vtysh_cmd = "docker exec -i bgp vtysh -c"
    try:
        # Currently, only support FRRouting
        command = "{} 'show version'".format(vtysh_cmd)
        rc, out, err = module.run_command(command)
        if rc != 0:
            err_message = "command %s failed rc=%d, out=%s, err=%s" % (command, rc, out, err)
            module.fail_json(msg=err_message)
            return
        if "FRRouting" not in out:
            module.fail_json(msg="Only support FRRouting command.")
            return

        isis = IsisModule(module, vtysh_cmd)
        isis.run()
    except Exception as e:
        fail_msg = "cannot correctly parse ISIS facts!\n"
        fail_msg += str(e)
        module.fail_json(msg=fail_msg)
    return


if __name__ == "__main__":
    main()
