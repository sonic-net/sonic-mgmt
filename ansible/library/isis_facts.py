#!/usr/bin/python

import re
from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
module:  isis_facts
version_added:  "1.0"
short_description: Retrieve ISIS information from FRRouting
description:
    - Retrieve IS-IS routing information from FRRouting, using the VTYSH command line
    - This is the first stage. If we need more info in the future, will continue working on this module.
      Currently supported parsing commands:
        * show isis neighbor detail
        * show isis database
        * show isis route
        * show isis hostname
        * show isis summary
        * show isis spf-delay-ietf
        * show running-config isisd
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

    def collect_data(self, command_str):
        """
            Collect isis information by reading output of 'vtysh' command line tool
        """
        docker_cmd = '{} "show isis {}" '.format(self.vty_cmd, command_str)
        try:
            rc, self.out, err = self.module.run_command(
                docker_cmd, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(msg=str(e))

        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, self.out, err))

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
        regex_nbr_state = re.compile(
            r'\s{4}Interface: (\w+), Level: ([12]), State: ([a-zA-Z]+), Expires in (\d+)s')
        neighbors = {}
        nbr = ''
        for line in nbrs_items:
            if regex_nbr.match(line):
                nbr = regex_nbr.match(line).group(1).strip()
                neighbors[nbr] = {}
            elif regex_nbr_state.match(line) and nbr:
                neighbors[nbr]['interface'] = regex_nbr_state.match(
                    line).group(1)
                neighbors[nbr]['level'] = regex_nbr_state.match(line).group(2)
                neighbors[nbr]['state'] = regex_nbr_state.match(line).group(3)
                neighbors[nbr]['expires'] = int(
                    regex_nbr_state.match(line).group(4))
        return neighbors

    def _parse_db_per_area(self, db_items):
        regex_lsp = \
            re.compile(
                r'(\S{1,14}.\d{2}-\d{2}\b)(\s+\*?\s+)(\d+\s+)(0x.{8}\s+)(0x.{4}\s+)(\d+)\s+\d+/\d+/(\d+)')
        datebase = {}
        for line in db_items:
            match = regex_lsp.match(line)
            if match:
                datebase[match.group(1)] = {
                    'pdulen': match.group(3),
                    'seqnum': match.group(4),
                    'chksum': match.group(5),
                    'holdtime': match.group(6),
                    'overload': match.group(7),
                    'local': True if match.group(2).strip().rstrip() == '*' else False,
                }
        return datebase

    def _parse_db_detail_per_area(self, db_items):

        def _parse_db_detail_lsp(lsp_items):
            lsp_details = {'extend_reachability': [],
                           'ipv4_address': [],
                           'extend_ip_reachability': [],
                           'ipv6_reachability': []}
            regex_protos = re.compile(r'Protocols Supported: (\S+, \S*)')
            regex_area = re.compile(r'Area Address: (\d+\.\d+)')
            regex_te_routeid = re.compile(
                r'TE Router ID: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            regex_extend_reachability = \
                re.compile(
                    r'Extended Reachability: (\d{4}.\d{4}.\d{4}\.\d{2}) \(Metric: (\d+)\)')
            regex_ipv4_address = \
                re.compile(
                    r'IPv4 Interface Address: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            regex_extend_ip_reachability = \
                re.compile(
                    r'Extended IP Reachability:\s+(\S+)\s+\(Metric:\s+(\d+)\)')
            regex_ipv6_reachability = \
                re.compile(r'IPv6 Reachability: (\S+)\s+\(Metric:\s+(\d+)\)')

            for item in lsp_items:
                if regex_protos.match(item):
                    lsp_details['protocols'] = regex_protos.match(
                        item).group(1)
                elif regex_area.match(item):
                    lsp_details['area_address'] = regex_area.match(
                        item).group(1)
                elif regex_te_routeid.match(item):
                    lsp_details['te_routeid'] = regex_te_routeid.match(
                        item).group(1)
                elif regex_extend_reachability.match(item):
                    m = regex_extend_reachability.match(item)
                    lsp_details['extend_reachability'].append(
                        {m.group(1): m.group(2)})
                elif regex_ipv4_address.match(item):
                    lsp_details['ipv4_address'].append(
                        regex_ipv4_address.match(item).group(1))
                elif regex_extend_ip_reachability.match(item):
                    m = regex_extend_ip_reachability.match(item)
                    lsp_details['extend_ip_reachability'].append(
                        {m.group(1): m.group(2)})
                elif regex_ipv6_reachability.match(item):
                    m = regex_ipv6_reachability.match(item)
                    lsp_details['ipv6_reachability'].append(
                        {m.group(1): m.group(2)})

            return lsp_details

        regex_lsp = \
            re.compile(
                r'(\S{1,14}.\d{2}-\d{2}\b)(\s+\*?\s+)(\d+\s+)(0x.{8}\s+)(0x.{4}\s+)(\d+)\s+\d+/\d+/(\d+)')

        database = {}
        while len(db_items) > 0:
            line = db_items.pop(0).strip()
            match_res = regex_lsp.match(line)
            if match_res:
                lsp_id = match_res.group(1)
                lsp_items = []
                while len(db_items) > 0 and db_items[0].strip().rstrip():
                    lsp_items.append(db_items.pop(0).strip().rstrip())
                database[lsp_id] = _parse_db_detail_lsp(lsp_items)
        return database

    def _parse_route_per_area(self, route_items):
        routes = {'ipv4': {}, 'ipv6': {}}
        regex_v4route = re.compile(
            r'\s*(\d+\.\d+\.\d+\.\d+\/\d+)\s+(\d+)\s+(\S*)\s+(\d+\.\d+\.\d+\.\d+|-).*')
        regex_v6route = re.compile(
            r'(\s*[0-9a-fA-F:]+\/\d+)(\s+\d+\s+)(\S+\s+)([0-9a-fA-F:\-]+)')
        for line in [item.strip() for item in route_items if item.strip()]:
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

    def _parse_summary_per_area(self, summary_items):

        def _parse_counter(counter_items):
            counters = {}
            regex_p2p_iih = re.compile(r'\s*P2P IIH: (\d+)')
            regex_l2_lsp = re.compile(r'\s*L2 LSP: (\d+)')
            regex_l2_csnp = re.compile(r'\s*L2 CSNP: (\d+)')
            regex_l2_psnp = re.compile(r'\s*L2 PSNP: (\d+)')
            for item in counter_items:
                if regex_p2p_iih.match(item):
                    counters['p2p_iih'] = int(
                        regex_p2p_iih.match(item).group(1))
                elif regex_l2_lsp.match(item):
                    counters['l2_lsp'] = int(regex_l2_lsp.match(item).group(1))
                elif regex_l2_csnp.match(item):
                    counters['l2_csnp'] = int(
                        regex_l2_csnp.match(item).group(1))
                elif regex_l2_psnp.match(item):
                    counters['l2_psnp'] = int(
                        regex_l2_psnp.match(item).group(1))
            return counters

        def _parse_summary_level(level_items):
            summary_level = {'IPv4': {}, 'IPv6': {}, 'spf_pending': False}
            regex_ip_version = re.compile(r'(IPv[46]) route computation:')
            regex_minimum_interval = re.compile(r'minimum interval  : (\d+)')
            regex_last_run_elapsed = re.compile(
                r'last run elapsed  : (\S+) ago')
            regex_run_count = re.compile(r'run count\s+: (\d+)')
            while len(level_items) > 0:
                line = level_items.pop(0).strip()
                if "SPF: (pending)" in line:
                    summary_level['spf_pending'] = True
                elif regex_minimum_interval.match(line):
                    summary_level['spf_interval'] = regex_minimum_interval.match(
                        line).group(1)
                elif regex_ip_version.match(line) and len(level_items) > 2:
                    ip_route_computation = {}
                    if regex_last_run_elapsed.match(level_items[0]):
                        ip_route_computation['last_run_elapsed'] = \
                            regex_last_run_elapsed.match(
                                level_items[0]).group(1)
                    if regex_run_count.match(level_items[2]):
                        ip_route_computation['run_count'] = \
                            regex_run_count.match(level_items[2]).group(1)
                    summary_level[regex_ip_version.match(
                        line).group(1)] = ip_route_computation
            return summary_level

        summary_items = [item.strip()
                         for item in summary_items if item.strip()]
        summary = {'tx_cnt': {}, 'rx_cnt': {}, 'level_2': {}}

        while len(summary_items) > 0:
            line = summary_items.pop(0).strip()
            if 'TX counters per PDU type:' in line:
                counter_items = []
                while len(summary_items) > 0 and 'RX counters per PDU type:' not in summary_items[0]:
                    counter_items.append(summary_items.pop(0).strip().rstrip())
                summary['tx_cnt'] = _parse_counter(counter_items)
            elif 'RX counters per PDU type:' in line:
                counter_items = []
                while len(summary_items) > 0 and 'Level-' not in summary_items[0]:
                    counter_items.append(summary_items.pop(0).strip().rstrip())
                summary['rx_cnt'] = _parse_counter(counter_items)
            elif 'Level-2:' in line:
                summary['level_2'] = _parse_summary_level(summary_items)
                summary_items = []

        return summary

    def _parse_spf_delay_ietf_per_area(self, spf_items):

        def _parse_level(level_items):
            level = {}
            regex_spf_delay_status = re.compile(
                r'\s*SPF delay status: (\S+.+)')
            regex_spf_delay_proto = re.compile(r'\s*Using (\S+.+)')
            regex_state = re.compile(r'\s*Current state:\s+(\S+)')
            regex_init_timer = re.compile(r'\s*Init timer:\s+(\d+) msec')
            regex_short_timer = re.compile(r'\s*Short timer:\s+(\d+) msec')
            regex_long_timer = re.compile(r'\s*Long timer:\s+(\d+) msec')
            regex_holddown_timer = re.compile(
                r'\s*Holddown timer:\s+(\d+) msec')
            regex_timetolearn_timer = re.compile(
                r'\s*TimeToLearn timer:\s+(\d+) msec')
            regex_first_event = re.compile(r'\s*First event:\s+(\S+.+)')
            regex_last_event = re.compile(r'\s*Last event:\s+(\S+.+)')

            while len(level_items) > 0:
                line = level_items.pop(0).strip()
                if regex_spf_delay_status.match(line):
                    level['spf_delay_status'] = regex_spf_delay_status.match(
                        line).group(1)
                elif regex_spf_delay_proto.match(line):
                    level['proto'] = regex_spf_delay_proto.match(line).group(1)
                elif regex_state.match(line):
                    level['state'] = regex_state.match(line).group(1)
                elif regex_init_timer.match(line):
                    level['init_timer'] = regex_init_timer.match(line).group(1)
                elif regex_short_timer.match(line):
                    level['short_timer'] = regex_short_timer.match(
                        line).group(1)
                elif regex_long_timer.match(line):
                    level['long_timer'] = regex_long_timer.match(line).group(1)
                elif regex_holddown_timer.match(line):
                    level['holddown_timer'] = regex_holddown_timer.match(
                        line).group(1)
                    if len(level_items) > 0:
                        level['holddown_state'] = level_items.pop(0).strip()
                elif regex_timetolearn_timer.match(line):
                    level['timetolearn_timer'] = regex_timetolearn_timer.match(
                        line).group(1)
                    if len(level_items) > 0:
                        level['timetolearn_state'] = level_items.pop(0).strip()
                elif regex_first_event.match(line):
                    level['first_event'] = regex_first_event.match(
                        line).group(1)
                elif regex_last_event.match(line):
                    level['last_event'] = regex_last_event.match(line).group(1)
            return level

        spf_items = [item.strip() for item in spf_items if item.strip()]
        spf_delay = {'Level-1': {}, 'Level-2': {}}
        regex_level = re.compile(r'(Level-[12]):')
        while len(spf_items) > 0:
            line = spf_items.pop(0).strip()
            if regex_level.match(line):
                level_items = []
                while len(spf_items) > 0 and not regex_level.match(spf_items[0]):
                    level_items.append(spf_items.pop(0).strip().rstrip())
                spf_delay[regex_level.match(line).group(
                    1)] = _parse_level(level_items)
        return spf_delay

    def parse_neighbors(self):
        self.facts['neighbors'] = self._parse_areas(
            self.out.split('\n'), self._parse_neighbors_per_area)

    def parse_database(self):
        self.facts['database'] = self._parse_areas(
            self.out.split('\n'), self._parse_db_per_area)

    def parse_database_detail(self):
        self.facts['database_detail'] = self._parse_areas(
            self.out.split('\n'), self._parse_db_detail_per_area)

    def parse_route(self):
        self.facts['route'] = self._parse_areas(
            self.out.split('\n'), self._parse_route_per_area)

    def parse_summary(self):
        self.facts['summary'] = self._parse_areas(
            self.out.split('\n'), self._parse_summary_per_area)

    def parse_spf_delay_ietf(self):
        self.facts['spf_delay_ietf'] = self._parse_areas(
            self.out.split('\n'), self._parse_spf_delay_ietf_per_area)

    def parse_hostname(self):
        regex_hostname = re.compile(
            r'(\s*[2\*]\s+)(\d{4}.\d{4}.\d{4}\s+)(\S+)')
        split_output = self.out.split('\n')
        hostnames = {}
        for line in split_output:
            match = regex_hostname.match(line)
            if match:
                hostnames[match.group(2).rstrip()] = match.group(3)
        self.facts['hostname'] = hostnames

    def collect_isis_config(self, command_str):
        docker_cmd = '{} "show {} isisd" '.format(self.vty_cmd, command_str)
        try:
            rc, self.out, err = self.module.run_command(
                docker_cmd, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(msg=str(e))

        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, self.out, err))
        else:
            self.facts['running-config'] = self.out

    def run(self):
        self.collect_data("neighbor detail")
        self.parse_neighbors()

        self.collect_data("database")
        self.parse_database()

        self.collect_data("database detail")
        self.parse_database_detail()

        self.collect_data("route")
        self.parse_route()

        self.collect_data("hostname")
        self.parse_hostname()

        self.collect_data("summary")
        self.parse_summary()

        self.collect_data("spf-delay-ietf")
        self.parse_spf_delay_ietf()

        self.collect_isis_config("running-config")

        self.module.exit_json(ansible_facts={'isis_facts': self.facts})


def main():
    module = AnsibleModule(argument_spec=dict(), supports_check_mode=False)

    vtysh_cmd = "docker exec -i bgp vtysh -c"
    try:
        # Currently, only support FRRouting
        command = "{} 'show version'".format(vtysh_cmd)
        rc, out, err = module.run_command(command)
        if rc != 0:
            err_message = "command %s failed rc=%d, out=%s, err=%s" % (
                command, rc, out, err)
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
