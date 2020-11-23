# This file contains API to configure route-maps.
# It provides a route-map config object where user can add all match
# and set statements
# User can then execute the full route-map in one go
# or
# obtain the configuration string so that it can be concatenated with other commands
# for faster execution of CLIs
# @author : Sayed Saquib (sayed.saquib@broadcom.com)

from spytest import st

class RouteMap:
    """
    Usage:
    rmap = RouteMap("testroutemap")

    rmap.add_permit_sequence('10')
    seq='10'
    rmap.add_sequence_description(seq, 'This is permit seq 10')
    #match
    rmap.add_sequence_match_prefix_list(seq, 'myprefixlist')
    rmap.add_sequence_match_prefix_length(seq, '32')
    rmap.add_sequence_match_ip_access_list(seq, '22')
    rmap.add_sequence_match_bgp_aspath_list(seq, 'mybgpaspathlist')
    #set
    rmap.add_sequence_set_metric(seq, '444')
    rmap.add_sequence_set_local_preference(seq, '6400')
    rmap.add_sequence_set_ipv4_next_hop(seq, '3.3.3.3')
    rmap.add_sequence_set_ipv6_next_hop_local(seq, 'fe80:1::1:1')
    rmap.add_sequence_set_ipv6_next_hop_global(seq, '2:2::2:2')
    rmap.add_sequence_set_ipv6_next_hop_peer_address(seq)
    rmap.add_sequence_set_ipv6_next_hop_prefer_global(seq)
    rmap.add_sequence_set_as_path_exclude(seq, ['65101', '65003'])
    rmap.add_sequence_set_as_path_prepend(seq, ['65102', '65004'])
    rmap.add_sequence_set_as_path_prepend_last_as(seq, '5')
    rmap.add_sequence_set_community_none(seq)

    rmap.add_deny_sequence('20')
    rmap.add_sequence_description('20', 'This is deny seq 20')
    rmap.add_sequence_match_community('20', '44:4444')
    rmap.add_sequence_set_community('20', ['44:4444', '55:5555', 'no-export'])
    """

    def __init__(self, name):
        self.name = name
        self.stanza = {}
        self.cmdkeyword = 'route-map'

    def add_permit_sequence(self, seq):
        stanza = dict()
        stanza['mode'] = 'permit'
        stanza['match'] = []
        stanza['set'] = []
        self.stanza[seq] = stanza

    def add_deny_sequence(self, seq):
        stanza = dict()
        stanza['mode'] = 'deny'
        stanza['match'] = []
        stanza['set'] = []
        self.stanza[seq] = stanza

    def add_sequence_description(self, seq, description):
        self.stanza[seq]['description'] = description

    def add_sequence_match_prefix_length(self, seq, length, family='ipv4'):
        matchstmt = dict()
        matchstmt['type'] = 'prefix-len'
        matchstmt['family'] = family
        matchstmt['length'] = length
        self.stanza[seq]['match'].append(matchstmt)

    def add_sequence_match_prefix_list(self, seq, prefix_list_name, family='ipv4'):
        matchstmt = dict()
        matchstmt['type'] = 'prefix-list'
        matchstmt['family'] = family
        matchstmt['name'] = prefix_list_name
        self.stanza[seq]['match'].append(matchstmt)

    def add_sequence_match_ip_access_list(self, seq, access_list_name_number, family='ipv4'):
        matchstmt = dict()
        matchstmt['type'] = 'access-list'
        matchstmt['family'] = family
        matchstmt['name'] = access_list_name_number
        self.stanza[seq]['match'].append(matchstmt)

    def add_sequence_match_bgp_aspath_list(self, seq, bgp_as_path_list_name):
        matchstmt = dict()
        matchstmt['type'] = 'aspath-access-list'
        matchstmt['name'] = bgp_as_path_list_name
        self.stanza[seq]['match'].append(matchstmt)

    def add_sequence_match_community(self, seq, community_number_name, exact_match=False):
        matchstmt = dict()
        matchstmt['type'] = 'community'
        matchstmt['community'] = community_number_name
        matchstmt['exact_match'] = exact_match
        self.stanza[seq]['match'].append(matchstmt)

    def add_sequence_match_source_protocol(self,seq, source_protocol):
        matchstmt = dict()
        matchstmt['type'] = 'source-protocol'
        matchstmt['source-protocol'] = source_protocol
        self.stanza[seq]['match'].append(matchstmt)

    def add_sequence_set_metric(self, seq, metric):
        setstmt = dict()
        setstmt['type'] = 'metric'
        setstmt['metric'] = metric
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_local_preference(self, seq, local_pref):
        setstmt = dict()
        setstmt['type'] = 'localpref'
        setstmt['value'] = local_pref
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_ipv4_next_hop(self, seq, nhop):
        setstmt = dict()
        setstmt['type'] = 'ipv4nexthop'
        setstmt['value'] = nhop
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_ipv6_next_hop_local(self, seq, nhop):
        setstmt = dict()
        setstmt['type'] = 'ipv6nexthoplocal'
        setstmt['value'] = nhop
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_ipv6_next_hop_global(self, seq, nhop):
        setstmt = dict()
        setstmt['type'] = 'ipv6nexthopglobal'
        setstmt['value'] = nhop
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_ipv6_next_hop_peer_address(self, seq):
        setstmt = dict()
        setstmt['type'] = 'ipv6nexthoppeeraddress'
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_ipv6_next_hop_prefer_global(self, seq):
        setstmt = dict()
        setstmt['type'] = 'ipv6nexthoppreferglobal'
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_as_path_exclude(self, seq, as_path_list):
        setstmt = dict()
        setstmt['type'] = 'aspathexclude'
        setstmt['as_path_list'] = as_path_list
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_as_path_prepend(self, seq, as_path_list):
        setstmt = dict()
        setstmt['type'] = 'aspathprepend'
        setstmt['as_path_list'] = as_path_list
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_as_path_prepend_last_as(self, seq, number):
        setstmt = dict()
        setstmt['type'] = 'aspathprependlastas'
        setstmt['value'] = number
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_community(self, seq, community_list):
        setstmt = dict()
        setstmt['type'] = 'community'
        setstmt['community_list'] = community_list
        self.stanza[seq]['set'].append(setstmt)

    def add_sequence_set_community_none(self, seq):
        setstmt = dict()
        setstmt['type'] = 'communitynone'
        self.stanza[seq]['set'].append(setstmt)

    def config_command_string(self):
        cli_type = st.get_ui_type()
        cli_type = 'vtysh' if cli_type in ['click', 'vtysh'] else cli_type
        if cli_type in ['rest-put', 'rest-patch']: cli_type = 'klish'
        command = ''
        for v in self.stanza.keys():
            command += '{} {} {} {}\n'.format(self.cmdkeyword, self.name, self.stanza[v]['mode'], v)
            if 'description' in self.stanza[v]:
                command += 'description {}\n'.format(self.stanza[v]['description'])

            for items in self.stanza[v]['match']:
                if items['type'] == 'prefix-len':
                    if items['family'] == 'ipv4':
                        command += 'match ip address prefix-len {}\n'.format(items['length'])
                    else:
                        command += 'match ipv6 address prefix-len {}\n'.format(items['length'])
                elif items['type'] == 'prefix-list':
                    if items['family'] == 'ipv4':
                        command += 'match ip address prefix-list {}\n'.format(items['name'])
                    else:
                        command += 'match ipv6 address prefix-list {}\n'.format(items['name'])
                elif items['type'] == 'access-list':
                    if items['family'] == 'ipv4':
                        command += 'match ip address {}\n'.format(items['name'])
                    else:
                        command += 'match ipv6 address {}\n'.format(items['name'])
                elif items['type'] == 'aspath-access-list':
                    command += 'match as-path {}\n'.format(items['name'])
                elif items['type'] == 'community':
                    command += 'match community {}'.format(items['community'])
                    if items['exact_match'] is True:
                        command += ' exact-match\n'
                    else:
                        command += '\n'
                elif items['type'] == 'source-protocol':
                    command += 'match source-protocol {}\n'.format(items['source-protocol'])
                else:
                    st.error("Invalid type({}) in match statement".format(items['type']))

            for items in self.stanza[v]['set']:
                if items['type'] == 'metric':
                    command += 'set metric {}\n'.format(items['metric'])
                elif items['type'] == 'localpref':
                    command += 'set local-preference {}\n'.format(items['value'])
                elif items['type'] == 'ipv4nexthop':
                    command += 'set ip next-hop {}\n'.format(items['value'])
                elif items['type'] == 'ipv6nexthoplocal':
                    command += 'set ipv6 next-hop local {}\n'.format(items['value'])
                elif items['type'] == 'ipv6nexthopglobal':
                    command += 'set ipv6 next-hop global {}\n'.format(items['value'])
                elif items['type'] == 'ipv6nexthoppeeraddress':
                    command += 'set ipv6 next-hop peer-address\n'
                elif items['type'] == 'ipv6nexthoppreferglobal':
                    command += 'set ipv6 next-hop prefer-global\n'
                elif items['type'] == 'aspathexclude':
                    command += 'set as-path exclude '
                    if cli_type == 'vtysh':
                        command += ' '.join(items['as_path_list'])
                    elif cli_type == 'klish':
                        command += ','.join(items['as_path_list'])
                    command += '\n'
                elif items['type'] == 'aspathprepend':
                    command += 'set as-path prepend '
                    if cli_type == 'vtysh':
                        command += ' '.join(items['as_path_list'])
                    elif cli_type == 'klish':
                        command += ','.join(items['as_path_list'])
                    command += '\n'
                elif items['type'] == 'aspathprependlastas':
                    command += 'set as-path prepend last-as {}\n'.format(items['value'])
                elif items['type'] == 'community':
                    command += 'set community'
                    for vv in items['community_list']:
                        command = command + ' ' + vv
                    command += '\n'
                elif items['type'] == 'communitynone':
                    command += 'set community none\n'
                else:
                    st.error("Invalid type({}) in set statement".format(items['type']))
        return command

    def unconfig_command_string(self):
        command = 'no {} {}\n'.format(self.cmdkeyword, self.name)
        return command

    def execute_command(self, dut, config='yes', **kwargs):
        cli_type = st.get_ui_type(dut, **kwargs)
        cli_type = 'vtysh' if cli_type in ['click', 'vtysh'] else 'klish'
        if cli_type in ['rest-put', 'rest-patch']: cli_type = 'klish'
        if config == 'no':
            command = self.unconfig_command_string()
        else:
            command = self.config_command_string()
        st.config(dut, command, type=cli_type)

