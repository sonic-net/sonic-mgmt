#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    normalize_interface_name,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

afi_safi_types_map = {
    'openconfig-bgp-types:IPV4_UNICAST': 'ipv4_unicast',
    'openconfig-bgp-types:IPV6_UNICAST': 'ipv6_unicast',
    'openconfig-bgp-types:L2VPN_EVPN': 'l2vpn_evpn',
}

AS_NOTATION_TYPES_MAP = {
    'ASDOT': 'asdot',
    'ASDOT_PLUS': 'asdot+',
}

AS_NOTATION_TO_TYPES_MAP = {
    'asdot': 'ASDOT',
    'asdot+': 'ASDOT_PLUS',
}

GET = "get"
network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
protocol_bgp_path = 'protocols/protocol=BGP,bgp/bgp'


def to_bgp_as_notation_request_type(as_notation):
    """Convert as_notation types to Openconfig As-dot enums"""
    return AS_NOTATION_TO_TYPES_MAP.get(as_notation)


class BgpAsn(str):
    """BgpAsn class to equate asdot+ and asplain"""
    def __new__(cls, as_val):
        if isinstance(as_val, str):
            obj = super().__new__(cls, as_val)
            obj.intval = int(as_val) if as_val.find('.') < 0 else (int(as_val.split('.')[0]) * 0x10000 + int(as_val.split('.')[1]))
            return obj
        if isinstance(as_val, int):
            obj = super().__new__(cls, as_val)
            obj.intval = as_val
        else:
            raise TypeError('Invalid BGP AS Number')
        return obj

    def __eq__(self, other):
        if isinstance(other, BgpAsn):
            return self.intval == other.intval
        if isinstance(other, str):
            if len(other) == 0:
                return False
            if other.find('.') < 0:
                if other.isdigit():
                    return self.intval == int(other)
                return False
            return self.intval == (int(other.split('.')[0]) * 0x10000 + int(other.split('.')[1]))
        if isinstance(other, int):
            return self.intval == other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_request_attr_fmt(self):
        """Return asn according to openconfig model (original input: asdot(+) as string, asplain as integer)"""
        return self.intval if self.__str__().find('.') < 0 else self.__str__()


def convert_bgp_asn(cfglist):
    """Convert Bgp Asn values (int/str) to BgpAsn class """
    if not cfglist:
        return
    for bgp in cfglist:
        if bgp.get('bgp_as'):
            bgp['bgp_as'] = BgpAsn(bgp['bgp_as'])
        if bgp.get('neighbors'):
            for nbr in bgp['neighbors']:
                if nbr.get('remote_as') and isinstance(nbr['remote_as'], dict):
                    if nbr['remote_as'].get('peer_as'):
                        nbr['remote_as']['peer_as'] = BgpAsn(nbr['remote_as']['peer_as'])
                if nbr.get('local_as') and isinstance(nbr['local_as'], dict):
                    if nbr['local_as'].get('as'):
                        nbr['local_as']['as'] = BgpAsn(nbr['local_as']['as'])
        if bgp.get('peer_group'):
            for pgrp in bgp['peer_group']:
                if pgrp.get('remote_as') and isinstance(pgrp['remote_as'], dict):
                    if pgrp['remote_as'].get('peer_as'):
                        pgrp['remote_as']['peer_as'] = BgpAsn(pgrp['remote_as']['peer_as'])
                if pgrp.get('local_as') and isinstance(pgrp['local_as'], dict):
                    if pgrp['local_as'].get('as'):
                        pgrp['local_as']['as'] = BgpAsn(pgrp['local_as']['as'])


class BgpAsnStrList(str):
    """BgpAsn String List class to equate string with asdot+ and asplain"""
    def __new__(cls, as_val):
        if isinstance(as_val, str):
            if as_val.find('.') >= 0:
                as_strlist = as_val.split(',')
                for idx, asn in enumerate(as_strlist):
                    if asn.count('.') == 1:
                        as_strlist[idx] = str(int(asn.split('.')[0]) * 0x10000 + int(asn.split('.')[1]))
                    elif not asn.isdigit():
                        raise TypeError('Invalid BGP AS Number List')
                obj = super().__new__(cls, as_val)
                obj.strvals = ','.join(as_strlist)
                return obj
            else:
                for asn in as_val.split(','):
                    if not asn.isdigit():
                        raise TypeError('Invalid BGP AS Number List')
                obj = super().__new__(cls, as_val)
                obj.strvals = as_val
                return obj
        raise TypeError('Invalid BGP AS Number List')

    def __eq__(self, other):
        if isinstance(other, BgpAsnStrList):
            return self.strvals == other.strvals
        if isinstance(other, str):
            if len(other) == 0:
                return False
            if other.find('.') < 0:
                return self.strvals == other
            o_strlist = other.split(',')
            for idx, asn in enumerate(o_strlist):
                if asn.find('.') >= 0:
                    o_strlist[idx] = str(int(asn.split('.')[0]) * 0x10000 + int(asn.split('.')[1]))
            return self.strvals == ','.join(o_strlist)
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_request_attr_fmt(self):
        """Return asn string list according to openconfig model (original input string)"""
        return self.__str__()


class BgpAsnNN(str):
    """BgpAsnNN class to equate ASN:NN with asdot+ and asplain"""
    def __new__(cls, as_val):
        if isinstance(as_val, str):
            asn = as_val.split(':')
            if len(asn) != 2 or not asn[1].isdigit():
                raise TypeError('Invalid ASN:NN_OR_IP-ADDRESS:NN')
            dotcnt = asn[0].count('.')
            if dotcnt == 1:
                obj = super().__new__(cls, as_val)
                obj.asnum_nn = str(int(asn[0].split('.')[0]) * 0x10000 + int(asn[0].split('.')[1])) + ':' + asn[1]
                return obj
            if (dotcnt == 0 and asn[0].isdigit) or dotcnt == 3:
                # asplain asn:nn or 3-dots for IPv4:NN
                obj = super().__new__(cls, as_val)
                obj.asnum_nn = as_val
                return obj
        raise TypeError('Invalid ASN:NN_OR_IP-ADDRESS:NN')

    def __eq__(self, other):
        if isinstance(other, BgpAsnNN):
            return self.asnum_nn == other.asnum_nn
        elif isinstance(other, str):
            if len(other) == 0:
                return False
            asn = other.split(':')
            if len(asn) != 2 or not asn[1].isdigit():
                return False
            if asn[0].count('.') == 1:
                return self.asnum_nn == str(int(asn[0].split('.')[0]) * 0x10000 + int(asn[0].split('.')[1])) + ':' + asn[1]
            if asn[0].isdigit:
                return self.asnum_nn == other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


def convert_routemap_bgp_asn(cfglist):
    """Convert Routemaps Bgp Asn-list-string and ext-commnunity ASN:NN to BgpAsnStrList and BgpAsnNN class """
    if not cfglist:
        return
    for rtmap in cfglist:
        if rtmap.get('set'):
            if rtmap['set'].get('as_path_prepend'):
                if isinstance(rtmap['set']['as_path_prepend'], str):
                    rtmap['set']['as_path_prepend'] = BgpAsnStrList(rtmap['set']['as_path_prepend'])
            if rtmap['set'].get('extcommunity'):
                for extcom_type in ['rt', 'soo']:
                    if rtmap['set']['extcommunity'].get(extcom_type):
                        for idx, asnn in enumerate(rtmap['set']['extcommunity'][extcom_type]):
                            rtmap['set']['extcommunity'][extcom_type][idx] = BgpAsnNN(asnn)


def to_extcom_str_list(asn_nn_list):
    """Return BgpAsnNN list as list of strings (original input string)"""
    return [extcm.__str__() for extcm in asn_nn_list]


def get_all_vrfs(module):
    """Get all VRF configurations available in chassis"""
    all_vrfs = []
    ret = []
    request = {"path": "data/sonic-vrf:sonic-vrf/VRF/VRF_LIST", "method": GET}
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        module.fail_json(msg=str(exc), code=exc.code)

    if 'sonic-vrf:VRF_LIST' in response[0][1]:
        all_vrf_data = response[0][1].get('sonic-vrf:VRF_LIST', [])
        if all_vrf_data:
            for vrf_data in all_vrf_data:
                all_vrfs.append(vrf_data['vrf_name'])

    return all_vrfs


def get_peergroups(module, vrf_name):
    peer_groups = []
    request_path = '%s=%s/protocols/protocol=BGP,bgp/bgp/peer-groups' % (network_instance_path, vrf_name)
    request = {"path": request_path, "method": GET}
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        module.fail_json(msg=str(exc), code=exc.code)

    resp = response[0][1]
    if 'openconfig-network-instance:peer-groups' in resp:
        data = resp['openconfig-network-instance:peer-groups']
        if 'peer-group' in data:
            for peer_group in data['peer-group']:
                pg = {}
                if 'config' in peer_group:
                    if 'peer-group-name' in peer_group['config']:
                        pg.update({'name': peer_group['config']['peer-group-name']})
                    if 'description' in peer_group['config']:
                        pg.update({'pg_description': peer_group['config']['description']})
                    if 'disable-ebgp-connected-route-check' in peer_group['config']:
                        pg.update({'disable_connected_check': peer_group['config']['disable-ebgp-connected-route-check']})
                    if 'dont-negotiate-capability' in peer_group['config']:
                        pg.update({'dont_negotiate_capability': peer_group['config']['dont-negotiate-capability']})
                    if 'enforce-first-as' in peer_group['config']:
                        pg.update({'enforce_first_as': peer_group['config']['enforce-first-as']})
                    if 'enforce-multihop' in peer_group['config']:
                        pg.update({'enforce_multihop': peer_group['config']['enforce-multihop']})
                    if 'extended-link-bandwidth' in peer_group['config']:
                        pg.update({'extended_link_bandwidth': peer_group['config']['extended-link-bandwidth']})
                    local_as = {}
                    if 'local-as' in peer_group['config']:
                        local_as.update({'as': peer_group['config']['local-as']})
                    if 'local-as-no-prepend' in peer_group['config']:
                        local_as.update({'no_prepend': peer_group['config']['local-as-no-prepend']})
                    if 'local-as-replace-as' in peer_group['config']:
                        local_as.update({'replace_as': peer_group['config']['local-as-replace-as']})
                    if 'override-capability' in peer_group['config']:
                        pg.update({'override_capability': peer_group['config']['override-capability']})
                    if 'shutdown-message' in peer_group['config']:
                        pg.update({'shutdown_msg': peer_group['config']['shutdown-message']})
                    if 'solo-peer' in peer_group['config']:
                        pg.update({'solo': peer_group['config']['solo-peer']})
                    if 'strict-capability-match' in peer_group['config']:
                        pg.update({'strict_capability_match': peer_group['config']['strict-capability-match']})
                    if 'ttl-security-hops' in peer_group['config']:
                        pg.update({'ttl_security': peer_group['config']['ttl-security-hops']})
                auth_pwd = {}
                if 'auth-password' in peer_group and 'config' in peer_group['auth-password']:
                    if 'encrypted' in peer_group['auth-password']['config']:
                        auth_pwd.update({'encrypted': peer_group['auth-password']['config']['encrypted']})
                    if 'password' in peer_group['auth-password']['config']:
                        auth_pwd.update({'pwd': peer_group['auth-password']['config']['password']})
                bfd = {}
                if 'enable-bfd' in peer_group and 'config' in peer_group['enable-bfd']:
                    if 'enabled' in peer_group['enable-bfd']['config']:
                        bfd.update({'enabled': peer_group['enable-bfd']['config']['enabled']})
                    if 'check-control-plane-failure' in peer_group['enable-bfd']['config']:
                        bfd.update({'check_failure': peer_group['enable-bfd']['config']['check-control-plane-failure']})
                    if 'bfd-profile' in peer_group['enable-bfd']['config']:
                        bfd.update({'profile': peer_group['enable-bfd']['config']['bfd-profile']})
                ebgp_multihop = {}
                if 'ebgp-multihop' in peer_group and 'config' in peer_group['ebgp-multihop']:
                    if 'enabled' in peer_group['ebgp-multihop']['config']:
                        ebgp_multihop.update({'enabled': peer_group['ebgp-multihop']['config']['enabled']})
                    if 'multihop-ttl' in peer_group['ebgp-multihop']['config']:
                        ebgp_multihop.update({'multihop_ttl': peer_group['ebgp-multihop']['config']['multihop-ttl']})
                if 'transport' in peer_group and 'config' in peer_group['transport']:
                    if 'local-address' in peer_group['transport']['config']:
                        pg.update({'local_address': peer_group['transport']['config']['local-address']})
                    if 'passive-mode' in peer_group['transport']['config']:
                        pg.update({'passive': peer_group['transport']['config']['passive-mode']})
                if 'timers' in peer_group and 'config' in peer_group['timers']:
                    if 'minimum-advertisement-interval' in peer_group['timers']['config']:
                        pg.update({'advertisement_interval': peer_group['timers']['config']['minimum-advertisement-interval']})
                timers = {}
                if 'hold-time' in peer_group['timers']['config']:
                    timers.update({'holdtime': peer_group['timers']['config']['hold-time']})
                if 'keepalive-interval' in peer_group['timers']['config']:
                    timers.update({'keepalive': peer_group['timers']['config']['keepalive-interval']})
                if 'connect-retry' in peer_group['timers']['config']:
                    timers.update({'connect_retry': peer_group['timers']['config']['connect-retry']})
                capability = {}
                if 'config' in peer_group and 'capability-dynamic' in peer_group['config']:
                    capability.update({'dynamic': peer_group['config']['capability-dynamic']})
                if 'config' in peer_group and 'capability-extended-nexthop' in peer_group['config']:
                    capability.update({'extended_nexthop': peer_group['config']['capability-extended-nexthop']})
                remote_as = {}
                if 'config' in peer_group and 'peer-as' in peer_group['config']:
                    remote_as.update({'peer_as': peer_group['config']['peer-as']})
                if 'config' in peer_group and 'peer-type' in peer_group['config']:
                    remote_as.update({'peer_type': peer_group['config']['peer-type'].lower()})
                afis = []
                if 'afi-safis' in peer_group and 'afi-safi' in peer_group['afi-safis']:
                    for each in peer_group['afi-safis']['afi-safi']:
                        samp = {}
                        if 'afi-safi-name' in each and each['afi-safi-name']:
                            tmp = each['afi-safi-name'].split(':')
                            if tmp:
                                split_tmp = tmp[1].split('_')
                                if split_tmp:
                                    afi = split_tmp[0].lower()
                                    safi = split_tmp[1].lower()
                                if afi and safi:
                                    samp.update({'afi': afi})
                                    samp.update({'safi': safi})
                        if 'config' in each and 'enabled' in each['config']:
                            samp.update({'activate': each['config']['enabled']})
                        if 'allow-own-as' in each and 'config' in each['allow-own-as']:
                            allowas_in = {}
                            allowas_conf = each['allow-own-as']['config']
                            if 'origin' in allowas_conf and allowas_conf['origin'] is not None:
                                allowas_in.update({'origin': allowas_conf['origin']})
                            if 'as-count' in allowas_conf and allowas_conf['as-count']:
                                allowas_in.update({'value': allowas_conf['as-count']})
                            if allowas_in:
                                samp.update({'allowas_in': allowas_in})
                        if 'ipv4-unicast' in each:
                            if 'config' in each['ipv4-unicast']:
                                ip_afi_conf = each['ipv4-unicast']['config']
                                ip_afi = update_bgp_nbr_pg_ip_afi_dict(ip_afi_conf)
                                if ip_afi:
                                    samp.update({'ip_afi': ip_afi})
                            if 'prefix-limit' in each['ipv4-unicast'] and 'config' in each['ipv4-unicast']['prefix-limit']:
                                pfx_lmt_conf = each['ipv4-unicast']['prefix-limit']['config']
                                prefix_limit = update_bgp_nbr_pg_prefix_limit_dict(pfx_lmt_conf)
                                if prefix_limit:
                                    samp.update({'prefix_limit': prefix_limit})
                        elif 'ipv6-unicast' in each:
                            if 'config' in each['ipv6-unicast']:
                                ip_afi_conf = each['ipv6-unicast']['config']
                                ip_afi = update_bgp_nbr_pg_ip_afi_dict(ip_afi_conf)
                                if ip_afi:
                                    samp.update({'ip_afi': ip_afi})
                            if 'prefix-limit' in each['ipv6-unicast'] and 'config' in each['ipv6-unicast']['prefix-limit']:
                                pfx_lmt_conf = each['ipv6-unicast']['prefix-limit']['config']
                                prefix_limit = update_bgp_nbr_pg_prefix_limit_dict(pfx_lmt_conf)
                                if prefix_limit:
                                    samp.update({'prefix_limit': prefix_limit})
                        if 'prefix-list' in each and 'config' in each['prefix-list']:
                            pfx_lst_conf = each['prefix-list']['config']
                            if 'import-policy' in pfx_lst_conf and pfx_lst_conf['import-policy']:
                                samp.update({'prefix_list_in': pfx_lst_conf['import-policy']})
                            if 'export-policy' in pfx_lst_conf and pfx_lst_conf['export-policy']:
                                samp.update({'prefix_list_out': pfx_lst_conf['export-policy']})
                        if samp:
                            afis.append(samp)
                if auth_pwd:
                    pg.update({'auth_pwd': auth_pwd})
                if bfd:
                    pg.update({'bfd': bfd})
                if ebgp_multihop:
                    pg.update({'ebgp_multihop': ebgp_multihop})
                if local_as:
                    pg.update({'local_as': local_as})
                if timers:
                    pg.update({'timers': timers})
                if capability:
                    pg.update({'capability': capability})
                if remote_as:
                    pg.update({'remote_as': remote_as})
                if afis and len(afis) > 0:
                    afis_dict = {}
                    afis_dict.update({'afis': afis})
                    pg.update({'address_family': afis_dict})
                peer_groups.append(pg)

    return peer_groups


def update_bgp_nbr_pg_ip_afi_dict(ip_afi_conf):
    ip_afi = {}
    if 'default-policy-name' in ip_afi_conf and ip_afi_conf['default-policy-name']:
        ip_afi.update({'default_policy_name': ip_afi_conf['default-policy-name']})
    if 'send-default-route' in ip_afi_conf and ip_afi_conf['send-default-route']:
        ip_afi.update({'send_default_route': ip_afi_conf['send-default-route']})

    return ip_afi


def update_bgp_nbr_pg_prefix_limit_dict(pfx_lmt_conf):
    prefix_limit = {}
    if 'max-prefixes' in pfx_lmt_conf and pfx_lmt_conf['max-prefixes']:
        prefix_limit.update({'max_prefixes': pfx_lmt_conf['max-prefixes']})
    if 'prevent-teardown' in pfx_lmt_conf and pfx_lmt_conf['prevent-teardown']:
        prefix_limit.update({'prevent_teardown': pfx_lmt_conf['prevent-teardown']})
    if 'warning-threshold-pct' in pfx_lmt_conf and pfx_lmt_conf['warning-threshold-pct']:
        prefix_limit.update({'warning_threshold': pfx_lmt_conf['warning-threshold-pct']})
    if 'restart-timer' in pfx_lmt_conf and pfx_lmt_conf['restart-timer']:
        prefix_limit.update({'restart_timer': pfx_lmt_conf['restart-timer']})
    if 'openconfig-bgp-ext:discard-extra' in pfx_lmt_conf and pfx_lmt_conf['openconfig-bgp-ext:discard-extra']:
        prefix_limit.update({'discard_extra': pfx_lmt_conf['openconfig-bgp-ext:discard-extra']})

    return prefix_limit


def get_ip_afi_cfg_payload(ip_afi):
    ip_afi_cfg = {}

    if ip_afi.get('default_policy_name', None) is not None:
        default_policy_name = ip_afi['default_policy_name']
        ip_afi_cfg.update({'default-policy-name': default_policy_name})
    if ip_afi.get('send_default_route', None) is not None:
        send_default_route = ip_afi['send_default_route']
        ip_afi_cfg.update({'send-default-route': send_default_route})

    return ip_afi_cfg


def get_prefix_limit_payload(prefix_limit):
    pfx_lmt_cfg = {}

    if prefix_limit.get('max_prefixes', None) is not None:
        max_prefixes = prefix_limit['max_prefixes']
        pfx_lmt_cfg.update({'max-prefixes': max_prefixes})
    if prefix_limit.get('prevent_teardown', None) is not None:
        prevent_teardown = prefix_limit['prevent_teardown']
        pfx_lmt_cfg.update({'prevent-teardown': prevent_teardown})
    if prefix_limit.get('warning_threshold', None) is not None:
        warning_threshold = prefix_limit['warning_threshold']
        pfx_lmt_cfg.update({'warning-threshold-pct': warning_threshold})
    if prefix_limit.get('restart_timer', None) is not None:
        restart_timer = prefix_limit['restart_timer']
        pfx_lmt_cfg.update({'restart-timer': restart_timer})
    if prefix_limit.get('discard_extra', None) is not None:
        discard_extra = prefix_limit['discard_extra']
        pfx_lmt_cfg.update({'discard-extra': discard_extra})

    return pfx_lmt_cfg


def get_all_bgp_af_redistribute(module, vrfs, af_redis_params_map):
    """Get all BGP Global Address Family Redistribute configurations available in chassis"""
    all_af_redis_data = []
    ret_redis_data = []
    for vrf_name in vrfs:
        af_redis_data = {}
        request_path = '%s=%s/table-connections' % (network_instance_path, vrf_name)
        request = {"path": request_path, "method": GET}
        try:
            response = edit_config(module, to_request(module, request))
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        if "openconfig-network-instance:table-connections" in response[0][1]:
            af_redis_data.update({vrf_name: response[0][1]['openconfig-network-instance:table-connections']})

        if af_redis_data:
            all_af_redis_data.append(af_redis_data)

    if all_af_redis_data:
        for vrf_name in vrfs:
            key = vrf_name
            val = next((af_redis_data for af_redis_data in all_af_redis_data if vrf_name in af_redis_data), None)
            if not val:
                continue

            val = val[vrf_name]
            redis_data = val.get('table-connection', [])
            if not redis_data:
                continue
            filtered_redis_data = []
            for e_cfg in redis_data:
                af_redis_data = get_from_params_map(af_redis_params_map, e_cfg)
                if af_redis_data:
                    filtered_redis_data.append(af_redis_data)

            if filtered_redis_data:
                ret_redis_data.append({key: filtered_redis_data})

    return ret_redis_data


def get_all_bgp_globals(module, vrfs):
    """Get all BGP configurations available in chassis"""
    all_bgp_globals = []
    for vrf_name in vrfs:
        get_path = '%s=%s/%s/global' % (network_instance_path, vrf_name, protocol_bgp_path)
        request = {"path": get_path, "method": GET}
        try:
            response = edit_config(module, to_request(module, request))
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)
        for resp in response:
            if "openconfig-network-instance:global" in resp[1]:
                bgp_data = {'global': resp[1].get("openconfig-network-instance:global", {})}
                bgp_data.update({'vrf_name': vrf_name})
                all_bgp_globals.append(bgp_data)
    return all_bgp_globals


def get_bgp_global_af_data(data, af_params_map):
    ret_af_data = {}
    for key, val in data.items():
        if key == 'global':
            if 'afi-safis' in val and 'afi-safi' in val['afi-safis']:
                global_af_data = []
                raw_af_data = val['afi-safis']['afi-safi']
                for each_af_data in raw_af_data:
                    af_data = get_from_params_map(af_params_map, each_af_data)
                    if af_data:
                        global_af_data.append(af_data)
                ret_af_data.update({'address_family': global_af_data})
            if 'config' in val and 'as' in val['config']:
                as_val = val['config']['as']
                ret_af_data.update({'bgp_as': as_val})
        if key == 'vrf_name':
            ret_af_data.update({'vrf_name': val})
    return ret_af_data


def get_bgp_global_data(data, global_params_map):
    bgp_data = {}
    for key, val in data.items():
        if key == 'global':
            global_data = get_from_params_map(global_params_map, val)
            bgp_data.update(global_data)
        if key == 'vrf_name':
            bgp_data.update({'vrf_name': val})
    return bgp_data


def get_from_params_map(params_map, data):
    ret_data = {}
    for want_key, config_key in params_map.items():
        tmp_data = {}
        for key, val in data.items():
            if key == 'config':
                for k, v in val.items():
                    if k == config_key:
                        if config_key == 'as-notation':
                            val_data = AS_NOTATION_TYPES_MAP.get(val[config_key])
                        else:
                            val_data = val[config_key]
                        ret_data.update({want_key: val_data})
                        if config_key == 'afi-safi-name':
                            ret_data.pop(want_key)
                            for type_k, type_val in afi_safi_types_map.items():
                                if type_k == val_data:
                                    afi_safi = type_val.split('_')
                                    val_data = afi_safi[0]
                                    ret_data.update({'safi': afi_safi[1]})
                                    ret_data.update({want_key: val_data})
                                    break
            else:
                if key == 'timers' and ('config' in val or 'state' in val):
                    tmp = {}
                    if key in ret_data:
                        tmp = ret_data[key]
                    cfg = val['config'] if 'config' in val else val['state']
                    for k, v in cfg.items():
                        if k == config_key:
                            if k != 'minimum-advertisement-interval':
                                tmp.update({want_key: cfg[config_key]})
                            else:
                                ret_data.update({want_key: cfg[config_key]})
                    if tmp:
                        ret_data.update({key: tmp})

                elif isinstance(config_key, list):
                    i = 0
                    if key == config_key[0]:
                        if key == 'afi-safi':
                            cfg_data = config_key[1]
                            for itm in afi_safi_types_map:
                                if cfg_data in itm:
                                    afi_safi = itm[cfg_data].split('_')
                                    cfg_data = afi_safi[0]
                                    ret_data.update({'safi': afi_safi[1]})
                                    ret_data.update({want_key: cfg_data})
                                    break
                        else:
                            cfg_data = {key: val}
                            for cfg_key in config_key:
                                if cfg_key == 'config':
                                    continue
                                new_data = None

                                if cfg_key in cfg_data:
                                    new_data = cfg_data[cfg_key]
                                elif isinstance(cfg_data, dict) and 'config' in cfg_data:
                                    if cfg_key in cfg_data['config']:
                                        new_data = cfg_data['config'][cfg_key]

                                if new_data is not None:
                                    cfg_data = new_data
                                else:
                                    break
                            else:
                                ret_data.update({want_key: cfg_data})
                else:
                    if key == config_key and val:
                        if config_key != 'afi-safi-name' and config_key != 'timers':
                            cfg_data = val
                            ret_data.update({want_key: cfg_data})

    return ret_data


def get_bgp_data(module, global_params_map):
    vrf_list = get_all_vrfs(module)
    data = get_all_bgp_globals(module, vrf_list)

    objs = []
    # operate on a collection of resource x
    for conf in data:
        if conf:
            obj = get_bgp_global_data(conf, global_params_map)
            if obj:
                objs.append(obj)
    return objs


def get_bgp_af_data(module, af_params_map):
    vrf_list = get_all_vrfs(module)
    data = get_all_bgp_globals(module, vrf_list)

    objs = []
    # operate on a collection of resource x
    for conf in data:
        if conf:
            obj = get_bgp_global_af_data(conf, af_params_map)
            if obj:
                objs.append(obj)

    return objs


def get_bgp_as(module, vrf_name):
    as_val = None
    get_path = '%s=%s/%s/global/config' % (network_instance_path, vrf_name, protocol_bgp_path)
    request = {"path": get_path, "method": GET}
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        module.fail_json(msg=str(exc), code=exc.code)

    resp = response[0][1]
    if "openconfig-network-instance:config" in resp and 'as' in resp['openconfig-network-instance:config']:
        as_val = resp['openconfig-network-instance:config']['as']
    return as_val


def get_bgp_bandwidth(module, vrf_name):
    as_val = None
    get_path = '%s=%s/%s/global/config' % (network_instance_path, vrf_name, protocol_bgp_path)
    request = {"path": get_path, "method": GET}
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        module.fail_json(msg=str(exc), code=exc.code)

    resp = response[0][1]
    if "openconfig-network-instance:config" in resp and 'as' in resp['openconfig-network-instance:config']:
        as_val = resp['openconfig-network-instance:config']['as']
    return as_val


def get_bgp_neighbors(module, vrf_name):
    neighbors_data = None
    get_path = '%s=%s/%s/neighbors' % (network_instance_path, vrf_name, protocol_bgp_path)
    request = {"path": get_path, "method": GET}
    try:
        response = edit_config(module, to_request(module, request))
    except ConnectionError as exc:
        module.fail_json(msg=str(exc), code=exc.code)

    resp = response[0][1]
    if "openconfig-network-instance:neighbors" in resp:
        neighbors_data = resp['openconfig-network-instance:neighbors']

    return neighbors_data


def get_all_bgp_neighbors(module):
    vrf_list = get_all_vrfs(module)
    """Get all BGP neighbor configurations available in chassis"""
    all_bgp_neighbors = []

    for vrf_name in vrf_list:
        neighbors_cfg = {}

        bgp_as = get_bgp_as(module, vrf_name)
        if bgp_as:
            neighbors_cfg['bgp_as'] = bgp_as
            neighbors_cfg['vrf_name'] = vrf_name
        else:
            continue

        neighbors = get_bgp_neighbors(module, vrf_name)
        if neighbors:
            neighbors_cfg['neighbors'] = neighbors

        if neighbors_cfg:
            all_bgp_neighbors.append(neighbors_cfg)

    return all_bgp_neighbors


def get_undefined_bgps(want, have, check_neighbors=None):
    if check_neighbors is None:
        check_neighbors = False

    undefined_resources = []

    if not want:
        return undefined_resources

    if not have:
        have = []

    for want_conf in want:
        undefined = {}
        want_bgp_as = want_conf['bgp_as']
        want_vrf = want_conf['vrf_name']
        have_conf = next((conf for conf in have if (want_bgp_as == conf['bgp_as'] and want_vrf == conf['vrf_name'])), None)
        if not have_conf:
            undefined['bgp_as'] = want_bgp_as
            undefined['vrf_name'] = want_vrf
            undefined_resources.append(undefined)
        if check_neighbors and have_conf:
            want_neighbors = want_conf.get('neighbors', [])
            have_neighbors = have_conf.get('neighbors', [])
            undefined_neighbors = get_undefined_neighbors(want_neighbors, have_neighbors)
            if undefined_neighbors:
                undefined['bgp_as'] = want_bgp_as
                undefined['vrf_name'] = want_vrf
                undefined['neighbors'] = undefined_neighbors
                undefined_resources.append(undefined)

    return undefined_resources


def get_undefined_neighbors(want, have):
    undefined_neighbors = []
    if not want:
        return undefined_neighbors

    if not have:
        have = []

    for want_neighbor in want:
        want_neighbor_val = want_neighbor['neighbor']
        have_neighbor = next((conf for conf in have if want_neighbor_val == conf['neighbor']), None)
        if not have_neighbor:
            undefined_neighbors.append({'neighbor': want_neighbor_val})

    return undefined_neighbors


def validate_bgps(module, want, have):
    validate_bgp_resources(module, want, have)


def validate_bgp_neighbors(module, want, have):
    validate_bgp_resources(module, want, have, check_neighbors=True)


def validate_bgp_resources(module, want, have, check_neighbors=None):
    undefined_resources = get_undefined_bgps(want, have, check_neighbors)
    if undefined_resources:
        err = "Resource not found! {res}".format(res=undefined_resources)
        module.fail_json(msg=err, code=404)


def normalize_neighbors_interface_name(want, module):
    if want:
        for conf in want:
            neighbors = conf.get('neighbors', None)
            if neighbors:
                normalize_interface_name(neighbors, module, 'neighbor')
