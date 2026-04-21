#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_npu_fpanomaly
short_description: NP6Lite anomaly protection
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_npu_fpanomaly:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            esp_minlen_err:
                aliases: ['esp-minlen-err']
                type: str
                description: Invalid IPv4 ESP short packet anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            icmp_csum_err:
                aliases: ['icmp-csum-err']
                type: str
                description: Invalid IPv4 ICMP packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            icmp_minlen_err:
                aliases: ['icmp-minlen-err']
                type: str
                description: Invalid IPv4 ICMP short packet anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_csum_err:
                aliases: ['ipv4-csum-err']
                type: str
                description: Invalid IPv4 packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_ihl_err:
                aliases: ['ipv4-ihl-err']
                type: str
                description: Invalid IPv4 header length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_len_err:
                aliases: ['ipv4-len-err']
                type: str
                description: Invalid IPv4 packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_opt_err:
                aliases: ['ipv4-opt-err']
                type: str
                description: Invalid IPv4 option parsing anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_ttlzero_err:
                aliases: ['ipv4-ttlzero-err']
                type: str
                description: Invalid IPv4 TTL field zero anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_ver_err:
                aliases: ['ipv4-ver-err']
                type: str
                description: Invalid IPv4 header version anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6_exthdr_len_err:
                aliases: ['ipv6-exthdr-len-err']
                type: str
                description: Invalid IPv6 packet chain extension header total length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6_exthdr_order_err:
                aliases: ['ipv6-exthdr-order-err']
                type: str
                description: Invalid IPv6 packet extension header ordering anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6_ihl_err:
                aliases: ['ipv6-ihl-err']
                type: str
                description: Invalid IPv6 packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6_plen_zero:
                aliases: ['ipv6-plen-zero']
                type: str
                description: Invalid IPv6 packet payload length zero anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6_ver_err:
                aliases: ['ipv6-ver-err']
                type: str
                description: Invalid IPv6 packet version anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp_csum_err:
                aliases: ['tcp-csum-err']
                type: str
                description: Invalid IPv4 TCP packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp_hlen_err:
                aliases: ['tcp-hlen-err']
                type: str
                description: Invalid IPv4 TCP header length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp_plen_err:
                aliases: ['tcp-plen-err']
                type: str
                description: Invalid IPv4 TCP packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp_csum_err:
                aliases: ['udp-csum-err']
                type: str
                description: Invalid IPv4 UDP packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp_hlen_err:
                aliases: ['udp-hlen-err']
                type: str
                description: Invalid IPv4 UDP packet header length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp_len_err:
                aliases: ['udp-len-err']
                type: str
                description: Invalid IPv4 UDP packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp_plen_err:
                aliases: ['udp-plen-err']
                type: str
                description: Invalid IPv4 UDP packet minimum length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udplite_cover_err:
                aliases: ['udplite-cover-err']
                type: str
                description: Invalid IPv4 UDP-Lite packet coverage anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udplite_csum_err:
                aliases: ['udplite-csum-err']
                type: str
                description: Invalid IPv4 UDP-Lite packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
                    - 'allow'
            unknproto_minlen_err:
                aliases: ['unknproto-minlen-err']
                type: str
                description: Invalid IPv4 L4 unknown protocol short packet anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp_fin_only:
                aliases: ['tcp-fin-only']
                type: str
                description: TCP SYN flood with only FIN flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optsecurity:
                aliases: ['ipv4-optsecurity']
                type: str
                description: Security option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optralert:
                aliases: ['ipv6-optralert']
                type: str
                description: Router alert option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_syn_fin:
                aliases: ['tcp-syn-fin']
                type: str
                description: TCP SYN flood SYN/FIN flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_proto_err:
                aliases: ['ipv4-proto-err']
                type: str
                description: Invalid layer 4 protocol anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_saddr_err:
                aliases: ['ipv6-saddr-err']
                type: str
                description: Source address as multicast anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            icmp_frag:
                aliases: ['icmp-frag']
                type: str
                description: Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optssrr:
                aliases: ['ipv4-optssrr']
                type: str
                description: Strict source record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_opthomeaddr:
                aliases: ['ipv6-opthomeaddr']
                type: str
                description: Home address option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            udp_land:
                aliases: ['udp-land']
                type: str
                description: UDP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optinvld:
                aliases: ['ipv6-optinvld']
                type: str
                description: Invalid option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_fin_noack:
                aliases: ['tcp-fin-noack']
                type: str
                description: TCP SYN flood with FIN flag set without ACK setting anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_proto_err:
                aliases: ['ipv6-proto-err']
                type: str
                description: Layer 4 invalid protocol anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_land:
                aliases: ['tcp-land']
                type: str
                description: TCP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_unknopt:
                aliases: ['ipv4-unknopt']
                type: str
                description: Unknown option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optstream:
                aliases: ['ipv4-optstream']
                type: str
                description: Stream option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optjumbo:
                aliases: ['ipv6-optjumbo']
                type: str
                description: Jumbo options anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            icmp_land:
                aliases: ['icmp-land']
                type: str
                description: ICMP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_winnuke:
                aliases: ['tcp-winnuke']
                type: str
                description: TCP WinNuke anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_daddr_err:
                aliases: ['ipv6-daddr-err']
                type: str
                description: Destination address as unspecified or loopback address anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_land:
                aliases: ['ipv4-land']
                type: str
                description: Land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_opttunnel:
                aliases: ['ipv6-opttunnel']
                type: str
                description: Tunnel encapsulation limit option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_no_flag:
                aliases: ['tcp-no-flag']
                type: str
                description: TCP SYN flood with no flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_land:
                aliases: ['ipv6-land']
                type: str
                description: Land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optlsrr:
                aliases: ['ipv4-optlsrr']
                type: str
                description: Loose source record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_opttimestamp:
                aliases: ['ipv4-opttimestamp']
                type: str
                description: Timestamp option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optrr:
                aliases: ['ipv4-optrr']
                type: str
                description: Record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optnsap:
                aliases: ['ipv6-optnsap']
                type: str
                description: Network service access point address option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_unknopt:
                aliases: ['ipv6-unknopt']
                type: str
                description: Unknown option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_syn_data:
                aliases: ['tcp-syn-data']
                type: str
                description: TCP SYN flood packets with data anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optendpid:
                aliases: ['ipv6-optendpid']
                type: str
                description: End point identification anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            gtpu_plen_err:
                aliases: ['gtpu-plen-err']
                type: str
                description: Gtpu plen err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            vxlan_minlen_err:
                aliases: ['vxlan-minlen-err']
                type: str
                description: Vxlan minlen err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            capwap_minlen_err:
                aliases: ['capwap-minlen-err']
                type: str
                description: Capwap minlen err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            gre_csum_err:
                aliases: ['gre-csum-err']
                type: str
                description: Gre csum err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
                    - 'allow'
            nvgre_minlen_err:
                aliases: ['nvgre-minlen-err']
                type: str
                description: Nvgre minlen err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp_l4len_err:
                aliases: ['sctp-l4len-err']
                type: str
                description: Sctp l4len err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp_hlenvsl4len_err:
                aliases: ['tcp-hlenvsl4len-err']
                type: str
                description: Tcp hlenvsl4len err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp_crc_err:
                aliases: ['sctp-crc-err']
                type: str
                description: Sctp crc err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp_clen_err:
                aliases: ['sctp-clen-err']
                type: str
                description: Sctp clen err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            uesp_minlen_err:
                aliases: ['uesp-minlen-err']
                type: str
                description: Uesp minlen err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp_csum_err:
                aliases: ['sctp-csum-err']
                type: str
                description: Invalid IPv4 SCTP checksum anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: NP6Lite anomaly protection
      fortinet.fortimanager.fmgr_system_npu_fpanomaly:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        system_npu_fpanomaly:
          # esp_minlen_err: <value in [drop, trap-to-host]>
          # icmp_csum_err: <value in [drop, trap-to-host]>
          # icmp_minlen_err: <value in [drop, trap-to-host]>
          # ipv4_csum_err: <value in [drop, trap-to-host]>
          # ipv4_ihl_err: <value in [drop, trap-to-host]>
          # ipv4_len_err: <value in [drop, trap-to-host]>
          # ipv4_opt_err: <value in [drop, trap-to-host]>
          # ipv4_ttlzero_err: <value in [drop, trap-to-host]>
          # ipv4_ver_err: <value in [drop, trap-to-host]>
          # ipv6_exthdr_len_err: <value in [drop, trap-to-host]>
          # ipv6_exthdr_order_err: <value in [drop, trap-to-host]>
          # ipv6_ihl_err: <value in [drop, trap-to-host]>
          # ipv6_plen_zero: <value in [drop, trap-to-host]>
          # ipv6_ver_err: <value in [drop, trap-to-host]>
          # tcp_csum_err: <value in [drop, trap-to-host]>
          # tcp_hlen_err: <value in [drop, trap-to-host]>
          # tcp_plen_err: <value in [drop, trap-to-host]>
          # udp_csum_err: <value in [drop, trap-to-host]>
          # udp_hlen_err: <value in [drop, trap-to-host]>
          # udp_len_err: <value in [drop, trap-to-host]>
          # udp_plen_err: <value in [drop, trap-to-host]>
          # udplite_cover_err: <value in [drop, trap-to-host]>
          # udplite_csum_err: <value in [drop, trap-to-host, allow]>
          # unknproto_minlen_err: <value in [drop, trap-to-host]>
          # tcp_fin_only: <value in [allow, drop, trap-to-host]>
          # ipv4_optsecurity: <value in [allow, drop, trap-to-host]>
          # ipv6_optralert: <value in [allow, drop, trap-to-host]>
          # tcp_syn_fin: <value in [allow, drop, trap-to-host]>
          # ipv4_proto_err: <value in [allow, drop, trap-to-host]>
          # ipv6_saddr_err: <value in [allow, drop, trap-to-host]>
          # icmp_frag: <value in [allow, drop, trap-to-host]>
          # ipv4_optssrr: <value in [allow, drop, trap-to-host]>
          # ipv6_opthomeaddr: <value in [allow, drop, trap-to-host]>
          # udp_land: <value in [allow, drop, trap-to-host]>
          # ipv6_optinvld: <value in [allow, drop, trap-to-host]>
          # tcp_fin_noack: <value in [allow, drop, trap-to-host]>
          # ipv6_proto_err: <value in [allow, drop, trap-to-host]>
          # tcp_land: <value in [allow, drop, trap-to-host]>
          # ipv4_unknopt: <value in [allow, drop, trap-to-host]>
          # ipv4_optstream: <value in [allow, drop, trap-to-host]>
          # ipv6_optjumbo: <value in [allow, drop, trap-to-host]>
          # icmp_land: <value in [allow, drop, trap-to-host]>
          # tcp_winnuke: <value in [allow, drop, trap-to-host]>
          # ipv6_daddr_err: <value in [allow, drop, trap-to-host]>
          # ipv4_land: <value in [allow, drop, trap-to-host]>
          # ipv6_opttunnel: <value in [allow, drop, trap-to-host]>
          # tcp_no_flag: <value in [allow, drop, trap-to-host]>
          # ipv6_land: <value in [allow, drop, trap-to-host]>
          # ipv4_optlsrr: <value in [allow, drop, trap-to-host]>
          # ipv4_opttimestamp: <value in [allow, drop, trap-to-host]>
          # ipv4_optrr: <value in [allow, drop, trap-to-host]>
          # ipv6_optnsap: <value in [allow, drop, trap-to-host]>
          # ipv6_unknopt: <value in [allow, drop, trap-to-host]>
          # tcp_syn_data: <value in [allow, drop, trap-to-host]>
          # ipv6_optendpid: <value in [allow, drop, trap-to-host]>
          # gtpu_plen_err: <value in [drop, trap-to-host]>
          # vxlan_minlen_err: <value in [drop, trap-to-host]>
          # capwap_minlen_err: <value in [drop, trap-to-host]>
          # gre_csum_err: <value in [drop, trap-to-host, allow]>
          # nvgre_minlen_err: <value in [drop, trap-to-host]>
          # sctp_l4len_err: <value in [drop, trap-to-host]>
          # tcp_hlenvsl4len_err: <value in [drop, trap-to-host]>
          # sctp_crc_err: <value in [drop, trap-to-host]>
          # sctp_clen_err: <value in [drop, trap-to-host]>
          # uesp_minlen_err: <value in [drop, trap-to-host]>
          # sctp_csum_err: <value in [allow, drop, trap-to-host]>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/system/npu/fp-anomaly',
        '/pm/config/global/obj/system/npu/fp-anomaly'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_fpanomaly': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'esp-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'icmp-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'icmp-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-ihl-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-opt-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-ttlzero-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-ver-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-exthdr-len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-exthdr-order-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-ihl-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-plen-zero': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-ver-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-hlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-plen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-hlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-plen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udplite-cover-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udplite-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host', 'allow'], 'type': 'str'},
                'unknproto-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-only': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optsecurity': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optralert': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-fin': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-proto-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-saddr-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'icmp-frag': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optssrr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opthomeaddr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'udp-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optinvld': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-noack': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-proto-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-unknopt': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optstream': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optjumbo': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'icmp-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-winnuke': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-daddr-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opttunnel': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-no-flag': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optlsrr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-opttimestamp': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optrr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optnsap': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-unknopt': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-data': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optendpid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'gtpu-plen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'vxlan-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'capwap-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'gre-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host', 'allow'], 'type': 'str'},
                'nvgre-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-l4len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-hlenvsl4len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-crc-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-clen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'uesp-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-csum-err': {'v_range': [['7.2.5', '7.2.11'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_fpanomaly'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
