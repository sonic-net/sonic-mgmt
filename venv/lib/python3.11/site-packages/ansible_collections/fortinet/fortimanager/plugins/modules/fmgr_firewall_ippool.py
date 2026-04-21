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
module: fmgr_firewall_ippool
short_description: Configure IPv4 IP pools.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    firewall_ippool:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            arp_intf:
                aliases: ['arp-intf']
                type: str
                description: Select an interface from available options that will reply to ARP requests.
            arp_reply:
                aliases: ['arp-reply']
                type: str
                description: Enable/disable replying to ARP requests when an IP Pool is added to a policy
                choices:
                    - 'disable'
                    - 'enable'
            associated_interface:
                aliases: ['associated-interface']
                type: str
                description: Associated interface name.
            block_size:
                aliases: ['block-size']
                type: int
                description: Number of addresses in a block
            comments:
                type: str
                description: Comment.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    arp_intf:
                        aliases: ['arp-intf']
                        type: str
                        description: Arp intf.
                    arp_reply:
                        aliases: ['arp-reply']
                        type: str
                        description: Arp reply.
                        choices:
                            - 'disable'
                            - 'enable'
                    associated_interface:
                        aliases: ['associated-interface']
                        type: str
                        description: Associated interface.
                    block_size:
                        aliases: ['block-size']
                        type: int
                        description: Block size.
                    comments:
                        type: str
                        description: Comments.
                    endip:
                        type: str
                        description: Endip.
                    num_blocks_per_user:
                        aliases: ['num-blocks-per-user']
                        type: int
                        description: Num blocks per user.
                    pba_timeout:
                        aliases: ['pba-timeout']
                        type: int
                        description: Pba timeout.
                    permit_any_host:
                        aliases: ['permit-any-host']
                        type: str
                        description: Permit any host.
                        choices:
                            - 'disable'
                            - 'enable'
                    source_endip:
                        aliases: ['source-endip']
                        type: str
                        description: Source endip.
                    source_startip:
                        aliases: ['source-startip']
                        type: str
                        description: Source startip.
                    startip:
                        type: str
                        description: Startip.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'overload'
                            - 'one-to-one'
                            - 'fixed-port-range'
                            - 'port-block-allocation'
                            - 'cgn-resource-allocation'
                    cgn_block_size:
                        aliases: ['cgn-block-size']
                        type: int
                        description: Cgn block size.
                    cgn_client_endip:
                        aliases: ['cgn-client-endip']
                        type: str
                        description: Cgn client endip.
                    cgn_client_startip:
                        aliases: ['cgn-client-startip']
                        type: str
                        description: Cgn client startip.
                    cgn_fixedalloc:
                        aliases: ['cgn-fixedalloc']
                        type: str
                        description: Cgn fixedalloc.
                        choices:
                            - 'disable'
                            - 'enable'
                    cgn_overload:
                        aliases: ['cgn-overload']
                        type: str
                        description: Cgn overload.
                        choices:
                            - 'disable'
                            - 'enable'
                    cgn_port_end:
                        aliases: ['cgn-port-end']
                        type: int
                        description: Cgn port end.
                    cgn_port_start:
                        aliases: ['cgn-port-start']
                        type: int
                        description: Cgn port start.
                    cgn_spa:
                        aliases: ['cgn-spa']
                        type: str
                        description: Cgn spa.
                        choices:
                            - 'disable'
                            - 'enable'
                    utilization_alarm_clear:
                        aliases: ['utilization-alarm-clear']
                        type: int
                        description: Utilization alarm clear.
                    utilization_alarm_raise:
                        aliases: ['utilization-alarm-raise']
                        type: int
                        description: Utilization alarm raise.
                    endport:
                        type: int
                        description: Final port number
                    port_per_user:
                        aliases: ['port-per-user']
                        type: int
                        description: Number of port for each user
                    startport:
                        type: int
                        description: First port number
                    add_nat64_route:
                        aliases: ['add-nat64-route']
                        type: str
                        description: Enable/disable adding NAT64 route.
                        choices:
                            - 'disable'
                            - 'enable'
                    cgn_client_ipv6shift:
                        aliases: ['cgn-client-ipv6shift']
                        type: int
                        description: IPv6 shift for fixed-allocation.
                    nat64:
                        type: str
                        description: Enable/disable NAT64.
                        choices:
                            - 'disable'
                            - 'enable'
                    subnet_broadcast_in_ippool:
                        aliases: ['subnet-broadcast-in-ippool']
                        type: str
                        description: Enable/disable inclusion of the subnetwork address and broadcast IP address in the NAT64 IP pool.
                        choices:
                            - 'disable'
                            - 'enable'
                    exclude_ip:
                        aliases: ['exclude-ip']
                        type: raw
                        description: (list) Exclude IPs x.
                    pba_interim_log:
                        aliases: ['pba-interim-log']
                        type: int
                        description: Port block allocation interim logging interval
                    client_prefix_length:
                        aliases: ['client-prefix-length']
                        type: int
                        description: Subnet length of a single deterministic NAT64 client
                    icmp_session_quota:
                        aliases: ['icmp-session-quota']
                        type: int
                        description: Maximum number of concurrent ICMP sessions allowed per client
                    privileged_port_use_pba:
                        aliases: ['privileged-port-use-pba']
                        type: str
                        description: Enable/disable selection of the external port from the port block allocation for NATing privileged ports
                        choices:
                            - 'disable'
                            - 'enable'
                    source_prefix6:
                        aliases: ['source-prefix6']
                        type: str
                        description: Source IPv6 network to be translated
                    tcp_session_quota:
                        aliases: ['tcp-session-quota']
                        type: int
                        description: Maximum number of concurrent TCP sessions allowed per client
                    udp_session_quota:
                        aliases: ['udp-session-quota']
                        type: int
                        description: Maximum number of concurrent UDP sessions allowed per client
            endip:
                type: str
                description: Final IPv4 address
            name:
                type: str
                description: IP pool name.
                required: true
            num_blocks_per_user:
                aliases: ['num-blocks-per-user']
                type: int
                description: Number of addresses blocks that can be used by a user
            pba_timeout:
                aliases: ['pba-timeout']
                type: int
                description: Port block allocation timeout
            permit_any_host:
                aliases: ['permit-any-host']
                type: str
                description: Enable/disable full cone NAT.
                choices:
                    - 'disable'
                    - 'enable'
            source_endip:
                aliases: ['source-endip']
                type: str
                description: Final IPv4 address
            source_startip:
                aliases: ['source-startip']
                type: str
                description: First IPv4 address
            startip:
                type: str
                description: First IPv4 address
            type:
                type: str
                description: IP pool type
                choices:
                    - 'overload'
                    - 'one-to-one'
                    - 'fixed-port-range'
                    - 'port-block-allocation'
                    - 'cgn-resource-allocation'
            utilization_alarm_clear:
                aliases: ['utilization-alarm-clear']
                type: int
                description: Pool utilization alarm clear threshold
            cgn_fixedalloc:
                aliases: ['cgn-fixedalloc']
                type: str
                description: Enable/disable fixed-allocation mode.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_client_startip:
                aliases: ['cgn-client-startip']
                type: str
                description: First client IPv4 address
            cgn_client_endip:
                aliases: ['cgn-client-endip']
                type: str
                description: Final client IPv4 address
            cgn_overload:
                aliases: ['cgn-overload']
                type: str
                description: Enable/disable overload mode.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_block_size:
                aliases: ['cgn-block-size']
                type: int
                description: Number of ports in a block
            utilization_alarm_raise:
                aliases: ['utilization-alarm-raise']
                type: int
                description: Pool utilization alarm raise threshold
            cgn_port_start:
                aliases: ['cgn-port-start']
                type: int
                description: Starting public port can be allocated.
            cgn_spa:
                aliases: ['cgn-spa']
                type: str
                description: Enable/disable single port allocation mode.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_port_end:
                aliases: ['cgn-port-end']
                type: int
                description: Ending public port can be allocated.
            endport:
                type: int
                description: Final port number
            port_per_user:
                aliases: ['port-per-user']
                type: int
                description: Number of port for each user
            startport:
                type: int
                description: First port number
            add_nat64_route:
                aliases: ['add-nat64-route']
                type: str
                description: Enable/disable adding NAT64 route.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_client_ipv6shift:
                aliases: ['cgn-client-ipv6shift']
                type: int
                description: IPv6 shift for fixed-allocation.
            subnet_broadcast_in_ippool:
                aliases: ['subnet-broadcast-in-ippool']
                type: str
                description: Enable/disable inclusion of the subnetwork address and broadcast IP address in the NAT64 IP pool.
                choices:
                    - 'disable'
                    - 'enable'
            exclude_ip:
                aliases: ['exclude-ip']
                type: raw
                description: (list) Exclude IPs x.
            pba_interim_log:
                aliases: ['pba-interim-log']
                type: int
                description: Port block allocation interim logging interval
            client_prefix_length:
                aliases: ['client-prefix-length']
                type: int
                description: Subnet length of a single deterministic NAT64 client
            icmp_session_quota:
                aliases: ['icmp-session-quota']
                type: int
                description: Maximum number of concurrent ICMP sessions allowed per client
            privileged_port_use_pba:
                aliases: ['privileged-port-use-pba']
                type: str
                description: Enable/disable selection of the external port from the port block allocation for NATing privileged ports
                choices:
                    - 'disable'
                    - 'enable'
            source_prefix6:
                aliases: ['source-prefix6']
                type: str
                description: Source IPv6 network to be translated
            tcp_session_quota:
                aliases: ['tcp-session-quota']
                type: int
                description: Maximum number of concurrent TCP sessions allowed per client
            udp_session_quota:
                aliases: ['udp-session-quota']
                type: int
                description: Maximum number of concurrent UDP sessions allowed per client
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure IPv4 IP pools.
      fortinet.fortimanager.fmgr_firewall_ippool:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_ippool:
          comments: "ansible-comment"
          endip: "222.222.222.254"
          name: "ansible-test"
          startip: "222.222.222.0"
          type: overload # <value in [overload, one-to-one, fixed-port-range, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv4 IP pools
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_ippool"
          params:
            adom: "ansible"
            ippool: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/ippool',
        '/pm/config/global/obj/firewall/ippool'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_ippool': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'arp-intf': {'type': 'str'},
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'associated-interface': {'type': 'str'},
                'block-size': {'type': 'int'},
                'comments': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'arp-intf': {'type': 'str'},
                        'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'associated-interface': {'type': 'str'},
                        'block-size': {'type': 'int'},
                        'comments': {'type': 'str'},
                        'endip': {'type': 'str'},
                        'num-blocks-per-user': {'type': 'int'},
                        'pba-timeout': {'type': 'int'},
                        'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-endip': {'type': 'str'},
                        'source-startip': {'type': 'str'},
                        'startip': {'type': 'str'},
                        'type': {
                            'choices': ['overload', 'one-to-one', 'fixed-port-range', 'port-block-allocation', 'cgn-resource-allocation'],
                            'type': 'str'
                        },
                        'cgn-block-size': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                        'cgn-client-endip': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                        'cgn-client-startip': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                        'cgn-fixedalloc': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cgn-overload': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cgn-port-end': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                        'cgn-port-start': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                        'cgn-spa': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'utilization-alarm-clear': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                        'utilization-alarm-raise': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                        'endport': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'port-per-user': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'startport': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'add-nat64-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cgn-client-ipv6shift': {'v_range': [['6.2.9', '6.2.13'], ['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                        'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'subnet-broadcast-in-ippool': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'exclude-ip': {'v_range': [['7.2.2', '']], 'type': 'raw'},
                        'pba-interim-log': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'client-prefix-length': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'icmp-session-quota': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'privileged-port-use-pba': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-prefix6': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'tcp-session-quota': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'udp-session-quota': {'v_range': [['7.6.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'endip': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'num-blocks-per-user': {'type': 'int'},
                'pba-timeout': {'type': 'int'},
                'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'source-endip': {'type': 'str'},
                'source-startip': {'type': 'str'},
                'startip': {'type': 'str'},
                'type': {'choices': ['overload', 'one-to-one', 'fixed-port-range', 'port-block-allocation', 'cgn-resource-allocation'], 'type': 'str'},
                'utilization-alarm-clear': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                'cgn-fixedalloc': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-client-startip': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                'cgn-client-endip': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'str'},
                'cgn-overload': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-block-size': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                'utilization-alarm-raise': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                'cgn-port-start': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                'cgn-spa': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-port-end': {'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']], 'type': 'int'},
                'endport': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'port-per-user': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'startport': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'add-nat64-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-client-ipv6shift': {'v_range': [['6.2.9', '6.2.13'], ['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                'subnet-broadcast-in-ippool': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'exclude-ip': {'v_range': [['7.2.2', '']], 'type': 'raw'},
                'pba-interim-log': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'client-prefix-length': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'icmp-session-quota': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'privileged-port-use-pba': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-prefix6': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'tcp-session-quota': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'udp-session-quota': {'v_range': [['7.6.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippool'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
