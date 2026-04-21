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
module: fmgr_devprof_system_snmp_community
short_description: SNMP community configuration.
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_snmp_community:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            events:
                type: list
                elements: str
                description: SNMP trap events.
                choices:
                    - 'cpu-high'
                    - 'mem-low'
                    - 'log-full'
                    - 'intf-ip'
                    - 'vpn-tun-up'
                    - 'vpn-tun-down'
                    - 'ha-switch'
                    - 'ha-hb-failure'
                    - 'ips-signature'
                    - 'ips-anomaly'
                    - 'av-virus'
                    - 'av-oversize'
                    - 'av-pattern'
                    - 'av-fragmented'
                    - 'fm-if-change'
                    - 'fm-conf-change'
                    - 'temperature-high'
                    - 'voltage-alert'
                    - 'ha-member-up'
                    - 'ha-member-down'
                    - 'ent-conf-change'
                    - 'av-conserve'
                    - 'av-bypass'
                    - 'av-oversize-passed'
                    - 'av-oversize-blocked'
                    - 'ips-pkg-update'
                    - 'power-supply-failure'
                    - 'amc-bypass'
                    - 'faz-disconnect'
                    - 'fan-failure'
                    - 'bgp-established'
                    - 'bgp-backward-transition'
                    - 'wc-ap-up'
                    - 'wc-ap-down'
                    - 'fswctl-session-up'
                    - 'fswctl-session-down'
                    - 'ips-fail-open'
                    - 'load-balance-real-server-down'
                    - 'device-new'
                    - 'enter-intf-bypass'
                    - 'exit-intf-bypass'
                    - 'per-cpu-high'
                    - 'power-blade-down'
                    - 'confsync_failure'
                    - 'dhcp'
                    - 'pool-usage'
                    - 'power-redundancy-degrade'
                    - 'power-redundancy-failure'
                    - 'ospf-nbr-state-change'
                    - 'ospf-virtnbr-state-change'
                    - 'disk-failure'
                    - 'disk-overload'
                    - 'faz-main-failover'
                    - 'faz-alt-failover'
                    - 'slbc'
                    - 'faz'
                    - 'power-supply'
                    - 'ippool'
                    - 'interface'
                    - 'security_level_change'
                    - 'cert-expiry'
                    - 'dio'
            hosts:
                type: list
                elements: dict
                description: Hosts.
                suboptions:
                    ha_direct:
                        aliases: ['ha-direct']
                        type: str
                        description: Enable/disable direct management of HA cluster members.
                        choices:
                            - 'disable'
                            - 'enable'
                    host_type:
                        aliases: ['host-type']
                        type: str
                        description: Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.
                        choices:
                            - 'any'
                            - 'query'
                            - 'trap'
                    id:
                        type: int
                        description: Host entry ID.
                    ip:
                        type: str
                        description: IPv4 address of the SNMP manager
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Source IPv4 address for SNMP traps.
                    interface_select_method:
                        aliases: ['interface-select-method']
                        type: str
                        description: Specify how to select outgoing interface to reach server.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    interface:
                        type: raw
                        description: (list) Specify outgoing interface to reach server.
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            hosts6:
                type: list
                elements: dict
                description: Hosts6.
                suboptions:
                    ha_direct:
                        aliases: ['ha-direct']
                        type: str
                        description: Enable/disable direct management of HA cluster members.
                        choices:
                            - 'disable'
                            - 'enable'
                    host_type:
                        aliases: ['host-type']
                        type: str
                        description: Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.
                        choices:
                            - 'any'
                            - 'query'
                            - 'trap'
                    id:
                        type: int
                        description: Host6 entry ID.
                    ipv6:
                        type: str
                        description: SNMP manager IPv6 address prefix.
                    source_ipv6:
                        aliases: ['source-ipv6']
                        type: str
                        description: Source IPv6 address for SNMP traps.
                    interface:
                        type: raw
                        description: (list) Specify outgoing interface to reach server.
                    interface_select_method:
                        aliases: ['interface-select-method']
                        type: str
                        description: Specify how to select outgoing interface to reach server.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            id:
                type: int
                description: Community ID.
                required: true
            name:
                type: str
                description: Community name.
            query_v1_port:
                aliases: ['query-v1-port']
                type: int
                description: SNMP v1 query port
            query_v1_status:
                aliases: ['query-v1-status']
                type: str
                description: Enable/disable SNMP v1 queries.
                choices:
                    - 'disable'
                    - 'enable'
            query_v2c_port:
                aliases: ['query-v2c-port']
                type: int
                description: SNMP v2c query port
            query_v2c_status:
                aliases: ['query-v2c-status']
                type: str
                description: Enable/disable SNMP v2c queries.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable this SNMP community.
                choices:
                    - 'disable'
                    - 'enable'
            trap_v1_lport:
                aliases: ['trap-v1-lport']
                type: int
                description: SNMP v1 trap local port
            trap_v1_rport:
                aliases: ['trap-v1-rport']
                type: int
                description: SNMP v1 trap remote port
            trap_v1_status:
                aliases: ['trap-v1-status']
                type: str
                description: Enable/disable SNMP v1 traps.
                choices:
                    - 'disable'
                    - 'enable'
            trap_v2c_lport:
                aliases: ['trap-v2c-lport']
                type: int
                description: SNMP v2c trap local port
            trap_v2c_rport:
                aliases: ['trap-v2c-rport']
                type: int
                description: SNMP v2c trap remote port
            trap_v2c_status:
                aliases: ['trap-v2c-status']
                type: str
                description: Enable/disable SNMP v2c traps.
                choices:
                    - 'disable'
                    - 'enable'
            mib_view:
                aliases: ['mib-view']
                type: str
                description: SNMP access control MIB view.
            vdoms:
                type: raw
                description: (list) SNMP access control VDOMs.
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
    - name: SNMP community configuration.
      fortinet.fortimanager.fmgr_devprof_system_snmp_community:
        bypass_validation: false
        adom: ansible
        devprof: "ansible-test" # system template name, could find it in FortiManager UI: Device Manager --> Provisioning Templates --> System Templates
        state: present
        devprof_system_snmp_community:
          events:
            - cpu-high
            - mem-low
            - log-full
            - intf-ip
            - vpn-tun-up
            - vpn-tun-down
            - ha-switch
            - ha-hb-failure
            - ips-signature
            - ips-anomaly
            - av-virus
            - av-oversize
            - av-pattern
            - av-fragmented
            - fm-if-change
            - fm-conf-change
            - temperature-high
            - voltage-alert
            - ha-member-up
            - ha-member-down
            - ent-conf-change
            - av-conserve
            - av-bypass
            - av-oversize-passed
            - av-oversize-blocked
            - ips-pkg-update
            - power-supply-failure
            - amc-bypass
            - faz-disconnect
            - fan-failure
            - bgp-established
            - bgp-backward-transition
            - wc-ap-up
            - wc-ap-down
            - fswctl-session-up
            - fswctl-session-down
            - ips-fail-open
            - load-balance-real-server-down
            - device-new
            - enter-intf-bypass
            - exit-intf-bypass
            - per-cpu-high
            - power-blade-down
            - confsync_failure
          hosts:
            - ha_direct: enable
              host_type: any
              id: 1
          id: 1
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the communities in system template
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "devprof_system_snmp_community"
          params:
            adom: "ansible"
            devprof: "ansible-test" # system template name, could find it in FortiManager UI: Device Manager --> Provisioning Templates --> System Templates
            community: "your_value"
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_snmp_community': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'events': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'cpu-high', 'mem-low', 'log-full', 'intf-ip', 'vpn-tun-up', 'vpn-tun-down', 'ha-switch', 'ha-hb-failure', 'ips-signature',
                        'ips-anomaly', 'av-virus', 'av-oversize', 'av-pattern', 'av-fragmented', 'fm-if-change', 'fm-conf-change', 'temperature-high',
                        'voltage-alert', 'ha-member-up', 'ha-member-down', 'ent-conf-change', 'av-conserve', 'av-bypass', 'av-oversize-passed',
                        'av-oversize-blocked', 'ips-pkg-update', 'power-supply-failure', 'amc-bypass', 'faz-disconnect', 'fan-failure',
                        'bgp-established', 'bgp-backward-transition', 'wc-ap-up', 'wc-ap-down', 'fswctl-session-up', 'fswctl-session-down',
                        'ips-fail-open', 'load-balance-real-server-down', 'device-new', 'enter-intf-bypass', 'exit-intf-bypass', 'per-cpu-high',
                        'power-blade-down', 'confsync_failure', 'dhcp', 'pool-usage', 'power-redundancy-degrade', 'power-redundancy-failure',
                        'ospf-nbr-state-change', 'ospf-virtnbr-state-change', 'disk-failure', 'disk-overload', 'faz-main-failover', 'faz-alt-failover',
                        'slbc', 'faz', 'power-supply', 'ippool', 'interface', 'security_level_change', 'cert-expiry', 'dio'
                    ],
                    'elements': 'str'
                },
                'hosts': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'type': 'list',
                    'options': {
                        'ha-direct': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'host-type': {
                            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                            'choices': ['any', 'query', 'trap'],
                            'type': 'str'
                        },
                        'id': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'source-ip': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'interface-select-method': {'v_range': [['7.6.0', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                        'interface': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                        'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'hosts6': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'type': 'list',
                    'options': {
                        'ha-direct': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'host-type': {
                            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                            'choices': ['any', 'query', 'trap'],
                            'type': 'str'
                        },
                        'id': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                        'ipv6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'source-ipv6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                        'interface': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                        'interface-select-method': {'v_range': [['7.6.0', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                        'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'query-v1-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'query-v1-status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-v2c-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'query-v2c-status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-v1-lport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'trap-v1-rport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'trap-v1-status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-v2c-lport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'trap-v2c-rport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'trap-v2c-status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mib-view': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'vdoms': {'v_range': [['7.2.0', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_snmp_community'),
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
