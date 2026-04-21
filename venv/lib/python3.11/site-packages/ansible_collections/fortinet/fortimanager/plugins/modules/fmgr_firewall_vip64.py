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
module: fmgr_firewall_vip64
short_description: Configure IPv6 to IPv4 virtual IPs.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
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
    firewall_vip64:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            arp_reply:
                aliases: ['arp-reply']
                type: str
                description: Enable ARP reply.
                choices:
                    - 'disable'
                    - 'enable'
            color:
                type: int
                description: Color of icon on the GUI.
            comment:
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
                    arp_reply:
                        aliases: ['arp-reply']
                        type: str
                        description: Arp reply.
                        choices:
                            - 'disable'
                            - 'enable'
                    color:
                        type: int
                        description: Color.
                    comment:
                        type: str
                        description: Comment.
                    extip:
                        type: str
                        description: Extip.
                    extport:
                        type: str
                        description: Extport.
                    id:
                        type: int
                        description: Id.
                    ldb_method:
                        aliases: ['ldb-method']
                        type: str
                        description: Ldb method.
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'least-session'
                            - 'least-rtt'
                            - 'first-alive'
                    mappedip:
                        type: str
                        description: Mappedip.
                    mappedport:
                        type: str
                        description: Mappedport.
                    monitor:
                        type: raw
                        description: (list or str) Monitor.
                    portforward:
                        type: str
                        description: Portforward.
                        choices:
                            - 'disable'
                            - 'enable'
                    protocol:
                        type: str
                        description: Protocol.
                        choices:
                            - 'tcp'
                            - 'udp'
                    server_type:
                        aliases: ['server-type']
                        type: str
                        description: Server type.
                        choices:
                            - 'http'
                            - 'tcp'
                            - 'udp'
                            - 'ip'
                    src_filter:
                        aliases: ['src-filter']
                        type: raw
                        description: (list) Src filter.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'static-nat'
                            - 'server-load-balance'
                    uuid:
                        type: str
                        description: Uuid.
            extip:
                type: str
                description: Start-external-IP [-end-external-IP].
            extport:
                type: str
                description: External service port.
            id:
                type: int
                description: Custom defined id.
            ldb_method:
                aliases: ['ldb-method']
                type: str
                description: Load balance method.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
            mappedip:
                type: str
                description: Start-mapped-IP [-end-mapped-IP].
            mappedport:
                type: str
                description: Mapped service port.
            monitor:
                type: raw
                description: (list or str) Health monitors.
            name:
                type: str
                description: VIP64 name.
                required: true
            portforward:
                type: str
                description: Enable port forwarding.
                choices:
                    - 'disable'
                    - 'enable'
            protocol:
                type: str
                description: Mapped port protocol.
                choices:
                    - 'tcp'
                    - 'udp'
            realservers:
                type: list
                elements: dict
                description: Realservers.
                suboptions:
                    client_ip:
                        aliases: ['client-ip']
                        type: str
                        description: Restrict server to a client IP in this range.
                    healthcheck:
                        type: str
                        description: Per server health check.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vip'
                    holddown_interval:
                        aliases: ['holddown-interval']
                        type: int
                        description: Hold down interval.
                    id:
                        type: int
                        description: Real server ID.
                    ip:
                        type: str
                        description: Mapped server IP.
                    max_connections:
                        aliases: ['max-connections']
                        type: int
                        description: Maximum number of connections allowed to server.
                    monitor:
                        type: raw
                        description: (list or str) Health monitors.
                    port:
                        type: int
                        description: Mapped server port.
                    status:
                        type: str
                        description: Server administrative status.
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
                    weight:
                        type: int
                        description: Weight.
            server_type:
                aliases: ['server-type']
                type: str
                description: Server type.
                choices:
                    - 'http'
                    - 'tcp'
                    - 'udp'
                    - 'ip'
            src_filter:
                aliases: ['src-filter']
                type: raw
                description: (list) Source IP6 filter
            type:
                type: str
                description: VIP type
                choices:
                    - 'static-nat'
                    - 'server-load-balance'
            uuid:
                type: str
                description: Universally Unique Identifier
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
    - name: Configure IPv6 to IPv4 virtual IPs.
      fortinet.fortimanager.fmgr_firewall_vip64:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_vip64:
          arp_reply: enable
          color: 1
          comment: "anisble-comment"
          id: 1
          name: "ansible-test-vip64"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv6 to IPv4 virtual IPs
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip64"
          params:
            adom: "ansible"
            vip64: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/vip64',
        '/pm/config/global/obj/firewall/vip64'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip64': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'color': {'type': 'int'},
                        'comment': {'type': 'str'},
                        'extip': {'type': 'str'},
                        'extport': {'type': 'str'},
                        'id': {'type': 'int'},
                        'ldb-method': {'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive'], 'type': 'str'},
                        'mappedip': {'type': 'str'},
                        'mappedport': {'type': 'str'},
                        'monitor': {'type': 'raw'},
                        'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'protocol': {'choices': ['tcp', 'udp'], 'type': 'str'},
                        'server-type': {'choices': ['http', 'tcp', 'udp', 'ip'], 'type': 'str'},
                        'src-filter': {'type': 'raw'},
                        'type': {'choices': ['static-nat', 'server-load-balance'], 'type': 'str'},
                        'uuid': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'extip': {'type': 'str'},
                'extport': {'type': 'str'},
                'id': {'type': 'int'},
                'ldb-method': {'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive'], 'type': 'str'},
                'mappedip': {'type': 'str'},
                'mappedport': {'type': 'str'},
                'monitor': {'type': 'raw'},
                'name': {'required': True, 'type': 'str'},
                'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'choices': ['tcp', 'udp'], 'type': 'str'},
                'realservers': {
                    'type': 'list',
                    'options': {
                        'client-ip': {'type': 'str'},
                        'healthcheck': {'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                        'holddown-interval': {'type': 'int'},
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'max-connections': {'type': 'int'},
                        'monitor': {'type': 'raw'},
                        'port': {'type': 'int'},
                        'status': {'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'weight': {'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'choices': ['http', 'tcp', 'udp', 'ip'], 'type': 'str'},
                'src-filter': {'type': 'raw'},
                'type': {'choices': ['static-nat', 'server-load-balance'], 'type': 'str'},
                'uuid': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip64'),
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
