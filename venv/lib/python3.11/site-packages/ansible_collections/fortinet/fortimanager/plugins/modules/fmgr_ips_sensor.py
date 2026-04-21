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
module: fmgr_ips_sensor
short_description: Configure IPS sensor.
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
    ips_sensor:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            block_malicious_url:
                aliases: ['block-malicious-url']
                type: str
                description: Enable/disable malicious URL blocking.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Action taken with traffic in which signatures are detected.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                            - 'default'
                    application:
                        type: raw
                        description: (list) Applications to be protected.
                    exempt_ip:
                        aliases: ['exempt-ip']
                        type: list
                        elements: dict
                        description: Exempt ip.
                        suboptions:
                            dst_ip:
                                aliases: ['dst-ip']
                                type: str
                                description: Destination IP address and netmask.
                            id:
                                type: int
                                description: Exempt IP ID.
                            src_ip:
                                aliases: ['src-ip']
                                type: str
                                description: Source IP address and netmask.
                    id:
                        type: int
                        description: Rule ID in IPS database
                    location:
                        type: raw
                        description: (list) Protect client or server traffic.
                    log:
                        type: str
                        description: Enable/disable logging of signatures included in filter.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_attack_context:
                        aliases: ['log-attack-context']
                        type: str
                        description: Enable/disable logging of attack context
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        aliases: ['log-packet']
                        type: str
                        description: Enable/disable packet logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    os:
                        type: raw
                        description: (list) Operating systems to be protected.
                    protocol:
                        type: raw
                        description: (list) Protocols to be examined.
                    quarantine:
                        type: str
                        description: Quarantine method.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine_expiry:
                        aliases: ['quarantine-expiry']
                        type: str
                        description: Duration of quarantine.
                    quarantine_log:
                        aliases: ['quarantine-log']
                        type: str
                        description: Enable/disable quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_count:
                        aliases: ['rate-count']
                        type: int
                        description: Count of the rate.
                    rate_duration:
                        aliases: ['rate-duration']
                        type: int
                        description: Duration
                    rate_mode:
                        aliases: ['rate-mode']
                        type: str
                        description: Rate limit mode.
                        choices:
                            - 'periodical'
                            - 'continuous'
                    rate_track:
                        aliases: ['rate-track']
                        type: str
                        description: Track the packet protocol field.
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                            - 'dhcp-client-mac'
                            - 'dns-domain'
                    rule:
                        type: raw
                        description: (list or str) Identifies the predefined or custom IPS signatures to add to the sensor.
                    severity:
                        type: raw
                        description: (list) Relative severity of the signature, from info to critical.
                    status:
                        type: str
                        description: Status of the signatures included in filter.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    tags:
                        type: str
                        description: Assign a custom tag filter to the IPS sensor.
                    cve:
                        type: raw
                        description: (list) List of CVE IDs of the signatures to add to the sensor
                    default_action:
                        aliases: ['default-action']
                        type: str
                        description: Signature default action filter.
                        choices:
                            - 'block'
                            - 'pass'
                            - 'all'
                            - 'drop'
                    default_status:
                        aliases: ['default-status']
                        type: str
                        description: Signature default status filter.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'all'
                    last_modified:
                        aliases: ['last-modified']
                        type: raw
                        description: (list or str) Filter by signature last modified date.
                    vuln_type:
                        aliases: ['vuln-type']
                        type: raw
                        description: (list) List of signature vulnerability types to filter by.
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable extended logging.
                choices:
                    - 'disable'
                    - 'enable'
            filter:
                type: list
                elements: dict
                description: Filter.
                suboptions:
                    action:
                        type: str
                        description: Action of selected rules.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'default'
                            - 'reset'
                    application:
                        type: raw
                        description: (list) Vulnerable application filter.
                    location:
                        type: raw
                        description: (list) Vulnerability location filter.
                    log:
                        type: str
                        description: Enable/disable logging of selected rules.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    log_packet:
                        aliases: ['log-packet']
                        type: str
                        description: Enable/disable packet logging of selected rules.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    name:
                        type: str
                        description: Filter name.
                    os:
                        type: raw
                        description: (list) Vulnerable OS filter.
                    protocol:
                        type: raw
                        description: (list) Vulnerable protocol filter.
                    quarantine:
                        type: str
                        description: Quarantine IP or interface.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine_expiry:
                        aliases: ['quarantine-expiry']
                        type: int
                        description: Duration of quarantine in minute.
                    quarantine_log:
                        aliases: ['quarantine-log']
                        type: str
                        description: Enable/disable logging of selected quarantine.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: raw
                        description: (list) Vulnerability severity filter.
                    status:
                        type: str
                        description: Selected rules status.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
            name:
                type: str
                description: Sensor name.
                required: true
            override:
                type: list
                elements: dict
                description: Override.
                suboptions:
                    action:
                        type: str
                        description: Action of override rule.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                    exempt_ip:
                        aliases: ['exempt-ip']
                        type: list
                        elements: dict
                        description: Exempt ip.
                        suboptions:
                            dst_ip:
                                aliases: ['dst-ip']
                                type: str
                                description: Destination IP address and netmask.
                            id:
                                type: int
                                description: Exempt IP ID.
                            src_ip:
                                aliases: ['src-ip']
                                type: str
                                description: Source IP address and netmask.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        aliases: ['log-packet']
                        type: str
                        description: Enable/disable packet logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    quarantine:
                        type: str
                        description: Quarantine IP or interface.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine_expiry:
                        aliases: ['quarantine-expiry']
                        type: int
                        description: Duration of quarantine in minute.
                    quarantine_log:
                        aliases: ['quarantine-log']
                        type: str
                        description: Enable/disable logging of selected quarantine.
                        choices:
                            - 'disable'
                            - 'enable'
                    rule_id:
                        aliases: ['rule-id']
                        type: int
                        description: Override rule ID.
                    status:
                        type: str
                        description: Enable/disable status of override rule.
                        choices:
                            - 'disable'
                            - 'enable'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group.
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Block or monitor connections to Botnet servers, or disable Botnet scanning.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            _baseline:
                type: str
                description: Baseline.
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
    - name: Configure IPS sensor.
      fortinet.fortimanager.fmgr_ips_sensor:
        bypass_validation: false
        adom: ansible
        state: present
        ips_sensor:
          block_malicious_url: disable
          comment: "ansible-comment"
          name: "ansible-test-ipssensor"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPS sensors
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "ips_sensor"
          params:
            adom: "ansible"
            sensor: "your_value"
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
        '/pm/config/adom/{adom}/obj/ips/sensor',
        '/pm/config/global/obj/ips/sensor',
        '/pm/config/adom/{adom}/obj/global/ips/sensor',
        '/pm/config/global/obj/global/ips/sensor'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ips_sensor': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'block-malicious-url': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'type': 'str'},
                'entries': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['pass', 'block', 'reset', 'default'], 'type': 'str'},
                        'application': {'type': 'raw'},
                        'exempt-ip': {
                            'type': 'list',
                            'options': {'dst-ip': {'type': 'str'}, 'id': {'type': 'int'}, 'src-ip': {'type': 'str'}},
                            'elements': 'dict'
                        },
                        'id': {'type': 'int'},
                        'location': {'type': 'raw'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-attack-context': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-packet': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'os': {'type': 'raw'},
                        'protocol': {'type': 'raw'},
                        'quarantine': {'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                        'quarantine-expiry': {'type': 'str'},
                        'quarantine-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-count': {'type': 'int'},
                        'rate-duration': {'type': 'int'},
                        'rate-mode': {'choices': ['periodical', 'continuous'], 'type': 'str'},
                        'rate-track': {'choices': ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain'], 'type': 'str'},
                        'rule': {'type': 'raw'},
                        'severity': {'type': 'raw'},
                        'status': {'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                        'tags': {'v_range': [['6.2.0', '6.4.15']], 'type': 'str'},
                        'cve': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                        'default-action': {'v_range': [['7.2.0', '']], 'choices': ['block', 'pass', 'all', 'drop'], 'type': 'str'},
                        'default-status': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable', 'all'], 'type': 'str'},
                        'last-modified': {'v_range': [['7.2.0', '']], 'type': 'raw'},
                        'vuln-type': {'v_range': [['7.2.0', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'extended-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'filter': {
                    'v_range': [['6.0.0', '6.2.0']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['pass', 'block', 'default', 'reset'], 'type': 'str'},
                        'application': {'v_range': [['6.0.0', '6.2.0']], 'type': 'raw'},
                        'location': {'v_range': [['6.0.0', '6.2.0']], 'type': 'raw'},
                        'log': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                        'log-packet': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                        'name': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'os': {'v_range': [['6.0.0', '6.2.0']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.0.0', '6.2.0']], 'type': 'raw'},
                        'quarantine': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                        'quarantine-expiry': {'v_range': [['6.0.0', '6.2.0']], 'type': 'int'},
                        'quarantine-log': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'severity': {'v_range': [['6.0.0', '6.2.0']], 'type': 'raw'},
                        'status': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'override': {
                    'v_range': [['6.0.0', '6.2.0']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['pass', 'block', 'reset'], 'type': 'str'},
                        'exempt-ip': {
                            'v_range': [['6.0.0', '6.2.0']],
                            'type': 'list',
                            'options': {
                                'dst-ip': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                                'id': {'v_range': [['6.0.0', '6.2.0']], 'type': 'int'},
                                'src-ip': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'log': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-packet': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quarantine': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                        'quarantine-expiry': {'v_range': [['6.0.0', '6.2.0']], 'type': 'int'},
                        'quarantine-log': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rule-id': {'v_range': [['6.0.0', '6.2.0']], 'type': 'int'},
                        'status': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'replacemsg-group': {'type': 'str'},
                'scan-botnet-connections': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                '_baseline': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_sensor'),
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
