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
module: fmgr_certificate_template
short_description: Certificate template
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
    certificate_template:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            city:
                type: str
                description: City.
            country:
                type: str
                description: Country.
            digest_type:
                aliases: ['digest-type']
                type: str
                description: Digest type.
                choices:
                    - 'sha1'
                    - 'sha256'
            email:
                type: str
                description: Email.
            id_type:
                aliases: ['id-type']
                type: str
                description: Id type.
                choices:
                    - 'host-ip'
                    - 'domain-name'
                    - 'email'
            key_size:
                aliases: ['key-size']
                type: str
                description: Key size.
                choices:
                    - '512'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '4096'
            key_type:
                aliases: ['key-type']
                type: str
                description: Key type.
                choices:
                    - 'rsa'
                    - 'ec'
            name:
                type: str
                description: Name.
                required: true
            organization:
                type: str
                description: Organization.
            organization_unit:
                aliases: ['organization-unit']
                type: raw
                description: (list) Organization unit.
            scep_password:
                aliases: ['scep-password']
                type: raw
                description: (list) Scep password.
            scep_server:
                aliases: ['scep-server']
                type: str
                description: Scep server.
            state:
                type: str
                description: State.
            subject_name:
                aliases: ['subject-name']
                type: str
                description: Subject name.
            type:
                type: str
                description: Type.
                choices:
                    - 'external'
                    - 'local'
            curve_name:
                aliases: ['curve-name']
                type: str
                description: Curve name.
                choices:
                    - 'secp256r1'
                    - 'secp384r1'
                    - 'secp521r1'
            scep_ca_identifier:
                aliases: ['scep-ca-identifier']
                type: str
                description: Scep ca identifier.
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
    - name: No description
      fortinet.fortimanager.fmgr_certificate_template:
        adom: ansible
        state: present
        certificate_template:
          # digest_type: sha1
          id_type: host-ip
          key_size: 512
          key_type: rsa
          name: "ansible-test"
          scep_password: "fortinet1"
          type: external

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the scripts
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "certificate_template"
          params:
            adom: "ansible"
            template: "your_value"
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
        '/pm/config/adom/{adom}/obj/certificate/template',
        '/pm/config/global/obj/certificate/template'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'certificate_template': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'city': {'type': 'str'},
                'country': {'type': 'str'},
                'digest-type': {'choices': ['sha1', 'sha256'], 'type': 'str'},
                'email': {'type': 'str'},
                'id-type': {'choices': ['host-ip', 'domain-name', 'email'], 'type': 'str'},
                'key-size': {'choices': ['512', '1024', '1536', '2048', '4096'], 'type': 'str'},
                'key-type': {'choices': ['rsa', 'ec'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'organization': {'type': 'str'},
                'organization-unit': {'type': 'raw'},
                'scep-password': {'no_log': True, 'type': 'raw'},
                'scep-server': {'type': 'str'},
                'state': {'type': 'str'},
                'subject-name': {'type': 'str'},
                'type': {'choices': ['external', 'local'], 'type': 'str'},
                'curve-name': {'v_range': [['6.2.1', '']], 'choices': ['secp256r1', 'secp384r1', 'secp521r1'], 'type': 'str'},
                'scep-ca-identifier': {'v_range': [['7.0.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'certificate_template'),
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
