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
module: fmgr_firewall_sslsshprofile_imaps
short_description: Configure IMAPS options.
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
    ssl-ssh-profile:
        description: Deprecated, please use "ssl_ssh_profile"
        type: str
    ssl_ssh_profile:
        description: The parameter (ssl-ssh-profile) in requested url.
        type: str
    firewall_sslsshprofile_imaps:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allow_invalid_server_cert:
                aliases: ['allow-invalid-server-cert']
                type: str
                description: When enabled, allows SSL sessions whose server certificate validation failed.
                choices:
                    - 'disable'
                    - 'enable'
            client_cert_request:
                aliases: ['client-cert-request']
                type: str
                description: Action based on client certificate request.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            ports:
                type: raw
                description: (list) Ports to use for scanning
            status:
                type: str
                description: Configure protocol inspection status.
                choices:
                    - 'disable'
                    - 'deep-inspection'
            unsupported_ssl:
                aliases: ['unsupported-ssl']
                type: str
                description: Action based on the SSL encryption used being unsupported.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            untrusted_cert:
                aliases: ['untrusted-cert']
                type: str
                description: Allow, ignore, or block the untrusted SSL session server certificate.
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            invalid_server_cert:
                aliases: ['invalid-server-cert']
                type: str
                description: Allow or block the invalid SSL session server certificate.
                choices:
                    - 'allow'
                    - 'block'
            sni_server_cert_check:
                aliases: ['sni-server-cert-check']
                type: str
                description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'strict'
            untrusted_server_cert:
                aliases: ['untrusted-server-cert']
                type: str
                description: Allow, ignore, or block the untrusted SSL session server certificate.
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            cert_validation_failure:
                aliases: ['cert-validation-failure']
                type: str
                description: Action based on certificate validation failure.
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            cert_validation_timeout:
                aliases: ['cert-validation-timeout']
                type: str
                description: Action based on certificate validation timeout.
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            client_certificate:
                aliases: ['client-certificate']
                type: str
                description: Action based on received client certificate.
                choices:
                    - 'bypass'
                    - 'inspect'
                    - 'block'
            expired_server_cert:
                aliases: ['expired-server-cert']
                type: str
                description: Action based on server certificate is expired.
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            proxy_after_tcp_handshake:
                aliases: ['proxy-after-tcp-handshake']
                type: str
                description: Proxy traffic after the TCP 3-way handshake has been established
                choices:
                    - 'disable'
                    - 'enable'
            revoked_server_cert:
                aliases: ['revoked-server-cert']
                type: str
                description: Action based on server certificate is revoked.
                choices:
                    - 'allow'
                    - 'block'
                    - 'ignore'
            unsupported_ssl_cipher:
                aliases: ['unsupported-ssl-cipher']
                type: str
                description: Action based on the SSL cipher used being unsupported.
                choices:
                    - 'allow'
                    - 'block'
            unsupported_ssl_negotiation:
                aliases: ['unsupported-ssl-negotiation']
                type: str
                description: Action based on the SSL negotiation used being unsupported.
                choices:
                    - 'allow'
                    - 'block'
            unsupported_ssl_version:
                aliases: ['unsupported-ssl-version']
                type: str
                description: Action based on the SSL version used being unsupported.
                choices:
                    - 'block'
                    - 'allow'
                    - 'inspect'
            min_allowed_ssl_version:
                aliases: ['min-allowed-ssl-version']
                type: str
                description: Min allowed ssl version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
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
    - name: Configure IMAPS options.
      fortinet.fortimanager.fmgr_firewall_sslsshprofile_imaps:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        ssl_ssh_profile: <your own value>
        firewall_sslsshprofile_imaps:
          # allow_invalid_server_cert: <value in [disable, enable]>
          # client_cert_request: <value in [bypass, inspect, block]>
          # ports: <list or integer>
          # status: <value in [disable, deep-inspection]>
          # unsupported_ssl: <value in [bypass, inspect, block]>
          # untrusted_cert: <value in [allow, block, ignore]>
          # invalid_server_cert: <value in [allow, block]>
          # sni_server_cert_check: <value in [disable, enable, strict]>
          # untrusted_server_cert: <value in [allow, block, ignore]>
          # cert_validation_failure: <value in [allow, block, ignore]>
          # cert_validation_timeout: <value in [allow, block, ignore]>
          # client_certificate: <value in [bypass, inspect, block]>
          # expired_server_cert: <value in [allow, block, ignore]>
          # proxy_after_tcp_handshake: <value in [disable, enable]>
          # revoked_server_cert: <value in [allow, block, ignore]>
          # unsupported_ssl_cipher: <value in [allow, block]>
          # unsupported_ssl_negotiation: <value in [allow, block]>
          # unsupported_ssl_version: <value in [block, allow, inspect]>
          # min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps'
    ]
    url_params = ['adom', 'ssl-ssh-profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ssl-ssh-profile': {'type': 'str', 'api_name': 'ssl_ssh_profile'},
        'ssl_ssh_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_sslsshprofile_imaps': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'allow-invalid-server-cert': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'ports': {'type': 'raw'},
                'status': {'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                'unsupported-ssl': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'untrusted-cert': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'invalid-server-cert': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                'sni-server-cert-check': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable', 'strict'], 'type': 'str'},
                'untrusted-server-cert': {'v_range': [['6.2.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'cert-validation-failure': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'cert-validation-timeout': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                'expired-server-cert': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'proxy-after-tcp-handshake': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'revoked-server-cert': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                'unsupported-ssl-cipher': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                'unsupported-ssl-negotiation': {'v_range': [['6.4.0', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                'min-allowed-ssl-version': {'v_range': [['7.0.3', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_imaps'),
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
