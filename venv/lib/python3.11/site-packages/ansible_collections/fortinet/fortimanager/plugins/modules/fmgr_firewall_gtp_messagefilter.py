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
module: fmgr_firewall_gtp_messagefilter
short_description: Message filter.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    gtp:
        description: The parameter (gtp) in requested url.
        type: str
        required: true
    firewall_gtp_messagefilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            create_aa_pdp:
                aliases: ['create-aa-pdp']
                type: str
                description: Create AA PDP.
                choices:
                    - 'allow'
                    - 'deny'
            create_mbms:
                aliases: ['create-mbms']
                type: str
                description: Create MBMS.
                choices:
                    - 'allow'
                    - 'deny'
            create_pdp:
                aliases: ['create-pdp']
                type: str
                description: Create PDP.
                choices:
                    - 'allow'
                    - 'deny'
            data_record:
                aliases: ['data-record']
                type: str
                description: Data record.
                choices:
                    - 'allow'
                    - 'deny'
            delete_aa_pdp:
                aliases: ['delete-aa-pdp']
                type: str
                description: Delete AA PDP.
                choices:
                    - 'allow'
                    - 'deny'
            delete_mbms:
                aliases: ['delete-mbms']
                type: str
                description: Delete MBMS.
                choices:
                    - 'allow'
                    - 'deny'
            delete_pdp:
                aliases: ['delete-pdp']
                type: str
                description: Delete PDP.
                choices:
                    - 'allow'
                    - 'deny'
            echo:
                type: str
                description: Echo.
                choices:
                    - 'allow'
                    - 'deny'
            error_indication:
                aliases: ['error-indication']
                type: str
                description: Error indication.
                choices:
                    - 'allow'
                    - 'deny'
            failure_report:
                aliases: ['failure-report']
                type: str
                description: Failure report.
                choices:
                    - 'allow'
                    - 'deny'
            fwd_relocation:
                aliases: ['fwd-relocation']
                type: str
                description: Forward relocation.
                choices:
                    - 'allow'
                    - 'deny'
            fwd_srns_context:
                aliases: ['fwd-srns-context']
                type: str
                description: Forward SRNS context.
                choices:
                    - 'allow'
                    - 'deny'
            gtp_pdu:
                aliases: ['gtp-pdu']
                type: str
                description: GTP PDU.
                choices:
                    - 'allow'
                    - 'deny'
            identification:
                type: str
                description: Identification.
                choices:
                    - 'allow'
                    - 'deny'
            mbms_notification:
                aliases: ['mbms-notification']
                type: str
                description: MBMS notification.
                choices:
                    - 'allow'
                    - 'deny'
            node_alive:
                aliases: ['node-alive']
                type: str
                description: Node alive.
                choices:
                    - 'allow'
                    - 'deny'
            note_ms_present:
                aliases: ['note-ms-present']
                type: str
                description: Note MS present.
                choices:
                    - 'allow'
                    - 'deny'
            pdu_notification:
                aliases: ['pdu-notification']
                type: str
                description: PDU notification.
                choices:
                    - 'allow'
                    - 'deny'
            ran_info:
                aliases: ['ran-info']
                type: str
                description: Ran info.
                choices:
                    - 'allow'
                    - 'deny'
            redirection:
                type: str
                description: Redirection.
                choices:
                    - 'allow'
                    - 'deny'
            relocation_cancel:
                aliases: ['relocation-cancel']
                type: str
                description: Relocation cancel.
                choices:
                    - 'allow'
                    - 'deny'
            send_route:
                aliases: ['send-route']
                type: str
                description: Send route.
                choices:
                    - 'allow'
                    - 'deny'
            sgsn_context:
                aliases: ['sgsn-context']
                type: str
                description: SGSN context.
                choices:
                    - 'allow'
                    - 'deny'
            support_extension:
                aliases: ['support-extension']
                type: str
                description: Support extension.
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message_action:
                aliases: ['unknown-message-action']
                type: str
                description: Unknown message action.
                choices:
                    - 'allow'
                    - 'deny'
            update_mbms:
                aliases: ['update-mbms']
                type: str
                description: Update MBMS.
                choices:
                    - 'allow'
                    - 'deny'
            update_pdp:
                aliases: ['update-pdp']
                type: str
                description: Update PDP.
                choices:
                    - 'allow'
                    - 'deny'
            version_not_support:
                aliases: ['version-not-support']
                type: str
                description: Version not supported.
                choices:
                    - 'allow'
                    - 'deny'
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
    - name: Message filter.
      fortinet.fortimanager.fmgr_firewall_gtp_messagefilter:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        gtp: <your own value>
        firewall_gtp_messagefilter:
          # create_aa_pdp: <value in [allow, deny]>
          # create_mbms: <value in [allow, deny]>
          # create_pdp: <value in [allow, deny]>
          # data_record: <value in [allow, deny]>
          # delete_aa_pdp: <value in [allow, deny]>
          # delete_mbms: <value in [allow, deny]>
          # delete_pdp: <value in [allow, deny]>
          # echo: <value in [allow, deny]>
          # error_indication: <value in [allow, deny]>
          # failure_report: <value in [allow, deny]>
          # fwd_relocation: <value in [allow, deny]>
          # fwd_srns_context: <value in [allow, deny]>
          # gtp_pdu: <value in [allow, deny]>
          # identification: <value in [allow, deny]>
          # mbms_notification: <value in [allow, deny]>
          # node_alive: <value in [allow, deny]>
          # note_ms_present: <value in [allow, deny]>
          # pdu_notification: <value in [allow, deny]>
          # ran_info: <value in [allow, deny]>
          # redirection: <value in [allow, deny]>
          # relocation_cancel: <value in [allow, deny]>
          # send_route: <value in [allow, deny]>
          # sgsn_context: <value in [allow, deny]>
          # support_extension: <value in [allow, deny]>
          # unknown_message_action: <value in [allow, deny]>
          # update_mbms: <value in [allow, deny]>
          # update_pdp: <value in [allow, deny]>
          # version_not_support: <value in [allow, deny]>
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-filter',
        '/pm/config/global/obj/firewall/gtp/{gtp}/message-filter'
    ]
    url_params = ['adom', 'gtp']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_messagefilter': {
            'type': 'dict',
            'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'create-aa-pdp': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'create-mbms': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'create-pdp': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'data-record': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-aa-pdp': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-mbms': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-pdp': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'echo': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'error-indication': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'failure-report': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'fwd-relocation': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'fwd-srns-context': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'gtp-pdu': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'identification': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'mbms-notification': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'node-alive': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'note-ms-present': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'pdu-notification': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'ran-info': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'redirection': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'relocation-cancel': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'send-route': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'sgsn-context': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'support-extension': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'unknown-message-action': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'update-mbms': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'update-pdp': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'version-not-support': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_messagefilter'),
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
