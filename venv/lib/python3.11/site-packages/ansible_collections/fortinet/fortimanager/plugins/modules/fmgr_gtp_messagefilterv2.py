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
module: fmgr_gtp_messagefilterv2
short_description: Message filter for GTPv2 messages.
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
    gtp_messagefilterv2:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bearer_resource_cmd_fail:
                aliases: ['bearer-resource-cmd-fail']
                type: str
                description: Bearer resource
                choices:
                    - 'allow'
                    - 'deny'
            change_notification:
                aliases: ['change-notification']
                type: str
                description: Change notification
                choices:
                    - 'allow'
                    - 'deny'
            create_bearer:
                aliases: ['create-bearer']
                type: str
                description: Create bearer
                choices:
                    - 'allow'
                    - 'deny'
            create_session:
                aliases: ['create-session']
                type: str
                description: Create session
                choices:
                    - 'allow'
                    - 'deny'
            delete_bearer_cmd_fail:
                aliases: ['delete-bearer-cmd-fail']
                type: str
                description: Delete bearer
                choices:
                    - 'allow'
                    - 'deny'
            delete_bearer_req_resp:
                aliases: ['delete-bearer-req-resp']
                type: str
                description: Delete bearer
                choices:
                    - 'allow'
                    - 'deny'
            delete_pdn_connection_set:
                aliases: ['delete-pdn-connection-set']
                type: str
                description: Delete PDN connection set
                choices:
                    - 'allow'
                    - 'deny'
            delete_session:
                aliases: ['delete-session']
                type: str
                description: Delete session
                choices:
                    - 'allow'
                    - 'deny'
            echo:
                type: str
                description: Echo
                choices:
                    - 'allow'
                    - 'deny'
            modify_bearer_cmd_fail:
                aliases: ['modify-bearer-cmd-fail']
                type: str
                description: Modify bearer
                choices:
                    - 'allow'
                    - 'deny'
            modify_bearer_req_resp:
                aliases: ['modify-bearer-req-resp']
                type: str
                description: Modify bearer
                choices:
                    - 'allow'
                    - 'deny'
            name:
                type: str
                description: Message filter name.
                required: true
            resume:
                type: str
                description: Resume
                choices:
                    - 'allow'
                    - 'deny'
            suspend:
                type: str
                description: Suspend
                choices:
                    - 'allow'
                    - 'deny'
            trace_session:
                aliases: ['trace-session']
                type: str
                description: Trace session
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message:
                aliases: ['unknown-message']
                type: str
                description: Allow or Deny unknown messages.
                choices:
                    - 'allow'
                    - 'deny'
            unknown_message_white_list:
                aliases: ['unknown-message-white-list']
                type: raw
                description: (list) White list
            update_bearer:
                aliases: ['update-bearer']
                type: str
                description: Update bearer
                choices:
                    - 'allow'
                    - 'deny'
            update_pdn_connection_set:
                aliases: ['update-pdn-connection-set']
                type: str
                description: Update PDN connection set
                choices:
                    - 'allow'
                    - 'deny'
            version_not_support:
                aliases: ['version-not-support']
                type: str
                description: Version not supported
                choices:
                    - 'allow'
                    - 'deny'
            context_req_res_ack:
                aliases: ['context-req-res-ack']
                type: str
                description: Context request/response/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            forward_relocation_cmp_notif_ack:
                aliases: ['forward-relocation-cmp-notif-ack']
                type: str
                description: Forward relocation complete notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            forward_relocation_req_res:
                aliases: ['forward-relocation-req-res']
                type: str
                description: Forward relocation request/response
                choices:
                    - 'allow'
                    - 'deny'
            alert_mme_notif_ack:
                aliases: ['alert-mme-notif-ack']
                type: str
                description: Alert MME notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            configuration_transfer_tunnel:
                aliases: ['configuration-transfer-tunnel']
                type: str
                description: Configuration transfer tunnel
                choices:
                    - 'allow'
                    - 'deny'
            create_forwarding_tunnel_req_resp:
                aliases: ['create-forwarding-tunnel-req-resp']
                type: str
                description: Create forwarding tunnel request/response
                choices:
                    - 'allow'
                    - 'deny'
            create_indirect_forwarding_tunnel_req_resp:
                aliases: ['create-indirect-forwarding-tunnel-req-resp']
                type: str
                description: Create indirect data forwarding tunnel request/response
                choices:
                    - 'allow'
                    - 'deny'
            cs_paging:
                aliases: ['cs-paging']
                type: str
                description: CS paging indication
                choices:
                    - 'allow'
                    - 'deny'
            delete_indirect_forwarding_tunnel_req_resp:
                aliases: ['delete-indirect-forwarding-tunnel-req-resp']
                type: str
                description: Delete indirect data forwarding tunnel request/response
                choices:
                    - 'allow'
                    - 'deny'
            detach_notif_ack:
                aliases: ['detach-notif-ack']
                type: str
                description: Detach notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            dlink_data_notif_ack:
                aliases: ['dlink-data-notif-ack']
                type: str
                description: Downlink data notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            dlink_notif_failure:
                aliases: ['dlink-notif-failure']
                type: str
                description: Downlink data notification failure indication
                choices:
                    - 'allow'
                    - 'deny'
            forward_access_notif_ack:
                aliases: ['forward-access-notif-ack']
                type: str
                description: Forward access context notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            identification_req_resp:
                aliases: ['identification-req-resp']
                type: str
                description: Identification request/response
                choices:
                    - 'allow'
                    - 'deny'
            isr_status:
                aliases: ['isr-status']
                type: str
                description: ISR status indication
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_start_req_resp:
                aliases: ['mbms-session-start-req-resp']
                type: str
                description: MBMS session start request/response
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_stop_req_resp:
                aliases: ['mbms-session-stop-req-resp']
                type: str
                description: MBMS session stop request/response
                choices:
                    - 'allow'
                    - 'deny'
            mbms_session_update_req_resp:
                aliases: ['mbms-session-update-req-resp']
                type: str
                description: MBMS session update request/response
                choices:
                    - 'allow'
                    - 'deny'
            modify_access_req_resp:
                aliases: ['modify-access-req-resp']
                type: str
                description: Modify access bearers request/response
                choices:
                    - 'allow'
                    - 'deny'
            pgw_dlink_notif_ack:
                aliases: ['pgw-dlink-notif-ack']
                type: str
                description: PGW downlink triggering notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            pgw_restart_notif_ack:
                aliases: ['pgw-restart-notif-ack']
                type: str
                description: PGW restart notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            ran_info_relay:
                aliases: ['ran-info-relay']
                type: str
                description: RAN information relay
                choices:
                    - 'allow'
                    - 'deny'
            release_access_bearer_req_resp:
                aliases: ['release-access-bearer-req-resp']
                type: str
                description: Release access bearers request/response
                choices:
                    - 'allow'
                    - 'deny'
            relocation_cancel_req_resp:
                aliases: ['relocation-cancel-req-resp']
                type: str
                description: Relocation cancel request/response
                choices:
                    - 'allow'
                    - 'deny'
            remote_ue_report_notif_ack:
                aliases: ['remote-ue-report-notif-ack']
                type: str
                description: Remote UE report notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            reserved_for_earlier_version:
                aliases: ['reserved-for-earlier-version']
                type: str
                description: Reserved for earlier version of the GTP specification
                choices:
                    - 'allow'
                    - 'deny'
            stop_paging_indication:
                aliases: ['stop-paging-indication']
                type: str
                description: Stop Paging Indication
                choices:
                    - 'allow'
                    - 'deny'
            ue_activity_notif_ack:
                aliases: ['ue-activity-notif-ack']
                type: str
                description: UE activity notification/acknowledge
                choices:
                    - 'allow'
                    - 'deny'
            ue_registration_query_req_resp:
                aliases: ['ue-registration-query-req-resp']
                type: str
                description: UE registration query request/response
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
    - name: Message filter for GTPv2 messages.
      fortinet.fortimanager.fmgr_gtp_messagefilterv2:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        gtp_messagefilterv2:
          name: "your value" # Required variable, string
          # bearer_resource_cmd_fail: <value in [allow, deny]>
          # change_notification: <value in [allow, deny]>
          # create_bearer: <value in [allow, deny]>
          # create_session: <value in [allow, deny]>
          # delete_bearer_cmd_fail: <value in [allow, deny]>
          # delete_bearer_req_resp: <value in [allow, deny]>
          # delete_pdn_connection_set: <value in [allow, deny]>
          # delete_session: <value in [allow, deny]>
          # echo: <value in [allow, deny]>
          # modify_bearer_cmd_fail: <value in [allow, deny]>
          # modify_bearer_req_resp: <value in [allow, deny]>
          # resume: <value in [allow, deny]>
          # suspend: <value in [allow, deny]>
          # trace_session: <value in [allow, deny]>
          # unknown_message: <value in [allow, deny]>
          # unknown_message_white_list: <list or integer>
          # update_bearer: <value in [allow, deny]>
          # update_pdn_connection_set: <value in [allow, deny]>
          # version_not_support: <value in [allow, deny]>
          # context_req_res_ack: <value in [allow, deny]>
          # forward_relocation_cmp_notif_ack: <value in [allow, deny]>
          # forward_relocation_req_res: <value in [allow, deny]>
          # alert_mme_notif_ack: <value in [allow, deny]>
          # configuration_transfer_tunnel: <value in [allow, deny]>
          # create_forwarding_tunnel_req_resp: <value in [allow, deny]>
          # create_indirect_forwarding_tunnel_req_resp: <value in [allow, deny]>
          # cs_paging: <value in [allow, deny]>
          # delete_indirect_forwarding_tunnel_req_resp: <value in [allow, deny]>
          # detach_notif_ack: <value in [allow, deny]>
          # dlink_data_notif_ack: <value in [allow, deny]>
          # dlink_notif_failure: <value in [allow, deny]>
          # forward_access_notif_ack: <value in [allow, deny]>
          # identification_req_resp: <value in [allow, deny]>
          # isr_status: <value in [allow, deny]>
          # mbms_session_start_req_resp: <value in [allow, deny]>
          # mbms_session_stop_req_resp: <value in [allow, deny]>
          # mbms_session_update_req_resp: <value in [allow, deny]>
          # modify_access_req_resp: <value in [allow, deny]>
          # pgw_dlink_notif_ack: <value in [allow, deny]>
          # pgw_restart_notif_ack: <value in [allow, deny]>
          # ran_info_relay: <value in [allow, deny]>
          # release_access_bearer_req_resp: <value in [allow, deny]>
          # relocation_cancel_req_resp: <value in [allow, deny]>
          # remote_ue_report_notif_ack: <value in [allow, deny]>
          # reserved_for_earlier_version: <value in [allow, deny]>
          # stop_paging_indication: <value in [allow, deny]>
          # ue_activity_notif_ack: <value in [allow, deny]>
          # ue_registration_query_req_resp: <value in [allow, deny]>
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
        '/pm/config/adom/{adom}/obj/gtp/message-filter-v2',
        '/pm/config/global/obj/gtp/message-filter-v2'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'gtp_messagefilterv2': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'bearer-resource-cmd-fail': {'choices': ['allow', 'deny'], 'type': 'str'},
                'change-notification': {'choices': ['allow', 'deny'], 'type': 'str'},
                'create-bearer': {'choices': ['allow', 'deny'], 'type': 'str'},
                'create-session': {'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-bearer-cmd-fail': {'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-bearer-req-resp': {'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-pdn-connection-set': {'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-session': {'choices': ['allow', 'deny'], 'type': 'str'},
                'echo': {'choices': ['allow', 'deny'], 'type': 'str'},
                'modify-bearer-cmd-fail': {'choices': ['allow', 'deny'], 'type': 'str'},
                'modify-bearer-req-resp': {'choices': ['allow', 'deny'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'resume': {'choices': ['allow', 'deny'], 'type': 'str'},
                'suspend': {'choices': ['allow', 'deny'], 'type': 'str'},
                'trace-session': {'choices': ['allow', 'deny'], 'type': 'str'},
                'unknown-message': {'choices': ['allow', 'deny'], 'type': 'str'},
                'unknown-message-white-list': {'type': 'raw'},
                'update-bearer': {'choices': ['allow', 'deny'], 'type': 'str'},
                'update-pdn-connection-set': {'choices': ['allow', 'deny'], 'type': 'str'},
                'version-not-support': {'choices': ['allow', 'deny'], 'type': 'str'},
                'context-req-res-ack': {'v_range': [['7.0.2', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'forward-relocation-cmp-notif-ack': {'v_range': [['7.0.2', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'forward-relocation-req-res': {'v_range': [['7.0.2', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'alert-mme-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'configuration-transfer-tunnel': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'create-forwarding-tunnel-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'create-indirect-forwarding-tunnel-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'cs-paging': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'delete-indirect-forwarding-tunnel-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'detach-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'dlink-data-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'dlink-notif-failure': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'forward-access-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'identification-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'isr-status': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'mbms-session-start-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'mbms-session-stop-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'mbms-session-update-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'modify-access-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'pgw-dlink-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'pgw-restart-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'ran-info-relay': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'release-access-bearer-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'relocation-cancel-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'remote-ue-report-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'reserved-for-earlier-version': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'stop-paging-indication': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'ue-activity-notif-ack': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'ue-registration-query-req-resp': {'v_range': [['7.2.1', '']], 'choices': ['allow', 'deny'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'gtp_messagefilterv2'),
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
