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
module: fmgr_videofilter_profile
short_description: Configure VideoFilter profile.
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
    videofilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            dailymotion:
                type: str
                description: Enable/disable Dailymotion video source.
                choices:
                    - 'disable'
                    - 'enable'
            fortiguard_category:
                aliases: ['fortiguard-category']
                type: dict
                description: Fortiguard category.
                suboptions:
                    filters:
                        type: list
                        elements: dict
                        description: Filters.
                        suboptions:
                            action:
                                type: str
                                description: VideoFilter action.
                                choices:
                                    - 'block'
                                    - 'bypass'
                                    - 'monitor'
                                    - 'allow'
                            category_id:
                                aliases: ['category-id']
                                type: int
                                description: Category ID.
                            id:
                                type: int
                                description: ID.
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
            name:
                type: str
                description: Name.
                required: true
            vimeo:
                type: str
                description: Enable/disable Vimeo video source.
                choices:
                    - 'disable'
                    - 'enable'
            vimeo_restrict:
                aliases: ['vimeo-restrict']
                type: str
                description: Set Vimeo-restrict
            youtube:
                type: str
                description: Enable/disable YouTube video source.
                choices:
                    - 'disable'
                    - 'enable'
            youtube_channel_filter:
                aliases: ['youtube-channel-filter']
                type: str
                description: Set YouTube channel filter.
            youtube_restrict:
                aliases: ['youtube-restrict']
                type: str
                description: Set YouTube-restrict mode.
                choices:
                    - 'strict'
                    - 'none'
                    - 'moderate'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group.
            default_action:
                aliases: ['default-action']
                type: str
                description: Video filter default action.
                choices:
                    - 'block'
                    - 'monitor'
                    - 'allow'
            log:
                type: str
                description: Enable/disable logging.
                choices:
                    - 'disable'
                    - 'enable'
            filters:
                type: list
                elements: dict
                description: Filters.
                suboptions:
                    action:
                        type: str
                        description: Video filter action.
                        choices:
                            - 'block'
                            - 'monitor'
                            - 'allow'
                    category:
                        type: str
                        description: FortiGuard category ID.
                    channel:
                        type: str
                        description: Channel ID.
                    comment:
                        type: str
                        description: Comment.
                    id:
                        type: int
                        description: ID.
                    keyword:
                        type: str
                        description: Video filter keyword ID.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: Filter type.
                        choices:
                            - 'category'
                            - 'channel'
                            - 'title'
                            - 'description'
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
    - name: Configure VideoFilter profile.
      fortinet.fortimanager.fmgr_videofilter_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        videofilter_profile:
          name: "your value" # Required variable, string
          # comment: <string>
          # dailymotion: <value in [disable, enable]>
          # fortiguard_category:
          #   filters:
          #     - action: <value in [block, bypass, monitor, ...]>
          #       category_id: <integer>
          #       id: <integer>
          #       log: <value in [disable, enable]>
          # vimeo: <value in [disable, enable]>
          # vimeo_restrict: <string>
          # youtube: <value in [disable, enable]>
          # youtube_channel_filter: <string>
          # youtube_restrict: <value in [strict, none, moderate]>
          # replacemsg_group: <string>
          # default_action: <value in [block, monitor, allow]>
          # log: <value in [disable, enable]>
          # filters:
          #   - action: <value in [block, monitor, allow]>
          #     category: <string>
          #     channel: <string>
          #     comment: <string>
          #     id: <integer>
          #     keyword: <string>
          #     log: <value in [disable, enable]>
          #     type: <value in [category, channel, title, ...]>
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
        '/pm/config/adom/{adom}/obj/videofilter/profile',
        '/pm/config/global/obj/videofilter/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'videofilter_profile': {
            'type': 'dict',
            'v_range': [['7.0.0', '']],
            'options': {
                'comment': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'dailymotion': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiguard-category': {
                    'v_range': [['7.0.0', '']],
                    'type': 'dict',
                    'options': {
                        'filters': {
                            'v_range': [['7.0.0', '']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['7.0.0', '']], 'choices': ['block', 'bypass', 'monitor', 'allow'], 'type': 'str'},
                                'category-id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'log': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        }
                    }
                },
                'name': {'v_range': [['7.0.0', '']], 'required': True, 'type': 'str'},
                'vimeo': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vimeo-restrict': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'youtube': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'youtube-channel-filter': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'youtube-restrict': {'v_range': [['7.0.0', '']], 'choices': ['strict', 'none', 'moderate'], 'type': 'str'},
                'replacemsg-group': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'default-action': {'v_range': [['7.2.3', '']], 'choices': ['block', 'monitor', 'allow'], 'type': 'str'},
                'log': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'filters': {
                    'v_range': [['7.4.2', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.2', '']], 'choices': ['block', 'monitor', 'allow'], 'type': 'str'},
                        'category': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'channel': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'comment': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'keyword': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'str'},
                        'log': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.4.2', '']], 'choices': ['category', 'channel', 'title', 'description'], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'videofilter_profile'),
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
