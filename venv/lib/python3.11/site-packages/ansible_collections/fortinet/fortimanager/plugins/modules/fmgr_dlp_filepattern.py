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
module: fmgr_dlp_filepattern
short_description: Configure file patterns used by DLP blocking.
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
    dlp_filepattern:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    file_type:
                        aliases: ['file-type']
                        type: str
                        description: Select a file type.
                        choices:
                            - 'unknown'
                            - 'ignored'
                            - 'exe'
                            - 'elf'
                            - 'bat'
                            - 'javascript'
                            - 'html'
                            - 'hta'
                            - 'msoffice'
                            - 'gzip'
                            - 'rar'
                            - 'tar'
                            - 'lzh'
                            - 'upx'
                            - 'zip'
                            - 'cab'
                            - 'bzip2'
                            - 'bzip'
                            - 'activemime'
                            - 'mime'
                            - 'hlp'
                            - 'arj'
                            - 'base64'
                            - 'binhex'
                            - 'uue'
                            - 'fsg'
                            - 'aspack'
                            - 'msc'
                            - 'petite'
                            - 'jpeg'
                            - 'gif'
                            - 'tiff'
                            - 'png'
                            - 'bmp'
                            - 'msi'
                            - 'mpeg'
                            - 'mov'
                            - 'mp3'
                            - 'wma'
                            - 'wav'
                            - 'pdf'
                            - 'avi'
                            - 'rm'
                            - 'torrent'
                            - 'hibun'
                            - '7z'
                            - 'xz'
                            - 'msofficex'
                            - 'mach-o'
                            - 'dmg'
                            - '.net'
                            - 'xar'
                            - 'chm'
                            - 'iso'
                            - 'crx'
                            - 'sis'
                            - 'prc'
                            - 'class'
                            - 'jad'
                            - 'cod'
                            - 'flac'
                            - 'registry'
                            - 'hwp'
                            - 'rpm'
                            - 'c/cpp'
                            - 'pfile'
                            - 'lzip'
                            - 'wasm'
                            - 'sylk'
                            - 'shellscript'
                            - 'dll'
                            - 'jnlp'
                    filter_type:
                        aliases: ['filter-type']
                        type: str
                        description: Filter by file name pattern or by file type.
                        choices:
                            - 'pattern'
                            - 'type'
                    pattern:
                        type: str
                        description: Add a file name pattern.
            id:
                type: int
                description: ID.
                required: true
            name:
                type: str
                description: Name of table containing the file pattern list.
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
    - name: Configure file patterns used by DLP blocking.
      fortinet.fortimanager.fmgr_dlp_filepattern:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        dlp_filepattern:
          id: 0 # Required variable, integer
          # comment: <string>
          # entries:
          #   - file_type: <value in [unknown, ignored, exe, ...]>
          #     filter_type: <value in [pattern, type]>
          #     pattern: <string>
          # name: <string>
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
        '/pm/config/adom/{adom}/obj/dlp/filepattern',
        '/pm/config/global/obj/dlp/filepattern'
    ]
    url_params = ['adom']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_filepattern': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'entries': {
                    'type': 'list',
                    'options': {
                        'file-type': {
                            'choices': [
                                'unknown', 'ignored', 'exe', 'elf', 'bat', 'javascript', 'html', 'hta', 'msoffice', 'gzip', 'rar', 'tar', 'lzh', 'upx',
                                'zip', 'cab', 'bzip2', 'bzip', 'activemime', 'mime', 'hlp', 'arj', 'base64', 'binhex', 'uue', 'fsg', 'aspack', 'msc',
                                'petite', 'jpeg', 'gif', 'tiff', 'png', 'bmp', 'msi', 'mpeg', 'mov', 'mp3', 'wma', 'wav', 'pdf', 'avi', 'rm', 'torrent',
                                'hibun', '7z', 'xz', 'msofficex', 'mach-o', 'dmg', '.net', 'xar', 'chm', 'iso', 'crx', 'sis', 'prc', 'class', 'jad',
                                'cod', 'flac', 'registry', 'hwp', 'rpm', 'c/cpp', 'pfile', 'lzip', 'wasm', 'sylk', 'shellscript', 'dll', 'jnlp'
                            ],
                            'type': 'str'
                        },
                        'filter-type': {'choices': ['pattern', 'type'], 'type': 'str'},
                        'pattern': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'required': True, 'type': 'int'},
                'name': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_filepattern'),
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
