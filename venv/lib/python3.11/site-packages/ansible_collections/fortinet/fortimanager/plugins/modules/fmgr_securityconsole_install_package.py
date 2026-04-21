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
module: fmgr_securityconsole_install_package
short_description: Copy and install a policy package to devices.
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
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    securityconsole_install_package:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Source ADOM name.
            adom_rev_comments:
                type: str
                description: If generate_rev flag is set, the comment for the new ADOM revision.
            adom_rev_name:
                type: str
                description: If generate_rev flag is set, the name for the new ADOM revision.
            dev_rev_comments:
                type: str
                description: Comments for the device configuration revision that will be generated during install.
            flags:
                type: list
                elements: str
                description:
                    - cp_all_objs - Assign all objects during global policy assignment.
                    - preview - Generate preview cache only.
                    - generate_rev - Generate new ADOM revision before install.
                    - copy_assigned_pkg - For global policy assignment - copy assigned package from ADOM to device.
                    - unassign - Remove global policy from ADOM.
                    - ifpolicy_only - Only install interface policies.
                    - no_ifpolicy - Install regular policies only - do not install interface policies.
                    - objs_only - Install object
                    - auto_lock_ws - Automatically lock and unlock workspace when performing security console task.
                    - copy_only - Only copy to device db.
                choices:
                    - 'none'
                    - 'cp_all_objs'
                    - 'preview'
                    - 'generate_rev'
                    - 'copy_assigned_pkg'
                    - 'unassign'
                    - 'ifpolicy_only'
                    - 'no_ifpolicy'
                    - 'objs_only'
                    - 'auto_lock_ws'
                    - 'check_pkg_st'
                    - 'copy_only'
            pkg:
                type: str
                description: Source package path and name.
            scope:
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
    - name: Copy and install a policy package to devices.
      fortinet.fortimanager.fmgr_securityconsole_install_package:
        bypass_validation: false
        securityconsole_install_package:
          adom: ansible
          adom_rev_comments: ansible-comment
          adom_rev_name: ansible-test
          dev_rev_comments: ansible-comment
          flags:
            - none
            - cp_all_objs
            - preview
            - generate_rev
            - copy_assigned_pkg
            - unassign
            - ifpolicy_only
            - no_ifpolicy
            - objs_only
            - auto_lock_ws
            - check_pkg_st
            - copy_only
          pkg: ansible
          scope:
            - name: Ansible-test
              vdom: root

- name: INSTALL PREVIEW - POLICY PACKAGE
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    adom: demo
    ppkg: ppkg_hubs
    device: fgt_00_1
  tasks:
    - name: Install for policy package [preview mode] {{ ppkg }}
      fortinet.fortimanager.fmgr_securityconsole_install_package:
        securityconsole_install_package:
          adom: "{{ adom }}"
          flags:
            - preview
          pkg: "{{ ppkg }}"
          scope:
            - name: "{{ device }}"
              vdom: root
      register: r
    - name: Poll the task of installing policy package
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ r.meta.response_data.task }}"
      register: taskinfo
      until: taskinfo.meta.response_data.percent == 100
      retries: 30
      delay: 5
    - name: Trigger the preview report generation for policy package {{ ppkg }}
      fortinet.fortimanager.fmgr_securityconsole_install_preview:
        securityconsole_install_preview:
          adom: "{{ adom }}"
          device: "{{ device }}"
          flags:
            - json
          vdoms: root
      register: r
    - name: Poll the task of generating preview report
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ r.meta.response_data.task }}"
      register: taskinfo
      until: taskinfo.meta.response_data.percent == 100
      retries: 30
      delay: 5
    - name: Get the preview report for policy package {{ ppkg }}
      fortinet.fortimanager.fmgr_securityconsole_preview_result:
        securityconsole_preview_result:
          adom: "{{ adom }}"
          device: "{{ device }}"
      register: r
    - name: Cancel install task for policy package {{ ppkg }}
      fortinet.fortimanager.fmgr_securityconsole_package_cancel_install:
        securityconsole_package_cancel_install:
          adom: "{{ adom }}"
    - name: Show preview report
      ansible.builtin.debug:
        msg: "{{ r }}"
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
        '/securityconsole/install/package'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'securityconsole_install_package': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'str'},
                'adom_rev_comments': {'type': 'str'},
                'adom_rev_name': {'type': 'str'},
                'dev_rev_comments': {'type': 'str'},
                'flags': {
                    'type': 'list',
                    'choices': [
                        'none', 'cp_all_objs', 'preview', 'generate_rev', 'copy_assigned_pkg', 'unassign', 'ifpolicy_only', 'no_ifpolicy', 'objs_only',
                        'auto_lock_ws', 'check_pkg_st', 'copy_only'
                    ],
                    'elements': 'str'
                },
                'pkg': {'type': 'str'},
                'scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_install_package'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_exec()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
