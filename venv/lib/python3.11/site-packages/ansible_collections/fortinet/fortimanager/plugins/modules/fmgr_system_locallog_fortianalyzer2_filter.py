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
module: fmgr_system_locallog_fortianalyzer2_filter
short_description: Filter for FortiAnalyzer2 logging.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    system_locallog_fortianalyzer2_filter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            devcfg:
                type: str
                description:
                    - Log device configuration message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            devops:
                type: str
                description:
                    - Managered devices operations messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            diskquota:
                type: str
                description:
                    - Log Fortianalyzer disk quota messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dm:
                type: str
                description:
                    - Log deployment manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dvm:
                type: str
                description:
                    - Log device manager messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            ediscovery:
                type: str
                description:
                    - Log Fortianalyzer ediscovery messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            epmgr:
                type: str
                description:
                    - Log endpoint manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            event:
                type: str
                description:
                    - Log event messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            eventmgmt:
                type: str
                description:
                    - Log Fortianalyzer event handler messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            faz:
                type: str
                description:
                    - Log Fortianalyzer messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fazha:
                type: str
                description:
                    - Log Fortianalyzer HA messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fazsys:
                type: str
                description:
                    - Log Fortianalyzer system messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fgd:
                type: str
                description:
                    - Log FortiGuard service message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm:
                type: str
                description:
                    - Log FGFM protocol message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fips:
                type: str
                description:
                    - Whether to log fips messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fmgws:
                type: str
                description:
                    - Log web service messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fmlmgr:
                type: str
                description:
                    - Log FortiMail manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fmwmgr:
                type: str
                description:
                    - Log firmware manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fortiview:
                type: str
                description:
                    - Log Fortianalyzer FortiView messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            glbcfg:
                type: str
                description:
                    - Log global database message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            ha:
                type: str
                description:
                    - Log HA message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            hcache:
                type: str
                description:
                    - Log Fortianalyzer hcache messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            iolog:
                type: str
                description:
                    - Log debug IO log message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logd:
                type: str
                description:
                    - Log the status of log daemon.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logdb:
                type: str
                description:
                    - Log Fortianalyzer log DB messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logdev:
                type: str
                description:
                    - Log Fortianalyzer log device messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            logfile:
                type: str
                description:
                    - Log Fortianalyzer log file messages.
                    - enable - Enable setting.
                    - disable - Disable setting.
                choices:
                    - 'enable'
                    - 'disable'
            logging:
                type: str
                description:
                    - Log Fortianalyzer logging messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            lrmgr:
                type: str
                description:
                    - Log log and report manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            objcfg:
                type: str
                description:
                    - Log object configuration change message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            report:
                type: str
                description:
                    - Log Fortianalyzer report messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            rev:
                type: str
                description:
                    - Log revision history message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            rtmon:
                type: str
                description:
                    - Log real-time monitor message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scfw:
                type: str
                description:
                    - Log firewall objects message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scply:
                type: str
                description:
                    - Log policy console message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scrmgr:
                type: str
                description:
                    - Log script manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            scvpn:
                type: str
                description:
                    - Log VPN console message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            system:
                type: str
                description:
                    - Log system manager message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            webport:
                type: str
                description:
                    - Log web portal message.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            incident:
                type: str
                description:
                    - Log Fortianalyzer incident messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            aid:
                type: str
                description:
                    - Log aid messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            docker:
                type: str
                description:
                    - Docker application generic messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            controller:
                type: str
                description:
                    - Controller application generic messages.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Filter for FortiAnalyzer2 logging.
      fortinet.fortimanager.fmgr_system_locallog_fortianalyzer2_filter:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_locallog_fortianalyzer2_filter:
          # devcfg: <value in [disable, enable]>
          # devops: <value in [disable, enable]>
          # diskquota: <value in [disable, enable]>
          # dm: <value in [disable, enable]>
          # dvm: <value in [disable, enable]>
          # ediscovery: <value in [disable, enable]>
          # epmgr: <value in [disable, enable]>
          # event: <value in [disable, enable]>
          # eventmgmt: <value in [disable, enable]>
          # faz: <value in [disable, enable]>
          # fazha: <value in [disable, enable]>
          # fazsys: <value in [disable, enable]>
          # fgd: <value in [disable, enable]>
          # fgfm: <value in [disable, enable]>
          # fips: <value in [disable, enable]>
          # fmgws: <value in [disable, enable]>
          # fmlmgr: <value in [disable, enable]>
          # fmwmgr: <value in [disable, enable]>
          # fortiview: <value in [disable, enable]>
          # glbcfg: <value in [disable, enable]>
          # ha: <value in [disable, enable]>
          # hcache: <value in [disable, enable]>
          # iolog: <value in [disable, enable]>
          # logd: <value in [disable, enable]>
          # logdb: <value in [disable, enable]>
          # logdev: <value in [disable, enable]>
          # logfile: <value in [enable, disable]>
          # logging: <value in [disable, enable]>
          # lrmgr: <value in [disable, enable]>
          # objcfg: <value in [disable, enable]>
          # report: <value in [disable, enable]>
          # rev: <value in [disable, enable]>
          # rtmon: <value in [disable, enable]>
          # scfw: <value in [disable, enable]>
          # scply: <value in [disable, enable]>
          # scrmgr: <value in [disable, enable]>
          # scvpn: <value in [disable, enable]>
          # system: <value in [disable, enable]>
          # webport: <value in [disable, enable]>
          # incident: <value in [disable, enable]>
          # aid: <value in [disable, enable]>
          # docker: <value in [disable, enable]>
          # controller: <value in [disable, enable]>
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
        '/cli/global/system/locallog/fortianalyzer2/filter'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_locallog_fortianalyzer2_filter': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'devcfg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'devops': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diskquota': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dvm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ediscovery': {'choices': ['disable', 'enable'], 'type': 'str'},
                'epmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'event': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eventmgmt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'faz': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fazha': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fazsys': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fgd': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fgfm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fips': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fmgws': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fmlmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fmwmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiview': {'choices': ['disable', 'enable'], 'type': 'str'},
                'glbcfg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ha': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hcache': {'choices': ['disable', 'enable'], 'type': 'str'},
                'iolog': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logd': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logdb': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logdev': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logfile': {'choices': ['enable', 'disable'], 'type': 'str'},
                'logging': {'choices': ['disable', 'enable'], 'type': 'str'},
                'lrmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'objcfg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'report': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rev': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rtmon': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scfw': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scrmgr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scvpn': {'choices': ['disable', 'enable'], 'type': 'str'},
                'system': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webport': {'choices': ['disable', 'enable'], 'type': 'str'},
                'incident': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aid': {'v_range': [['6.4.1', '7.2.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'docker': {'v_range': [['6.4.3', '7.2.10'], ['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'controller': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_locallog_fortianalyzer2_filter'),
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
