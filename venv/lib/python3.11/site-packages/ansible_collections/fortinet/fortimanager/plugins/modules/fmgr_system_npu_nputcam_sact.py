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
module: fmgr_system_npu_nputcam_sact
short_description: Source action of TCAM.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.4.0"
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
    npu-tcam:
        description: Deprecated, please use "npu_tcam"
        type: str
    npu_tcam:
        description: The parameter (npu-tcam) in requested url.
        type: str
    system_npu_nputcam_sact:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            act:
                type: int
                description: Tcam sact act.
            act_v:
                aliases: ['act-v']
                type: str
                description: Enable to set sact act.
                choices:
                    - 'disable'
                    - 'enable'
            bmproc:
                type: int
                description: Tcam sact bmproc.
            bmproc_v:
                aliases: ['bmproc-v']
                type: str
                description: Enable to set sact bmproc.
                choices:
                    - 'disable'
                    - 'enable'
            df_lif:
                aliases: ['df-lif']
                type: int
                description: Tcam sact df-lif.
            df_lif_v:
                aliases: ['df-lif-v']
                type: str
                description: Enable to set sact df-lif.
                choices:
                    - 'disable'
                    - 'enable'
            dfr:
                type: int
                description: Tcam sact dfr.
            dfr_v:
                aliases: ['dfr-v']
                type: str
                description: Enable to set sact dfr.
                choices:
                    - 'disable'
                    - 'enable'
            dmac_skip:
                aliases: ['dmac-skip']
                type: int
                description: Tcam sact dmac-skip.
            dmac_skip_v:
                aliases: ['dmac-skip-v']
                type: str
                description: Enable to set sact dmac-skip.
                choices:
                    - 'disable'
                    - 'enable'
            dosen:
                type: int
                description: Tcam sact dosen.
            dosen_v:
                aliases: ['dosen-v']
                type: str
                description: Enable to set sact dosen.
                choices:
                    - 'disable'
                    - 'enable'
            espff_proc:
                aliases: ['espff-proc']
                type: int
                description: Tcam sact espff-proc.
            espff_proc_v:
                aliases: ['espff-proc-v']
                type: str
                description: Enable to set sact espff-proc.
                choices:
                    - 'disable'
                    - 'enable'
            etype_pid:
                aliases: ['etype-pid']
                type: int
                description: Tcam sact etype-pid.
            etype_pid_v:
                aliases: ['etype-pid-v']
                type: str
                description: Enable to set sact etype-pid.
                choices:
                    - 'disable'
                    - 'enable'
            frag_proc:
                aliases: ['frag-proc']
                type: int
                description: Tcam sact frag-proc.
            frag_proc_v:
                aliases: ['frag-proc-v']
                type: str
                description: Enable to set sact frag-proc.
                choices:
                    - 'disable'
                    - 'enable'
            fwd:
                type: int
                description: Tcam sact fwd.
            fwd_lif:
                aliases: ['fwd-lif']
                type: int
                description: Tcam sact fwd-lif.
            fwd_lif_v:
                aliases: ['fwd-lif-v']
                type: str
                description: Enable to set sact fwd-lif.
                choices:
                    - 'disable'
                    - 'enable'
            fwd_tvid:
                aliases: ['fwd-tvid']
                type: int
                description: Tcam sact fwd-tvid.
            fwd_tvid_v:
                aliases: ['fwd-tvid-v']
                type: str
                description: Enable to set sact fwd-vid.
                choices:
                    - 'disable'
                    - 'enable'
            fwd_v:
                aliases: ['fwd-v']
                type: str
                description: Enable to set sact fwd.
                choices:
                    - 'disable'
                    - 'enable'
            icpen:
                type: int
                description: Tcam sact icpen.
            icpen_v:
                aliases: ['icpen-v']
                type: str
                description: Enable to set sact icpen.
                choices:
                    - 'disable'
                    - 'enable'
            igmp_mld_snp:
                aliases: ['igmp-mld-snp']
                type: int
                description: Tcam sact igmp-mld-snp.
            igmp_mld_snp_v:
                aliases: ['igmp-mld-snp-v']
                type: str
                description: Enable to set sact igmp-mld-snp.
                choices:
                    - 'disable'
                    - 'enable'
            learn:
                type: int
                description: Tcam sact learn.
            learn_v:
                aliases: ['learn-v']
                type: str
                description: Enable to set sact learn.
                choices:
                    - 'disable'
                    - 'enable'
            m_srh_ctrl:
                aliases: ['m-srh-ctrl']
                type: int
                description: Tcam sact m-srh-ctrl.
            m_srh_ctrl_v:
                aliases: ['m-srh-ctrl-v']
                type: str
                description: Enable to set sact m-srh-ctrl.
                choices:
                    - 'disable'
                    - 'enable'
            mac_id:
                aliases: ['mac-id']
                type: int
                description: Tcam sact mac-id.
            mac_id_v:
                aliases: ['mac-id-v']
                type: str
                description: Enable to set sact mac-id.
                choices:
                    - 'disable'
                    - 'enable'
            mss:
                type: int
                description: Tcam sact mss.
            mss_v:
                aliases: ['mss-v']
                type: str
                description: Enable to set sact mss.
                choices:
                    - 'disable'
                    - 'enable'
            pleen:
                type: int
                description: Tcam sact pleen.
            pleen_v:
                aliases: ['pleen-v']
                type: str
                description: Enable to set sact pleen.
                choices:
                    - 'disable'
                    - 'enable'
            prio_pid:
                aliases: ['prio-pid']
                type: int
                description: Tcam sact prio-pid.
            prio_pid_v:
                aliases: ['prio-pid-v']
                type: str
                description: Enable to set sact prio-pid.
                choices:
                    - 'disable'
                    - 'enable'
            promis:
                type: int
                description: Tcam sact promis.
            promis_v:
                aliases: ['promis-v']
                type: str
                description: Enable to set sact promis.
                choices:
                    - 'disable'
                    - 'enable'
            rfsh:
                type: int
                description: Tcam sact rfsh.
            rfsh_v:
                aliases: ['rfsh-v']
                type: str
                description: Enable to set sact rfsh.
                choices:
                    - 'disable'
                    - 'enable'
            smac_skip:
                aliases: ['smac-skip']
                type: int
                description: Tcam sact smac-skip.
            smac_skip_v:
                aliases: ['smac-skip-v']
                type: str
                description: Enable to set sact smac-skip.
                choices:
                    - 'disable'
                    - 'enable'
            tp_smchk_v:
                aliases: ['tp-smchk-v']
                type: str
                description: Enable to set sact tp mode.
                choices:
                    - 'disable'
                    - 'enable'
            tp_smchk:
                type: int
                description: Tcam sact tp mode.
            tpe_id:
                aliases: ['tpe-id']
                type: int
                description: Tcam sact tpe-id.
            tpe_id_v:
                aliases: ['tpe-id-v']
                type: str
                description: Enable to set sact tpe-id.
                choices:
                    - 'disable'
                    - 'enable'
            vdm:
                type: int
                description: Tcam sact vdm.
            vdm_v:
                aliases: ['vdm-v']
                type: str
                description: Enable to set sact vdm.
                choices:
                    - 'disable'
                    - 'enable'
            vdom_id:
                aliases: ['vdom-id']
                type: int
                description: Tcam sact vdom-id.
            vdom_id_v:
                aliases: ['vdom-id-v']
                type: str
                description: Enable to set sact vdom-id.
                choices:
                    - 'disable'
                    - 'enable'
            x_mode:
                aliases: ['x-mode']
                type: int
                description: Tcam sact x-mode.
            x_mode_v:
                aliases: ['x-mode-v']
                type: str
                description: Enable to set sact x-mode.
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
    - name: Source action of TCAM.
      fortinet.fortimanager.fmgr_system_npu_nputcam_sact:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        npu_tcam: <your own value>
        system_npu_nputcam_sact:
          # act: <integer>
          # act_v: <value in [disable, enable]>
          # bmproc: <integer>
          # bmproc_v: <value in [disable, enable]>
          # df_lif: <integer>
          # df_lif_v: <value in [disable, enable]>
          # dfr: <integer>
          # dfr_v: <value in [disable, enable]>
          # dmac_skip: <integer>
          # dmac_skip_v: <value in [disable, enable]>
          # dosen: <integer>
          # dosen_v: <value in [disable, enable]>
          # espff_proc: <integer>
          # espff_proc_v: <value in [disable, enable]>
          # etype_pid: <integer>
          # etype_pid_v: <value in [disable, enable]>
          # frag_proc: <integer>
          # frag_proc_v: <value in [disable, enable]>
          # fwd: <integer>
          # fwd_lif: <integer>
          # fwd_lif_v: <value in [disable, enable]>
          # fwd_tvid: <integer>
          # fwd_tvid_v: <value in [disable, enable]>
          # fwd_v: <value in [disable, enable]>
          # icpen: <integer>
          # icpen_v: <value in [disable, enable]>
          # igmp_mld_snp: <integer>
          # igmp_mld_snp_v: <value in [disable, enable]>
          # learn: <integer>
          # learn_v: <value in [disable, enable]>
          # m_srh_ctrl: <integer>
          # m_srh_ctrl_v: <value in [disable, enable]>
          # mac_id: <integer>
          # mac_id_v: <value in [disable, enable]>
          # mss: <integer>
          # mss_v: <value in [disable, enable]>
          # pleen: <integer>
          # pleen_v: <value in [disable, enable]>
          # prio_pid: <integer>
          # prio_pid_v: <value in [disable, enable]>
          # promis: <integer>
          # promis_v: <value in [disable, enable]>
          # rfsh: <integer>
          # rfsh_v: <value in [disable, enable]>
          # smac_skip: <integer>
          # smac_skip_v: <value in [disable, enable]>
          # tp_smchk_v: <value in [disable, enable]>
          # tp_smchk: <integer>
          # tpe_id: <integer>
          # tpe_id_v: <value in [disable, enable]>
          # vdm: <integer>
          # vdm_v: <value in [disable, enable]>
          # vdom_id: <integer>
          # vdom_id_v: <value in [disable, enable]>
          # x_mode: <integer>
          # x_mode_v: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/sact',
        '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/sact'
    ]
    url_params = ['adom', 'npu-tcam']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'npu-tcam': {'type': 'str', 'api_name': 'npu_tcam'},
        'npu_tcam': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_nputcam_sact': {
            'type': 'dict',
            'v_range': [['7.4.2', '']],
            'options': {
                'act': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'act-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bmproc': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'bmproc-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'df-lif': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'df-lif-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dfr': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'dfr-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dmac-skip': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'dmac-skip-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dosen': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'dosen-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'espff-proc': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'espff-proc-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'etype-pid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'etype-pid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'frag-proc': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'frag-proc-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fwd': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'fwd-lif': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'fwd-lif-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fwd-tvid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'fwd-tvid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fwd-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'icpen': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'icpen-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'igmp-mld-snp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'igmp-mld-snp-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'learn': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'learn-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'm-srh-ctrl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'm-srh-ctrl-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'mac-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mss': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'mss-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pleen': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'pleen-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'prio-pid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'prio-pid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'promis': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'promis-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rfsh': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'rfsh-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'smac-skip': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'smac-skip-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tp-smchk-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tp_smchk': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'tpe-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'tpe-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vdm': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'vdm-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vdom-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'vdom-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'x-mode': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'x-mode-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_nputcam_sact'),
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
