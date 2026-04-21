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
module: fmgr_dvmdb_device
short_description: Device table, most attributes are read-only and can only be changed internally.
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    dvmdb_device:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adm_pass:
                type: raw
                description: (list) Adm pass.
            adm_usr:
                type: str
                description: Adm usr.
            app_ver:
                type: str
                description: App ver.
            av_ver:
                type: str
                description: Av ver.
            beta:
                type: int
                description: Beta.
            branch_pt:
                type: int
                description: Branch pt.
            build:
                type: int
                description: Build.
            checksum:
                type: str
                description: Checksum.
            conf_status:
                type: str
                description: Conf status.
                choices:
                    - 'unknown'
                    - 'insync'
                    - 'outofsync'
            conn_mode:
                type: str
                description: Conn mode.
                choices:
                    - 'active'
                    - 'passive'
            conn_status:
                type: str
                description: Conn status.
                choices:
                    - 'UNKNOWN'
                    - 'up'
                    - 'down'
            db_status:
                type: str
                description: Db status.
                choices:
                    - 'unknown'
                    - 'nomod'
                    - 'mod'
            desc:
                type: str
                description: Desc.
            dev_status:
                type: str
                description: Dev status.
                choices:
                    - 'none'
                    - 'unknown'
                    - 'checkedin'
                    - 'inprogress'
                    - 'installed'
                    - 'aborted'
                    - 'sched'
                    - 'retry'
                    - 'canceled'
                    - 'pending'
                    - 'retrieved'
                    - 'changed_conf'
                    - 'sync_fail'
                    - 'timeout'
                    - 'rev_revert'
                    - 'auto_updated'
            fap_cnt:
                type: int
                description: Fap cnt.
            faz_full_act:
                aliases: ['faz.full_act']
                type: int
                description: Faz.
            faz_perm:
                aliases: ['faz.perm']
                type: int
                description: Faz.
            faz_quota:
                aliases: ['faz.quota']
                type: int
                description: Faz.
            faz_used:
                aliases: ['faz.used']
                type: int
                description: Faz.
            fex_cnt:
                type: int
                description: Fex cnt.
            flags:
                type: list
                elements: str
                description: Flags.
                choices:
                    - 'has_hdd'
                    - 'vdom_enabled'
                    - 'discover'
                    - 'reload'
                    - 'interim_build'
                    - 'offline_mode'
                    - 'is_model'
                    - 'fips_mode'
                    - 'linked_to_model'
                    - 'ip-conflict'
                    - 'faz-autosync'
                    - 'need_reset'
                    - 'backup_mode'
                    - 'azure_vwan_nva'
                    - 'fgsp_configured'
                    - 'cnf_mode'
                    - 'sase_managed'
                    - 'override_management_intf'
                    - 'sdwan_management'
                    - 'deny_api_access'
            foslic_cpu:
                type: int
                description: VM Meter vCPU count.
            foslic_dr_site:
                type: str
                description: VM Meter DR Site status.
                choices:
                    - 'disable'
                    - 'enable'
            foslic_inst_time:
                type: int
                description: VM Meter first deployment time
            foslic_last_sync:
                type: int
                description: VM Meter last synchronized time
            foslic_ram:
                type: int
                description: VM Meter device RAM size
            foslic_type:
                type: str
                description: VM Meter license type.
                choices:
                    - 'temporary'
                    - 'trial'
                    - 'regular'
                    - 'trial_expired'
            foslic_utm:
                type: list
                elements: str
                description:
                    - VM Meter services
                    - fw - Firewall
                    - av - Anti-virus
                    - ips - IPS
                    - app - App control
                    - url - Web filter
                    - utm - Full UTM
                    - fwb - FortiWeb
                choices:
                    - 'fw'
                    - 'av'
                    - 'ips'
                    - 'app'
                    - 'url'
                    - 'utm'
                    - 'fwb'
            fsw_cnt:
                type: int
                description: Fsw cnt.
            ha_group_id:
                type: int
                description: Ha group id.
            ha_group_name:
                type: str
                description: Ha group name.
            ha_mode:
                type: str
                description: Enabled - Value reserved for non-FOS HA devices.
                choices:
                    - 'standalone'
                    - 'AP'
                    - 'AA'
                    - 'ELBC'
                    - 'DUAL'
                    - 'enabled'
                    - 'unknown'
                    - 'fmg-enabled'
                    - 'autoscale'
            ha_slave:
                type: list
                elements: dict
                description: Ha slave.
                suboptions:
                    idx:
                        type: int
                        description: Idx.
                    name:
                        type: str
                        description: Name.
                    prio:
                        type: int
                        description: Prio.
                    role:
                        type: str
                        description: Role.
                        choices:
                            - 'slave'
                            - 'master'
                    sn:
                        type: str
                        description: Sn.
                    status:
                        type: int
                        description: Status.
                    conf_status:
                        type: int
                        description: Conf status.
            hdisk_size:
                type: int
                description: Hdisk size.
            hostname:
                type: str
                description: Hostname.
            hw_rev_major:
                type: int
                description: Hw rev major.
            hw_rev_minor:
                type: int
                description: Hw rev minor.
            ip:
                type: str
                description: Ip.
            ips_ext:
                type: int
                description: Ips ext.
            ips_ver:
                type: str
                description: Ips ver.
            last_checked:
                type: int
                description: Last checked.
            last_resync:
                type: int
                description: Last resync.
            latitude:
                type: str
                description: Latitude.
            lic_flags:
                type: int
                description: Lic flags.
            lic_region:
                type: str
                description: Lic region.
            location_from:
                type: str
                description: Location from.
            logdisk_size:
                type: int
                description: Logdisk size.
            longitude:
                type: str
                description: Longitude.
            maxvdom:
                type: int
                description: Maxvdom.
            meta_fields:
                aliases: ['meta fields']
                type: dict
                description: Default metafields
            mgmt_id:
                type: int
                description: Mgmt id.
            mgmt_if:
                type: str
                description: Mgmt if.
            mgmt_mode:
                type: str
                description: Mgmt mode.
                choices:
                    - 'unreg'
                    - 'fmg'
                    - 'faz'
                    - 'fmgfaz'
            mgt_vdom:
                type: str
                description: Mgt vdom.
            mr:
                type: int
                description: Mr.
            name:
                type: str
                description: Unique name for the device.
            os_type:
                type: str
                description: Os type.
                choices:
                    - 'unknown'
                    - 'fos'
                    - 'fsw'
                    - 'foc'
                    - 'fml'
                    - 'faz'
                    - 'fwb'
                    - 'fch'
                    - 'fct'
                    - 'log'
                    - 'fmg'
                    - 'fsa'
                    - 'fdd'
                    - 'fac'
                    - 'fpx'
                    - 'fna'
                    - 'fdc'
                    - 'ffw'
                    - 'fsr'
                    - 'fad'
                    - 'fap'
                    - 'fxt'
                    - 'fts'
                    - 'fai'
                    - 'fwc'
                    - 'fis'
                    - 'fed'
                    - 'fpa'
                    - 'fca'
                    - 'ftc'
                    - 'fss'
                    - 'fra'
                    - 'sim'
            os_ver:
                type: str
                description: Os ver.
                choices:
                    - 'unknown'
                    - '0.0'
                    - '1.0'
                    - '2.0'
                    - '3.0'
                    - '4.0'
                    - '5.0'
                    - '6.0'
                    - '7.0'
                    - '8.0'
                    - '9.0'
            patch:
                type: int
                description: Patch.
            platform_str:
                type: str
                description: Platform str.
            psk:
                type: str
                description: Psk.
            sn:
                type: str
                description: Unique value for each device.
            vdom:
                type: list
                elements: dict
                description: Vdom.
                suboptions:
                    comments:
                        type: str
                        description: Comments.
                    name:
                        type: str
                        description: Name.
                    opmode:
                        type: str
                        description: Opmode.
                        choices:
                            - 'nat'
                            - 'transparent'
                    rtm_prof_id:
                        type: int
                        description: Rtm prof id.
                    status:
                        type: str
                        description: Status.
                    vpn_id:
                        type: int
                        description: Vpn id.
                    meta_fields:
                        aliases: ['meta fields']
                        type: dict
                        description: Meta fields.
                    vdom_type:
                        type: str
                        description: Vdom type.
                        choices:
                            - 'traffic'
                            - 'admin'
            version:
                type: int
                description: Version.
            vm_cpu:
                type: int
                description: Vm cpu.
            vm_cpu_limit:
                type: int
                description: Vm cpu limit.
            vm_lic_expire:
                type: int
                description: Vm lic expire.
            vm_mem:
                type: int
                description: Vm mem.
            vm_mem_limit:
                type: int
                description: Vm mem limit.
            vm_status:
                type: raw
                description: (int or str) Vm status.
            module_sn:
                type: str
                description: Module sn.
            prefer_img_ver:
                type: str
                description: Prefer img ver.
            prio:
                type: int
                description: Prio.
            role:
                type: str
                description: Role.
                choices:
                    - 'master'
                    - 'ha-slave'
                    - 'autoscale-slave'
            hyperscale:
                type: int
                description: Hyperscale.
            nsxt_service_name:
                type: str
                description: Nsxt service name.
            private_key:
                type: str
                description: Private key.
            private_key_status:
                type: int
                description: Private key status.
            vm_lic_overdue_since:
                type: int
                description: Vm lic overdue since.
            first_tunnel_up:
                type: int
                description: First tunnel up.
            eip:
                type: str
                description: Eip.
            mgmt_uuid:
                type: str
                description: Mgmt uuid.
            hw_generation:
                type: int
                description: Hw generation.
            relver_info:
                type: str
                description: Relver info.
            cluster_worker:
                type: str
                description: Cluster worker.
            ha_vsn:
                aliases: ['ha.vsn']
                type: str
                description: Ha.
            ha_upgrade_mode:
                type: int
                description: Ha upgrade mode.
            vm_payg_status:
                type: int
                description: Vm payg status.
            sov_sase_license:
                type: str
                description: Sov sase license.
'''

EXAMPLES = '''
- name: Delete first FOS devices from FMG In a specific adom
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
    device_adom: "root"
  tasks:
    - name: Fetch all devices
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dvmdb_device"
          params:
            adom: "{{ device_adom }}"
            device: "your_value"
      register: alldevices
    - name: No name
      when: alldevices.meta.response_data != []
      ansible.builtin.debug:
        msg:
          - "We are going to delete device: {{ alldevices.meta.response_data[0].name }}"
          - "IP of the device is: {{ alldevices.meta.response_data[0].ip }}"
    - name: Create The Task To Delete The Device
      when: alldevices.meta.response_data != [] and False
      fortinet.fortimanager.fmgr_dvm_cmd_del_device:
        dvm_cmd_del_device:
          device: "{{ alldevices.meta.response_data[0].name }}"
          adom: "{{ device_adom }}"
          flags:
            - "create_task"
            - "nonblocking"
      register: uninstalling_task
    - name: Poll the task of deleting device
      when: alldevices.meta.response_data != [] and False
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "task_task"
          params:
            task: "{{ uninstalling_task.meta.response_data.taskid }}"
      register: taskinfo
      until: taskinfo.meta.response_data.percent == 100
      retries: 30
      delay: 5
      failed_when: taskinfo.meta.response_data.state == 'error'
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
        '/dvmdb/adom/{adom}/device/{device}',
        '/dvmdb/device/{device}'
    ]
    url_params = ['adom', 'device']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'device': {'required': True, 'type': 'str'},
        'dvmdb_device': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adm_pass': {'no_log': True, 'type': 'raw'},
                'adm_usr': {'type': 'str'},
                'app_ver': {'type': 'str'},
                'av_ver': {'type': 'str'},
                'beta': {'type': 'int'},
                'branch_pt': {'type': 'int'},
                'build': {'type': 'int'},
                'checksum': {'type': 'str'},
                'conf_status': {'choices': ['unknown', 'insync', 'outofsync'], 'type': 'str'},
                'conn_mode': {'choices': ['active', 'passive'], 'type': 'str'},
                'conn_status': {'choices': ['UNKNOWN', 'up', 'down'], 'type': 'str'},
                'db_status': {'choices': ['unknown', 'nomod', 'mod'], 'type': 'str'},
                'desc': {'type': 'str'},
                'dev_status': {
                    'choices': [
                        'none', 'unknown', 'checkedin', 'inprogress', 'installed', 'aborted', 'sched', 'retry', 'canceled', 'pending', 'retrieved',
                        'changed_conf', 'sync_fail', 'timeout', 'rev_revert', 'auto_updated'
                    ],
                    'type': 'str'
                },
                'fap_cnt': {'type': 'int'},
                'faz.full_act': {'type': 'int'},
                'faz.perm': {'type': 'int'},
                'faz.quota': {'type': 'int'},
                'faz.used': {'type': 'int'},
                'fex_cnt': {'type': 'int'},
                'flags': {
                    'type': 'list',
                    'choices': [
                        'has_hdd', 'vdom_enabled', 'discover', 'reload', 'interim_build', 'offline_mode', 'is_model', 'fips_mode', 'linked_to_model',
                        'ip-conflict', 'faz-autosync', 'need_reset', 'backup_mode', 'azure_vwan_nva', 'fgsp_configured', 'cnf_mode', 'sase_managed',
                        'override_management_intf', 'sdwan_management', 'deny_api_access'
                    ],
                    'elements': 'str'
                },
                'foslic_cpu': {'type': 'int'},
                'foslic_dr_site': {'choices': ['disable', 'enable'], 'type': 'str'},
                'foslic_inst_time': {'type': 'int'},
                'foslic_last_sync': {'type': 'int'},
                'foslic_ram': {'type': 'int'},
                'foslic_type': {'choices': ['temporary', 'trial', 'regular', 'trial_expired'], 'type': 'str'},
                'foslic_utm': {'type': 'list', 'choices': ['fw', 'av', 'ips', 'app', 'url', 'utm', 'fwb'], 'elements': 'str'},
                'fsw_cnt': {'type': 'int'},
                'ha_group_id': {'type': 'int'},
                'ha_group_name': {'type': 'str'},
                'ha_mode': {'choices': ['standalone', 'AP', 'AA', 'ELBC', 'DUAL', 'enabled', 'unknown', 'fmg-enabled', 'autoscale'], 'type': 'str'},
                'ha_slave': {
                    'type': 'list',
                    'options': {
                        'idx': {'type': 'int'},
                        'name': {'type': 'str'},
                        'prio': {'type': 'int'},
                        'role': {'choices': ['slave', 'master'], 'type': 'str'},
                        'sn': {'type': 'str'},
                        'status': {'type': 'int'},
                        'conf_status': {'v_range': [['7.0.10', '7.0.14'], ['7.2.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'hdisk_size': {'type': 'int'},
                'hostname': {'type': 'str'},
                'hw_rev_major': {'type': 'int'},
                'hw_rev_minor': {'type': 'int'},
                'ip': {'type': 'str'},
                'ips_ext': {'type': 'int'},
                'ips_ver': {'type': 'str'},
                'last_checked': {'type': 'int'},
                'last_resync': {'type': 'int'},
                'latitude': {'type': 'str'},
                'lic_flags': {'type': 'int'},
                'lic_region': {'type': 'str'},
                'location_from': {'type': 'str'},
                'logdisk_size': {'type': 'int'},
                'longitude': {'type': 'str'},
                'maxvdom': {'type': 'int'},
                'meta fields': {'type': 'dict'},
                'mgmt_id': {'v_range': [['6.0.0', '7.2.0']], 'type': 'int'},
                'mgmt_if': {'type': 'str'},
                'mgmt_mode': {'choices': ['unreg', 'fmg', 'faz', 'fmgfaz'], 'type': 'str'},
                'mgt_vdom': {'type': 'str'},
                'mr': {'type': 'int'},
                'name': {'type': 'str'},
                'os_type': {
                    'choices': [
                        'unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw',
                        'fsr', 'fad', 'fap', 'fxt', 'fts', 'fai', 'fwc', 'fis', 'fed', 'fpa', 'fca', 'ftc', 'fss', 'fra', 'sim'
                    ],
                    'type': 'str'
                },
                'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                'patch': {'type': 'int'},
                'platform_str': {'type': 'str'},
                'psk': {'type': 'str'},
                'sn': {'type': 'str'},
                'vdom': {
                    'type': 'list',
                    'options': {
                        'comments': {'type': 'str'},
                        'name': {'type': 'str'},
                        'opmode': {'choices': ['nat', 'transparent'], 'type': 'str'},
                        'rtm_prof_id': {'type': 'int'},
                        'status': {'type': 'str'},
                        'vpn_id': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'meta fields': {'v_range': [['6.4.3', '']], 'type': 'dict'},
                        'vdom_type': {'v_range': [['7.2.0', '']], 'choices': ['traffic', 'admin'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'version': {'type': 'int'},
                'vm_cpu': {'type': 'int'},
                'vm_cpu_limit': {'type': 'int'},
                'vm_lic_expire': {'type': 'int'},
                'vm_mem': {'type': 'int'},
                'vm_mem_limit': {'type': 'int'},
                'vm_status': {'type': 'raw'},
                'module_sn': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'prefer_img_ver': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'prio': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'role': {'v_range': [['6.4.1', '']], 'choices': ['master', 'ha-slave', 'autoscale-slave'], 'type': 'str'},
                'hyperscale': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'nsxt_service_name': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'private_key': {'v_range': [['6.2.7', '6.2.13'], ['6.4.4', '']], 'no_log': True, 'type': 'str'},
                'private_key_status': {'v_range': [['6.2.7', '6.2.13'], ['6.4.4', '']], 'no_log': True, 'type': 'int'},
                'vm_lic_overdue_since': {'v_range': [['6.4.12', '6.4.15'], ['7.0.8', '7.0.14'], ['7.2.3', '']], 'type': 'int'},
                'first_tunnel_up': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'int'},
                'eip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'mgmt_uuid': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'hw_generation': {'v_range': [['7.2.4', '7.2.11'], ['7.4.1', '']], 'type': 'int'},
                'relver_info': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'cluster_worker': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'ha.vsn': {'v_range': [['7.2.6', '7.2.11'], ['7.4.4', '']], 'type': 'str'},
                'ha_upgrade_mode': {'v_range': [['7.4.4', '']], 'type': 'int'},
                'vm_payg_status': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'int'},
                'sov_sase_license': {'v_range': [['7.4.7', '7.4.7']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_device'),
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
