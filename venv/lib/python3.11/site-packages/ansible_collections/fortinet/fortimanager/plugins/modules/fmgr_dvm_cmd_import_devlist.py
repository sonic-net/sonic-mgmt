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
module: fmgr_dvm_cmd_import_devlist
short_description: Import a list of ADOMs and devices.
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
    dvm_cmd_import_devlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: Name or ID of the ADOM where the command is to be executed on.
            flags:
                type: list
                elements: str
                description:
                    - create_task - Create a new task in task manager database.
                    - nonblocking - The API will return immediately in for non-blocking call.
                choices:
                    - 'none'
                    - 'create_task'
                    - 'nonblocking'
                    - 'log_dev'
            import_adom_members:
                aliases: ['import-adom-members']
                type: list
                elements: dict
                description: Associations between devices and ADOMs.
                suboptions:
                    adom:
                        type: str
                        description: Target ADOM to associate device VDOM with.
                    dev:
                        type: str
                        description: Dev.
                    vdom:
                        type: str
                        description: Vdom.
            import_adoms:
                aliases: ['import-adoms']
                type: list
                elements: dict
                description: A list of ADOM and device group objects to be imported.
                suboptions:
                    desc:
                        type: str
                        description: Desc.
                    flags:
                        type: list
                        elements: str
                        description: Flags.
                        choices:
                            - 'migration'
                            - 'db_export'
                            - 'no_vpn_console'
                            - 'backup'
                            - 'other_devices'
                            - 'central_sdwan'
                            - 'is_autosync'
                            - 'per_device_wtp'
                            - 'policy_check_on_install'
                            - 'install_on_policy_check_fail'
                            - 'auto_push_cfg'
                            - 'per_device_fsw'
                            - 'install_deselect_all'
                    log_db_retention_hours:
                        type: int
                        description: Log db retention hours.
                    log_disk_quota:
                        type: int
                        description: Log disk quota.
                    log_disk_quota_alert_thres:
                        type: int
                        description: Log disk quota alert thres.
                    log_disk_quota_split_ratio:
                        type: int
                        description: Log disk quota split ratio.
                    log_file_retention_hours:
                        type: int
                        description: Log file retention hours.
                    meta_fields:
                        aliases: ['meta fields']
                        type: dict
                        description: Default metafields
                    mig_mr:
                        type: int
                        description: Mig mr.
                    mig_os_ver:
                        type: str
                        description: Mig os ver.
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
                    mode:
                        type: str
                        description:
                            - ems -
                            - provider - Global database.
                        choices:
                            - 'ems'
                            - 'gms'
                            - 'provider'
                    mr:
                        type: int
                        description: Mr.
                    name:
                        type: str
                        description: Name.
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
                    restricted_prds:
                        type: raw
                        description: (list or str) Restricted prds.
                        choices:
                            - 'fos'
                            - 'foc'
                            - 'fml'
                            - 'fch'
                            - 'fwb'
                            - 'log'
                            - 'fct'
                            - 'faz'
                            - 'fsa'
                            - 'fsw'
                            - 'fmg'
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
                            - 'fabric'
                            - 'fpa'
                            - 'fca'
                            - 'ftc'
                            - 'fss'
                            - 'sim'
                            - 'fra'
                    state:
                        type: int
                        description: State.
                    uuid:
                        type: str
                        description: Uuid.
                    create_time:
                        type: int
                        description: Create time.
                    workspace_mode:
                        type: int
                        description: Workspace mode.
                    tz:
                        type: int
                        description: Tz.
                    lock_override:
                        type: int
                        description: Lock override.
                    primary_dns_ip4:
                        type: str
                        description: Primary dns ip4.
                    primary_dns_ip6_1:
                        type: int
                        description: Primary dns ip6 1.
                    primary_dns_ip6_2:
                        type: int
                        description: Primary dns ip6 2.
                    primary_dns_ip6_3:
                        type: int
                        description: Primary dns ip6 3.
                    primary_dns_ip6_4:
                        type: int
                        description: Primary dns ip6 4.
                    secondary_dns_ip4:
                        type: str
                        description: Secondary dns ip4.
                    secondary_dns_ip6_1:
                        type: int
                        description: Secondary dns ip6 1.
                    secondary_dns_ip6_2:
                        type: int
                        description: Secondary dns ip6 2.
                    secondary_dns_ip6_3:
                        type: int
                        description: Secondary dns ip6 3.
                    secondary_dns_ip6_4:
                        type: int
                        description: Secondary dns ip6 4.
            import_devices:
                aliases: ['import-devices']
                type: list
                elements: dict
                description: A list of device objects to be imported.
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
            import_group_members:
                aliases: ['import-group-members']
                type: list
                elements: dict
                description: Associations between devices and device groups.
                suboptions:
                    adom:
                        type: str
                        description: ADOM where the device group is located.
                    dev:
                        type: str
                        description: Dev.
                    grp:
                        type: str
                        description: Target device group to associate device VDOM with.
                    vdom:
                        type: str
                        description: Vdom.
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
    - name: Import a list of ADOMs and devices.
      fortinet.fortimanager.fmgr_dvm_cmd_import_devlist:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        dvm_cmd_import_devlist:
          # adom: <string>
          # flags:
          #   - "none"
          #   - "create_task"
          #   - "nonblocking"
          #   - "log_dev"
          # import_adom_members:
          #   - adom: <string>
          #     dev: <string>
          #     vdom: <string>
          # import_adoms:
          #   - desc: <string>
          #     flags:
          #       - "migration"
          #       - "db_export"
          #       - "no_vpn_console"
          #       - "backup"
          #       - "other_devices"
          #       - "central_sdwan"
          #       - "is_autosync"
          #       - "per_device_wtp"
          #       - "policy_check_on_install"
          #       - "install_on_policy_check_fail"
          #       - "auto_push_cfg"
          #       - "per_device_fsw"
          #       - "install_deselect_all"
          #     log_db_retention_hours: <integer>
          #     log_disk_quota: <integer>
          #     log_disk_quota_alert_thres: <integer>
          #     log_disk_quota_split_ratio: <integer>
          #     log_file_retention_hours: <integer>
          #     meta_fields: <dict>
          #     mig_mr: <integer>
          #     mig_os_ver: <value in [unknown, 0.0, 1.0, ...]>
          #     mode: <value in [ems, gms, provider]>
          #     mr: <integer>
          #     name: <string>
          #     os_ver: <value in [unknown, 0.0, 1.0, ...]>
          #     restricted_prds: # <list or string>
          #       - "fos"
          #       - "foc"
          #       - "fml"
          #       - "fch"
          #       - "fwb"
          #       - "log"
          #       - "fct"
          #       - "faz"
          #       - "fsa"
          #       - "fsw"
          #       - "fmg"
          #       - "fdd"
          #       - "fac"
          #       - "fpx"
          #       - "fna"
          #       - "fdc"
          #       - "ffw"
          #       - "fsr"
          #       - "fad"
          #       - "fap"
          #       - "fxt"
          #       - "fts"
          #       - "fai"
          #       - "fwc"
          #       - "fis"
          #       - "fed"
          #       - "fabric"
          #       - "fpa"
          #       - "fca"
          #       - "ftc"
          #       - "fss"
          #       - "sim"
          #       - "fra"
          #     state: <integer>
          #     uuid: <string>
          #     create_time: <integer>
          #     workspace_mode: <integer>
          #     tz: <integer>
          #     lock_override: <integer>
          #     primary_dns_ip4: <string>
          #     primary_dns_ip6_1: <integer>
          #     primary_dns_ip6_2: <integer>
          #     primary_dns_ip6_3: <integer>
          #     primary_dns_ip6_4: <integer>
          #     secondary_dns_ip4: <string>
          #     secondary_dns_ip6_1: <integer>
          #     secondary_dns_ip6_2: <integer>
          #     secondary_dns_ip6_3: <integer>
          #     secondary_dns_ip6_4: <integer>
          # import_devices:
          #   - adm_pass: <list or string>
          #     adm_usr: <string>
          #     app_ver: <string>
          #     av_ver: <string>
          #     beta: <integer>
          #     branch_pt: <integer>
          #     build: <integer>
          #     checksum: <string>
          #     conf_status: <value in [unknown, insync, outofsync]>
          #     conn_mode: <value in [active, passive]>
          #     conn_status: <value in [UNKNOWN, up, down]>
          #     db_status: <value in [unknown, nomod, mod]>
          #     desc: <string>
          #     dev_status: <value in [none, unknown, checkedin, ...]>
          #     fap_cnt: <integer>
          #     faz_full_act: <integer>
          #     faz_perm: <integer>
          #     faz_quota: <integer>
          #     faz_used: <integer>
          #     fex_cnt: <integer>
          #     flags:
          #       - "has_hdd"
          #       - "vdom_enabled"
          #       - "discover"
          #       - "reload"
          #       - "interim_build"
          #       - "offline_mode"
          #       - "is_model"
          #       - "fips_mode"
          #       - "linked_to_model"
          #       - "ip-conflict"
          #       - "faz-autosync"
          #       - "need_reset"
          #       - "backup_mode"
          #       - "azure_vwan_nva"
          #       - "fgsp_configured"
          #       - "cnf_mode"
          #       - "sase_managed"
          #       - "override_management_intf"
          #       - "sdwan_management"
          #       - "deny_api_access"
          #     foslic_cpu: <integer>
          #     foslic_dr_site: <value in [disable, enable]>
          #     foslic_inst_time: <integer>
          #     foslic_last_sync: <integer>
          #     foslic_ram: <integer>
          #     foslic_type: <value in [temporary, trial, regular, ...]>
          #     foslic_utm:
          #       - "fw"
          #       - "av"
          #       - "ips"
          #       - "app"
          #       - "url"
          #       - "utm"
          #       - "fwb"
          #     fsw_cnt: <integer>
          #     ha_group_id: <integer>
          #     ha_group_name: <string>
          #     ha_mode: <value in [standalone, AP, AA, ...]>
          #     ha_slave:
          #       - idx: <integer>
          #         name: <string>
          #         prio: <integer>
          #         role: <value in [slave, master]>
          #         sn: <string>
          #         status: <integer>
          #         conf_status: <integer>
          #     hdisk_size: <integer>
          #     hostname: <string>
          #     hw_rev_major: <integer>
          #     hw_rev_minor: <integer>
          #     ip: <string>
          #     ips_ext: <integer>
          #     ips_ver: <string>
          #     last_checked: <integer>
          #     last_resync: <integer>
          #     latitude: <string>
          #     lic_flags: <integer>
          #     lic_region: <string>
          #     location_from: <string>
          #     logdisk_size: <integer>
          #     longitude: <string>
          #     maxvdom: <integer>
          #     meta_fields: <dict>
          #     mgmt_id: <integer>
          #     mgmt_if: <string>
          #     mgmt_mode: <value in [unreg, fmg, faz, ...]>
          #     mgt_vdom: <string>
          #     mr: <integer>
          #     name: <string>
          #     os_type: <value in [unknown, fos, fsw, ...]>
          #     os_ver: <value in [unknown, 0.0, 1.0, ...]>
          #     patch: <integer>
          #     platform_str: <string>
          #     psk: <string>
          #     sn: <string>
          #     vdom:
          #       - comments: <string>
          #         name: <string>
          #         opmode: <value in [nat, transparent]>
          #         rtm_prof_id: <integer>
          #         status: <string>
          #         vpn_id: <integer>
          #         meta_fields: <dict>
          #         vdom_type: <value in [traffic, admin]>
          #     version: <integer>
          #     vm_cpu: <integer>
          #     vm_cpu_limit: <integer>
          #     vm_lic_expire: <integer>
          #     vm_mem: <integer>
          #     vm_mem_limit: <integer>
          #     vm_status: <value in [N/A, No License, Startup, ...]>
          #     module_sn: <string>
          #     prefer_img_ver: <string>
          #     prio: <integer>
          #     role: <value in [master, ha-slave, autoscale-slave]>
          #     hyperscale: <integer>
          #     nsxt_service_name: <string>
          #     private_key: <string>
          #     private_key_status: <integer>
          #     vm_lic_overdue_since: <integer>
          #     first_tunnel_up: <integer>
          #     eip: <string>
          #     mgmt_uuid: <string>
          #     hw_generation: <integer>
          #     relver_info: <string>
          #     cluster_worker: <string>
          #     ha_vsn: <string>
          #     ha_upgrade_mode: <integer>
          #     vm_payg_status: <integer>
          #     sov_sase_license: <string>
          # import_group_members:
          #   - adom: <string>
          #     dev: <string>
          #     grp: <string>
          #     vdom: <string>
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
        '/dvm/cmd/import/dev-list'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'dvm_cmd_import_devlist': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'str'},
                'flags': {'type': 'list', 'choices': ['none', 'create_task', 'nonblocking', 'log_dev'], 'elements': 'str'},
                'import-adom-members': {
                    'type': 'list',
                    'options': {'adom': {'type': 'str'}, 'dev': {'type': 'str'}, 'vdom': {'type': 'str'}},
                    'elements': 'dict'
                },
                'import-adoms': {
                    'type': 'list',
                    'options': {
                        'desc': {'type': 'str'},
                        'flags': {
                            'type': 'list',
                            'choices': [
                                'migration', 'db_export', 'no_vpn_console', 'backup', 'other_devices', 'central_sdwan', 'is_autosync', 'per_device_wtp',
                                'policy_check_on_install', 'install_on_policy_check_fail', 'auto_push_cfg', 'per_device_fsw', 'install_deselect_all'
                            ],
                            'elements': 'str'
                        },
                        'log_db_retention_hours': {'type': 'int'},
                        'log_disk_quota': {'type': 'int'},
                        'log_disk_quota_alert_thres': {'type': 'int'},
                        'log_disk_quota_split_ratio': {'type': 'int'},
                        'log_file_retention_hours': {'type': 'int'},
                        'meta fields': {'type': 'dict'},
                        'mig_mr': {'type': 'int'},
                        'mig_os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                        'mode': {'choices': ['ems', 'gms', 'provider'], 'type': 'str'},
                        'mr': {'type': 'int'},
                        'name': {'type': 'str'},
                        'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                        'restricted_prds': {
                            'type': 'raw',
                            'choices': [
                                'fos', 'foc', 'fml', 'fch', 'fwb', 'log', 'fct', 'faz', 'fsa', 'fsw', 'fmg', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw',
                                'fsr', 'fad', 'fap', 'fxt', 'fts', 'fai', 'fwc', 'fis', 'fed', 'fabric', 'fpa', 'fca', 'ftc', 'fss', 'sim', 'fra'
                            ]
                        },
                        'state': {'type': 'int'},
                        'uuid': {'type': 'str'},
                        'create_time': {'v_range': [['6.4.1', '']], 'type': 'int'},
                        'workspace_mode': {'v_range': [['6.4.3', '']], 'type': 'int'},
                        'tz': {'v_range': [['7.4.0', '']], 'type': 'int'},
                        'lock_override': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'primary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'primary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'primary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'primary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'primary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'secondary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'secondary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'import-devices': {
                    'type': 'list',
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
                                'none', 'unknown', 'checkedin', 'inprogress', 'installed', 'aborted', 'sched', 'retry', 'canceled', 'pending',
                                'retrieved', 'changed_conf', 'sync_fail', 'timeout', 'rev_revert', 'auto_updated'
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
                                'has_hdd', 'vdom_enabled', 'discover', 'reload', 'interim_build', 'offline_mode', 'is_model', 'fips_mode',
                                'linked_to_model', 'ip-conflict', 'faz-autosync', 'need_reset', 'backup_mode', 'azure_vwan_nva', 'fgsp_configured',
                                'cnf_mode', 'sase_managed', 'override_management_intf', 'sdwan_management', 'deny_api_access'
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
                        'ha_mode': {
                            'choices': ['standalone', 'AP', 'AA', 'ELBC', 'DUAL', 'enabled', 'unknown', 'fmg-enabled', 'autoscale'],
                            'type': 'str'
                        },
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
                                'unknown', 'fos', 'fsw', 'foc', 'fml', 'faz', 'fwb', 'fch', 'fct', 'log', 'fmg', 'fsa', 'fdd', 'fac', 'fpx', 'fna',
                                'fdc', 'ffw', 'fsr', 'fad', 'fap', 'fxt', 'fts', 'fai', 'fwc', 'fis', 'fed', 'fpa', 'fca', 'ftc', 'fss', 'fra', 'sim'
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
                    },
                    'elements': 'dict'
                },
                'import-group-members': {
                    'type': 'list',
                    'options': {'adom': {'type': 'str'}, 'dev': {'type': 'str'}, 'grp': {'type': 'str'}, 'vdom': {'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvm_cmd_import_devlist'),
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
