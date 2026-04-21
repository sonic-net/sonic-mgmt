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
module: fmgr_system_admin_profile
short_description: Admin profile.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    system_admin_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom_lock:
                aliases: ['adom-lock']
                type: str
                description:
                    - ADOM locking
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            adom_policy_packages:
                aliases: ['adom-policy-packages']
                type: str
                description:
                    - ADOM policy packages.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            adom_switch:
                aliases: ['adom-switch']
                type: str
                description:
                    - Administrator domain.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            app_filter:
                aliases: ['app-filter']
                type: str
                description:
                    - App filter.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            assignment:
                type: str
                description:
                    - Assignment permission.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            change_password:
                aliases: ['change-password']
                type: str
                description:
                    - Enable/disable restricted user to change self password.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            config_retrieve:
                aliases: ['config-retrieve']
                type: str
                description:
                    - Configuration retrieve.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            config_revert:
                aliases: ['config-revert']
                type: str
                description:
                    - Revert Configuration from Revision History
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            consistency_check:
                aliases: ['consistency-check']
                type: str
                description:
                    - Consistency check.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            datamask:
                type: str
                description:
                    - Enable/disable data masking.
                    - disable - Disable data masking.
                    - enable - Enable data masking.
                choices:
                    - 'disable'
                    - 'enable'
            datamask_custom_fields:
                aliases: ['datamask-custom-fields']
                type: list
                elements: dict
                description: Datamask custom fields.
                suboptions:
                    field_category:
                        aliases: ['field-category']
                        type: list
                        elements: str
                        description:
                            - Field categories.
                            - log - Log.
                            - fortiview - FortiView.
                            - alert - Event management.
                            - ueba - UEBA.
                            - all - All.
                        choices:
                            - 'log'
                            - 'fortiview'
                            - 'alert'
                            - 'ueba'
                            - 'all'
                    field_name:
                        aliases: ['field-name']
                        type: str
                        description: Field name.
                    field_status:
                        aliases: ['field-status']
                        type: str
                        description:
                            - Field status.
                            - disable - Disable field.
                            - enable - Enable field.
                        choices:
                            - 'disable'
                            - 'enable'
                    field_type:
                        aliases: ['field-type']
                        type: str
                        description:
                            - Field type.
                            - string - String.
                            - ip - IP.
                            - mac - MAC address.
                            - email - Email address.
                            - unknown - Unknown.
                        choices:
                            - 'string'
                            - 'ip'
                            - 'mac'
                            - 'email'
                            - 'unknown'
            datamask_custom_priority:
                aliases: ['datamask-custom-priority']
                type: str
                description:
                    - Prioritize custom fields.
                    - disable - Disable custom field search priority.
                    - enable - Enable custom field search priority.
                choices:
                    - 'disable'
                    - 'enable'
            datamask_fields:
                aliases: ['datamask-fields']
                type: list
                elements: str
                description:
                    - Data masking fields.
                    - user - User name.
                    - srcip - Source IP.
                    - srcname - Source name.
                    - srcmac - Source MAC.
                    - dstip - Destination IP.
                    - dstname - Dst name.
                    - email - Email.
                    - message - Message.
                    - domain - Domain.
                choices:
                    - 'user'
                    - 'srcip'
                    - 'srcname'
                    - 'srcmac'
                    - 'dstip'
                    - 'dstname'
                    - 'email'
                    - 'message'
                    - 'domain'
            datamask_key:
                aliases: ['datamask-key']
                type: raw
                description: (list) Data masking encryption key.
            deploy_management:
                aliases: ['deploy-management']
                type: str
                description:
                    - Install to devices.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            description:
                type: str
                description: Description.
            device_ap:
                aliases: ['device-ap']
                type: str
                description:
                    - Manage AP.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_config:
                aliases: ['device-config']
                type: str
                description:
                    - Manage device configurations.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_forticlient:
                aliases: ['device-forticlient']
                type: str
                description:
                    - Manage FortiClient.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_fortiswitch:
                aliases: ['device-fortiswitch']
                type: str
                description:
                    - Manage FortiSwitch.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_manager:
                aliases: ['device-manager']
                type: str
                description:
                    - Device manager.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_op:
                aliases: ['device-op']
                type: str
                description:
                    - Device add/delete/edit.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_policy_package_lock:
                aliases: ['device-policy-package-lock']
                type: str
                description:
                    - Device/Policy Package locking
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_profile:
                aliases: ['device-profile']
                type: str
                description:
                    - Device profile permission.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_revision_deletion:
                aliases: ['device-revision-deletion']
                type: str
                description:
                    - Delete device revision.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device_wan_link_load_balance:
                aliases: ['device-wan-link-load-balance']
                type: str
                description:
                    - Manage WAN link load balance.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            event_management:
                aliases: ['event-management']
                type: str
                description:
                    - Event management.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd_center_advanced:
                aliases: ['fgd-center-advanced']
                type: str
                description:
                    - FortiGuard Center Advanced.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd_center_fmw_mgmt:
                aliases: ['fgd-center-fmw-mgmt']
                type: str
                description:
                    - FortiGuard Center Firmware Management.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd_center_licensing:
                aliases: ['fgd-center-licensing']
                type: str
                description:
                    - FortiGuard Center Licensing.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd_center:
                type: str
                description:
                    - FortiGuard Center.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            global_policy_packages:
                aliases: ['global-policy-packages']
                type: str
                description:
                    - Global policy packages.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            import_policy_packages:
                aliases: ['import-policy-packages']
                type: str
                description:
                    - Import Policy Package.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            intf_mapping:
                aliases: ['intf-mapping']
                type: str
                description:
                    - Interface Mapping
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips_filter:
                aliases: ['ips-filter']
                type: str
                description:
                    - IPS filter.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            log_viewer:
                aliases: ['log-viewer']
                type: str
                description:
                    - Log viewer.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            policy_objects:
                aliases: ['policy-objects']
                type: str
                description:
                    - Policy objects permission.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            profileid:
                type: str
                description: Profile ID.
                required: true
            read_passwd:
                aliases: ['read-passwd']
                type: str
                description:
                    - View password in clear text.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            realtime_monitor:
                aliases: ['realtime-monitor']
                type: str
                description:
                    - Realtime monitor.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            report_viewer:
                aliases: ['report-viewer']
                type: str
                description:
                    - Report viewer.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            scope:
                type: str
                description:
                    - Scope.
                    - global - Global scope.
                    - adom - ADOM scope.
                choices:
                    - 'global'
                    - 'adom'
            set_install_targets:
                aliases: ['set-install-targets']
                type: str
                description:
                    - Edit installation targets.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            system_setting:
                aliases: ['system-setting']
                type: str
                description:
                    - System setting.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            term_access:
                aliases: ['term-access']
                type: str
                description:
                    - Terminal access.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            type:
                type: str
                description:
                    - profile type.
                    - system - System admin.
                    - restricted - Restricted admin.
                choices:
                    - 'system'
                    - 'restricted'
            vpn_manager:
                aliases: ['vpn-manager']
                type: str
                description:
                    - VPN manager.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            web_filter:
                aliases: ['web-filter']
                type: str
                description:
                    - Web filter.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            datamask_unmasked_time:
                aliases: ['datamask-unmasked-time']
                type: int
                description: Time in days without data masking.
            super_user_profile:
                aliases: ['super-user-profile']
                type: str
                description:
                    - Enable/disable super user profile
                    - disable - Disable super user profile
                    - enable - Enable super user profile
                choices:
                    - 'disable'
                    - 'enable'
            allow_to_install:
                aliases: ['allow-to-install']
                type: str
                description:
                    - Enable/disable the restricted user to install objects to the devices.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            extension_access:
                aliases: ['extension-access']
                type: str
                description:
                    - Manage extension access.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fabric_viewer:
                aliases: ['fabric-viewer']
                type: str
                description:
                    - Fabric viewer.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            run_report:
                aliases: ['run-report']
                type: str
                description:
                    - Run reports.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            script_access:
                aliases: ['script-access']
                type: str
                description:
                    - Script access.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            triage_events:
                aliases: ['triage-events']
                type: str
                description:
                    - Triage events.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            update_incidents:
                aliases: ['update-incidents']
                type: str
                description:
                    - Create/update incidents.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips_objects:
                aliases: ['ips-objects']
                type: str
                description:
                    - Ips objects configuration.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ipv6_trusthost1:
                type: str
                description: Admin user trusted host IPv6, default
            ipv6_trusthost10:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost2:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost3:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost4:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost5:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost6:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost7:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost8:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost9:
                type: str
                description: Admin user trusted host IPv6, default ffff
            rpc_permit:
                aliases: ['rpc-permit']
                type: str
                description:
                    - Set none/read/read-write rpc-permission
                    - read-write - Read-write permission.
                    - none - No permission.
                    - read - Read-only permission.
                choices:
                    - 'read-write'
                    - 'none'
                    - 'read'
            trusthost1:
                type: str
                description: Admin user trusted host IP, default 0.
            trusthost10:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost2:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost3:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost4:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost5:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost6:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost7:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost8:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost9:
                type: str
                description: Admin user trusted host IP, default 255.
            ips_baseline_cfg:
                aliases: ['ips-baseline-cfg']
                type: str
                description:
                    - Ips baseline sensor configration.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips_baseline_ovrd:
                aliases: ['ips-baseline-ovrd']
                type: str
                description:
                    - Enable/disable override baseline ips sensor.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            device_fortiextender:
                aliases: ['device-fortiextender']
                type: str
                description:
                    - Manage FortiExtender.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips_lock:
                aliases: ['ips-lock']
                type: str
                description:
                    - IPS locking
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgt_gui_proxy:
                aliases: ['fgt-gui-proxy']
                type: str
                description:
                    - FortiGate GUI proxy.
                    - disable - No permission.
                    - enable - With permission.
                choices:
                    - 'disable'
                    - 'enable'
            policy_ips_attrs:
                aliases: ['policy-ips-attrs']
                type: str
                description:
                    - Policy ips attributes configuration.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            write_passwd_access:
                aliases: ['write-passwd-access']
                type: str
                description:
                    - set all/specify-by-user/specify-by-profile write password access mode.
                    - all - All except super users.
                    - specify-by-user - Specify by user.
                    - specify-by-profile - Specify by profile.
                choices:
                    - 'all'
                    - 'specify-by-user'
                    - 'specify-by-profile'
            write_passwd_profiles:
                aliases: ['write-passwd-profiles']
                type: list
                elements: dict
                description: Write passwd profiles.
                suboptions:
                    profileid:
                        type: str
                        description: Profile ID.
            write_passwd_user_list:
                aliases: ['write-passwd-user-list']
                type: list
                elements: dict
                description: Write passwd user list.
                suboptions:
                    userid:
                        type: str
                        description: User ID.
            adom_admin:
                aliases: ['adom-admin']
                type: str
                description:
                    - Enable Adom Admin.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            device_fwm_profile:
                aliases: ['device-fwm-profile']
                type: str
                description:
                    - Device firmware profile permission.
                    - none - No permission.
                    - read - Read permission.
                    - read-write - Read-write permission.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
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
    - name: Admin profile.
      fortinet.fortimanager.fmgr_system_admin_profile:
        bypass_validation: false
        state: present
        system_admin_profile:
          description: ansible-test-description
          profileid: ansible-test-profile
          scope: adom # <value in [global, adom]>
          type: system # <value in [system, restricted]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the admin profiles
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_admin_profile"
          params:
            profile: "your_value"
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
        '/cli/global/system/admin/profile'
    ]
    url_params = []
    module_primary_key = 'profileid'
    module_arg_spec = {
        'system_admin_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adom-lock': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'adom-policy-packages': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'adom-switch': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'app-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'assignment': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'change-password': {'choices': ['disable', 'enable'], 'type': 'str'},
                'config-retrieve': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'config-revert': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'consistency-check': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'datamask': {'choices': ['disable', 'enable'], 'type': 'str'},
                'datamask-custom-fields': {
                    'type': 'list',
                    'options': {
                        'field-category': {'type': 'list', 'choices': ['log', 'fortiview', 'alert', 'ueba', 'all'], 'elements': 'str'},
                        'field-name': {'type': 'str'},
                        'field-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'field-type': {'choices': ['string', 'ip', 'mac', 'email', 'unknown'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'datamask-custom-priority': {'choices': ['disable', 'enable'], 'type': 'str'},
                'datamask-fields': {
                    'type': 'list',
                    'choices': ['user', 'srcip', 'srcname', 'srcmac', 'dstip', 'dstname', 'email', 'message', 'domain'],
                    'elements': 'str'
                },
                'datamask-key': {'no_log': True, 'type': 'raw'},
                'deploy-management': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'description': {'type': 'str'},
                'device-ap': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-config': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-forticlient': {'v_range': [['6.0.0', '7.4.2']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-fortiswitch': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-manager': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-op': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-policy-package-lock': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-profile': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-revision-deletion': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'device-wan-link-load-balance': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'event-management': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgd-center-advanced': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgd-center-fmw-mgmt': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgd-center-licensing': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgd_center': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'global-policy-packages': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'import-policy-packages': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'intf-mapping': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-viewer': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'policy-objects': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'profileid': {'required': True, 'type': 'str'},
                'read-passwd': {'v_range': [['6.0.0', '7.4.2']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'realtime-monitor': {'v_range': [['6.0.0', '7.4.2']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'report-viewer': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'scope': {'choices': ['global', 'adom'], 'type': 'str'},
                'set-install-targets': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'system-setting': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'term-access': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'type': {'choices': ['system', 'restricted'], 'type': 'str'},
                'vpn-manager': {'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'web-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'datamask-unmasked-time': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'super-user-profile': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allow-to-install': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extension-access': {'v_range': [['6.4.2', '7.2.10'], ['7.4.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fabric-viewer': {'v_range': [['6.4.6', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'run-report': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'script-access': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'triage-events': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'update-incidents': {'v_range': [['7.0.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-objects': {'v_range': [['7.2.0', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ipv6_trusthost1': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost10': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost2': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost3': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost4': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost5': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost6': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost7': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost8': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ipv6_trusthost9': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'rpc-permit': {'v_range': [['7.0.3', '']], 'choices': ['read-write', 'none', 'read'], 'type': 'str'},
                'trusthost1': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost10': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost2': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost3': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost4': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost5': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost6': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost7': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost8': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'trusthost9': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'ips-baseline-cfg': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-baseline-ovrd': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device-fortiextender': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips-lock': {'v_range': [['7.2.2', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fgt-gui-proxy': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-ips-attrs': {'v_range': [['7.4.2', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'write-passwd-access': {'v_range': [['7.4.2', '']], 'choices': ['all', 'specify-by-user', 'specify-by-profile'], 'type': 'str'},
                'write-passwd-profiles': {
                    'v_range': [['7.4.2', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {'profileid': {'v_range': [['7.4.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'write-passwd-user-list': {
                    'v_range': [['7.4.2', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {'userid': {'v_range': [['7.4.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'adom-admin': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device-fwm-profile': {'v_range': [['7.4.7', '7.4.7']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_profile'),
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
