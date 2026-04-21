#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_domain_permissions_profile
short_description: Manages domain-permissions-profile objects on Checkpoint over Web Services API
description:
  - Manages domain-permissions-profile objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "3.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  permission_type:
    description:
      - The type of the Permissions Profile.
    type: str
    choices: ['read write all', 'read only all', 'customized']
  edit_common_objects:
    description:
      - Define and manage objects in the Check Point database, Network Objects, Services, Custom Application Site, VPN Community, Users, Servers,
        Resources, Time, UserCheck, and Limit.<br>Only a 'Customized' permission-type profile can edit this permission.
    type: bool
  access_control:
    description:
      - Access Control permissions.<br>Only a 'Customized' permission-type profile can edit these permissions.
    type: dict
    suboptions:
      show_policy:
        description:
          - Select to let administrators work with Access Control rules and NAT rules. If not selected, administrators cannot see these rules.
        type: bool
      policy_layers:
        description:
          - Layer editing permissions.<br>Available only if show-policy is set to true.
        type: dict
        suboptions:
          edit_layers:
            description:
              - a "By Software Blades" - Edit Access Control layers that contain the blades enabled in the Permissions Profile.<br>"By
                Selected Profile In A Layer Editor" - Administrators can only edit the layer if the Access Control layer editor gives editing permission to
                their profiles.
            type: str
            choices: ['By Software Blades', 'By Selected Profile In A Layer Editor']
          app_control_and_url_filtering:
            description:
              - Use Application and URL Filtering in Access Control rules.<br>Available only if edit-layers is set to "By Software Blades".
            type: bool
          content_awareness:
            description:
              - Use specified data types in Access Control rules.<br>Available only if edit-layers is set to "By Software Blades".
            type: bool
          firewall:
            description:
              - Work with Access Control and other Software Blades that do not have their own Policies.<br>Available only if edit-layers is
                set to "By Software Blades".
            type: bool
          mobile_access:
            description:
              - Work with Mobile Access rules.<br>Available only if edit-layers is set to "By Software Blades".
            type: bool
      dlp_policy:
        description:
          - Configure DLP rules and Policies.
        type: str
        choices: ['read', 'write', 'disabled']
      geo_control_policy:
        description:
          - Work with Access Control rules that control traffic to and from specified countries.
        type: str
        choices: ['read', 'write', 'disabled']
      nat_policy:
        description:
          - Work with NAT in Access Control rules.
        type: str
        choices: ['read', 'write', 'disabled']
      qos_policy:
        description:
          - Work with QoS Policies and rules.
        type: str
        choices: ['read', 'write', 'disabled']
      access_control_objects_and_settings:
        description:
          - Allow editing of the following objet types, VPN Community, Access Role, Custom application group,Custom application, Custom category,
            Limit, Application - Match Settings, Application Category - Match Settings,Override Categorization, Application and URL filtering blade - Advanced
            Settings, Content Awareness blade - Advanced Settings.
        type: str
        choices: ['read', 'write', 'disabled']
      app_control_and_url_filtering_update:
        description:
          - Install Application and URL Filtering updates.
        type: bool
      install_policy:
        description:
          - Install Access Control Policies.
        type: bool
  endpoint:
    description:
      - Endpoint permissions. Not supported for Multi-Domain Servers.<br>Only a 'Customized' permission-type profile can edit these permissions.
    type: dict
    suboptions:
      manage_policies_and_software_deployment:
        description:
          - The administrator can work with policies, rules and actions.
        type: bool
      edit_endpoint_policies:
        description:
          - Available only if manage-policies-and-software-deployment is set to true.
        type: bool
      policies_installation:
        description:
          - The administrator can install policies on endpoint computers.
        type: bool
      edit_software_deployment:
        description:
          - The administrator can define deployment rules, create packages for export, and configure advanced package settings.<br>Available only
            if manage-policies-and-software-deployment is set to true.
        type: bool
      software_deployment_installation:
        description:
          - The administrator can deploy packages and install endpoint clients.
        type: bool
      allow_executing_push_operations:
        description:
          - The administrator can start operations that the Security Management Server pushes directly to client computers with no policy
            installation required.
        type: bool
      authorize_preboot_users:
        description:
          - The administrator can add and remove the users who are permitted to log on to Endpoint Security client computers with Full Disk Encryption.
        type: bool
      recovery_media:
        description:
          - The administrator can create recovery media on endpoint computers and devices.
        type: bool
      remote_help:
        description:
          - The administrator can use the Remote Help feature to reset user passwords and give access to locked out users.
        type: bool
      reset_computer_data:
        description:
          - The administrator can reset a computer, which deletes all information about the computer from the Security Management Server.
        type: bool
  events_and_reports:
    description:
      - Events and Reports permissions.<br>Only a 'Customized' permission-type profile can edit these permissions.
    type: dict
    suboptions:
      smart_event:
        description:
          - a 'Custom' - Configure SmartEvent permissions.
        type: str
        choices: ['custom', 'app control and url filtering reports only']
      events:
        description:
          - Work with event queries on the Events tab. Create custom event queries.<br>Available only if smart-event is set to 'Custom'.
        type: str
        choices: ['read', 'write', 'disabled']
      policy:
        description:
          - Configure SmartEvent Policy rules and install SmartEvent Policies.<br>Available only if smart-event is set to 'Custom'.
        type: str
        choices: ['read', 'write', 'disabled']
      reports:
        description:
          - Create and run SmartEvent reports.<br>Available only if smart-event is set to 'Custom'.
        type: bool
  gateways:
    description:
      - Gateways permissions. <br>Only a 'Customized' permission-type profile can edit these permissions.
    type: dict
    suboptions:
      smart_update:
        description:
          - Install, update and delete Check Point licenses. This includes permissions to use SmartUpdate to manage licenses.
        type: str
        choices: ['read', 'write', 'disabled']
      lsm_gw_db:
        description:
          - Access to objects defined in LSM gateway tables. These objects are managed in the SmartProvisioning GUI or LSMcli
            command-line.<br>Note, 'Write' permission on lsm-gw-db allows administrator to run a script on SmartLSM gateway in Expert mode.
        type: str
        choices: ['read', 'write', 'disabled']
      manage_provisioning_profiles:
        description:
          - Administrator can add, edit, delete, and assign provisioning profiles to gateways (both LSM and non-LSM).<br>Available for edit only
            if lsm-gw-db is set with 'Write' permission.<br>Note, 'Read' permission on lsm-gw-db enables 'Read' permission for manage-provisioning-profiles.
        type: str
        choices: ['read', 'write', 'disabled']
      vsx_provisioning:
        description:
          - Create and configure Virtual Systems and other VSX virtual objects.
        type: bool
      system_backup:
        description:
          - Backup Security Gateways.
        type: bool
      system_restore:
        description:
          - Restore Security Gateways from saved backups.
        type: bool
      open_shell:
        description:
          - Use the SmartConsole CLI to run commands.
        type: bool
      run_one_time_script:
        description:
          - Run user scripts from the command line.
        type: bool
      run_repository_script:
        description:
          - Run scripts from the repository.
        type: bool
      manage_repository_scripts:
        description:
          - Add, change and remove scripts in the repository.
        type: str
        choices: ['read', 'write', 'disabled']
  management:
    description:
      - Management permissions.
    type: dict
    suboptions:
      cme_operations:
        description:
          - Permission to read / edit the Cloud Management Extension (CME) configuration.<br>Not supported for Multi-Domain Servers.
        type: str
        choices: ['read', 'write', 'disabled']
      manage_admins:
        description:
          - Controls the ability to manage Administrators, Permission Profiles, Trusted clients,API settings and Policy settings.<br>Only a "Read
            Write All" permission-type profile can edit this permission.<br>Not supported for Multi-Domain Servers.
        type: bool
      management_api_login:
        description:
          - Permission to log in to the Security Management Server and run API commands using thesetools, mgmt_cli (Linux and Windows binaries),
            Gaia CLI (clish) and Web Services (REST). Useful if you want to prevent administrators from running automatic scripts on the Management.<br>Note,
            This permission is not required to run commands from within the API terminal in SmartConsole.<br>Not supported for Multi-Domain Servers.
        type: bool
      manage_sessions:
        description:
          - Lets you disconnect, discard, publish, or take over other administrator sessions.<br>Only a "Read Write All" permission-type profile
            can edit this permission.
        type: bool
      high_availability_operations:
        description:
          - Configure and work with Domain High Availability.<br>Only a 'Customized' permission-type profile can edit this permission.
        type: bool
      approve_or_reject_sessions:
        description:
          - Approve / reject other sessions.
        type: bool
      publish_sessions:
        description:
          - Allow session publishing without an approval.
        type: bool
      manage_integration_with_cloud_services:
        description:
          - Manage integration with Cloud Services.
        type: bool
  monitoring_and_logging:
    description:
      - Monitoring and Logging permissions.<br>'Customized' permission-type profile can edit all these permissions. "Read Write All" permission-type
        can edit only dlp-logs-including-confidential-fields and manage-dlp-messages permissions.
    type: dict
    suboptions:
      monitoring:
        description:
          - See monitoring views and reports.
        type: str
        choices: ['read', 'write', 'disabled']
      management_logs:
        description:
          - See Multi-Domain Server audit logs.
        type: str
        choices: ['read', 'write', 'disabled']
      track_logs:
        description:
          - Use the log tracking features in SmartConsole.
        type: str
        choices: ['read', 'write', 'disabled']
      app_and_url_filtering_logs:
        description:
          - Work with Application and URL Filtering logs.
        type: bool
      https_inspection_logs:
        description:
          - See logs generated by HTTPS Inspection.
        type: bool
      packet_capture_and_forensics:
        description:
          - See logs generated by the IPS and Forensics features.
        type: bool
      show_packet_capture_by_default:
        description:
          - Enable packet capture by default.
        type: bool
      identities:
        description:
          - Show user and computer identity information in logs.
        type: bool
      show_identities_by_default:
        description:
          - Show user and computer identity information in logs by default.
        type: bool
      dlp_logs_including_confidential_fields:
        description:
          - Show DLP logs including confidential fields.
        type: bool
      manage_dlp_messages:
        description:
          - View/Release/Discard DLP messages.<br>Available only if dlp-logs-including-confidential-fields is set to true.
        type: bool
  threat_prevention:
    description:
      - Threat Prevention permissions.<br>Only a 'Customized' permission-type profile can edit these permissions.
    type: dict
    suboptions:
      policy_layers:
        description:
          - Configure Threat Prevention Policy rules.<br>Note, To have policy-layers permissions you must set policy-exceptionsand profiles
            permissions. To have 'Write' permissions for policy-layers, policy-exceptions must be set with 'Write' permission as well.
        type: str
        choices: ['read', 'write', 'disabled']
      edit_layers:
        description:
          - a 'ALL' -  Gives permission to edit all layers.<br>"By Selected Profile In A Layer Editor" -  Administrators can only edit the layer
            if the Threat Prevention layer editor gives editing permission to their profiles.<br>Available only if policy-layers is set to 'Write'.
        type: str
        choices: ['By Selected Profile In A Layer Editor', 'All']
      edit_settings:
        description:
          - Work with general Threat Prevention settings.
        type: bool
      policy_exceptions:
        description:
          - Configure exceptions to Threat Prevention rules.<br>Note, To have policy-exceptions you must set the protections permission.
        type: str
        choices: ['read', 'write', 'disabled']
      profiles:
        description:
          - Configure Threat Prevention profiles.
        type: str
        choices: ['read', 'write', 'disabled']
      protections:
        description:
          - Work with malware protections.
        type: str
        choices: ['read', 'write', 'disabled']
      install_policy:
        description:
          - Install Policies.
        type: bool
      ips_update:
        description:
          - Update IPS protections.<br>Note, You do not have to log into the User Center to receive IPS updates.
        type: bool
  others:
    description:
      - Additional permissions.<br>Only a 'Customized' permission-type profile can edit these permissions.
    type: dict
    suboptions:
      client_certificates:
        description:
          - Create and manage client certificates for Mobile Access.
        type: bool
      edit_cp_users_db:
        description:
          - Work with user accounts and groups.
        type: bool
      https_inspection:
        description:
          - Enable and configure HTTPS Inspection rules.
        type: str
        choices: ['read', 'write', 'disabled']
      ldap_users_db:
        description:
          - Work with the LDAP database and user accounts, groups and OUs.
        type: str
        choices: ['read', 'write', 'disabled']
      user_authority_access:
        description:
          - Work with Check Point User Authority authentication.
        type: str
        choices: ['read', 'write', 'disabled']
      user_device_mgmt_conf:
        description:
          - Gives access to the UDM (User & Device Management) web-based application that handles security challenges in a "bring your own device"
            (BYOD) workspace.
        type: str
        choices: ['read', 'write', 'disabled']
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-domain-permissions-profile
  cp_mgmt_domain_permissions_profile:
    name: customized profile
    state: present

- name: set-domain-permissions-profile
  cp_mgmt_domain_permissions_profile:
    access_control:
      policy_layers: By Selected Profile In A Layer Editor
    name: read profile
    permission_type: customized
    state: present

- name: delete-domain-permissions-profile
  cp_mgmt_domain_permissions_profile:
    name: profile
    state: absent
"""

RETURN = """
cp_mgmt_domain_permissions_profile:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_objects,
    api_call,
)


def main():
    argument_spec = dict(
        name=dict(type="str", required=True),
        permission_type=dict(
            type="str",
            choices=["read write all", "read only all", "customized"],
        ),
        edit_common_objects=dict(type="bool"),
        access_control=dict(
            type="dict",
            options=dict(
                show_policy=dict(type="bool"),
                policy_layers=dict(
                    type="dict",
                    options=dict(
                        edit_layers=dict(
                            type="str",
                            choices=[
                                "By Software Blades",
                                "By Selected Profile In A Layer Editor",
                            ],
                        ),
                        app_control_and_url_filtering=dict(type="bool"),
                        content_awareness=dict(type="bool"),
                        firewall=dict(type="bool"),
                        mobile_access=dict(type="bool"),
                    ),
                ),
                dlp_policy=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                geo_control_policy=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                nat_policy=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                qos_policy=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                access_control_objects_and_settings=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                app_control_and_url_filtering_update=dict(type="bool"),
                install_policy=dict(type="bool"),
            ),
        ),
        endpoint=dict(
            type="dict",
            options=dict(
                manage_policies_and_software_deployment=dict(type="bool"),
                edit_endpoint_policies=dict(type="bool"),
                policies_installation=dict(type="bool"),
                edit_software_deployment=dict(type="bool"),
                software_deployment_installation=dict(type="bool"),
                allow_executing_push_operations=dict(type="bool"),
                authorize_preboot_users=dict(type="bool"),
                recovery_media=dict(type="bool"),
                remote_help=dict(type="bool"),
                reset_computer_data=dict(type="bool"),
            ),
        ),
        events_and_reports=dict(
            type="dict",
            options=dict(
                smart_event=dict(
                    type="str",
                    choices=[
                        "custom",
                        "app control and url filtering reports only",
                    ],
                ),
                events=dict(type="str", choices=["read", "write", "disabled"]),
                policy=dict(type="str", choices=["read", "write", "disabled"]),
                reports=dict(type="bool"),
            ),
        ),
        gateways=dict(
            type="dict",
            options=dict(
                smart_update=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                lsm_gw_db=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                manage_provisioning_profiles=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                vsx_provisioning=dict(type="bool"),
                system_backup=dict(type="bool"),
                system_restore=dict(type="bool"),
                open_shell=dict(type="bool"),
                run_one_time_script=dict(type="bool"),
                run_repository_script=dict(type="bool"),
                manage_repository_scripts=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
            ),
        ),
        management=dict(
            type="dict",
            options=dict(
                cme_operations=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                manage_admins=dict(type="bool"),
                management_api_login=dict(type="bool"),
                manage_sessions=dict(type="bool"),
                high_availability_operations=dict(type="bool"),
                approve_or_reject_sessions=dict(type="bool"),
                publish_sessions=dict(type="bool"),
                manage_integration_with_cloud_services=dict(type="bool"),
            ),
        ),
        monitoring_and_logging=dict(
            type="dict",
            options=dict(
                monitoring=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                management_logs=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                track_logs=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                app_and_url_filtering_logs=dict(type="bool"),
                https_inspection_logs=dict(type="bool"),
                packet_capture_and_forensics=dict(type="bool"),
                show_packet_capture_by_default=dict(type="bool"),
                identities=dict(type="bool"),
                show_identities_by_default=dict(type="bool"),
                dlp_logs_including_confidential_fields=dict(type="bool"),
                manage_dlp_messages=dict(type="bool"),
            ),
        ),
        threat_prevention=dict(
            type="dict",
            options=dict(
                policy_layers=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                edit_layers=dict(
                    type="str",
                    choices=["By Selected Profile In A Layer Editor", "All"],
                ),
                edit_settings=dict(type="bool"),
                policy_exceptions=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                profiles=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                protections=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                install_policy=dict(type="bool"),
                ips_update=dict(type="bool"),
            ),
        ),
        others=dict(
            type="dict",
            options=dict(
                client_certificates=dict(type="bool"),
                edit_cp_users_db=dict(type="bool"),
                https_inspection=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                ldap_users_db=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                user_authority_access=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
                user_device_mgmt_conf=dict(
                    type="str", choices=["read", "write", "disabled"]
                ),
            ),
        ),
        tags=dict(type="list", elements="str"),
        color=dict(
            type="str",
            choices=[
                "aquamarine",
                "black",
                "blue",
                "crete blue",
                "burlywood",
                "cyan",
                "dark green",
                "khaki",
                "orchid",
                "dark orange",
                "dark sea green",
                "pink",
                "turquoise",
                "dark blue",
                "firebrick",
                "brown",
                "forest green",
                "gold",
                "dark gold",
                "gray",
                "dark gray",
                "light green",
                "lemon chiffon",
                "coral",
                "sea green",
                "sky blue",
                "magenta",
                "purple",
                "slate blue",
                "violet red",
                "navy blue",
                "olive",
                "orange",
                "red",
                "sienna",
                "yellow",
            ],
        ),
        comments=dict(type="str"),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
        ignore_warnings=dict(type="bool"),
        ignore_errors=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )
    api_call_object = "domain-permissions-profile"

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
