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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_checkpoint_host
short_description: Manages checkpoint-host objects on Checkpoint over Web Services API
description:
  - Manages checkpoint-host objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80.40 JHF management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  ip_address:
    description:
      - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly.
    type: str
  ipv4_address:
    description:
      - IPv4 address.
    type: str
  ipv6_address:
    description:
      - IPv6 address.
    type: str
  interfaces:
    description:
      - Check Point host interfaces.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Interface name.
        type: str
      subnet:
        description:
          - IPv4 or IPv6 network address. If both addresses are required use subnet4 and subnet6 fields explicitly.
        type: str
      subnet4:
        description:
          - IPv4 network address.
        type: str
      subnet6:
        description:
          - IPv6 network address.
        type: str
      mask_length:
        description:
          - IPv4 or IPv6 network mask length. If both masks are required use mask-length4 and mask-length6 fields explicitly. Instead of IPv4 mask
            length it is possible to specify IPv4 mask itself in subnet-mask field.
        type: int
      mask_length4:
        description:
          - IPv4 network mask length.
        type: int
      mask_length6:
        description:
          - IPv6 network mask length.
        type: int
      subnet_mask:
        description:
          - IPv4 network mask.
        type: str
      color:
        description:
          - Color of the object. Should be one of existing colors.
        type: str
        choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange',
                 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray',
                 'light green', 'lemon chiffon', 'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive',
                 'orange', 'red', 'sienna', 'yellow']
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
  nat_settings:
    description:
      - NAT settings.
    type: dict
    suboptions:
      auto_rule:
        description:
          - Whether to add automatic address translation rules.
        type: bool
      ip_address:
        description:
          - IPv4 or IPv6 address. If both addresses are required use ipv4-address and ipv6-address fields explicitly. This parameter is not
            required in case "method" parameter is "hide" and "hide-behind" parameter is "gateway".
        type: str
      ipv4_address:
        description:
          - IPv4 address.
        type: str
      ipv6_address:
        description:
          - IPv6 address.
        type: str
      hide_behind:
        description:
          - Hide behind method. This parameter is forbidden in case "method" parameter is "static".
        type: str
        choices: ['gateway', 'ip-address']
      install_on:
        description:
          - Which gateway should apply the NAT translation.
        type: str
      method:
        description:
          - NAT translation method.
        type: str
        choices: ['hide', 'static']
  one_time_password:
    description:
      - Secure internal connection one time password.
    type: str
  hardware:
    description:
      - Hardware name.
    type: str
  os:
    description:
      - Operating system name.
    type: str
  check_point_host_version:
    description:
      - Check Point host platform version.
    type: str
  management_blades:
    description:
      - Management blades.
    type: dict
    suboptions:
      network_policy_management:
        description:
          - Enable Network Policy Management.
        type: bool
      logging_and_status:
        description:
          - Enable Logging & Status.
        type: bool
      smart_event_server:
        description:
          - Enable SmartEvent server. </br>When activating SmartEvent server, blades 'logging-and-status' and 'smart-event-correlation' should be
            set to True. </br>To complete SmartEvent configuration, perform Install Database or Install Policy on your Security Management servers and Log
            servers. </br>Activating SmartEvent Server is not recommended in Management High Availability environment. For more information refer to sk25164.
        type: bool
      smart_event_correlation:
        description:
          - Enable SmartEvent Correlation Unit.
        type: bool
      endpoint_policy:
        description:
          - Enable Endpoint Policy. </br>To complete Endpoint Security Management configuration, perform Install Database on your Endpoint
            Management Server. </br>Field is not supported on Multi Domain Server environment.
        type: bool
      compliance:
        description:
          - Compliance blade. Can be set when 'network-policy-management' was selected to be True.
        type: bool
      user_directory:
        description:
          - Enable User Directory. Can be set when 'network-policy-management' was selected to be True.
        type: bool
  logs_settings:
    description:
      - Logs settings.
    type: dict
    suboptions:
      free_disk_space_metrics:
        description:
          - Free disk space metrics.
        type: str
        choices: ['mbytes', 'percent']
      accept_syslog_messages:
        description:
          - Enable accept syslog messages.
        type: bool
      alert_when_free_disk_space_below:
        description:
          - Enable alert when free disk space is below threshold.
        type: bool
      alert_when_free_disk_space_below_threshold:
        description:
          - Alert when free disk space below threshold.
        type: int
      alert_when_free_disk_space_below_type:
        description:
          - Alert when free disk space below type.
        type: str
        choices: ['none', 'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1', 'user defined alert no.2',
                 'user defined alert no.3']
      before_delete_keep_logs_from_the_last_days:
        description:
          - Enable before delete keep logs from the last days.
        type: bool
      before_delete_keep_logs_from_the_last_days_threshold:
        description:
          - Before delete keep logs from the last days threshold.
        type: int
      before_delete_run_script:
        description:
          - Enable Before delete run script.
        type: bool
      before_delete_run_script_command:
        description:
          - Before delete run script command.
        type: str
      delete_index_files_older_than_days:
        description:
          - Enable delete index files older than days.
        type: bool
      delete_index_files_older_than_days_threshold:
        description:
          - Delete index files older than days threshold.
        type: int
      delete_when_free_disk_space_below:
        description:
          - Enable delete when free disk space below.
        type: bool
      delete_when_free_disk_space_below_threshold:
        description:
          - Delete when free disk space below threshold.
        type: int
      detect_new_citrix_ica_application_names:
        description:
          - Enable detect new Citrix ICA application names.
        type: bool
      distribute_logs_between_all_active_servers:
        description:
          - Distribute logs between all active servers.
          - Available from R81.20 management version.
        type: bool
      enable_log_indexing:
        description:
          - Enable log indexing.
        type: bool
      forward_logs_to_log_server:
        description:
          - Enable forward logs to log server.
        type: bool
      forward_logs_to_log_server_name:
        description:
          - Forward logs to log server name.
        type: str
      forward_logs_to_log_server_schedule_name:
        description:
          - Forward logs to log server schedule name.
        type: str
      rotate_log_by_file_size:
        description:
          - Enable rotate log by file size.
        type: bool
      rotate_log_file_size_threshold:
        description:
          - Log file size threshold.
        type: int
      rotate_log_on_schedule:
        description:
          - Enable rotate log on schedule.
        type: bool
      rotate_log_schedule_name:
        description:
          - Rotate log schedule name.
        type: str
      smart_event_intro_correletion_unit:
        description:
          - Enable SmartEvent intro correlation unit.
        type: bool
      stop_logging_when_free_disk_space_below:
        description:
          - Enable stop logging when free disk space below.
        type: bool
      stop_logging_when_free_disk_space_below_threshold:
        description:
          - Stop logging when free disk space below threshold.
        type: int
      turn_on_qos_logging:
        description:
          - Enable turn on QoS Logging.
        type: bool
      update_account_log_every:
        description:
          - Update account log in every amount of seconds.
        type: int
  save_logs_locally:
    description:
      - Enable save logs locally.
    type: bool
  send_alerts_to_server:
    description:
      - Collection of Server(s) to send alerts to identified by the name or UID.
    type: list
    elements: str
  send_logs_to_backup_server:
    description:
      - Collection of Backup server(s) to send logs to identified by the name or UID.
    type: list
    elements: str
  send_logs_to_server:
    description:
      - Collection of Server(s) to send logs to identified by the name or UID.
    type: list
    elements: str
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
  groups:
    description:
      - Collection of group identifiers.
    type: list
    elements: str
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
- name: add-checkpoint-host
  cp_mgmt_checkpoint_host:
    ipv4_address: 5.5.5.5
    management_blades:
      logging_and_status: true
      network_policy_management: true
    name: secondarylogserver
    state: present

- name: set-checkpoint-host
  cp_mgmt_checkpoint_host:
    hardware: Smart-1
    management_blades:
      compliance: true
      network_policy_management: true
      user_directory: true
    name: secondarylogserver
    os: Linux
    state: present

- name: delete-checkpoint-host
  cp_mgmt_checkpoint_host:
    name: secondarylogserver
    state: absent
"""

RETURN = """
cp_mgmt_checkpoint_host:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        ip_address=dict(type='str'),
        ipv4_address=dict(type='str'),
        ipv6_address=dict(type='str'),
        interfaces=dict(type='list', elements='dict', options=dict(
            name=dict(type='str'),
            subnet=dict(type='str'),
            subnet4=dict(type='str'),
            subnet6=dict(type='str'),
            mask_length=dict(type='int'),
            mask_length4=dict(type='int'),
            mask_length6=dict(type='int'),
            subnet_mask=dict(type='str'),
            color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan',
                                            'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick',
                                            'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral',
                                            'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red',
                                            'sienna', 'yellow']),
            comments=dict(type='str'),
            details_level=dict(type='str', choices=['uid', 'standard', 'full']),
            ignore_warnings=dict(type='bool'),
            ignore_errors=dict(type='bool')
        )),
        nat_settings=dict(type='dict', options=dict(
            auto_rule=dict(type='bool'),
            ip_address=dict(type='str'),
            ipv4_address=dict(type='str'),
            ipv6_address=dict(type='str'),
            hide_behind=dict(type='str', choices=['gateway', 'ip-address']),
            install_on=dict(type='str'),
            method=dict(type='str', choices=['hide', 'static'])
        )),
        one_time_password=dict(type='str', no_log=True),
        hardware=dict(type='str'),
        os=dict(type='str'),
        check_point_host_version=dict(type='str'),
        management_blades=dict(type='dict', options=dict(
            network_policy_management=dict(type='bool'),
            logging_and_status=dict(type='bool'),
            smart_event_server=dict(type='bool'),
            smart_event_correlation=dict(type='bool'),
            endpoint_policy=dict(type='bool'),
            compliance=dict(type='bool'),
            user_directory=dict(type='bool')
        )),
        logs_settings=dict(type='dict', options=dict(
            free_disk_space_metrics=dict(type='str', choices=['mbytes', 'percent']),
            accept_syslog_messages=dict(type='bool'),
            alert_when_free_disk_space_below=dict(type='bool'),
            alert_when_free_disk_space_below_threshold=dict(type='int'),
            alert_when_free_disk_space_below_type=dict(type='str', choices=['none',
                                                                            'log', 'popup alert', 'mail alert', 'snmp trap alert', 'user defined alert no.1',
                                                                            'user defined alert no.2', 'user defined alert no.3']),
            before_delete_keep_logs_from_the_last_days=dict(type='bool'),
            before_delete_keep_logs_from_the_last_days_threshold=dict(type='int'),
            before_delete_run_script=dict(type='bool'),
            before_delete_run_script_command=dict(type='str'),
            delete_index_files_older_than_days=dict(type='bool'),
            delete_index_files_older_than_days_threshold=dict(type='int'),
            delete_when_free_disk_space_below=dict(type='bool'),
            delete_when_free_disk_space_below_threshold=dict(type='int'),
            detect_new_citrix_ica_application_names=dict(type='bool'),
            distribute_logs_between_all_active_servers=dict(type='bool'),
            enable_log_indexing=dict(type='bool'),
            forward_logs_to_log_server=dict(type='bool'),
            forward_logs_to_log_server_name=dict(type='str'),
            forward_logs_to_log_server_schedule_name=dict(type='str'),
            rotate_log_by_file_size=dict(type='bool'),
            rotate_log_file_size_threshold=dict(type='int'),
            rotate_log_on_schedule=dict(type='bool'),
            rotate_log_schedule_name=dict(type='str'),
            smart_event_intro_correletion_unit=dict(type='bool'),
            stop_logging_when_free_disk_space_below=dict(type='bool'),
            stop_logging_when_free_disk_space_below_threshold=dict(type='int'),
            turn_on_qos_logging=dict(type='bool'),
            update_account_log_every=dict(type='int')
        )),
        save_logs_locally=dict(type='bool'),
        send_alerts_to_server=dict(type='list', elements='str'),
        send_logs_to_backup_server=dict(type='list', elements='str'),
        send_logs_to_server=dict(type='list', elements='str'),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        groups=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'checkpoint-host'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
