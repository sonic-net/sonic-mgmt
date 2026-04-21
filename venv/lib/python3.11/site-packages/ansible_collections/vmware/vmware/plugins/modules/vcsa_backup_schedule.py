#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vcsa_backup_schedule
short_description: Configure the vCenter Server Appliance backup schedule
description:
    - Configure the vCenter Server Appliance backup schedule.
    - Only one schedule per vCenter Server Appliance can exist.
    - Before taking a backup, a backup server must be set up and configured such that the vCenter server has access to it.
      The protocols supported for backup are FTPS, HTTPS, SFTP, FTP, NFS, SMB and HTTP.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    name:
        description:
            - The name of the backup schedule. This must be unique, and is used as an identifier for the schedule.
            - Your VCSA may only allow for one schedule. If you create this schedule via the web UI, its name is 'default'.
            - You can change the name by deleting the existing schedule and creating a new one with a new name.
        type: str
        required: false
        default: default
    state:
        description:
            - Whether the schedule should be present or absent.
        type: str
        choices: [present, absent]
        default: present
    encryption_password:
        description:
            - A password to use to encrypt the backup.
            - If this is unset, the backup is not encrypted.
        type: str
        required: false
    location:
        description:
            - Options describing the location where the backup should be stored.
        type: dict
        required: false
        suboptions:
            url:
                description:
                    - The remote server where the backup should be sent. The vCenter server must be able to access this location.
                    - This should be a url in the format of protocol://server-address<:port-number>/folder/subfolder
                    - The protocols supported for backup are FTPS, HTTPS, SFTP, FTP, NFS, SMB and HTTP.
                type: path
                required: true
            username:
                description:
                    - The username to use to authenticate to the location URL, if one is required.
                type: str
                required: false
            password:
                description:
                    - The password to use to authenticate to the location URL, if one is required.
                type: str
                required: false
    enabled:
        description:
            - Whether or not the schedule should be enabled.
        type: bool
        default: true
    schedule:
        description:
            - Options describing the timing and recurrence of the backup schedule.
        required: false
        type: dict
        suboptions:
            minute:
                description:
                    - The minute of the hour that this backup should be run.
                type: int
                required: true
            hour:
                description:
                    - The hour of the day in 24-hour format that this backup should be run.
                type: int
                required: true
            days_of_week:
                description:
                    - The days of the week that this backup should be run.
                    - At least one day should be selected.
                    - Options are MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY, SUNDAY
                type: list
                elements: str
                required: true
    retain_count:
        description:
            - The number of backups to retain.
            - If this is set to 0, all backups are kept.
        type: int
        default: 3
    db_fast_backup:
        description:
            - If true, the underlying Postgres DB/VCDB will use a fast backup method.
        type: bool
        default: false
    include_supervisors_control_plane:
        description:
            - If true, the supervisors control plane will be included in the backups.
        type: bool
        default: true
    include_stats_events_and_tasks:
        description:
            - If true, historical data about stats, events, and tasks will be included in the backups.
        type: bool
        default: true
    always_update_password:
        description:
            - If true and O(encryption_password) or O(location.password) is set, this module will always report a change and
              set the appropriate password values.
            - If false, other properties are still checked for differences. If a difference is found,
              the value of O(encryption_password) and/or O(location.password) is still used.
            - If the password options are unset, this parameter is ignored.
            - This option is needed because there is no way to check the current password value and
              compare it against the desired password value.
        default: true
        type: bool

attributes:
    check_mode:
        description: The check_mode support.
        support: full

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Configure The Default Schedule
  vmware.vmware.vcsa_backup_schedule:
    schedule:
      hour: 23
      minute: 59
      days_of_week:
        - saturday
    location:
      url: nfs://10.10.10.10:/nfs/iso_datastore/vcenterbackup/
      username: root
    retain_count: 3

- name: Remove The Default Schedule
  vmware.vmware.vcsa_backup_schedule:
    state: absent
'''

RETURN = r'''
schedule:
    description:
        - Dictionary identifying the schedule that was modified
    returned: always
    type: dict
    sample: {
        "name": "default"
    }
vcsa:
    description:
        - Identifying information about the appliance
    returned: always
    type: dict
    sample: {
        "vcsa": {
            "hostname": "my-appliance",
            "port": 443
        },
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec
from ansible.module_utils.common.text.converters import to_native

try:
    from com.vmware.vapi.std.errors_client import NotFound, AlreadyExists
except ImportError:
    pass


ACCEPTED_URL_SCHEMES = ('ftps', 'https', 'sftp', 'ftp', 'nfs', 'smb', 'http')
ACCEPTED_SCHEDULE_DAYS = ['MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY']


class VcsaBackupSchedule(ModuleRestBase):
    def __init__(self, module):
        super().__init__(module)
        self.backup_service = self.api_client.appliance.recovery.backup
        try:
            self.schedule = self.backup_service.Schedules.get(self.params['name'])
        except NotFound:
            self.schedule = None

    def validate_present_params(self):
        if not self.params['location']['url'].startswith(ACCEPTED_URL_SCHEMES):
            self.module.fail_json(msg="Location url does not utilize an accepted URL protocol: %s" % ', '.join(ACCEPTED_URL_SCHEMES))

        if self.params['schedule']['hour'] < 0 or self.params['schedule']['hour'] > 23:
            self.module.fail_json(msg="Schedule hour must be a number from 0 to 23")

        if self.params['schedule']['minute'] < 0 or self.params['schedule']['minute'] > 59:
            self.module.fail_json(msg="Schedule minute must be a number from 0 to 59")

        if not set(ACCEPTED_SCHEDULE_DAYS).issuperset(self.days_of_week):
            self.module.fail_json(msg="Schedule days of week must be values from this list: %s" % ', '.join(ACCEPTED_SCHEDULE_DAYS))

    @property
    def days_of_week(self):
        return set(x.upper() for x in self.params['schedule']['days_of_week'])

    @property
    def part_ids(self):
        """
            Each vCenter backup consists of one or more parts. Common is required but the other parts are optional.
            This method compiles the list of part IDs based on the user input.
            Note that the 'seat' ID is mapped to 'stats' when it is shown to the user in the info module. This aligns the value with
            what is shown in the CI.
            To get the part IDs, you can use [{'id':p.id, 'desc': str(p.description)} for p in self.backup_service.Parts.list()]
            Returns:
                set, The IDs of the parts to include in the backup.
        """
        parts = set(['common'])

        if self.params['include_supervisors_control_plane']:
            parts.add('supervisors')

        if self.params['include_stats_events_and_tasks']:
            parts.add('seat')

        return parts

    def create_spec_from_params(self):
        """
            Create a schedule Create or Update spec based on user parameters.
            Returns:
                Schedule spec
        """
        if self.schedule:
            spec = self.backup_service.Schedules.UpdateSpec()
        else:
            spec = self.backup_service.Schedules.CreateSpec()

        spec.parts = self.part_ids
        spec.name = self.params['name']
        spec.backup_password = self.params.get('encryption_password', None)
        spec.location = self.params['location']['url']
        spec.location_user = self.params['location'].get('username', None)
        spec.location_password = self.params['location'].get('password', None)
        spec.enable = self.params['enabled']
        spec.recurrence_info = self.backup_service.Schedules.RecurrenceInfo(
            minute=self.params['schedule']['minute'],
            hour=self.params['schedule']['hour'],
            days=self.days_of_week
        )
        if self.params['retain_count']:
            spec.retention_info = self.backup_service.Schedules.RetentionInfo(max_count=self.params['retain_count'])
        spec.fast_backup = self.params['db_fast_backup']

        return spec

    def spec_matches_live(self, spec):
        """
            Compare if a spec matches the live schedule.
            Returns:
               bool, True if spec matches live.
        """
        _compare = {'location', 'location_user', 'enable', 'retention_info', 'fast_backup'}
        if self.params['always_update_password']:
            _compare.add('backup_password')
            _compare.add('location_password')

        if self.schedule is None:
            return False

        for _c in _compare:
            if getattr(spec, _c, None) != getattr(self.schedule, _c, None):
                return False

        if set(spec.parts) != set(self.schedule.parts):
            return False

        if any([
            (spec.recurrence_info.minute != self.schedule.recurrence_info.minute),
            (spec.recurrence_info.hour != self.schedule.recurrence_info.hour),
            (set(spec.recurrence_info.days) != set(self.schedule.recurrence_info.days))
        ]):
            return False

        return True

    def create_schedule_from_spec(self, spec):
        """
            Create or update a schedule from a spec
        """
        try:
            if self.schedule:
                self.backup_service.Schedules.update(self.params['name'], spec)
            else:
                self.backup_service.Schedules.create(self.params['name'], spec)
        except AlreadyExists as e:
            try:
                self.module.fail_json(msg=e.messages[0].default_message)
            except (AttributeError, IndexError):
                self.module.fail_json(msg=to_native(e))

    def delete_schedule(self):
        self.backup_service.Schedules.delete(self.params['name'])


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', default='default'),
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            encryption_password=dict(type='str', required=False, no_log=True),
            location=dict(type='dict', required=False, options=dict(
                url=dict(type='path', required=True),
                username=dict(type='str', required=False),
                password=dict(type='str', required=False, no_log=True),
            )),
            enabled=dict(type='bool', default=True),
            schedule=dict(type='dict', required=False, options=dict(
                minute=dict(type='int', required=True),
                hour=dict(type='int', required=True),
                days_of_week=dict(type='list', elements='str', required=True),
            )),
            retain_count=dict(type='int', default=3),
            db_fast_backup=dict(type='bool', default=False),
            include_supervisors_control_plane=dict(type='bool', default=True),
            include_stats_events_and_tasks=dict(type='bool', default=True),
            always_update_password=dict(type='bool', default=True, no_log=False),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('location', 'schedule'), False)
        ]
    )
    result = dict(
        changed=False,
        schedule={
            'name': module.params['name']
        },
        vcsa={
            'hostname': module.params['hostname'],
            'port': module.params['port']
        }
    )

    vcsa = VcsaBackupSchedule(module)
    if module.params['state'] == 'absent':
        if vcsa.schedule:
            result['changed'] = True
            if not module.check_mode:
                vcsa.delete_schedule()

    if module.params['state'] == 'present':
        vcsa.validate_present_params()
        spec = vcsa.create_spec_from_params()
        if not vcsa.spec_matches_live(spec):
            result['changed'] = True
            if not module.check_mode:
                vcsa.create_schedule_from_spec(spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
