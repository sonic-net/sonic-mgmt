#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vcsa_backup_schedule_info
short_description: Gather info about one or more VCSA backup schedules.
description:
    - Gather info about vCenter server appliance backup schedules.
    - If a name is provided, only the schedule with that name will be included in the output.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    name:
        description:
            - The name of the backup schedule for which to gather info.
            - If no name is provided, all backup schedules are returned.
        type: str
        required: false

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather All Backup Schedules Info
  vmware.vmware.vcsa_backup_schedule_info: {}

- name: Gather The Default Schedule Info
  vmware.vmware.vcsa_backup_schedule_info:
    name: default
'''

RETURN = r'''
schedules:
    description:
        - List of dictionaries describing the backup schedules found
    returned: On success
    type: list
    sample: [
        {
            "enabled": true,
            "fast_backup": false,
            "location": "nfs://10.10.10.10:/nfs/iso_datastore/vcenterbackup/",
            "location_user": "root",
            "name": "default",
            "includes_stats_events_and_tasks": true,
            "includes_supervisors_control_plane": true,
            "retain_count": 3,
            "schedule": {
                "days_of_week": [
                    "SATURDAY"
                ],
                "hour": 12,
                "minute": 59
            }
        }
    ]
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


class VcsaBackupSchedule(ModuleRestBase):
    def __init__(self, module):
        super().__init__(module)
        self.backup_service = self.api_client.appliance.recovery.backup

    def get_schedules(self):
        listed_schedules = self.backup_service.Schedules.list()
        if not listed_schedules:
            return []

        schedules = []
        for schedule_id, schedule in listed_schedules.items():
            if self.params['name'] and schedule_id != self.params['name']:
                continue

            _sched = {
                'name': schedule_id,
                'location': schedule.location,
                'location_user': schedule.location_user,
                'enabled': schedule.enable,
                'fast_backup': schedule.fast_backup or False,
                'schedule': {},
                'retain_count': 0,
                'includes_stats_events_and_tasks': bool('seat' in schedule.parts),
                'includes_supervisors_control_plane': bool('supervisors' in schedule.parts)
            }
            if schedule.recurrence_info:
                _sched['schedule'] = {
                    'minute': schedule.recurrence_info.minute,
                    'hour': schedule.recurrence_info.hour,
                    'days_of_week': schedule.recurrence_info.days
                }
            if schedule.retention_info:
                _sched['retain_count'] = schedule.retention_info.max_count

            schedules.append(_sched)
            if self.params['name']:
                break

        return schedules


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type='str', required=False),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    result = dict(
        changed=False,
        vcsa={
            'hostname': module.params['hostname'],
            'port': module.params['port']
        }
    )

    vcsa = VcsaBackupSchedule(module)
    result['schedules'] = vcsa.get_schedules()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
