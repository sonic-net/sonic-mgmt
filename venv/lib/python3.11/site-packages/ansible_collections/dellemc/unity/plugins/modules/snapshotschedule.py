#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing snapshot schedules on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: snapshotschedule
version_added: '1.1.0'
short_description: Manage snapshot schedules on Unity storage system
description:
- Managing snapshot schedules on Unity storage system includes
  creating new snapshot schedule, getting details of snapshot schedule,
  modifying attributes of snapshot schedule, and deleting snapshot schedule.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Akash Shendge (@shenda1) <ansible.team@dell.com>

options:
  name:
    description:
    - The name of the snapshot schedule.
    - Name is mandatory for a create operation.
    - Specify either I(name) or I(id) (but not both) for any operation.
    type: str
  id:
    description:
    - The ID of the snapshot schedule.
    type: str
  type:
    description:
    - Type of the rule to be included in snapshot schedule.
    - Type is mandatory for any create or modify operation.
    - Once the snapshot schedule is created with one type it can be modified.
    type: str
    choices:  ['every_n_hours', 'every_day', 'every_n_days', 'every_week',
     'every_month']
  interval:
    description:
    - Number of hours between snapshots.
    - Applicable only when rule type is C(every_n_hours).
    type: int
  hours_of_day:
    description:
    - Hours of the day when the snapshot will be taken.
    - Applicable only when rule type is C(every_day).
    type: list
    elements: int
  day_interval:
    description:
    - Number of days between snapshots.
    - Applicable only when rule type is C(every_n_days).
    type: int
  days_of_week:
    description:
    - Days of the week for which the snapshot schedule rule applies.
    - Applicable only when rule type is C(every_week).
    type: list
    elements: str
    choices: ['SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY',
     'FRIDAY', 'SATURDAY']
  day_of_month:
    description:
    - Day of the month for which the snapshot schedule rule applies.
    - Applicable only when rule type is C(every_month).
    - Value should be [1, 31].
    type: int
  hour:
    description:
    - The hour when the snapshot will be taken.
    - Applicable for C(every_n_days), C(every_week), C(every_month) rule types.
    - For create operation, if I(hour) parameter is not specified, value will
     be taken as C(0).
    - Value should be [0, 23].
    type: int
  minute:
    description:
    - Minute offset from the hour when the snapshot will be taken.
    - Applicable for all rule types.
    - For a create operation, if I(minute) parameter is not specified, value will
     be taken as C(0).
    - Value should be [0, 59].
    type: int
  desired_retention:
    description:
    - The number of days/hours for which snapshot will be retained.
    - When I(auto_delete) is C(true), I(desired_retention) cannot be specified.
    - Maximum desired retention supported is 31 days or 744 hours.
    type: int
  retention_unit:
    description:
    - The retention unit for the snapshot.
    default: 'hours'
    type: str
    choices: ['hours' , 'days']
  auto_delete:
    description:
    - Indicates whether the system can automatically delete the snapshot.
    type: bool
  state:
    description:
    - Define whether the snapshot schedule should exist or not.
    type: str
    required: true
    choices: [absent, present]
notes:
- Snapshot schedule created through Ansible will have only one rule.
- Modification of rule type is not allowed. Within the same type, other
  parameters can be modified.
- If an existing snapshot schedule has more than 1 rule in it, only get and
  delete operation is allowed.
- The I(check_mode) is not supported.
"""

EXAMPLES = r"""
- name: Create snapshot schedule (Rule Type - every_n_hours)
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_N_Hours_Testing"
      type: "every_n_hours"
      interval: 6
      desired_retention: 24
      state: "{{state_present}}"

- name: Create snapshot schedule (Rule Type - every_day)
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_Day_Testing"
      type: "every_day"
      hours_of_day:
          - 8
          - 14
      auto_delete: true
      state: "{{state_present}}"

- name: Create snapshot schedule (Rule Type - every_n_days)
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_N_Day_Testing"
      type: "every_n_days"
      day_interval: 2
      desired_retention: 16
      retention_unit: "days"
      state: "{{state_present}}"

- name: Create snapshot schedule (Rule Type - every_week)
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_Week_Testing"
      type: "every_week"
      days_of_week:
          - MONDAY
          - FRIDAY
      hour: 12
      minute: 30
      desired_retention: 200
      state: "{{state_present}}"

- name: Create snapshot schedule (Rule Type - every_month)
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_Month_Testing"
      type: "every_month"
      day_of_month: 17
      auto_delete: true
      state: "{{state_present}}"

- name: Get snapshot schedule details using name
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_N_Hours_Testing"
      state: "{{state_present}}"

- name: Get snapshot schedule details using id
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      id: "{{id}}"
      state: "{{state_present}}"

- name: Modify snapshot schedule details id
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      id: "{{id}}"
      type: "every_n_hours"
      interval: 8
      state: "{{state_present}}"

- name: Modify snapshot schedule using name
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_Day_Testing"
      type: "every_day"
      desired_retention: 200
      auto_delete: false
      state: "{{state_present}}"

- name: Delete snapshot schedule using id
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      id: "{{id}}"
      state: "{{state_absent}}"

- name: Delete snapshot schedule using name
  snapshotschedule:
      unispherehost: "{{unispherehost}}"
      validate_certs: "{{validate_certs}}"
      username: "{{username}}"
      password: "{{password}}"
      name: "Ansible_Every_Day_Testing"
      state: "{{state_absent}}"
"""

RETURN = r"""
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

snapshot_schedule_details:
    description: Details of the snapshot schedule.
    returned: When snapshot schedule exists
    type: dict
    contains:
        id:
            description: The system ID given to the snapshot schedule.
            type: str
        name:
            description: The name of the snapshot schedule.
            type: str
        luns:
            description: Details of volumes for which snapshot schedule
             applied.
            type: dict
            contains:
                UnityLunList:
                    description: List of volumes for which snapshot schedule
                     applied.
                    type: list
                    contains:
                        UnityLun:
                            description: Detail of volume.
                            type: dict
                            contains:
                                id:
                                    description: The system ID given to volume.
                                    type: str
        rules:
            description: Details of rules that apply to snapshot schedule.
            type: list
            contains:
                id:
                    description: The system ID of the rule.
                    type: str
                interval:
                    description: Number of days or hours between snaps,
                                 depending on the rule type.
                    type: int
                hours:
                    description: Hourly frequency for the snapshot
                                 schedule rule.
                    type: list
                minute:
                    description: Minute frequency for the snapshot
                                 schedule rule.
                    type: int
                days_of_week:
                    description: Days of the week for which the snapshot
                     schedule rule applies.
                    type: dict
                    contains:
                        DayOfWeekEnumList:
                            description: Enumeration of days of the week.
                            type: list
                days_of_month:
                    description: Days of the month for which the snapshot
                                 schedule rule applies.
                    type: list
                retention_time:
                    description: Period of time in seconds for which to keep
                                 the snapshot.
                    type: int
                retention_time_in_hours:
                    description: Period of time in hours for which to keep the
                                 snapshot.
                    type: int
                rule_type:
                    description: Type of the rule applied to snapshot schedule.
                    type: str
                is_auto_delete:
                    description: Indicates whether the system can automatically
                                 delete the snapshot based on pool automatic-deletion
                                 thresholds.
                    type: bool
        storage_resources:
            description: Details of storage resources for which snapshot.
             schedule applied.
            type: dict
            contains:
                UnityStorageResourceList:
                    description: List of storage resources for which snapshot
                     schedule applied.
                    type: list
                    contains:
                        UnityStorageResource:
                            description: Detail of storage resource.
                            type: dict
                            contains:
                                id:
                                    description: The system ID given to storage
                                                 resource.
                                    type: str
    sample: {
        "existed": true,
        "hash": 8742032390151,
        "id": "snapSch_63",
        "is_default": false,
        "is_modified": null,
        "is_sync_replicated": false,
        "luns": null,
        "modification_time": "2021-12-14 21:37:47.905000+00:00",
        "name": "SS7_empty_hour_SS",
        "rules": [
            {
                "access_type": "FilesystemSnapAccessTypeEnum.CHECKPOINT",
                "days_of_month": null,
                "days_of_week": {
                    "DayOfWeekEnumList": []
                },
                "existed": true,
                "hash": 8742032280772,
                "hours": [
                    0
                ],
                "id": "SchedRule_109",
                "interval": 2,
                "is_auto_delete": false,
                "minute": 0,
                "retention_time": 86400,
                "retention_time_in_hours": 24,
                "rule_type": "every_n_days",
                "type": "ScheduleTypeEnum.N_DAYS_AT_HHMM"
            }
        ],
        "storage_resources": null,
        "version": "ScheduleVersionEnum.LEGACY"
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('snapshotschedule')

application_type = "Ansible/1.7.1"


class SnapshotSchedule(object):
    """Class with snapshot schedule operations"""

    def __init__(self):
        """Define all parameters required by this module"""

        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_snapshotschedule_parameters())

        mutually_exclusive = [['name', 'id'], ['interval', 'hour'],
                              ['hours_of_day', 'hour'],
                              ['interval', 'hours_of_day', 'day_interval',
                               'days_of_week', 'day_of_month']]
        required_one_of = [['name', 'id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mutually_exclusive,
            required_one_of=required_one_of
        )
        utils.ensure_required_libs(self.module)

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)

    def schedule_modify_required(self, schedule_details):
        """Check if the desired snapshot schedule state is different from
            existing snapshot schedule state
            :param schedule_details: The dict containing snapshot schedule
             details
            :return: Boolean value to indicate if modification is needed
        """

        # Check if existing snapshot schedule has auto_delete = True and
        # playbook sets desired retention without mentioning auto_delete
        if schedule_details['rules'][0]['is_auto_delete'] and\
                self.module.params['desired_retention']\
                and self.module.params['auto_delete'] is None:
            self.module.fail_json(msg="Desired retention cannot be "
                                      "specified when auto_delete is true"
                                  )
        if schedule_details['rules'][0]['retention_time'] and \
                self.module.params['auto_delete']:
            self.module.fail_json(msg="auto_delete cannot be specified when"
                                      " existing desired retention is set")

        desired_rule_type = get_schedule_value(self.module.params['type'])
        existing_rule_string = schedule_details['rules'][0][
            'type'].split(".")[1]
        existing_rule_type = utils.ScheduleTypeEnum[
            existing_rule_string]._get_properties()['value']
        modified = False

        # Check if rule type is modified
        if desired_rule_type != existing_rule_type:
            self.module.fail_json(msg="Modification of rule type is not"
                                      " allowed.")

        # Convert desired retention to seconds
        duration_in_sec = convert_retention_to_seconds(
            self.module.params['desired_retention'],
            self.module.params['retention_unit'])

        if not duration_in_sec:
            duration_in_sec = schedule_details['rules'][0]['retention_time']

        # Check if common parameters for the rules getting modified
        if (duration_in_sec and duration_in_sec != schedule_details[
                'rules'][0]['retention_time']):
            modified = True
        elif (self.module.params['auto_delete'] is not None and
              self.module.params['auto_delete'] != schedule_details['rules']
              [0]['is_auto_delete']):
            modified = True

        if (self.module.params['minute'] is not None and self.module.params[
                'minute'] != schedule_details['rules'][0]['minute']):
            modified = True

        if not modified and desired_rule_type == 0:
            if (self.module.params['interval'] and self.module.params[
                    'interval'] != schedule_details['rules'][0]['interval']):
                modified = True
        elif not modified and desired_rule_type == 1:
            if (self.module.params['hours_of_day'] and
                    set(self.module.params['hours_of_day']) !=
                    set(schedule_details['rules'][0]['hours'])):
                modified = True
        elif not modified and desired_rule_type == 2:
            if (self.module.params['day_interval'] and self.module.params[
                'day_interval'] != schedule_details['rules'][0]['interval'])\
                    or (self.module.params['hour'] is not None and
                        self.module.params['hour'] != schedule_details[
                            'rules'][0]['hours'][0]):
                modified = True
        elif not modified and desired_rule_type == 3:
            days = schedule_details['rules'][0]['days_of_week'][
                'DayOfWeekEnumList']
            existing_days = list()

            for day in days:
                temp = day.split(".")
                existing_days.append(temp[1])

            if (self.module.params['days_of_week'] and
                set(self.module.params['days_of_week']) !=
                set(existing_days)) or\
                    (self.module.params['hour'] is not None and
                     self.module.params['hour'] != schedule_details['rules'][
                         0]['hours'][0]):
                modified = True
        elif not modified and desired_rule_type == 4:
            if (self.module.params['day_of_month'] and self.module.params[
                'day_of_month'] != schedule_details['rules'][0][
                'days_of_month'][0]) or\
                    (self.module.params['hour'] is not None and
                     self.module.params['hour'] != schedule_details['rules'][
                         0]['hours'][0]):
                modified = True
        LOG.info("Modify Flag: %s", modified)
        return modified

    def get_days_of_week_enum(self, days_of_week):
        """Get the enum for days of week.
            :param days_of_week: The list of days of week
            :return: The list of days_of_week enum
        """

        days_of_week_enum = []
        for day in days_of_week:
            if day in utils.DayOfWeekEnum.__members__:
                days_of_week_enum.append(utils.DayOfWeekEnum[day])
            else:
                errormsg = "Invalid choice {0} for days of week".format(day)
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)
        return days_of_week_enum

    def create_rule(self, type, interval, hours_of_day, day_interval,
                    days_of_week, day_of_month, hour, minute,
                    desired_retention, retention_unit, auto_delete,
                    schedule_details=None):
        """Create the rule."""

        duration_in_sec = None
        if desired_retention:
            duration_in_sec = convert_retention_to_seconds(desired_retention,
                                                           retention_unit)

        if not duration_in_sec and schedule_details:
            duration_in_sec = schedule_details['rules'][0]['retention_time']

        if hour is None and schedule_details is None:
            hour = 0

        if hour is None and schedule_details:
            if schedule_details['rules'][0]['hours'] is not None:
                hour = schedule_details['rules'][0]['hours'][0]

        if minute is None and schedule_details is None:
            minute = 0

        if minute is None and schedule_details:
            minute = schedule_details['rules'][0]['minute']

        try:
            if type == "every_n_hours":
                if not interval:
                    interval = schedule_details['rules'][0]['interval']
                rule_dict = utils.snap_schedule.UnitySnapScheduleRule.\
                    every_n_hours(hour_interval=interval, minute=minute,
                                  retention_time=duration_in_sec,
                                  is_auto_delete=auto_delete)
            elif type == "every_day":
                if not hours_of_day:
                    hours_of_day = schedule_details['rules'][0]['hours']

                rule_dict = utils.snap_schedule.UnitySnapScheduleRule.\
                    every_day(hours=hours_of_day, minute=minute,
                              retention_time=duration_in_sec,
                              is_auto_delete=auto_delete)
            elif type == "every_n_days":
                if not day_interval:
                    day_interval = schedule_details['rules'][0]['interval']

                rule_dict = utils.snap_schedule.UnitySnapScheduleRule.\
                    every_n_days(day_interval=day_interval, hour=hour,
                                 minute=minute,
                                 retention_time=duration_in_sec,
                                 is_auto_delete=auto_delete)
            elif type == "every_week":
                if days_of_week:
                    days_of_week_enum = self.get_days_of_week_enum(days_of_week)
                else:
                    days = schedule_details['rules'][0]['days_of_week'][
                        'DayOfWeekEnumList']
                    existing_days = list()

                    for day in days:
                        temp = day.split(".")
                        existing_days.append(temp[1])
                    days_of_week_enum = self.get_days_of_week_enum(days_of_week)

                rule_dict = utils.snap_schedule.UnitySnapScheduleRule.\
                    every_week(days_of_week=days_of_week_enum, hour=hour,
                               minute=minute, retention_time=duration_in_sec,
                               is_auto_delete=auto_delete)
            else:
                if day_of_month:
                    day_of_month_list = [day_of_month]
                else:
                    day_of_month_list = schedule_details['rules'][0][
                        'days_of_month']

                rule_dict = utils.snap_schedule.UnitySnapScheduleRule.\
                    every_month(days_of_month=day_of_month_list, hour=hour,
                                minute=minute, retention_time=duration_in_sec,
                                is_auto_delete=auto_delete)

            return rule_dict

        except Exception as e:
            errormsg = "Create operation of snapshot schedule rule " \
                       " failed with error {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_snapshot_schedule(self, name, rule_dict):
        """Create snapshot schedule.
            :param name: The name of the snapshot schedule
            :param rule_dict: The dict of the rule
            :return: Boolean value to indicate if snapshot schedule created
        """

        try:
            utils.snap_schedule.UnitySnapSchedule.create(
                cli=self.unity_conn._cli, name=name, rules=[rule_dict])
            return True

        except Exception as e:
            errormsg = "Create operation of snapshot schedule {0} failed" \
                       " with error {1}".format(name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_desired_retention(self, desired_retention, retention_unit):
        """Validates the specified desired retention.
            :param desired_retention: Desired retention of the snapshot
             schedule
            :param retention_unit: Retention unit for the snapshot schedule
        """

        if retention_unit == 'hours' and (desired_retention < 1 or
                                          desired_retention > 744):
            self.module.fail_json(msg="Please provide a valid integer as the"
                                      " desired retention between 1 and 744.")
        elif retention_unit == 'days' and (desired_retention < 1 or
                                           desired_retention > 31):
            self.module.fail_json(msg="Please provide a valid integer as the"
                                      " desired retention between 1 and 31.")

    def return_schedule_instance(self, id):
        """Return the snapshot schedule instance
            :param id: The id of the snapshot schedule
            :return: Instance of the snapshot schedule
        """

        try:
            obj_schedule = utils.snap_schedule.UnitySnapSchedule.get(
                self.unity_conn._cli, id)
            return obj_schedule

        except Exception as e:
            error_msg = "Failed to get the snapshot schedule {0} instance" \
                        " with error {1}".format(id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def delete_snapshot_schedule(self, id):
        """Delete snapshot schedule.
            :param id: The ID of the snapshot schedule
            :return: The boolean value to indicate if snapshot schedule
             deleted
        """

        try:
            obj_schedule = self.return_schedule_instance(id=id)
            obj_schedule.delete()
            return True

        except Exception as e:
            errormsg = "Delete operation of snapshot schedule id:{0} failed" \
                       " with error {1}".format(id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_snapshot_schedule(self, id, schedule_details):
        """Modify snapshot schedule details.
            :param id: The id of the snapshot schedule
            :param schedule_details: The dict containing schedule details
            :return: The boolean value to indicate if snapshot schedule
             modified
        """

        try:
            obj_schedule = self.return_schedule_instance(id=id)
            rule_id = schedule_details['rules'][0]['id']

            if self.module.params['auto_delete'] is None:
                auto_delete = schedule_details['rules'][0]['is_auto_delete']
            else:
                auto_delete = self.module.params['auto_delete']

            if schedule_details['rules'][0]['is_auto_delete'] and\
                    self.module.params['desired_retention'] and\
                    self.module.params['auto_delete'] is False:
                auto_delete = False
            elif schedule_details['rules'][0]['retention_time']:
                auto_delete = None

            rule_dict = self.create_rule(
                self.module.params['type'], self.module.params['interval'],
                self.module.params['hours_of_day'],
                self.module.params['day_interval'],
                self.module.params['days_of_week'],
                self.module.params['day_of_month'],
                self.module.params['hour'], self.module.params['minute'],
                self.module.params['desired_retention'],
                self.module.params['retention_unit'], auto_delete,
                schedule_details)

            obj_schedule.modify(add_rules=[rule_dict],
                                remove_rule_ids=[rule_id])
            return True
        except Exception as e:
            errormsg = "Modify operation of snapshot schedule id:{0} failed" \
                       " with error {1}".format(id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_details(self, id=None, name=None):
        """Get snapshot schedule details.
            :param id: The id of the snapshot schedule
            :param name: The name of the snapshot schedule
            :return: Dict containing snapshot schedule details if exists
        """

        id_or_name = id if id else name
        errormsg = "Failed to get details of snapshot schedule {0} with" \
                   " error {1}"
        try:
            if not id:
                details = utils.snap_schedule.UnitySnapScheduleList.get(
                    self.unity_conn._cli, name=name)

                if details:
                    id = details[0].id

            if id:
                details = self.unity_conn.get_snap_schedule(_id=id)

            if id and details.existed:
                rule_list = [rules._get_properties() for rules in
                             details.rules]
                for rule in rule_list:
                    rule['retention_time_in_hours'] = int(
                        rule['retention_time'] / 3600)
                    rule['rule_type'] = get_rule_type(rule['type'])
                schedule_details = details._get_properties()
                schedule_details['rules'] = rule_list
                return schedule_details
            else:
                LOG.info("Failed to get the snapshot schedule %s", id_or_name)
                return None

        except utils.HttpError as e:
            if e.http_status == 401:
                auth_err = "Incorrect username or password, {0}".format(
                    e.message)
                msg = errormsg.format(id_or_name, auth_err)
                LOG.error(msg)
                self.module.fail_json(msg=msg)
            else:
                msg = errormsg.format(id_or_name, str(e))
                LOG.error(msg)
                self.module.fail_json(msg=msg)

        except utils.UnityResourceNotFoundError as e:
            msg = errormsg.format(id_or_name, str(e))
            LOG.error(msg)
            return None

        except Exception as e:
            msg = errormsg.format(id_or_name, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def validate_parameters(self):
        """Validate the parameters."""

        try:
            if self.module.params['interval'] is not None and\
                    self.module.params['interval'] <= 0:
                self.module.fail_json(msg="Interval can not be less than or"
                                      " equal to 0.")

            param_list = ['day_interval', 'day_of_month']
            for param in param_list:
                if self.module.params[param] is not None and\
                        self.module.params[param] == 0:
                    self.module.fail_json(msg="{0} can not be 0.".format(
                        param))

        except Exception as e:
            errormsg = "Failed to validate the module param with error" \
                       " {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def perform_module_operation(self):
        """
        Perform different actions on snapshot schedule module based on
        parameters chosen in playbook
        """
        name = self.module.params['name']
        id = self.module.params['id']
        type = self.module.params['type']
        interval = self.module.params['interval']
        hours_of_day = self.module.params['hours_of_day']
        day_interval = self.module.params['day_interval']
        days_of_week = self.module.params['days_of_week']
        day_of_month = self.module.params['day_of_month']
        hour = self.module.params['hour']
        minute = self.module.params['minute']
        desired_retention = self.module.params['desired_retention']
        retention_unit = self.module.params['retention_unit']
        auto_delete = self.module.params['auto_delete']
        state = self.module.params['state']

        # result is a dictionary that contains changed status and snapshot
        # schedule details
        result = dict(
            changed=False,
            snapshot_schedule_details={}
        )

        self.validate_parameters()

        if desired_retention is not None:
            self.validate_desired_retention(desired_retention, retention_unit)

        if auto_delete and desired_retention:
            self.module.fail_json(msg="Desired retention cannot be "
                                      "specified when auto_delete is true"
                                  )

        schedule_details = self.get_details(name=name, id=id)

        if not id and schedule_details:
            id = schedule_details['id']

        if state == 'present' and not schedule_details:
            if not name:
                msg = "The parameter name length is 0. It is too short." \
                      " The min length is 1."
                self.module.fail_json(msg=msg)

            if not type:
                self.module.fail_json(msg="Rule type is necessary to create"
                                          " snapshot schedule")

            if type == "every_n_hours" and interval is None:
                self.module.fail_json(msg="To create snapshot schedule with"
                                          " rule type every_n_hours, interval"
                                          " is the mandatory parameter.")
            elif type == "every_day" and hours_of_day is None:
                self.module.fail_json(msg="To create snapshot schedule with"
                                          " rule type every_day, hours_of_day"
                                          " is the mandatory parameter.")
            elif type == "every_n_days" and day_interval is None:
                self.module.fail_json(msg="To create snapshot schedule with"
                                          " rule type every_n_days,"
                                          " day_interval is the mandatory"
                                          " parameter.")
            elif type == "every_week" and days_of_week is None:
                self.module.fail_json(msg="To create snapshot schedule with"
                                          " rule type every_week,"
                                          " days_of_week is the mandatory"
                                          " parameter.")
            elif type == "every_month" and day_of_month is None:
                self.module.fail_json(msg="To create snapshot schedule with"
                                          " rule type every_month,"
                                          " day_of_month is the mandatory"
                                          " parameter.")

            rule_dict = self.create_rule(type, interval, hours_of_day,
                                         day_interval, days_of_week,
                                         day_of_month, hour, minute,
                                         desired_retention, retention_unit,
                                         auto_delete)
            result['changed'] = self.create_snapshot_schedule(name, rule_dict)

        elif state == 'absent' and schedule_details:
            result['changed'] = self.delete_snapshot_schedule(id)

        if state == 'present' and type and schedule_details and\
                len(schedule_details['rules']) == 1:
            if (self.schedule_modify_required(schedule_details)):
                result['changed'] = self.modify_snapshot_schedule(
                    id, schedule_details)

        result['snapshot_schedule_details'] = self.get_details(name=name,
                                                               id=id)
        self.module.exit_json(**result)


def get_rule_type(type):
    """Get the rule type of schedule.
        :param type: The schedule type enum
        :return: The rule type of snapshot schedule
    """

    schedule_type = {
        "ScheduleTypeEnum.N_HOURS_AT_MM": "every_n_hours",
        "ScheduleTypeEnum.DAY_AT_HHMM": "every_day",
        "ScheduleTypeEnum.N_DAYS_AT_HHMM": "every_n_days",
        "ScheduleTypeEnum.SELDAYS_AT_HHMM": "every_week",
        "ScheduleTypeEnum.NTH_DAYOFMONTH_AT_HHMM": "every_month"
    }

    return schedule_type.get(type)


def get_schedule_value(type):
    """Get the enum for schedule.
            :param type: The type of rule
            :return: The enum value for rule
    """

    rule_type = {
        "every_n_hours": 0,
        "every_day": 1,
        "every_n_days": 2,
        "every_week": 3,
        "every_month": 4
    }

    return rule_type.get(type)


def convert_retention_to_seconds(desired_retention, retention_unit):
    """Convert desired retention to seconds.
        :param desired_retention: The desired retention for snapshot
         schedule
        :param retention_unit: The retention unit for snapshot schedule
        :return: The integer value in seconds
    """

    duration_in_sec = None
    if desired_retention:
        if retention_unit == 'hours':
            duration_in_sec = desired_retention * 60 * 60
        else:
            duration_in_sec = desired_retention * 24 * 60 * 60
    return duration_in_sec


def get_snapshotschedule_parameters():
    """This method provide parameters required for the ansible snapshot
    schedule module on Unity"""

    return dict(
        name=dict(type='str'),
        id=dict(type='str'),
        type=dict(type='str', choices=['every_n_hours', 'every_day',
                                       'every_n_days', 'every_week',
                                       'every_month']),
        interval=dict(type='int'),
        hours_of_day=dict(type='list', elements='int'),
        day_interval=dict(type='int'),
        days_of_week=dict(type='list', elements='str',
                          choices=['SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY',
                                   'THURSDAY', 'FRIDAY', 'SATURDAY']),
        day_of_month=dict(type='int'),
        hour=dict(type='int'),
        minute=dict(type='int'),
        desired_retention=dict(type='int'),
        retention_unit=dict(type='str', choices=['hours', 'days'],
                            default='hours'),
        auto_delete=dict(type='bool'),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create Unity snapshot schedule object and perform action on it
        based on user input from playbook"""
    obj = SnapshotSchedule()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
