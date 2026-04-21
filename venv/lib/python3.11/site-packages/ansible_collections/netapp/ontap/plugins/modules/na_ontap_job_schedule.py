#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_job_schedule
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_job_schedule
short_description: NetApp ONTAP Job Schedule
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create/Delete/Modify job-schedules on ONTAP
options:
  state:
    description:
      - Whether the specified job schedule should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present
  name:
    description:
      - The name of the job-schedule to manage.
    required: true
    type: str
  job_minutes:
    description:
      - The minute(s) of each hour when the job should be run.
        Job Manager cron scheduling minute.
      - 1 represents all minutes.
        Range is [-1..59]
      - Required for create.
    type: list
    elements: int
  job_hours:
    version_added: 2.8.0
    description:
      - The hour(s) of the day when the job should be run.
        Job Manager cron scheduling hour.
      - 1 represents all hours.
        Range is [-1..23]
    type: list
    elements: int
  job_months:
    version_added: 2.8.0
    description:
      - The month(s) when the job should be run.
        Job Manager cron scheduling month.
      - 1 represents all months.
        Range is [-1..12], 0 and 12 may or may not be supported, see C(month_offset)
    type: list
    elements: int
  job_days_of_month:
    version_added: 2.8.0
    description:
      - The day(s) of the month when the job should be run.
        Job Manager cron scheduling day of month.
      - 1 represents all days of a month from 1 to 31.
        Range is [-1..31]
    type: list
    elements: int
  job_days_of_week:
    version_added: 2.8.0
    description:
      - The day(s) in the week when the job should be run.
        Job Manager cron scheduling day of week.
      - Zero represents Sunday. -1 represents all days of a week.
        Range is [-1..6]
    type: list
    elements: int
  month_offset:
    description:
      - whether January starts at 0 or 1.  By default, ZAPI is using a 0..11 range, while REST is using 1..12.
      - default to 0 when using ZAPI, and to 1 when using REST.
      - when set to 0, a value of 12 or higher is rejected.
      - when set to 1, a value of 0 or of 13 or higher is rejected.
    type: int
    choices: [0, 1]
    version_added: 21.9.0
  cluster:
    description:
       - Defaults to local cluster.
       - In a MetroCluster configuration, user-created schedules owned by the local cluster are replicated to the partner cluster.
         Likewise, user-created schedules owned by the partner cluster are replicated to the local cluster.
       - Normally, only schedules owned by the local cluster can be created, modified, and deleted on the local cluster.
         However, when a MetroCluster configuration is in switchover, the cluster in switchover state can
         create, modify, and delete schedules owned by the partner cluster.
    type: str
    version_added: 21.22.0
  vserver:
    description:
       - name of the vserver.
    type: str
    version_added: 23.2.0
  interval:
    description:
      - The interval at which the job should be run.
      - This is specified in an ISO-8601 duration formatted string.
      - This parameter does not work with cron jobs.
    type: str
    version_added: 23.2.0
'''

EXAMPLES = """
- name: Create Job for 11.30PM at 10th of every month
  netapp.ontap.na_ontap_job_schedule:
    state: present
    name: jobName
    job_minutes: 30
    job_hours: 23
    job_days_of_month: 10
    job_months: -1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create Job for 11.30PM at 10th of January, April, July, October for ZAPI and REST
  netapp.ontap.na_ontap_job_schedule:
    state: present
    name: jobName
    job_minutes: 30
    job_hours: 23
    job_days_of_month: 10
    job_months: 1,4,7,10
    month_offset: 1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create Job for 11.30PM at 10th of January, April, July, October for ZAPI and REST
  netapp.ontap.na_ontap_job_schedule:
    state: present
    name: jobName
    job_minutes: 30
    job_hours: 23
    job_days_of_month: 10
    job_months: 0,3,6,9
    month_offset: 0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create Job for 11.30PM at 10th of January when using REST and February when using ZAPI !!!
  netapp.ontap.na_ontap_job_schedule:
    state: present
    name: jobName
    job_minutes: 30
    job_hours: 23
    job_days_of_month: 10
    job_months: 1
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create Interval Job using REST
  netapp.ontap.na_ontap_job_schedule:
    state: present
    name: jobName
    interval: P1DT2H3M4S
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete Job
  netapp.ontap.na_ontap_job_schedule:
    state: absent
    name: jobName
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """

"""


import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPJob:
    '''Class with job schedule cron methods'''

    def __init__(self):

        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            job_minutes=dict(required=False, type='list', elements='int'),
            job_months=dict(required=False, type='list', elements='int'),
            job_hours=dict(required=False, type='list', elements='int'),
            job_days_of_month=dict(required=False, type='list', elements='int'),
            job_days_of_week=dict(required=False, type='list', elements='int'),
            month_offset=dict(required=False, type='int', choices=[0, 1]),
            cluster=dict(required=False, type='str'),
            vserver=dict(required=False, type='str'),
            interval=dict(required=False, type='str')
        ))

        self.uuid = None
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        self.month_offset = self.parameters.get('month_offset')
        if self.month_offset is None:
            # maintain backward compatibility
            self.month_offset = 1 if self.use_rest else 0
        if self.month_offset == 1 and self.parameters.get('job_months') and 0 in self.parameters['job_months']:
            # we explictly test for 0 as it would be converted to -1, which has a special meaning (all).
            # other value errors will be reported by the API.
            self.module.fail_json(msg='Error: 0 is not a valid value in months if month_offset is set to 1: %s' % self.parameters['job_months'])

        if self.use_rest:
            self.set_playbook_api_key_map()
        elif not netapp_utils.has_netapp_lib():
            self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
            self.set_playbook_zapi_key_map()

    def set_playbook_zapi_key_map(self):
        self.na_helper.zapi_string_keys = {
            'name': 'job-schedule-name',
            'cluster': 'job-schedule-cluster'
        }
        self.na_helper.zapi_list_keys = {
            'job_minutes': ('job-schedule-cron-minute', 'cron-minute'),
            'job_months': ('job-schedule-cron-month', 'cron-month'),
            'job_hours': ('job-schedule-cron-hour', 'cron-hour'),
            'job_days_of_month': ('job-schedule-cron-day', 'cron-day-of-month'),
            'job_days_of_week': ('job-schedule-cron-day-of-week', 'cron-day-of-week')
        }

    def set_playbook_api_key_map(self):
        self.na_helper.params_to_rest_api_keys = {
            'job_minutes': 'minutes',
            'job_months': 'months',
            'job_hours': 'hours',
            'job_days_of_month': 'days',
            'job_days_of_week': 'weekdays'
        }

    def get_job_schedule_rest(self):
        """
        Return details about the job
        :param:
            name : Job name
        :return: Details about the Job. None if not found.
        :rtype: dict
        """
        query = {'name': self.parameters['name']}
        if self.parameters.get('cluster'):
            query['cluster'] = self.parameters['cluster']
        if self.parameters.get('vserver'):
            query['svm'] = self.parameters['vserver']
        record, error = rest_generic.get_one_record(self.rest_api, 'cluster/schedules', query, 'uuid,cron,interval,type')
        if error is not None:
            self.module.fail_json(msg="Error fetching job schedule: %s" % error)
        if record:
            self.uuid = record['uuid']
            job_details = {'name': record['name'], 'type': record['type']}
            if 'svm' in record:
                job_details['vserver'] = record['svm']['name']
            if record['type'] == 'cron':
                for param_key, rest_key in self.na_helper.params_to_rest_api_keys.items():
                    if rest_key in record['cron']:
                        job_details[param_key] = record['cron'][rest_key]
                    else:
                        # if any of the job_hours, job_minutes, job_months, job_days are empty:
                        # it means the value is -1 using ZAPI convention
                        job_details[param_key] = [-1]
                # adjust offsets if necessary
                if 'job_months' in job_details and self.month_offset == 0:
                    job_details['job_months'] = [x - 1 if x > 0 else x for x in job_details['job_months']]
                # adjust minutes if necessary, -1 means all in ZAPI and for our user facing parameters
                # while REST returns all values
                if 'job_minutes' in job_details and len(job_details['job_minutes']) == 60:
                    job_details['job_minutes'] = [-1]
            else:
                job_details['interval'] = record['interval']

            return job_details
        return None

    def get_job_schedule(self):
        """
        Return details about the job
        :param:
            name : Job name
        :return: Details about the Job. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_job_schedule_rest()

        job_get_iter = netapp_utils.zapi.NaElement('job-schedule-cron-get-iter')
        query = {'job-schedule-cron-info': {'job-schedule-name': self.parameters['name']}}
        if self.parameters.get('cluster'):
            query['job-schedule-cron-info']['job-schedule-cluster'] = self.parameters['cluster']
        job_get_iter.translate_struct({'query': query})
        try:
            result = self.server.invoke_successfully(job_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching job schedule %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        job_details = None
        # check if job exists
        if result.get_child_by_name('num-records') and int(result['num-records']) >= 1:
            job_info = result['attributes-list']['job-schedule-cron-info']
            job_details = {}
            for item_key, zapi_key in self.na_helper.zapi_string_keys.items():
                job_details[item_key] = job_info[zapi_key]
            for item_key, zapi_key in self.na_helper.zapi_list_keys.items():
                parent, dummy = zapi_key
                job_details[item_key] = self.na_helper.get_value_for_list(from_zapi=True,
                                                                          zapi_parent=job_info.get_child_by_name(parent)
                                                                          )
                if item_key == 'job_months' and self.month_offset == 1:
                    job_details[item_key] = [int(x) + 1 if int(x) >= 0 else int(x) for x in job_details[item_key]]
                elif item_key == 'job_minutes' and len(job_details[item_key]) == 60:
                    job_details[item_key] = [-1]
                else:
                    job_details[item_key] = [int(x) for x in job_details[item_key]]
                # if any of the job_hours, job_minutes, job_months, job_days are empty:
                # it means the value is -1 for ZAPI
                if not job_details[item_key]:
                    job_details[item_key] = [-1]
        return job_details

    def add_job_details(self, na_element_object, values):
        """
        Add children node for create or modify NaElement object
        :param na_element_object: modify or create NaElement object
        :param values: dictionary of cron values to be added
        :return: None
        """
        for item_key, item_value in values.items():
            if item_key in self.na_helper.zapi_string_keys:
                zapi_key = self.na_helper.zapi_string_keys.get(item_key)
                na_element_object[zapi_key] = item_value
            elif item_key in self.na_helper.zapi_list_keys:
                parent_key, child_key = self.na_helper.zapi_list_keys.get(item_key)
                data = item_value
                if data:
                    if item_key == 'job_months' and self.month_offset == 1:
                        # -1 is a special value
                        data = [str(x - 1) if x > 0 else str(x) for x in data]
                    else:
                        data = [str(x) for x in data]
                na_element_object.add_child_elem(self.na_helper.get_value_for_list(from_zapi=False,
                                                                                   zapi_parent=parent_key,
                                                                                   zapi_child=child_key,
                                                                                   data=data))

    def create_job_schedule(self):
        """
        Creates a job schedule
        """
        if self.use_rest:
            cron = {}
            for param_key, rest_key in self.na_helper.params_to_rest_api_keys.items():
                # -1 means all in zapi, while empty means all in api.
                if self.parameters.get(param_key):
                    if len(self.parameters[param_key]) == 1 and self.parameters[param_key][0] == -1:
                        # need to set empty value for minutes as this is a required parameter
                        if rest_key == 'minutes':
                            cron[rest_key] = []
                    elif param_key == 'job_months' and self.month_offset == 0:
                        cron[rest_key] = [x + 1 if x >= 0 else x for x in self.parameters[param_key]]
                    else:
                        cron[rest_key] = self.parameters[param_key]

            params = {
                'name': self.parameters['name'],
                'cron': cron
            }
            if self.parameters.get('cluster'):
                params['cluster'] = self.parameters['cluster']
            if self.parameters.get('vserver'):
                params['svm'] = self.parameters['vserver']
            if self.parameters.get('interval'):
                params['interval'] = self.parameters['interval']
            api = 'cluster/schedules'
            dummy, error = self.rest_api.post(api, params)
            if error is not None:
                self.module.fail_json(msg="Error creating job schedule: %s" % error)

        else:
            job_schedule_create = netapp_utils.zapi.NaElement('job-schedule-cron-create')
            self.add_job_details(job_schedule_create, self.parameters)
            try:
                self.server.invoke_successfully(job_schedule_create,
                                                enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error creating job schedule %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())

    def delete_job_schedule(self):
        """
        Delete a job schedule
        """
        if self.use_rest:
            api = 'cluster/schedules/' + self.uuid
            dummy, error = self.rest_api.delete(api)
            if error is not None:
                self.module.fail_json(msg="Error deleting job schedule: %s" % error)
        else:
            job_schedule_delete = netapp_utils.zapi.NaElement('job-schedule-cron-destroy')
            self.add_job_details(job_schedule_delete, self.parameters)
            try:
                self.server.invoke_successfully(job_schedule_delete,
                                                enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error deleting job schedule %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())

    def modify_job_schedule(self, modify, current):
        """
        modify a job schedule
        """

        def set_cron(param_key, rest_key, params, cron):
            # -1 means all in zapi, while empty means all in api.
            if params[param_key] == [-1]:
                cron[rest_key] = []
            elif param_key == 'job_months' and self.month_offset == 0:
                cron[rest_key] = [x + 1 for x in params[param_key]]
            else:
                cron[rest_key] = params[param_key]

        if self.use_rest:
            cron = {}
            for param_key, rest_key in self.na_helper.params_to_rest_api_keys.items():
                if modify.get(param_key):
                    set_cron(param_key, rest_key, modify, cron)
                elif current.get(param_key):
                    # Usually only include modify attributes, but omitting an attribute means all in api.
                    # Need to add the current attributes in params.
                    set_cron(param_key, rest_key, current, cron)
            params = {
                'cron': cron
            }
            if modify.get('interval'):
                params['interval'] = modify['interval']
            api = 'cluster/schedules/' + self.uuid
            dummy, error = self.rest_api.patch(api, params)
            if error is not None:
                self.module.fail_json(msg="Error modifying job schedule: %s" % error)
        else:
            job_schedule_modify = netapp_utils.zapi.NaElement.create_node_with_children(
                'job-schedule-cron-modify', **{'job-schedule-name': self.parameters['name']})
            self.add_job_details(job_schedule_modify, modify)
            try:
                self.server.invoke_successfully(job_schedule_modify, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying job schedule %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())

    def apply(self):
        """
        Apply action to job-schedule
        """
        modify = None
        current = self.get_job_schedule()
        action = self.na_helper.get_cd_action(current, self.parameters)
        if action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            if action == 'create':
                self.create_job_schedule()
            elif action == 'delete':
                self.delete_job_schedule()
            elif modify:
                self.modify_job_schedule(modify, current)
        result = netapp_utils.generate_result(self.na_helper.changed, action, modify)
        self.module.exit_json(**result)


def main():
    '''Execute action'''
    job_obj = NetAppONTAPJob()
    job_obj.apply()


if __name__ == '__main__':
    main()
