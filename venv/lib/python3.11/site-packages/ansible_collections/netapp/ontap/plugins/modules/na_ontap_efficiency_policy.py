#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_efficiency_policy
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_efficiency_policy
short_description: NetApp ONTAP manage efficiency policies (sis policies)
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Modify/Delete efficiency policies (sis policies)
options:
  state:
    description:
      - Whether the specified efficiency policy should exist or not.
    choices: ['present', 'absent']
    default: 'present'
    type: str

  policy_name:
    description:
      - the name of the efficiency policy
    required: true
    type: str

  comment:
    description:
      - A brief description of the policy.
    type: str

  duration:
    description:
      - The duration in hours for which the scheduled efficiency operation should run.
        After this time expires, the efficiency operation will be stopped even if the operation is incomplete.
        If '-' is specified as the duration, the efficiency operation will run till it completes. Otherwise, the duration has to be an integer greater than 0.
        By default, the operation runs till it completes.
    type: str

  enabled:
    description:
      - If the value is true, the efficiency policy is active in this cluster.
        If the value is false this policy will not be activated by the schedulers and hence will be inactive.
    type: bool

  policy_type:
    description:
      - The policy type reflects the reason a volume using this policy will start processing a changelog.
      - (Changelog processing is identifying and eliminating duplicate blocks which were written since the changelog was last processed.)
      - threshold Changelog processing occurs once the changelog reaches a certain percent full.
      - scheduled Changelog processing will be triggered by time.
    choices: ['threshold', 'scheduled']
    type: str

  qos_policy:
    description:
      - QoS policy for the efficiency operation.
      - background efficiency operation will run in background with minimal or no impact on data serving client operations,
      - best-effort efficiency operations may have some impact on data serving client operations.
    choices: ['background', 'best_effort']
    type: str

  schedule:
    description:
      - Cron type job schedule name. When the associated policy is set on a volume, the efficiency operation will be triggered for the volume on this schedule.
      - These schedules can be created using the na_ontap_job_schedule module
    type: str

  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str

  changelog_threshold_percent:
    description:
      - Specifies the percentage at which the changelog will be processed for a threshold type of policy, tested once each hour.
    type: int
    version_added: '19.11.0'
'''

EXAMPLES = """
- name: Create threshold efficiency policy
  netapp.ontap.na_ontap_efficiency_policy:
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    vserver: ansible
    state: present
    policy_name: test
    comment: This policy is for x and y
    enabled: true
    policy_type: threshold
    qos_policy: background
    changelog_threshold_percent: 20

- name: Create Scheduled efficiency Policy
  netapp.ontap.na_ontap_efficiency_policy:
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    vserver: ansible
    state: present
    policy_name: test2
    comment: This policy is for x and y
    enabled: true
    schedule: new_job_schedule
    duration: 1
    policy_type: scheduled
    qos_policy: background
"""

RETURN = """
"""

import traceback
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapEfficiencyPolicy(object):
    """
    Create, delete and modify efficiency policy
    """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            policy_name=dict(required=True, type='str'),
            comment=dict(required=False, type='str'),
            duration=dict(required=False, type='str'),
            enabled=dict(required=False, type='bool'),
            policy_type=dict(required=False, choices=['threshold', 'scheduled']),
            qos_policy=dict(required=False, choices=['background', 'best_effort']),
            schedule=dict(required=False, type='str'),
            vserver=dict(required=True, type='str'),
            changelog_threshold_percent=dict(required=False, type='int')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[('changelog_threshold_percent', 'duration'), ('changelog_threshold_percent', 'schedule')]
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.uuid = None

        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 8, 0):
            msg = 'REST requires ONTAP 9.8 or later for efficiency_policy APIs.'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)

        if self.parameters.get('policy_type') and self.parameters['state'] == 'present':
            if self.parameters['policy_type'] == 'threshold':
                if self.parameters.get('duration'):
                    self.module.fail_json(msg="duration cannot be set if policy_type is threshold")
                if self.parameters.get('schedule'):
                    self.module.fail_json(msg='schedule cannot be set if policy_type is threshold')
            # if policy_type is 'scheduled'
            else:
                if self.parameters.get('changelog_threshold_percent'):
                    self.module.fail_json(msg='changelog_threshold_percent cannot be set if policy_type is scheduled')

        # if duration not set for a policy, ZAPI returns "-", whereas REST returns 0.
        # "-" is an invalid value in REST, set to 0 if REST.
        if self.parameters.get('duration') == "-" and self.use_rest:
            self.parameters['duration'] = '0'

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
            self.set_playbook_zapi_key_map()

    def set_playbook_zapi_key_map(self):

        self.na_helper.zapi_int_keys = {
            'changelog_threshold_percent': 'changelog-threshold-percent'
        }
        self.na_helper.zapi_str_keys = {
            'policy_name': 'policy-name',
            'comment': 'comment',
            'policy_type': 'policy-type',
            'qos_policy': 'qos-policy',
            'schedule': 'schedule',
            'duration': 'duration'
        }
        self.na_helper.zapi_bool_keys = {
            'enabled': 'enabled'
        }

    def get_efficiency_policy(self):
        """
        Get a efficiency policy
        :return: a efficiency-policy info
        """
        if self.use_rest:
            return self.get_efficiency_policy_rest()
        sis_policy_obj = netapp_utils.zapi.NaElement("sis-policy-get-iter")
        query = netapp_utils.zapi.NaElement("query")
        sis_policy_info = netapp_utils.zapi.NaElement("sis-policy-info")
        sis_policy_info.add_new_child("policy-name", self.parameters['policy_name'])
        sis_policy_info.add_new_child("vserver", self.parameters['vserver'])
        query.add_child_elem(sis_policy_info)
        sis_policy_obj.add_child_elem(query)
        try:
            results = self.server.invoke_successfully(sis_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error searching for efficiency policy %s: %s" % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())
        return_value = {}
        if results.get_child_by_name('num-records') and int(results.get_child_content('num-records')) == 1:
            attributes_list = results.get_child_by_name('attributes-list')
            sis_info = attributes_list.get_child_by_name('sis-policy-info')
            for option, zapi_key in self.na_helper.zapi_int_keys.items():
                return_value[option] = self.na_helper.get_value_for_int(from_zapi=True, value=sis_info.get_child_content(zapi_key))
            for option, zapi_key in self.na_helper.zapi_bool_keys.items():
                return_value[option] = self.na_helper.get_value_for_bool(from_zapi=True, value=sis_info.get_child_content(zapi_key))
            for option, zapi_key in self.na_helper.zapi_str_keys.items():
                return_value[option] = sis_info.get_child_content(zapi_key)
            return return_value
        return None

    def get_efficiency_policy_rest(self):
        api = 'storage/volume-efficiency-policies'
        query = {'name': self.parameters['policy_name'], 'svm.name': self.parameters['vserver']}
        fields = 'name,type,start_threshold_percent,qos_policy,schedule,comment,duration,enabled'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg="Error searching for efficiency policy %s: %s" % (self.parameters['policy_name'], error))
        if record:
            self.uuid = record['uuid']
            current = {
                'policy_name': record['name'],
                'policy_type': record['type'],
                'qos_policy': record['qos_policy'],
                'schedule': record['schedule']['name'] if 'schedule' in record else None,
                'enabled': record['enabled'],
                'duration': str(record['duration']) if 'duration' in record else None,
                'changelog_threshold_percent': record['start_threshold_percent'] if 'start_threshold_percent' in record else None,
                'comment': record['comment']
            }
            return current
        return None

    def create_efficiency_policy(self):
        """
        Creates a efficiency policy
        :return: None
        """
        if self.use_rest:
            return self.create_efficiency_policy_rest()
        sis_policy_obj = netapp_utils.zapi.NaElement("sis-policy-create")
        for option, zapi_key in self.na_helper.zapi_int_keys.items():
            if self.parameters.get(option):
                sis_policy_obj.add_new_child(zapi_key,
                                             self.na_helper.get_value_for_int(from_zapi=False,
                                                                              value=self.parameters[option]))
        for option, zapi_key in self.na_helper.zapi_bool_keys.items():
            if self.parameters.get(option):
                sis_policy_obj.add_new_child(zapi_key,
                                             self.na_helper.get_value_for_bool(from_zapi=False,
                                                                               value=self.parameters[option]))
        for option, zapi_key in self.na_helper.zapi_str_keys.items():
            if self.parameters.get(option):
                sis_policy_obj.add_new_child(zapi_key, str(self.parameters[option]))
        try:
            self.server.invoke_successfully(sis_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error creating efficiency policy %s: %s" % (self.parameters["policy_name"], to_native(error)),
                                  exception=traceback.format_exc())

    def create_efficiency_policy_rest(self):
        api = 'storage/volume-efficiency-policies'
        body = {
            'svm.name': self.parameters['vserver'],
            'name': self.parameters['policy_name']
        }
        create_or_modify_body = self.form_create_or_modify_body(self.parameters)
        if create_or_modify_body:
            body.update(create_or_modify_body)
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating efficiency policy %s: %s" % (self.parameters["policy_name"], error))

    def form_create_or_modify_body(self, create_or_modify):
        """
        Form body contents for create or modify efficiency policy.
        :return: create or modify body.
        """
        body = {}
        if 'comment' in create_or_modify:
            body['comment'] = create_or_modify['comment']
        if 'duration' in create_or_modify:
            body['duration'] = create_or_modify['duration']
        if 'enabled' in create_or_modify:
            body['enabled'] = create_or_modify['enabled']
        if 'qos_policy' in create_or_modify:
            body['qos_policy'] = create_or_modify['qos_policy']
        if 'schedule' in create_or_modify:
            body['schedule'] = {'name': create_or_modify['schedule']}
        if 'changelog_threshold_percent' in create_or_modify:
            body['start_threshold_percent'] = create_or_modify['changelog_threshold_percent']
        if 'policy_type' in create_or_modify:
            body['type'] = create_or_modify['policy_type']
        return body

    def delete_efficiency_policy(self):
        """
        Delete a efficiency Policy
        :return: None
        """
        if self.use_rest:
            return self.delete_efficiency_policy_rest()
        sis_policy_obj = netapp_utils.zapi.NaElement("sis-policy-delete")
        sis_policy_obj.add_new_child("policy-name", self.parameters['policy_name'])
        try:
            self.server.invoke_successfully(sis_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error deleting efficiency policy %s: %s" % (self.parameters["policy_name"], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_efficiency_policy_rest(self):
        api = 'storage/volume-efficiency-policies'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid)
        if error:
            self.module.fail_json(msg="Error deleting efficiency policy %s: %s" % (self.parameters["policy_name"], error))

    def modify_efficiency_policy(self, modify):
        """
        Modify a efficiency policy
        :return: None
        """
        if self.use_rest:
            return self.modify_efficiency_policy_rest(modify)
        sis_policy_obj = netapp_utils.zapi.NaElement("sis-policy-modify")
        sis_policy_obj.add_new_child("policy-name", self.parameters['policy_name'])
        for attribute in modify:
            sis_policy_obj.add_new_child(self.attribute_to_name(attribute), str(self.parameters[attribute]))
        try:
            self.server.invoke_successfully(sis_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error modifying efficiency policy %s: %s" % (self.parameters["policy_name"], to_native(error)),
                                  exception=traceback.format_exc())

    @staticmethod
    def attribute_to_name(attribute):
        return str.replace(attribute, '_', '-')

    def validate_modify(self, current, modify):
        """
        sis-policy-create zapi pre-checks the options and fails if it's not supported.
        is-policy-modify pre-checks one of the options, but tries to modify the others even it's not supported. And it will mess up the vsim.
        Do the checks before sending to the zapi.
        This checks applicable for REST modify too.
        """
        if current['policy_type'] == 'scheduled' and self.parameters.get('policy_type') != 'threshold':
            if modify.get('changelog_threshold_percent'):
                self.module.fail_json(msg="changelog_threshold_percent cannot be set if policy_type is scheduled")
        elif current['policy_type'] == 'threshold' and self.parameters.get('policy_type') != 'scheduled':
            if modify.get('duration'):
                self.module.fail_json(msg="duration cannot be set if policy_type is threshold")
            elif modify.get('schedule'):
                self.module.fail_json(msg="schedule cannot be set if policy_type is threshold")

    def modify_efficiency_policy_rest(self, modify):
        api = 'storage/volume-efficiency-policies'
        body = self.form_create_or_modify_body(modify)
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            self.module.fail_json(msg="Error modifying efficiency policy %s: %s" % (self.parameters["policy_name"], error))

    def apply(self):
        current = self.get_efficiency_policy()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if modify:
                self.validate_modify(current, modify)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_efficiency_policy()
            elif cd_action == 'delete':
                self.delete_efficiency_policy()
            elif modify:
                self.modify_efficiency_policy(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapEfficiencyPolicy()
    obj.apply()


if __name__ == '__main__':
    main()
