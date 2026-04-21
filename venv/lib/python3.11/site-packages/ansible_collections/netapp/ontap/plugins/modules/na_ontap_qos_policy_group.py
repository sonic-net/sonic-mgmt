#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_qos_policy_group
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_qos_policy_group
short_description: NetApp ONTAP manage policy group in Quality of Service.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create, destroy, modify, or rename QoS policy group on NetApp ONTAP.
  - With ZAPI, only fixed QoS policy group is supported.
  - With REST, both fixed and adaptive QoS policy group are supported.

options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified policy group should exist or not.
    default: 'present'
    type: str

  name:
    description:
      - The name of the policy group to manage.
    required: true
    type: str

  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str

  from_name:
    description:
      - Name of the existing policy group to be renamed to name.
    type: str

  max_throughput:
    description:
      - Maximum throughput defined by this policy.
      - Not supported with REST, use C(fixed_qos_options).
    type: str

  min_throughput:
    description:
      - Minimum throughput defined by this policy.
      - Not supported with REST, use C(fixed_qos_options).
    type: str

  is_shared:
    description:
      - Whether the SLOs of the policy group are shared between the workloads or if the SLOs are applied separately to each workload.
      - Not supported with REST, use C(fixed_qos_options).
    type: bool
    version_added: 20.12.0

  force:
    type: bool
    description:
      - Setting to 'true' forces the deletion of the workloads associated with the policy group along with the policy group.
      - Not supported with REST.

  fixed_qos_options:
    version_added: 21.19.0
    type: dict
    description:
      - Set Minimum and Maximum throughput defined by this policy.
      - Only supported with REST.
      - Required one of throughtput options when creating qos_policy.
    suboptions:
      capacity_shared:
        description:
          - Whether the SLOs of the policy group are shared between the workloads or if the SLOs are applied separately to each workload.
          - Default value is False if not used in creating qos policy.
        type: bool
      max_throughput_iops:
        description:
          - Maximum throughput defined by this policy. It is specified in terms of IOPS.
          - 0 means no maximum throughput is enforced.
        type: int
      max_throughput_mbps:
        description:
          - Maximum throughput defined by this policy. It is specified in terms of Mbps.
          - 0 means no maximum throughput is enforced.
        type: int
      min_throughput_iops:
        description:
          - Minimum throughput defined by this policy. It is specified in terms of IOPS.
          - 0 means no minimum throughput is enforced.
          - These floors are not guaranteed on non-AFF platforms or when FabricPool tiering policies are set.
        type: int
      min_throughput_mbps:
        description:
          - Minimum throughput defined by this policy. It is specified in terms of Mbps.
          - 0 means no minimum throughput is enforced.
          - Requires ONTAP 9.8 or later, and REST support.
        type: int

  adaptive_qos_options:
    version_added: 21.19.0
    type: dict
    description:
      - Adaptive QoS policy-groups define measurable service level objectives (SLOs) that adjust based on the storage object used space
        and the storage object allocated space.
      - Only supported with REST.
    suboptions:
      absolute_min_iops:
        description:
          - Specifies the absolute minimum IOPS that is used as an override when the expected_iops is less than this value.
          - These floors are not guaranteed on non-AFF platforms or when FabricPool tiering policies are set.
        type: int
        required: true
      expected_iops:
        description:
          - Expected IOPS. Specifies the minimum expected IOPS per TB allocated based on the storage object allocated size.
          - These floors are not guaranteed on non-AFF platforms or when FabricPool tiering policies are set.
        type: int
        required: true
      peak_iops:
        description:
          - Peak IOPS. Specifies the maximum possible IOPS per TB allocated based on the storage object allocated size or
            the storage object used size.
        type: int
        required: true
      block_size:
        description:
          - Specifies the block size.
          - Requires ONTAP 9.10.1 or later.
        type: str
        required: false
        choices: ['any', '4k', '8k', '16k', '32k', '64k', '128k']
        version_added: 22.6.0
      expected_iops_allocation:
        description:
          - Specifies the size to be used to calculate expected IOPS per TB.
          - Supported only with REST; requires ONTAP 9.10.1 or later.
        type: str
        required: false
        choices: ['used_space', 'allocated_space']
        version_added: 22.8.0
      peak_iops_allocation:
        description:
          - Specifies the size to be used to calculate peak IOPS per TB.
          - Supported only with REST; requires ONTAP 9.10.1 or later.
        type: str
        required: false
        choices: ['used_space', 'allocated_space']
        version_added: 22.8.0
'''

EXAMPLES = """
- name: Create qos policy group in ZAPI.
  netapp.ontap.na_ontap_qos_policy_group:
    state: present
    name: policy_1
    vserver: policy_vserver
    max_throughput: 800KB/s,800iops
    min_throughput: 100iops
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    use_rest: never

- name: Modify qos policy group max throughput in ZAPI.
  netapp.ontap.na_ontap_qos_policy_group:
    state: present
    name: policy_1
    vserver: policy_vserver
    max_throughput: 900KB/s,800iops
    min_throughput: 100iops
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    use_rest: never

- name: Delete qos policy group
  netapp.ontap.na_ontap_qos_policy_group:
    state: absent
    name: policy_1
    vserver: policy_vserver
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create qos policy group in REST.
  netapp.ontap.na_ontap_qos_policy_group:
    state: present
    name: policy_1
    vserver: policy_vserver
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    use_rest: always
    fixed_qos_options:
      max_throughput_iops: 800
      max_throughput_mbps: 200
      min_throughput_iops: 500
      min_throughput_mbps: 100
      capacity_shared: true

- name: Modify qos policy max_throughput in REST.
  netapp.ontap.na_ontap_qos_policy_group:
    state: present
    name: policy_1
    vserver: policy_vserver
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    use_rest: always
    fixed_qos_options:
      max_throughput_iops: 1000
      max_throughput_mbps: 300

- name: Create adaptive qos policy group in REST.
  netapp.ontap.na_ontap_qos_policy_group:
    state: present
    name: adaptive_policy
    vserver: policy_vserver
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    use_rest: always
    adaptive_qos_options:
      absolute_min_iops: 100
      expected_iops: 200
      peak_iops: 500

- name: Modify adaptive qos policy group in REST.
  netapp.ontap.na_ontap_qos_policy_group:
    state: present
    name: adaptive_policy
    vserver: policy_vserver
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    use_rest: always
    adaptive_qos_options:
      expected_iops_allocation: used_space
      peak_iops_allocation: allocated_space
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapQosPolicyGroup:
    """
    Create, delete, modify and rename a policy group.
    """
    def __init__(self):
        """
        Initialize the Ontap qos policy group class.
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            vserver=dict(required=True, type='str'),
            max_throughput=dict(required=False, type='str'),
            min_throughput=dict(required=False, type='str'),
            is_shared=dict(required=False, type='bool'),
            force=dict(required=False, type='bool'),
            fixed_qos_options=dict(required=False, type='dict', options=dict(
                capacity_shared=dict(required=False, type='bool'),
                max_throughput_iops=dict(required=False, type='int'),
                max_throughput_mbps=dict(required=False, type='int'),
                min_throughput_iops=dict(required=False, type='int'),
                min_throughput_mbps=dict(required=False, type='int')
            )),
            adaptive_qos_options=dict(required=False, type='dict', options=dict(
                absolute_min_iops=dict(required=True, type='int'),
                expected_iops=dict(required=True, type='int'),
                peak_iops=dict(required=True, type='int'),
                block_size=dict(required=False, type='str', choices=['any', '4k', '8k', '16k', '32k', '64k', '128k']),
                expected_iops_allocation=dict(required=False, type='str', choices=['used_space', 'allocated_space']),
                peak_iops_allocation=dict(required=False, type='str', choices=['used_space', 'allocated_space'])
            ))
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[
                ['max_throughput', 'fixed_qos_options'],
                ['min_throughput', 'fixed_qos_options'],
                ['max_throughput', 'adaptive_qos_options'],
                ['min_throughput', 'adaptive_qos_options'],
                ['fixed_qos_options', 'adaptive_qos_options'],
                ['is_shared', 'adaptive_qos_options'],
                ['is_shared', 'fixed_qos_options']
            ]
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['is_shared', 'max_throughput', 'min_throughput', 'force']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)

        if self.use_rest and self.parameters['state'] == 'present':
            if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 8) and \
                    self.na_helper.safe_get(self.parameters, ['fixed_qos_options', 'min_throughput_mbps']):
                self.module.fail_json(msg="Minimum version of ONTAP for 'fixed_qos_options.min_throughput_mbps' is (9, 8, 0)")

            ontap_9_10_adaptive_options = ['block_size', 'expected_iops_allocation', 'peak_iops_allocation']
            if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1) and \
                    any(self.na_helper.safe_get(self.parameters, ['adaptive_qos_options', option]) for option in ontap_9_10_adaptive_options):
                self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_9_10_adaptive_options, version='9.10.1'))
        self.uuid = None

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            if 'adaptive_qos_options' in self.parameters:
                self.module.fail_json(msg="Error: use 'na_ontap_qos_adaptive_policy_group' module for create/modify/delete adaptive policy with ZAPI")
            if 'fixed_qos_options' in self.parameters and self.parameters['state'] == 'present':
                self.module.fail_json(msg="Error: 'fixed_qos_options' not supported with ZAPI, use 'max_throughput' and 'min_throughput'")
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
            # default value for force is false in ZAPI.
            self.parameters['force'] = False

    def get_policy_group(self, policy_group_name=None):
        """
        Return details of a policy group.
        :param policy_group_name: policy group name
        :return: policy group details.
        :rtype: dict.
        """
        if policy_group_name is None:
            policy_group_name = self.parameters['name']
        if self.use_rest:
            return self.get_policy_group_rest(policy_group_name)
        policy_group_get_iter = netapp_utils.zapi.NaElement('qos-policy-group-get-iter')
        policy_group_info = netapp_utils.zapi.NaElement('qos-policy-group-info')
        policy_group_info.add_new_child('policy-group', policy_group_name)
        policy_group_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(policy_group_info)
        policy_group_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(policy_group_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching qos policy group %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        policy_group_detail = None

        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) == 1:
            policy_info = result.get_child_by_name('attributes-list').get_child_by_name('qos-policy-group-info')

            policy_group_detail = {
                'name': policy_info.get_child_content('policy-group'),
                'vserver': policy_info.get_child_content('vserver'),
                'max_throughput': policy_info.get_child_content('max-throughput'),
                'min_throughput': policy_info.get_child_content('min-throughput'),
                'is_shared': self.na_helper.get_value_for_bool(True, policy_info.get_child_content('is-shared'))
            }
        return policy_group_detail

    def get_policy_group_rest(self, policy_group_name):
        api = 'storage/qos/policies'
        query = {
            'name': policy_group_name,
            'svm.name': self.parameters['vserver']
        }
        fields = 'name,svm'
        if 'fixed_qos_options' in self.parameters:
            fields += ',fixed'
        elif 'adaptive_qos_options' in self.parameters:
            fields += ',adaptive'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg='Error fetching qos policy group %s: %s' %
                                  (self.parameters['name'], error))
        current = None
        if record:
            self.uuid = record['uuid']
            current = {
                'name': record['name'],
                'vserver': record['svm']['name']
            }

            if 'fixed' in record:
                current['fixed_qos_options'] = {}
                for fixed_qos_option in ['capacity_shared', 'max_throughput_iops', 'max_throughput_mbps', 'min_throughput_iops']:
                    current['fixed_qos_options'][fixed_qos_option] = record['fixed'].get(fixed_qos_option)
                if self.na_helper.safe_get(self.parameters, ['fixed_qos_options', 'min_throughput_mbps']):
                    current['fixed_qos_options']['min_throughput_mbps'] = record['fixed'].get('min_throughput_mbps')

            if 'adaptive' in record:
                current['adaptive_qos_options'] = {}
                for adaptive_qos_option in ['absolute_min_iops', 'expected_iops', 'peak_iops', 'block_size',
                                            'expected_iops_allocation', 'peak_iops_allocation']:
                    current['adaptive_qos_options'][adaptive_qos_option] = record['adaptive'].get(adaptive_qos_option)
        return current

    def create_policy_group(self):
        """
        create a policy group name.
        """
        if self.use_rest:
            return self.create_policy_group_rest()
        policy_group = netapp_utils.zapi.NaElement('qos-policy-group-create')
        policy_group.add_new_child('policy-group', self.parameters['name'])
        policy_group.add_new_child('vserver', self.parameters['vserver'])
        if self.parameters.get('max_throughput'):
            policy_group.add_new_child('max-throughput', self.parameters['max_throughput'])
        if self.parameters.get('min_throughput'):
            policy_group.add_new_child('min-throughput', self.parameters['min_throughput'])
        if self.parameters.get('is_shared') is not None:
            policy_group.add_new_child('is-shared', self.na_helper.get_value_for_bool(False, self.parameters['is_shared']))
        try:
            self.server.invoke_successfully(policy_group, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating qos policy group %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_policy_group_rest(self):
        api = 'storage/qos/policies'
        body = {
            'name': self.parameters['name'],
            'svm.name': self.parameters['vserver']
        }
        if 'fixed_qos_options' in self.parameters:
            body['fixed'] = self.na_helper.filter_out_none_entries(self.parameters['fixed_qos_options'])
            # default value for capacity_shared is False in REST.
            if self.na_helper.safe_get(body, ['fixed', 'capacity_shared']) is None:
                body['fixed']['capacity_shared'] = False
        else:
            body['adaptive'] = self.na_helper.filter_out_none_entries(self.parameters['adaptive_qos_options'])
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating qos policy group %s: %s' %
                                  (self.parameters['name'], error))

    def delete_policy_group(self, policy_group=None):
        """
        delete an existing policy group.
        :param policy_group: policy group name.
        """
        if self.use_rest:
            return self.delete_policy_group_rest()
        if policy_group is None:
            policy_group = self.parameters['name']
        policy_group_obj = netapp_utils.zapi.NaElement('qos-policy-group-delete')
        policy_group_obj.add_new_child('policy-group', policy_group)
        if self.parameters.get('force'):
            policy_group_obj.add_new_child('force', str(self.parameters['force']))
        try:
            self.server.invoke_successfully(policy_group_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting qos policy group %s: %s' %
                                  (policy_group, to_native(error)),
                                  exception=traceback.format_exc())

    def delete_policy_group_rest(self):
        api = 'storage/qos/policies'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid)
        if error:
            self.module.fail_json(msg='Error deleting qos policy group %s: %s' %
                                  (self.parameters['name'], error))

    def modify_policy_group(self, modify):
        """
        Modify policy group.
        """
        if self.use_rest:
            return self.modify_policy_group_rest(modify)
        policy_group_obj = netapp_utils.zapi.NaElement('qos-policy-group-modify')
        policy_group_obj.add_new_child('policy-group', self.parameters['name'])
        if self.parameters.get('max_throughput'):
            policy_group_obj.add_new_child('max-throughput', self.parameters['max_throughput'])
        if self.parameters.get('min_throughput'):
            policy_group_obj.add_new_child('min-throughput', self.parameters['min_throughput'])
        try:
            self.server.invoke_successfully(policy_group_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying qos policy group %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_policy_group_rest(self, modify):
        api = 'storage/qos/policies'
        body = {}
        if 'fixed_qos_options' in modify:
            body['fixed'] = modify['fixed_qos_options']
        else:
            if 'block_size' not in self.na_helper.safe_get(modify, ['adaptive_qos_options']) and \
                    self.na_helper.safe_get(self.parameters, ['adaptive_qos_options', 'block_size']) is None:
                # if block_size is not to be modified then remove it from the params
                # to avoid error with block_size option during modification of other adaptive qos options
                del self.parameters['adaptive_qos_options']['block_size']
            body['adaptive'] = self.parameters['adaptive_qos_options']
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            self.module.fail_json(msg='Error modifying qos policy group %s: %s' %
                                  (self.parameters['name'], error))

    def rename_policy_group(self):
        """
        Rename policy group name.
        """
        if self.use_rest:
            return self.rename_policy_group_rest()
        rename_obj = netapp_utils.zapi.NaElement('qos-policy-group-rename')
        rename_obj.add_new_child('new-name', self.parameters['name'])
        rename_obj.add_new_child('policy-group-name', self.parameters['from_name'])
        try:
            self.server.invoke_successfully(rename_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming qos policy group %s: %s' %
                                  (self.parameters['from_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def rename_policy_group_rest(self):
        api = 'storage/qos/policies'
        body = {'name': self.parameters['name']}
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            self.module.fail_json(msg='Error renaming qos policy group %s: %s' %
                                  (self.parameters['from_name'], error))

    def modify_helper(self, modify):
        """
        helper method to modify policy group.
        :param modify: modified attributes.
        """
        if any(
            attribute in modify
            for attribute in ['max_throughput', 'min_throughput', 'fixed_qos_options', 'adaptive_qos_options']
        ):
            self.modify_policy_group(modify)

    def validate_adaptive_or_fixed_qos_options(self):
        error = None
        # one of the fixed throughput option required in create qos_policy.
        if 'fixed_qos_options' in self.parameters:
            fixed_options = ['max_throughput_iops', 'max_throughput_mbps', 'min_throughput_iops', 'min_throughput_mbps']
            if not any(x in self.na_helper.filter_out_none_entries(self.parameters['fixed_qos_options']) for x in fixed_options):
                error = True
        # error if both fixed_qos_options or adaptive_qos_options not present in creating qos policy.
        elif self.parameters.get('fixed_qos_options', self.parameters.get('adaptive_qos_options')) is None:
            error = True
        return error

    def apply(self):
        """
        Run module based on playbook
        """
        current = self.get_policy_group()
        rename, cd_action = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('from_name'):
            # create policy by renaming an existing one
            old_policy = self.get_policy_group(self.parameters['from_name'])
            rename = self.na_helper.is_rename_action(old_policy, current)
            if rename:
                current = old_policy
                cd_action = None
            if rename is None:
                self.module.fail_json(msg='Error renaming qos policy group: cannot find %s' %
                                      self.parameters['from_name'])
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else {}
        if 'is_shared' in modify or self.na_helper.safe_get(modify, ['fixed_qos_options', 'capacity_shared']) is not None:
            self.module.fail_json(msg="Error cannot modify '%s' attribute." %
                                  ('is_shared' if 'is_shared' in modify else 'fixed_qos_options.capacity_shared'))
        if self.use_rest and cd_action == 'create' and self.validate_adaptive_or_fixed_qos_options():
            error = "Error: atleast one throughput in 'fixed_qos_options' or all 'adaptive_qos_options' required in creating qos_policy in REST."
            self.module.fail_json(msg=error)
        if self.na_helper.changed and not self.module.check_mode:
            if rename:
                self.rename_policy_group()
            if cd_action == 'create':
                self.create_policy_group()
            elif cd_action == 'delete':
                self.delete_policy_group()
            elif modify:
                self.modify_helper(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Apply vserver operations from playbook'''
    qos_policy_group = NetAppOntapQosPolicyGroup()
    qos_policy_group.apply()


if __name__ == '__main__':
    main()
