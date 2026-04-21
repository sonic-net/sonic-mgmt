#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_s3_buckets
short_description: NetApp ONTAP S3 Buckets
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.19.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete, or modify S3 buckets on NetApp ONTAP.

options:
  state:
    description:
      - Whether the specified S3 bucket should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'

  name:
    description:
      - The name of the S3 or NAS bucket.
    type: str
    required: true

  vserver:
    description:
      - Name of the vserver to use.
    type: str
    required: true

  aggregates:
    description:
      - List of aggregates names to use for the S3 bucket.
      - This option is not supported when I(type=nas).
    type: list
    elements: str

  constituents_per_aggregate:
    description:
      - Number of constituents per aggregate.
      - This option is not supported when I(type=nas).
    type: int

  size:
    description:
      - Size of the S3 bucket in bytes.
      - This option is not supported when I(type=nas).
    type: int

  comment:
    description:
      - Comment for the S3 bucket.
    type: str

  type:
    description:
      - Specifies the bucket type. Valid values are "s3"and "nas".
    type: str
    choices: ['s3', 'nas']
    version_added: 22.6.0

  nas_path:
    description:
      - Specifies the NAS path to which the nas bucket corresponds to.
    type: str
    version_added: 22.7.0

  versioning_state:
    description:
      - Specifies the versioning state of the bucket.
      - The versioning state cannot be modified to 'disabled' from any other state.
      - Requires ONTAP 9.11.1 or later.
    type: str
    choices: ['disabled', 'enabled', 'suspended']
    version_added: 22.13.0

  policy:
    description:
      - Access policy uses the Amazon Web Services (AWS) policy language syntax to allow S3 tenants to create access policies to their data
    type: dict
    suboptions:
      statements:
        description:
          - Policy statements are built using this structure to specify permissions
          - Grant <Effect> to allow/deny <Principal> to perform <Action> on <Resource> when <Condition> applies
        type: list
        elements: dict
        suboptions:
          sid:
            description: Statement ID
            type: str
          resources:
            description:
              - The bucket and any object it contains.
              - The wildcard characters * and ? can be used to form a regular expression for specifying a resource.
            type: list
            elements: str
          actions:
            description:
              - You can specify * to mean all actions, or a list of one or more of the following
              - GetObject
              - PutObject
              - DeleteObject
              - ListBucket
              - GetBucketAcl
              - GetObjectAcl
              - ListBucketMultipartUploads
              - ListMultipartUploadParts
            type: list
            elements: str
          effect:
            description: The statement may allow or deny access
            type: str
            choices:
              - allow
              - deny
          principals:
            description: A list of one or more S3 users or groups.
            type: list
            elements: str
          conditions:
            description: Conditions for when a policy is in effect.
            type: list
            elements: dict
            suboptions:
              operator:
                description:
                  - The operator to use for the condition.
                type: str
                choices:
                  - ip_address
                  - not_ip_address
                  - string_equals
                  - string_not_equals
                  - string_equals_ignore_case
                  - string_not_equals_ignore_case
                  - string_like
                  - string_not_like
                  - numeric_equals
                  - numeric_not_equals
                  - numeric_greater_than
                  - numeric_greater_than_equals
                  - numeric_less_than
                  - numeric_less_than_equals
              max_keys:
                description:
                  - The maximum number of keys that can be returned in a request.
                type: list
                elements: str
              delimiters:
                description:
                 - The delimiter used to identify a prefix in a list of objects.
                type: list
                elements: str
              source_ips:
                description:
                  - The source IP address of the request.
                type: list
                elements: str
              prefixes:
                description:
                  - The prefixes of the objects that you want to list.
                type: list
                elements: str
              usernames:
                description:
                  - The user names that you want to allow to access the bucket.
                type: list
                elements: str

  qos_policy:
    description:
      - A policy group defines measurable service level objectives (SLOs) that apply to the storage objects with which the policy group is associated.
      - If you do not assign a policy group to a bucket, the system wil not monitor and control the traffic to it.
      - This option is not supported when I(type=nas).
    type: dict
    suboptions:
      max_throughput_iops:
        description: The maximum throughput in IOPS.
        type: int
      max_throughput_mbps:
        description: The maximum throughput in MBPS.
        type: int
      min_throughput_iops:
        description: The minimum throughput in IOPS.
        type: int
      min_throughput_mbps:
        description: The minimum throughput in MBPS.
        type: int
      name:
        description: The QoS policy group name. This is mutually exclusive with other QoS attributes.
        type: str

  audit_event_selector:
    description:
      - Audit event selector allows you to specify access and permission types to audit.
      - This option is not supported when I(type=nas).
    type: dict
    suboptions:
      access:
        description:
          - specifies the type of event access to be audited, read-only, write-only or all (default is all).
        type: str
        choices:
          - read
          - write
          - all
      permission:
        description:
          - specifies the type of event permission to be audited, allow-only, deny-only or all (default is all).
        type: str
        choices:
          - allow
          - deny
          - all

  snapshot_policy:
    description:
      - Specifies the snapshot policy for the bucket.
    type: str
    version_added: 23.1.0

notes:
  - module will try to set desired C(audit_event_selector) if the bucket is not configured with audit_event_selector options,
    but may not take effect if there is no audit configuration present in vserver.
'''

EXAMPLES = """
- name: Create S3 bucket
  netapp.ontap.na_ontap_s3_buckets:
    state: present
    name: carchi-test-bucket
    comment: carchi8py was here
    size: 838860800
    vserver: ansibleSVM
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always

- name: Create S3 bucket with a policy
  netapp.ontap.na_ontap_s3_buckets:
    state: present
    name: carchi-test-bucket
    comment: carchi8py was here
    size: 838860800
    policy:
      statements:
        - sid: FullAccessToUser1
          resources:
            - bucket1
            - bucket1/*
          actions:
            - GetObject
            - PutObject
            - DeleteObject
            - ListBucket
          effect: allow
          conditions:
            - operator: ip_address
              max_keys:
                - 1000
              delimiters:
                - "/"
              source_ips:
                - 1.1.1.1
                - 1.2.2.0/24
              prefixes:
                - prex
              usernames:
                - user1
          principals:
            - user1
            - group/grp1
    vserver: ansibleSVM
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always

- name: Delete S3 bucket
  netapp.ontap.na_ontap_s3_buckets:
    state: absent
    name: carchi-test-bucket
    vserver: ansibleSVM
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
    use_rest: always
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapS3Buckets:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            aggregates=dict(required=False, type='list', elements='str'),
            constituents_per_aggregate=dict(required=False, type='int'),
            size=dict(required=False, type='int'),
            comment=dict(required=False, type='str'),
            type=dict(required=False, type='str', choices=['s3', 'nas']),
            nas_path=dict(required=False, type='str'),
            versioning_state=dict(required=False, type='str', choices=['disabled', 'enabled', 'suspended']),
            policy=dict(type='dict', options=dict(
                statements=dict(type='list', elements='dict', options=dict(
                    sid=dict(required=False, type='str'),
                    resources=dict(required=False, type='list', elements='str'),
                    actions=dict(required=False, type='list', elements='str'),
                    effect=dict(required=False, type='str', choices=['allow', 'deny']),
                    conditions=dict(type='list', elements='dict', options=dict(
                        operator=dict(required=False, type='str', choices=['ip_address',
                                                                           'not_ip_address',
                                                                           'string_equals',
                                                                           'string_not_equals',
                                                                           'string_equals_ignore_case',
                                                                           'string_not_equals_ignore_case',
                                                                           'string_like',
                                                                           'string_not_like',
                                                                           'numeric_equals',
                                                                           'numeric_not_equals',
                                                                           'numeric_greater_than',
                                                                           'numeric_greater_than_equals',
                                                                           'numeric_less_than',
                                                                           'numeric_less_than_equals']),
                        max_keys=dict(required=False, type='list', elements='str', no_log=False),
                        delimiters=dict(required=False, type='list', elements='str'),
                        source_ips=dict(required=False, type='list', elements='str'),
                        prefixes=dict(required=False, type='list', elements='str'),
                        usernames=dict(required=False, type='list', elements='str'))),
                    principals=dict(type='list', elements='str')
                )))),
            qos_policy=dict(type='dict', options=dict(
                max_throughput_iops=dict(type='int'),
                max_throughput_mbps=dict(type='int'),
                name=dict(type='str'),
                min_throughput_iops=dict(type='int'),
                min_throughput_mbps=dict(type='int'),
            )),
            audit_event_selector=dict(type='dict', options=dict(
                access=dict(type='str', choices=['read', 'write', 'all']),
                permission=dict(type='str', choices=['allow', 'deny', 'all']))),
            snapshot_policy=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.svm_uuid = None
        self.uuid = None
        self.volume_uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_s3_buckets', 9, 8)
        partially_supported_rest_properties = [['audit_event_selector', (9, 10, 1)], ['versioning_state', (9, 11, 1)],
                                               ['type', (9, 12, 1)], ['nas_path', (9, 12, 1)], ['snapshot_policy', (9, 16, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)
        # few keys in policy.statements will be configured with default value if not set in create.
        # so removing None entries to avoid idempotent issue in next run.
        if self.parameters.get('policy'):
            # below keys can be reset with empty list.
            #   - statements.
            #   - conditions.
            #   - actions.
            #   - principals.
            self.parameters['policy'] = self.na_helper.filter_out_none_entries(self.parameters['policy'], True)
            for statement in self.parameters['policy'].get('statements', []):
                if {} in self.parameters['policy']['statements']:
                    self.module.fail_json(msg="Error: cannot set empty dict for policy statements.")
                if len(statement.get('resources', [])) == 1 and statement['resources'] == ["*"]:
                    statement['resources'] = [self.parameters['name'], self.parameters['name'] + '/*']
                for condition in statement.get('conditions', []):
                    updated_ips = []
                    for ip in condition.get('source_ips', []):
                        if '/' in ip:
                            updated_ips.append(ip)
                        else:
                            # if cidr notation not set in each ip, append /32.
                            # cidr unset ip address will return with /32 in next run.
                            updated_ips.append(ip + '/32')
                    if updated_ips:
                        condition['source_ips'] = updated_ips

    def get_s3_bucket(self):
        api = 'protocols/s3/buckets'
        fields = 'name,svm.name,size,comment,volume.uuid,policy,policy.statements,qos_policy'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            fields += ',audit_event_selector'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 11, 1):
            fields += ',versioning_state'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 12, 1):
            fields += ',type,nas_path'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 1):
            fields += ',snapshot_policy'
        params = {'name': self.parameters['name'],
                  'svm.name': self.parameters['vserver'],
                  'fields': fields}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching S3 bucket %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return self.form_current(record) if record else None

    def form_current(self, record):
        self.set_uuid(record)
        body = {
            'comment': self.na_helper.safe_get(record, ['comment']),
            'size': self.na_helper.safe_get(record, ['size']),
            'policy': self.na_helper.safe_get(record, ['policy']),
            'qos_policy': self.na_helper.safe_get(record, ['qos_policy']),
            'audit_event_selector': self.na_helper.safe_get(record, ['audit_event_selector']),
            'type': self.na_helper.safe_get(record, ['type']),
            'nas_path': self.na_helper.safe_get(record, ['nas_path']),
            'versioning_state': self.na_helper.safe_get(record, ['versioning_state']),
            'snapshot_policy': self.na_helper.safe_get(record, ['snapshot_policy', 'name']),
        }
        if body['policy']:
            for policy_statement in body['policy'].get('statements', []):
                # So we treat SID as a String as it can accept Words, or Numbers.
                # ONTAP will return it as a String, unless it is just
                # numbers then it is returned as an INT.
                policy_statement['sid'] = str(policy_statement['sid'])
                # setting keys in each condition to None if not present to avoid idempotency issue.
                if not policy_statement.get('conditions'):
                    policy_statement['conditions'] = []
                else:
                    for condition in policy_statement['conditions']:
                        condition['delimiters'] = condition.get('delimiters')
                        condition['max_keys'] = condition.get('max_keys')
                        condition['operator'] = condition.get('operator')
                        condition['prefixes'] = condition.get('prefixes')
                        condition['source_ips'] = condition.get('source_ips')
                        condition['usernames'] = condition.get('usernames')
        # empty [] is used to reset policy statements.
        # setting policy statements to [] to avoid idempotency issue.
        else:
            body['policy'] = {'statements': []}
        return body

    def set_uuid(self, record):
        self.uuid = record['uuid']
        self.svm_uuid = record['svm']['uuid']
        # volume key is not returned for NAS buckets.
        self.volume_uuid = self.na_helper.safe_get(record, ['volume', 'uuid'])

    def create_s3_bucket(self):
        api = 'protocols/s3/buckets'
        body = {'svm.name': self.parameters['vserver'], 'name': self.parameters['name']}
        body.update(self.form_create_or_modify_body())
        dummy, error = rest_generic.post_async(self.rest_api, api, body, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error creating S3 bucket %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_s3_bucket(self):
        api = 'protocols/s3/buckets'
        uuids = '%s/%s' % (self.svm_uuid, self.uuid)
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuids, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error deleting S3 bucket %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_s3_bucket(self, modify):
        api = 'protocols/s3/buckets'
        uuids = '%s/%s' % (self.svm_uuid, self.uuid)
        body = self.form_create_or_modify_body(modify)
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuids, body, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error modifying S3 bucket %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def form_create_or_modify_body(self, params=None):
        if params is None:
            params = self.parameters
        body = {}
        options = ['aggregates', 'constituents_per_aggregate', 'size', 'comment', 'type', 'nas_path',
                   'policy', 'versioning_state', 'snapshot_policy']
        for option in options:
            if option in params:
                body[option] = params[option]
        if 'qos_policy' in params:
            body['qos_policy'] = self.na_helper.filter_out_none_entries(params['qos_policy'])
        if 'audit_event_selector' in params:
            body['audit_event_selector'] = self.na_helper.filter_out_none_entries(params['audit_event_selector'])
        return body

    def check_volume_aggr(self):
        api = 'storage/volumes/%s' % self.volume_uuid
        params = {'fields': 'aggregates.name'}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg=error)
        aggr_names = [aggr['name'] for aggr in record['aggregates']]
        if self.parameters.get('aggregates'):
            if sorted(aggr_names) != sorted(self.parameters['aggregates']):
                return True
        return False

    def validate_modify_required(self, modify, current):
        # if desired statement length different than current, allow modify.
        if len(modify['policy']['statements']) != len(current['policy']['statements']):
            return True
        match_found = []
        for statement in modify['policy']['statements']:
            for index, current_statement in enumerate(current['policy']['statements']):
                # continue to next if the current statement already has a match.
                if index in match_found:
                    continue
                statement_modified = self.na_helper.get_modified_attributes(current_statement, statement)
                # no modify required, match found for the statment.
                # break the loop and check next desired policy statement has match.
                if not statement_modified:
                    match_found.append(index)
                    break
                # match not found, switch to next current statement and continue to find desired statement is present.
                if len(statement_modified) > 1:
                    continue
                # 'conditions' key in policy.statements is list type, each element is dict.
                # if the len of the desired conditions different than current, allow for modify.
                # check for modify if 'conditions' is the only key present in statement_modified.
                # check for difference in each modify[policy.statements[index][conditions] with current[policy.statements[index][conditions].
                if statement_modified.get('conditions'):
                    if not current_statement['conditions']:
                        continue
                    if len(statement_modified.get('conditions')) != len(current_statement['conditions']):
                        continue

                    # each condition should be checked for modify based on the operator key.
                    def require_modify(desired, current):
                        for condition in desired:
                            # operator is a required field for condition, if not present, REST will throw error.
                            if condition.get('operator'):
                                for current_condition in current:
                                    if condition['operator'] == current_condition['operator']:
                                        condition_modified = self.na_helper.get_modified_attributes(current_condition, condition)
                                        if condition_modified:
                                            return True
                            else:
                                return True
                    if not require_modify(statement_modified['conditions'], current_statement['conditions']):
                        match_found.append(index)
                        break
        # allow modify
        #   - if not match found
        #   - if only partial policy statements has match found.
        return not match_found or len(match_found) != len(modify['policy']['statements'])

    def apply(self):
        current = self.get_s3_bucket()
        cd_action, modify = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if modify.get('type'):
                self.module.fail_json(msg='Error: cannot modify bucket type.')
            if modify.get('versioning_state') == 'disabled' and\
                    current.get('versioning_state') in ('enabled', 'suspended'):
                self.module.fail_json(msg='Error: cannot disable bucket versioning once it has been enabled.')
            if len(modify) == 1 and 'policy' in modify and current.get('policy'):
                if modify['policy'].get('statements'):
                    self.na_helper.changed = self.validate_modify_required(modify, current)
                    if not self.na_helper.changed:
                        modify = False
            # volume uuid returned only for s3 buckets.
            if current and self.volume_uuid and self.check_volume_aggr():
                self.module.fail_json(msg='Aggregates cannot be modified for S3 bucket %s' % self.parameters['name'])
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_s3_bucket()
            if cd_action == 'delete':
                self.delete_s3_bucket()
            if modify:
                self.modify_s3_bucket(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Apply volume operations from playbook'''
    obj = NetAppOntapS3Buckets()
    obj.apply()


if __name__ == '__main__':
    main()
