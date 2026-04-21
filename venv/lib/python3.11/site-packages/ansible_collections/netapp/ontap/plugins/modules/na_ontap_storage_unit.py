#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_storage_unit
short_description: NetApp ONTAP ASA r2 storage unit
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 23.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Clone a storage unit.
  - Split a storage unit clone.
  - Move a storage unit.
  - Restore a storage unit to a prior snapshot.
options:
  state:
    description:
      - Manage storage unit operations, only present is supported.
    choices: ['present']
    type: str
    default: present

  name:
    description:
      - Specifies the name of the storage unit (LUN or NVMe namespace).
    type: str
    required: true

  clone:
    type: dict
    description:
      - Identifiers of the parent storage unit or storage unit snapshot from which to clone a new storage unit.
      - The storage unit clone and its source must reside on the same SVM.
    suboptions:
      snapshot:
        description:
          - The name of the snapshot the source storage unit resides in.
        type: str
      storage_unit:
        description:
          - The name of the source storage unit.
        type: str

  split_initiated:
    description:
      - Setting this field initiates a split of a FlexClone storage unit from a FlexVol storage unit.
      - This operation stops the replication of data but doesn't remove the snapshots from the replicas.
    type: bool

  vserver:
    description:
      - Specifies the SVM in which the storage unit is located.
    type: str
    required: true

  restore_to_snapshot:
    description:
      - Specifies the name of the snapshot to restore the storage unit to the point in time the snapshot was taken.
    type: str

  target_location:
    description:
      - Specifies the name of the destination storage availability zone for moving the storage unit.
    type: str

  restore_to:
    description:
      - Specifies the name of the snapshot to restore the storage unit to the point in time the snapshot was taken.
    type: str

  time_out:
    description:
      - With C(wait_for_completion) set, specifies time to wait for any storage unit clone, split, restore or move operations in seconds.
    type: int
    default: 180

  wait_for_completion:
    description:
      - Set this parameter to 'true' for synchronous execution.
      - For asynchronous, execution exits as soon as the request is sent, and the operation continues in the background.
    type: bool
    default: true

notes:
  - Only supported with REST and requires ONTAP 9.16.1 or later.
  - Only suppored with ASA r2 systems.
  - The storage unit clone and its source must reside on the same SVM.
  - Module is not idempotent when C(restore_to) is set.
  - Storage unit REST API doesn't support DELETE operation. Kindly refer to module \
    C(na_ontap_lun) or C(na_ontap_nvme_namespace) for deleting corresponding storage unit.
"""

EXAMPLES = """
- name: Create a new storage unit(LUN) clone
  netapp.ontap.na_ontap_storage_unit:
    state: present
    name: lun1_clone1
    vserver: svm1
    clone:
      storage_unit: lun1
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Split a storage unit(LUN) clone
  netapp.ontap.na_ontap_storage_unit:
    state: present
    name: lun1_clone1
    vserver: svm1
    split_initiated: true
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Create a new storage unit(LUN) clone using snapshot
  netapp.ontap.na_ontap_storage_unit:
    state: present
    name: lun1_clone1
    vserver: svm1
    clone:
      storage_unit: lun1
      snapshot: "hourly.2025-04-23_0205"
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Clone a storage unit(LUN), split new clone simultaneously
  netapp.ontap.na_ontap_storage_unit:
    state: present
    name: lun1_clone1
    vserver: svm1
    clone:
      storage_unit: lun1
    split_initiated: true
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Restore a storage unit(LUN) to a prior snapshot
  netapp.ontap.na_ontap_storage_unit:
    state: present
    name: lun1
    vserver: svm1
    restore_to: "hourly.2025-04-21_0905"
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Move a storage unit(LUN)
  netapp.ontap.na_ontap_storage_unit:
    state: present
    name: lun1
    vserver: svm1
    target_location: storage_availability_zone_0
    wait_for_completion: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_ontap_personality


class NetAppOntapStorageUnit:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            name=dict(required=True, type='str'),
            clone=dict(type='dict', options=dict(
                snapshot=dict(type='str'),
                storage_unit=dict(type='str')
            )),
            split_initiated=dict(required=False, type='bool'),
            vserver=dict(required=True, type='str'),
            restore_to_snapshot=dict(required=False, type='str'),
            target_location=dict(required=False, type='str'),
            restore_to=dict(required=False, type='str'),
            time_out=dict(required=False, type='int', default=180),
            wait_for_completion=dict(required=False, type='bool', default=True),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ['clone', 'restore_to', 'target_location'],
                ['split_initiated', 'restore_to', 'target_location']
            ],
            supports_check_mode=True
        )

        self.uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_storage_unit:', 9, 16, 1)
        asa_r2_system = self.is_asa_r2_system()
        if not asa_r2_system:
            self.module.fail_json(msg="na_ontap_storage_unit module is only supported with ASA r2 systems.")

    def is_asa_r2_system(self):
        ''' checks if the given host is a ASA r2 system or not '''
        return rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)

    def get_storage_unit(self):
        """ Retrieves storage unit by name """
        api = 'storage/storage-units'
        fields = 'name,uuid,type,'
        if 'clone' in self.parameters or 'split_initiated' in self.parameters:
            fields += 'clone.*,'
        if 'target_location' in self.parameters:
            fields += 'location.storage_availability_zone.name,'
        params = {
            'name': self.parameters['name'],
            'svm.name': self.parameters['vserver'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error while fetching storage unit named %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.uuid = record.get('uuid')
            return {
                'name': record.get('name'),
                'type': record.get('type'),
                'is_flexclone': self.na_helper.safe_get(record, ['clone', 'is_flexclone']),
                'target_location': self.na_helper.safe_get(record, ['location', 'storage_availability_zone', 'name']),
                'split_initiated': self.na_helper.safe_get(record, ['clone', 'split_initiated'])
            }
        return None

    def clone_storage_unit(self):
        """ Clone a storage unit """
        api = 'storage/storage-units'
        query = {'return_timeout': 0} if not self.parameters['wait_for_completion'] else None
        timeout = 0 if not self.parameters['wait_for_completion'] else self.parameters['time_out']
        body = {
            'name': self.parameters['name'],
            'svm.name': self.parameters['vserver'],
            'clone': {'source': {}}
        }
        source_storage_unit = self.na_helper.safe_get(self.parameters, ['clone', 'storage_unit'])
        source_snapshot = self.na_helper.safe_get(self.parameters, ['clone', 'snapshot'])
        if source_storage_unit is not None:
            body['clone']['source'].update({'storage_unit': {'name': source_storage_unit}})
            if source_snapshot is not None:
                body['clone']['source'].update({'snapshot': {'name': source_snapshot}})
        if self.parameters.get('split_initiated') is True:
            body['clone'].update({'split_initiated': True})

        dummy, error = rest_generic.post_async(self.rest_api, api, body, query, job_timeout=timeout)
        if error:
            if 'job reported error:' in error and 'Timeout error: Process still running' in error:
                if not self.parameters['wait_for_completion']:
                    warning = "Process is still running in the background, exiting with no further waiting as 'wait_for_completion' is set to false."
                else:
                    warning = ('Storage unit cloning is still in progress after %d seconds.' % self.parameters['time_out'])
                self.module.warn(warning)
                return
            self.module.fail_json(msg="Error while cloning storage unit %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def clone_split_storage_unit(self):
        """ Clone split operation """
        api = 'storage/storage-units'
        query = {'return_timeout': 0} if not self.parameters['wait_for_completion'] else None
        timeout = 0 if not self.parameters['wait_for_completion'] else self.parameters['time_out']
        body = {'clone': {'split_initiated': True}}

        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body, query, job_timeout=timeout)
        if error:
            if 'job reported error:' in error and 'Timeout error: Process still running' in error:
                if not self.parameters['wait_for_completion']:
                    warning = "Process is still running in the background, exiting with no further waiting as 'wait_for_completion' is set to false."
                else:
                    warning = ('Storage unit clone split is still in progress after %d seconds.' % self.parameters['time_out'])
                self.module.warn(warning)
                return
            self.module.fail_json(msg="Error while splitting storage unit clone %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def move_storage_unit(self):
        """ Move a storage unit """
        api = 'storage/storage-units'
        query = {'return_timeout': 0} if not self.parameters['wait_for_completion'] else {}
        timeout = 0 if not self.parameters['wait_for_completion'] else self.parameters['time_out']
        body = {
            'location.storage_availability_zone.name': self.parameters['target_location']
        }

        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body, query, job_timeout=timeout)
        if error:
            if 'job reported error:' in error and 'Timeout error: Process still running' in error:
                if not self.parameters['wait_for_completion']:
                    warning = "Process is still running in the background, exiting with no further waiting as 'wait_for_completion' is set to false."
                else:
                    warning = ('Storage unit is still getting moved after %d seconds.' % self.parameters['time_out'])
                self.module.warn(warning)
                return
            self.module.fail_json(msg="Error while moving storage unit %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def restore_storage_unit(self):
        """ Restore a storage unit to given snapshot """
        api = 'storage/storage-units'
        query = {'return_timeout': 0} if not self.parameters['wait_for_completion'] else {}
        timeout = 0 if not self.parameters['wait_for_completion'] else self.parameters['time_out']
        query.update({'restore_to.snapshot.name': self.parameters['restore_to']})

        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body=None, query=query, job_timeout=timeout)
        if error:
            if "entry doesn't exist" in error:
                self.module.fail_json(msg="The given snapshot does not seem to exist.")
            if 'job reported error:' in error and 'Timeout error: Process still running' in error:
                if not self.parameters['wait_for_completion']:
                    warning = "Process is still running in the background, exiting with no further waiting as 'wait_for_completion' is set to false."
                else:
                    warning = ('Storage unit is still restoring after %d seconds.' % self.parameters['time_out'])
                self.module.warn(warning)
                return
            self.module.fail_json(msg="Error while restoring storage unit %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_storage_unit()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if not current['is_flexclone'] and 'split_initiated' in modify:
                self.module.warn('Clone split operation can be performed only for a FlexClone storage unit.')
                modify.pop('split_initiated')
                self.na_helper.changed = False
            if 'restore_to' in self.parameters:
                self.na_helper.changed = True
                modify['restore_to'] = self.parameters['restore_to']
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.clone_storage_unit()
            elif modify:
                if 'split_initiated' in modify:
                    self.clone_split_storage_unit()
                elif 'target_location' in modify:
                    self.move_storage_unit()
                elif 'restore_to' in modify:
                    self.restore_storage_unit()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    storage_unit = NetAppOntapStorageUnit()
    storage_unit.apply()


if __name__ == '__main__':
    main()
