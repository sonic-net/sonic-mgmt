#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_storage_unit_snapshot
short_description: NetApp ONTAP ASA r2 storage unit snapshot
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 23.0.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/modify/delete storage unit snapshot.
options:
  state:
    description:
      - Specifies whether the specified storage unit should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present

  name:
    description:
      - Specifies the name of the snapshot.
    type: str
    required: true

  from_name:
    description:
      - Specifies the name of the snapshot to be renamed.
    type: str

  expiry_time:
    description:
      - Specifies the expiry time for the snapshot. Example, 2025-04-09T07:30:00-04:00.
      - Snapshots with an expiry time set are not allowed to be deleted until the retention time is reached.
    type: str

  snapmirror_label:
    description:
      - Specifies label for SnapMirror operations.
    type: str

  storage_unit:
    description:
      - Specifies the storage unit in which the snapshot is located.
    type: str
    required: true

  vserver:
    description:
      - Specifies the SVM in which the storage unit is located.
    type: str
    required: true

  comment:
    description:
      - A comment associated with the snapshot.
    type: str

notes:
  - Only supported with REST and requires ONTAP 9.16.1 or later.
  - Only suppored with ASA r2 systems.
"""

EXAMPLES = """
- name: Create a snapshot for LUN storage unit
  netapp.ontap.na_ontap_storage_unit_snapshot:
    state: present
    name: lun1_snap1
    vserver: ansibleSVM
    storage_unit: lun1
    expiry_time: 2025-04-09T07:30:00-04:00
    snapmirror_label: my_label
    comment: "snapshot for lun1"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Update a snapshot
  netapp.ontap.na_ontap_storage_unit_snapshot:
    name: lun1_snap1
    vserver: ansibleSVM
    storage_unit: lun1
    expiry_time: 2025-04-09T08:30:00-04:00
    snapmirror_label: another_label
    comment: "updated expiry date, label"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Rename a storage unit snapshot
  netapp.ontap.na_ontap_storage_unit_snapshot:
    name: lun1_snapshot1
    from_name: lun1_snap1
    vserver: ansibleSVM
    storage_unit: lun1
    expiry_time: 2025-04-09T08:30:00-04:00
    snapmirror_label: another_label
    comment: "snapshot for lun1"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
    use_rest: always

- name: Delete a snapshot
  netapp.ontap.na_ontap_mav_approval_group:
    state: absent
    name: lun1_snapshot1
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


class NetAppOntapStorageUnitSnapshot:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            expiry_time=dict(required=False, type='str'),
            snapmirror_label=dict(required=False, type='str'),
            storage_unit=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            comment=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.storage_unit_uuid, self.snapshot_uuid = None, None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_storage_unit_snapshot:', 9, 16, 1)
        asa_r2_system = self.is_asa_r2_system()
        if not asa_r2_system:
            self.module.fail_json(msg="na_ontap_storage_unit_snapshot module is only supported with ASA r2 systems.")

    def is_asa_r2_system(self):
        ''' checks if the given host is a ASA r2 system or not '''
        return rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)

    def get_storage_unit(self):
        """ Retrieves storage unit by name """
        api = 'storage/storage-units'
        params = {
            'name': self.parameters['storage_unit'],
            'svm.name': self.parameters['vserver'],
            'fields': 'name,uuid,type'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error while fetching storage unit named %s: %s" % (self.parameters['storage_unit'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.storage_unit_uuid = record.get('uuid')
            return {
                'name': record.get('name'),
                'type': record.get('type')
            }
        return None

    def get_storage_unit_snapshot(self, name=None):
        """ Retrieves storage unit snapshot by name """
        api = 'storage/storage-units/%s/snapshots' % self.storage_unit_uuid
        fields = 'name,uuid,comment,expiry_time,snapmirror_label,'
        params = {
            'name': name if name else self.parameters['name'],
            'svm.name': self.parameters['vserver'],
            'fields': fields
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error while fetching storage unit snapshot named %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            self.snapshot_uuid = record.get('uuid')
            return {
                'name': record.get('name'),
                'uuid': record.get('uuid'),
                'expiry_time': record.get('expiry_time'),
                'snapmirror_label': record.get('snapmirror_label'),
                'comment': record.get('comment')
            }
        return None

    def create_storage_unit_snapshot(self):
        """ Create a storage unit snapshot """
        api = 'storage/storage-units/%s/snapshots' % self.storage_unit_uuid
        body = {
            'name': self.parameters['name'],
            'svm.name': self.parameters['vserver'],
            'storage_unit.name': self.parameters['storage_unit'],
        }
        if 'comment' in self.parameters:
            body['comment'] = self.parameters['comment']
        if 'expiry_time' in self.parameters:
            body['expiry_time'] = self.parameters['expiry_time']
        if 'snapmirror_label' in self.parameters:
            body['snapmirror_label'] = self.parameters['snapmirror_label']

        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error while creating storage unit snapshot %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_storage_unit_snapshot(self, modify, rename=False):
        """ Modify storage unit snapshot """
        api = 'storage/storage-units/%s/snapshots/%s' % (self.storage_unit_uuid, self.snapshot_uuid)
        body = {'name': self.parameters['name']} if rename else {}
        if 'comment' in modify:
            body['comment'] = modify['comment']
        if 'snapmirror_label' in modify:
            body['snapmirror_label'] = modify['snapmirror_label']
        if 'expiry_time' in modify:
            body['expiry_time'] = modify['expiry_time']

        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid_or_name=None, body=body)
        if error:
            self.module.fail_json(msg="Error while modifying storage unit snapshot %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_storage_unit_snapshot(self):
        """ Delete a storage unit snapshot """
        api = 'storage/storage-units/%s/snapshots/%s' % (self.storage_unit_uuid, self.snapshot_uuid)
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid=None)
        if error:
            self.module.fail_json(msg="Error while deleting storage unit snapshot %s: %s." % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        storage_unit = self.get_storage_unit()
        current = self.get_storage_unit_snapshot()
        modify = None
        rename = False
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and 'from_name' in self.parameters:
            # create by renaming existing snapshot, if it exists
            old_snapshot = self.get_storage_unit_snapshot(self.parameters['from_name'])
            snapshot_rename = self.na_helper.is_rename_action(old_snapshot, current)
            if snapshot_rename is None:
                self.module.fail_json(msg="Error renaming storage unit snapshot: %s does not exist" % self.parameters['from_name'])
            if snapshot_rename:
                current = old_snapshot
                self.snapshot_uuid = current.get('uuid')
                rename = True
                cd_action = None
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_storage_unit_snapshot()
            elif cd_action == 'delete':
                self.delete_storage_unit_snapshot()
            elif modify:
                self.modify_storage_unit_snapshot(modify, rename=rename)

        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    snapshot = NetAppOntapStorageUnitSnapshot()
    snapshot.apply()


if __name__ == '__main__':
    main()
