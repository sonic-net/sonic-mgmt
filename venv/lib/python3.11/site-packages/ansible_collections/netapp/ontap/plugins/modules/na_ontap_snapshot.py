#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_snapshot
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_snapshot
short_description: NetApp ONTAP manage Snapshots
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Modify/Delete ONTAP snapshots
options:
  state:
    description:
      - If you want to create/modify a snapshot, or delete it.
    choices: ['present', 'absent']
    type: str
    default: present
  snapshot:
    description:
      - Name of the snapshot to be managed.
      - The maximum string length is 256 characters.
    required: true
    type: str
  from_name:
    description:
      - Name of the existing snapshot to be renamed to.
    version_added: 2.8.0
    type: str
  volume:
    description:
      - Name of the volume on which the snapshot is to be created.
    required: true
    type: str
  async_bool:
    description:
      - If true, the snapshot is to be created asynchronously.
    type: bool
  comment:
    description:
      - A human readable comment attached with the snapshot.
      - The size of the comment can be at most 255 characters.
    type: str
  snapmirror_label:
    description:
      - A human readable SnapMirror Label attached with the snapshot.
      - Size of the label can be at most 31 characters.
      - Supported with REST on Ontap 9.7 or higher.
    type: str
  ignore_owners:
    description:
      - if this field is true, snapshot will be deleted even if some other processes are accessing it.
    type: bool
  snapshot_instance_uuid:
    description:
      - The 128 bit unique snapshot identifier expressed in the form of UUID.
    type: str
  vserver:
    description:
      - The Vserver name
    required: true
    type: str
  expiry_time:
    description:
      - Snapshot expire time, only available with REST.
      - format should be in the timezone configured with cluster.
    type: str
    version_added: 21.8.0
  snaplock_expiry_time:
    description:
      - SnapLock expiry time for the snapshot, if the snapshot is taken on a SnapLock volume.
      - Only supported with REST, requires ONTAP 9.15.1 or later.
    type: str
    version_added: 23.2.0
'''
EXAMPLES = """
- name: Create SnapShot
  netapp.ontap.na_ontap_snapshot:
    state: present
    snapshot: "{{ snapshot_name }}"
    volume: "{{ vol_name }}"
    comment: "sample comment"
    expiry_time: "2022-02-04T14:00:00-05:00"
    vserver: "{{ vserver name }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete SnapShot
  netapp.ontap.na_ontap_snapshot:
    state: absent
    snapshot: "{{ snapshot_name }}"
    volume: "{{ vol_name }}"
    vserver: "{{ vserver_name }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify SnapShot
  netapp.ontap.na_ontap_snapshot:
    state: present
    snapshot: "{{ snapshot_name }}"
    comment: "New comments are great"
    volume: "{{ vol_name }}"
    vserver: "{{ vserver_name }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import traceback
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils import rest_volume


class NetAppOntapSnapshot:
    """
    Creates, modifies, and deletes a Snapshot
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            from_name=dict(required=False, type='str'),
            snapshot=dict(required=True, type="str"),
            volume=dict(required=True, type="str"),
            async_bool=dict(required=False, type="bool"),
            comment=dict(required=False, type="str"),
            snapmirror_label=dict(required=False, type="str"),
            ignore_owners=dict(required=False, type="bool"),
            snapshot_instance_uuid=dict(required=False, type="str"),
            vserver=dict(required=True, type="str"),
            expiry_time=dict(required=False, type="str"),
            snaplock_expiry_time=dict(required=False, type="str"),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        unsupported_rest_properties = ['async_bool', 'ignore_owners', 'snapshot_instance_uuid']
        partially_supported_rest_properties = [['snapmirror_label', (9, 7)],
                                               ['snaplock_expiry_time', (9, 15, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)

        if not self.use_rest:
            if self.parameters.get('expiry_time'):
                self.module.fail_json(msg="expiry_time is currently only supported with REST on Ontap 9.6 or higher")
            if self.parameters.get('snaplock_expiry_time'):
                self.module.fail_json(msg="snaplock_expiry_time is only supported with REST on Ontap 9.15.1 or higher")
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_snapshot(self, snapshot_name=None, volume_id=None):
        """
        Checks to see if a snapshot exists or not
        :return: Return True if a snapshot exists, False if it doesn't
        """
        if self.use_rest:
            api = ('storage/volumes/%s/snapshots' % volume_id)
            params = {
                'svm.name': self.parameters['vserver'],
                'fields': 'uuid,comment,expiry_time,volume,name',
            }
            if self.parameters.get('snapmirror_label'):
                params['fields'] += ',snapmirror_label'
            if self.parameters.get('snaplock_expiry_time'):
                params['fields'] += ',snaplock.expiry_time'
            params['name'] = snapshot_name or self.parameters['snapshot']
            snapshot, error = rest_generic.get_one_record(self.rest_api, api, params)
            if error:
                self.module.fail_json(msg='Error fetching snapshot %s: %s' %
                                      (params['name'], to_native(error)),
                                      exception=traceback.format_exc())
            if snapshot:
                return {
                    'uuid': snapshot['uuid'],
                    'snapshot': snapshot['name'],
                    'snapmirror_label': snapshot.get('snapmirror_label'),
                    'expiry_time': snapshot.get('expiry_time'),
                    'comment': snapshot.get('comment'),
                    'snaplock_expiry_time': self.na_helper.safe_get(snapshot, ['snaplock', 'expiry_time'])
                }
            return None

        else:
            if snapshot_name is None:
                snapshot_name = self.parameters['snapshot']
            snapshot_obj = netapp_utils.zapi.NaElement("snapshot-get-iter")
            desired_attr = netapp_utils.zapi.NaElement("desired-attributes")
            snapshot_info = netapp_utils.zapi.NaElement('snapshot-info')
            comment = netapp_utils.zapi.NaElement('comment')
            snapmirror_label = netapp_utils.zapi.NaElement('snapmirror-label')
            # add more desired attributes that are allowed to be modified
            snapshot_info.add_child_elem(comment)
            snapshot_info.add_child_elem(snapmirror_label)
            desired_attr.add_child_elem(snapshot_info)
            snapshot_obj.add_child_elem(desired_attr)
            # compose query
            query = netapp_utils.zapi.NaElement("query")
            snapshot_info_obj = netapp_utils.zapi.NaElement("snapshot-info")
            snapshot_info_obj.add_new_child("name", snapshot_name)
            snapshot_info_obj.add_new_child("volume", self.parameters['volume'])
            snapshot_info_obj.add_new_child("vserver", self.parameters['vserver'])
            query.add_child_elem(snapshot_info_obj)
            snapshot_obj.add_child_elem(query)
            try:
                result = self.server.invoke_successfully(snapshot_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error fetching snapshot %s: %s' %
                                      (snapshot_name, to_native(error)),
                                      exception=traceback.format_exc())
            return_value = None
            if result.get_child_by_name('num-records') and \
                    int(result.get_child_content('num-records')) == 1:
                attributes_list = result.get_child_by_name('attributes-list')
                snap_info = attributes_list.get_child_by_name('snapshot-info')
                return_value = {
                    'comment': snap_info.get_child_content('comment'),
                    'snapmirror_label': None
                }
                if snap_info.get_child_by_name('snapmirror-label'):
                    return_value['snapmirror_label'] = snap_info.get_child_content('snapmirror-label')
            return return_value

    def create_snapshot(self, volume_id=None):
        """
        Creates a new snapshot
        """

        if self.use_rest:
            api = ('storage/volumes/%s/snapshots' % volume_id)
            body = {
                'name': self.parameters['snapshot'],
                'svm': {
                    'name': self.parameters['vserver']
                }
            }
            if self.parameters.get('comment'):
                body['comment'] = self.parameters['comment']
            if self.parameters.get('snapmirror_label'):
                body['snapmirror_label'] = self.parameters['snapmirror_label']
            if self.parameters.get('expiry_time'):
                body['expiry_time'] = self.parameters['expiry_time']
            if self.parameters.get('snaplock_expiry_time'):
                body['snaplock.expiry_time'] = self.parameters['snaplock_expiry_time']
            response, error = rest_generic.post_async(self.rest_api, api, body)
            if error:
                self.module.fail_json(msg="Error when creating snapshot: %s" % error)

        else:
            snapshot_obj = netapp_utils.zapi.NaElement("snapshot-create")

            # set up required variables to create a snapshot
            snapshot_obj.add_new_child("snapshot", self.parameters['snapshot'])
            snapshot_obj.add_new_child("volume", self.parameters['volume'])
            # Set up optional variables to create a snapshot
            if self.parameters.get('async_bool'):
                snapshot_obj.add_new_child("async", str(self.parameters['async_bool']))
            if self.parameters.get('comment'):
                snapshot_obj.add_new_child("comment", self.parameters['comment'])
            if self.parameters.get('snapmirror_label'):
                snapshot_obj.add_new_child(
                    "snapmirror-label", self.parameters['snapmirror_label'])
            try:
                self.server.invoke_successfully(snapshot_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error creating snapshot %s: %s' %
                                      (self.parameters['snapshot'], to_native(error)),
                                      exception=traceback.format_exc())

    def delete_snapshot(self, volume_id=None, uuid=None):
        """
        Deletes an existing snapshot
        """
        if self.use_rest:
            api = ('storage/volumes/%s/snapshots/%s' % (volume_id, uuid))
            response, error = rest_generic.delete_async(self.rest_api, api, None)
            if error:
                self.module.fail_json(msg="Error when deleting snapshot: %s" % error)

        else:
            snapshot_obj = netapp_utils.zapi.NaElement("snapshot-delete")

            # Set up required variables to delete a snapshot
            snapshot_obj.add_new_child("snapshot", self.parameters['snapshot'])
            snapshot_obj.add_new_child("volume", self.parameters['volume'])
            # set up optional variables to delete a snapshot
            if self.parameters.get('ignore_owners'):
                snapshot_obj.add_new_child("ignore-owners", str(self.parameters['ignore_owners']))
            if self.parameters.get('snapshot_instance_uuid'):
                snapshot_obj.add_new_child("snapshot-instance-uuid", self.parameters['snapshot_instance_uuid'])
            try:
                self.server.invoke_successfully(snapshot_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error deleting snapshot %s: %s' %
                                      (self.parameters['snapshot'], to_native(error)),
                                      exception=traceback.format_exc())

    def modify_snapshot(self, volume_id=None, uuid=None, rename=False):
        """
        Modify an existing snapshot
        :return:
        """
        if self.use_rest:
            api = 'storage/volumes/%s/snapshots/%s' % (volume_id, uuid)
            body = {'name': self.parameters['snapshot']} if rename else {}
            if self.parameters.get('comment'):
                body['comment'] = self.parameters['comment']
            if self.parameters.get('snapmirror_label'):
                body['snapmirror_label'] = self.parameters['snapmirror_label']
            if self.parameters.get('expiry_time'):
                body['expiry_time'] = self.parameters['expiry_time']
            if self.parameters.get('snaplock_expiry_time'):
                body['snaplock.expiry_time'] = self.parameters['snaplock_expiry_time']
            response, error = rest_generic.patch_async(self.rest_api, api, None, body)
            if error:
                self.module.fail_json(msg="Error when modifying snapshot: %s" % error)

        else:
            snapshot_obj = netapp_utils.zapi.NaElement("snapshot-modify-iter")
            # Create query object, this is the existing object
            query = netapp_utils.zapi.NaElement("query")
            snapshot_info_obj = netapp_utils.zapi.NaElement("snapshot-info")
            snapshot_info_obj.add_new_child("name", self.parameters['snapshot'])
            snapshot_info_obj.add_new_child("vserver", self.parameters['vserver'])
            query.add_child_elem(snapshot_info_obj)
            snapshot_obj.add_child_elem(query)

            # this is what we want to modify in the snapshot object
            attributes = netapp_utils.zapi.NaElement("attributes")
            snapshot_info_obj = netapp_utils.zapi.NaElement("snapshot-info")
            snapshot_info_obj.add_new_child("name", self.parameters['snapshot'])
            if self.parameters.get('comment'):
                snapshot_info_obj.add_new_child("comment", self.parameters['comment'])
            if self.parameters.get('snapmirror_label'):
                snapshot_info_obj.add_new_child("snapmirror-label", self.parameters['snapmirror_label'])
            attributes.add_child_elem(snapshot_info_obj)
            snapshot_obj.add_child_elem(attributes)
            try:
                self.server.invoke_successfully(snapshot_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying snapshot %s: %s' %
                                      (self.parameters['snapshot'], to_native(error)),
                                      exception=traceback.format_exc())

    def rename_snapshot(self):
        """
        Rename the sanpshot
        """
        snapshot_obj = netapp_utils.zapi.NaElement("snapshot-rename")

        # set up required variables to rename a snapshot
        snapshot_obj.add_new_child("current-name", self.parameters['from_name'])
        snapshot_obj.add_new_child("new-name", self.parameters['snapshot'])
        snapshot_obj.add_new_child("volume", self.parameters['volume'])
        try:
            self.server.invoke_successfully(snapshot_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming snapshot %s to %s: %s' %
                                  (self.parameters['from_name'], self.parameters['snapshot'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_volume_uuid(self):
        """
        Get a volume's UUID
        :return: uuid of the volume
        """
        response, error = rest_volume.get_volume(self.rest_api, self.parameters['vserver'], self.parameters['volume'])
        if error is not None:
            self.module.fail_json(msg="Error getting volume info: %s" % error)
        return response['uuid'] if response else None

    def apply(self):
        """
        Check to see which play we should run
        """
        volume_id = None
        uuid = None
        current = None
        if not self.use_rest:
            current = self.get_snapshot()
        else:
            volume_id = self.get_volume_uuid()
            if volume_id is None:
                self.module.fail_json(msg="Error: volume %s not found for vserver %s." % (self.parameters['volume'], self.parameters['vserver']))
            current = self.get_snapshot(volume_id=volume_id)

        rename = False
        modify = {}
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('from_name'):
            current = self.get_snapshot(self.parameters['from_name'], volume_id=volume_id)
            if current is None:
                self.module.fail_json(msg='Error renaming snapshot: %s - no snapshot with from_name: %s.'
                                      % (self.parameters['snapshot'], self.parameters['from_name']))
            rename = True
            cd_action = None
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            uuid = current['uuid'] if current and self.use_rest else None
            if rename and not self.use_rest:
                # with REST, rename forces a change in modify for 'name'
                self.rename_snapshot()
            if cd_action == 'create':
                self.create_snapshot(volume_id=volume_id)
            elif cd_action == 'delete':
                self.delete_snapshot(volume_id=volume_id, uuid=uuid)
            elif modify:
                self.modify_snapshot(volume_id=volume_id, uuid=uuid, rename=rename)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates, modifies, and deletes a Snapshot
    """
    obj = NetAppOntapSnapshot()
    obj.apply()


if __name__ == '__main__':
    main()
