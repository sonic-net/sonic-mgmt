#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
short_description: NetApp ONTAP manage consistency group snapshot
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create or delete consistency group snapshot for ONTAP volumes.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_cg_snapshot
options:
  state:
    description:
      - Specifies whether to create  or delete the snapshot.
      - Choice 'absent' is valid only with REST.
    default: present
    choices: ['present', 'absent']
    type: str
  vserver:
    required: true
    type: str
    description:
      - Name of the vserver.
  volumes:
    required: false
    type: list
    elements: str
    description:
      - A list of volumes in this filer that is part of this CG operation.
      - Required with ZAPI.
  consistency_group:
    required: false
    type: str
    description:
      - Name of the consistency group for which snapshot needs to be created or deleted.
      - Valid only with REST.
    version_added: 22.8.0
  snapshot:
    required: true
    type: str
    description:
      - The provided name of the snapshot that is created in each volume.
  timeout:
    description:
      - Timeout selector.
      - Not supported with REST.
    choices: ['urgent', 'medium', 'relaxed']
    type: str
    default: medium
  snapmirror_label:
    description:
      - A human readable SnapMirror label to be attached with the consistency group snapshot copies.
    type: str
  comment:
    description:
      - Comment for the snapshot copy.
      - Only supported with REST.
    type: str
    version_added: 22.8.0
  consistency_type:
    description:
      - Type of consistency guarantee for the snapshot.
      - Only supported with REST.
    choices: ['crash', 'application']
    type: str
    default: crash
    version_added: 23.2.0
version_added: 2.7.0

notes:
  - REST support requires ONTAP 9.10 or later.
  - Delete operation is supported only with REST.

'''

EXAMPLES = """
- name: Create CG snapshot
  na_ontap_cg_snapshot:
    state: present
    vserver: vserver_name
    snapshot: snapshot name
    volumes: vol_name
    # consistency_type defaults to 'crash' if not specified
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Create CG snapshot using CG name - REST
  na_ontap_cg_snapshot:
    state: present
    vserver: vserver_name
    snapshot: snapshot_name
    consistency_group: cg_name
    snapmirror_label: sm_label
    consistency_type: application
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Create CG snapshot using volumes - REST
  na_ontap_cg_snapshot:
    state: present
    vserver: vserver_name
    snapshot: snapshot_name
    volumes:
      - vol1
      - vol2
    snapmirror_label: sm_label
    consistency_type: crash
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete CG snapshot - REST
  na_ontap_cg_snapshot:
    state: absent
    vserver: vserver_name
    snapshot: snapshot_name
    consistency_group: cg_name
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPCGSnapshot(object):
    """
    Methods to create or delete CG snapshots
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            volumes=dict(required=False, type='list', elements='str'),
            snapshot=dict(required=True, type='str'),
            timeout=dict(required=False, type='str', choices=[
                'urgent', 'medium', 'relaxed'], default='medium'),
            snapmirror_label=dict(required=False, type='str'),
            consistency_group=dict(required=False, type='str'),
            comment=dict(required=False, type='str'),
            consistency_type=dict(required=False, type='str', choices=['crash', 'application'], default='crash'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
            mutually_exclusive=[
                ['consistency_group', 'volumes']]
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if self.use_rest:
            if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
                self.module.fail_json(msg='REST requires ONTAP 9.10.1 or later for /application/consistency-groups APIs.')
            self.cg_uuid = None
        else:
            self.cgid = None
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.zapi_errors()
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def does_snapshot_exist(self, volume):
        """
        This is duplicated from na_ontap_snapshot
        Checks to see if a snapshot exists or not
        :return: Return True if a snapshot exists, false if it dosen't
        """
        # TODO: Remove this method and import snapshot module and
        # call get after re-factoring __init__ across all the modules
        # we aren't importing now, since __init__ does a lot of Ansible setup
        snapshot_obj = netapp_utils.zapi.NaElement("snapshot-get-iter")
        desired_attr = netapp_utils.zapi.NaElement("desired-attributes")
        snapshot_info = netapp_utils.zapi.NaElement('snapshot-info')
        comment = netapp_utils.zapi.NaElement('comment')
        # add more desired attributes that are allowed to be modified
        snapshot_info.add_child_elem(comment)
        desired_attr.add_child_elem(snapshot_info)
        snapshot_obj.add_child_elem(desired_attr)
        # compose query
        query = netapp_utils.zapi.NaElement("query")
        snapshot_info_obj = netapp_utils.zapi.NaElement("snapshot-info")
        snapshot_info_obj.add_new_child("name", self.parameters['snapshot'])
        snapshot_info_obj.add_new_child("volume", volume)
        snapshot_info_obj.add_new_child("vserver", self.parameters['vserver'])
        query.add_child_elem(snapshot_info_obj)
        snapshot_obj.add_child_elem(query)
        result = self.server.invoke_successfully(snapshot_obj, True)
        return_value = None
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:
            attributes_list = result.get_child_by_name('attributes-list')
            snap_info = attributes_list.get_child_by_name('snapshot-info')
            return_value = {'comment': snap_info.get_child_content('comment')}
        return return_value

    def cgcreate(self):
        """
        Calls cg-start and cg-commit (when cg-start succeeds)
        """
        started = self.cg_start()
        if started:
            if self.cgid is not None:
                self.cg_commit()
            else:
                self.module.fail_json(msg="Error fetching CG ID for CG commit %s" % self.parameters['snapshot'],
                                      exception=traceback.format_exc())
        return started

    def cg_start(self):
        """
        For the given list of volumes, creates cg-snapshot
        """
        snapshot_started = False
        cgstart = netapp_utils.zapi.NaElement("cg-start")
        cgstart.add_new_child("snapshot", self.parameters['snapshot'])
        cgstart.add_new_child("timeout", self.parameters['timeout'])
        volume_list = netapp_utils.zapi.NaElement("volumes")
        cgstart.add_child_elem(volume_list)
        for vol in self.parameters['volumes']:
            snapshot_exists = self.does_snapshot_exist(vol)
            if snapshot_exists is None:
                snapshot_started = True
                volume_list.add_new_child("volume-name", vol)
        if snapshot_started:
            if self.parameters.get('snapmirror_label') is not None:
                cgstart.add_new_child("snapmirror-label",
                                      self.parameters['snapmirror_label'])
            try:
                cgresult = self.server.invoke_successfully(
                    cgstart, enable_tunneling=True)
                if cgresult.get_child_by_name('cg-id'):
                    self.cgid = cgresult['cg-id']
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg="Error creating CG snapshot %s: %s" %
                                      (self.parameters['snapshot'], to_native(error)),
                                      exception=traceback.format_exc())
        return snapshot_started

    def cg_commit(self):
        """
        When cg-start is successful, performs a cg-commit with the cg-id
        """
        cgcommit = netapp_utils.zapi.NaElement.create_node_with_children(
            'cg-commit', **{'cg-id': self.cgid})
        try:
            self.server.invoke_successfully(cgcommit,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error committing CG snapshot %s: %s" %
                                  (self.parameters['snapshot'], to_native(error)),
                                  exception=traceback.format_exc())

    def zapi_errors(self):
        unsupported_zapi_properties = ['consistency_group', 'comment', 'consistency_type']
        used_unsupported_zapi_properties = [option for option in unsupported_zapi_properties if option in self.parameters]
        if used_unsupported_zapi_properties:
            self.module.fail_json(msg="Error: %s options supported only with REST." % " ,".join(used_unsupported_zapi_properties))
        if self.parameters.get('volumes') is None:
            self.module.fail_json(msg="Error: 'volumes' option is mandatory while using ZAPI.")
        if self.parameters.get('state') == 'absent':
            self.module.fail_json(msg="Deletion of consistency group snapshot is not supported with ZAPI.")

    def get_cg_rest(self):
        """
        Retrieve consistency group with the given CG name or list of volumes
        """
        api = '/application/consistency-groups'
        query = {
            'svm.name': self.parameters['vserver'],
            'fields': 'svm.uuid,name,uuid,'
        }

        if self.parameters.get('consistency_group') is not None:
            query['name'] = self.parameters['consistency_group']
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                self.module.fail_json(msg='Error searching for consistency group %s: %s' % (self.parameters['consistency_group'], to_native(error)),
                                      exception=traceback.format_exc())
            if record:
                self.cg_uuid = record.get('uuid')

        if self.parameters.get('volumes') is not None:
            query['fields'] += 'volumes.name,'
            records, error = rest_generic.get_0_or_more_records(self.rest_api, api, query)
            if error:
                self.module.fail_json(msg='Error searching for consistency group having volumes %s: %s' % (set(self.parameters['volumes']), to_native(error)),
                                      exception=traceback.format_exc())
            if records:
                for record in records:
                    if record.get('volumes') is not None:
                        cg_volumes = [vol_item['name'] for vol_item in record['volumes']]
                        if sorted(cg_volumes) == sorted(set(self.parameters['volumes'])):
                            self.cg_uuid = record.get('uuid')
                            break
        return None

    def get_cg_snapshot_rest(self):
        """
        Retrieve CG snapshots using fetched CG uuid
        """
        self.get_cg_rest()
        if self.cg_uuid is None:
            if self.parameters.get('consistency_group') is not None:
                self.module.fail_json(msg="Consistency group named '%s' not found" % self.parameters.get('consistency_group'))
            if self.parameters.get('volumes') is not None:
                self.module.fail_json(msg="Consistency group having volumes '%s' not found" % self.parameters.get('volumes'))

        api = '/application/consistency-groups/%s/snapshots' % self.cg_uuid
        query = {'name': self.parameters['snapshot'],
                 'fields': 'name,'
                           'uuid,'
                           'consistency_group,'
                           'snapmirror_label,'
                           'comment,'
                           'consistency_type,'}
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg='Error searching for consistency group snapshot %s: %s' % (self.parameters['snapshot'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            return {
                'snapshot': record.get('name'),
                'snapshot_uuid': record.get('uuid'),
                'consistency_group': self.na_helper.safe_get(record, ['consistency_group', 'name']),
                'snapmirror_label': record.get('snapmirror_label'),
                'comment': record.get('comment'),
                'consistency_type': record.get('consistency_type'),
            }
        return None

    def create_cg_snapshot_rest(self):
        """Create CG snapshot"""
        api = '/application/consistency-groups/%s/snapshots' % self.cg_uuid
        body = {'name': self.parameters['snapshot']}
        if self.parameters.get('snapmirror_label'):
            body['snapmirror_label'] = self.parameters['snapmirror_label']
        if self.parameters.get('comment'):
            body['comment'] = self.parameters['comment']
        if self.parameters.get('consistency_type'):
            body['consistency_type'] = self.parameters['consistency_type']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating consistency group snapshot %s: %s' % (self.parameters['snapshot'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_cg_snapshot_rest(self, current):
        """Delete CG snapshot"""
        api = '/application/consistency-groups/%s/snapshots' % self.cg_uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, current['snapshot_uuid'])
        if error:
            self.module.fail_json(msg='Error deleting consistency group snapshot %s: %s' % (self.parameters['snapshot'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        """Applies action from playbook"""
        if not self.use_rest:
            if not self.module.check_mode:
                changed = self.cgcreate()
            self.module.exit_json(changed=changed)
        current = self.get_cg_snapshot_rest()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_cg_snapshot_rest()
            elif cd_action == 'delete':
                self.delete_cg_snapshot_rest(current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """Execute action from playbook"""
    cg_obj = NetAppONTAPCGSnapshot()
    cg_obj.apply()


if __name__ == '__main__':
    main()
