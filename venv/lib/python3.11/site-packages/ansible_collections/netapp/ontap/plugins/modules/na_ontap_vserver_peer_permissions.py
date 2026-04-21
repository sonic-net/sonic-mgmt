#!/usr/bin/python

# (c) 2023-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_vserver_peer_permissions
short_description: NetApp Ontap - create, delete or modify vserver peer permission.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create, delete or modify vserver peer permission.
options:
  state:
    description:
      - Whether the specified vserver peer permission should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str
  vserver:
    description:
      - Specifies name of the source Vserver in the relationship.
    required: true
    type: str
  applications:
    type: list
    elements: str
    required: true
    description:
      - List of applications which can make use of the peering relationship.
      - FlexCache supported from ONTAP 9.5 onwards.
  cluster_peer:
    description:
      - Specifies name of the peer Cluster.
    type: str
    required: true
"""

EXAMPLES = """
- name: Create vserver peer permission for an SVM
  netapp.ontap.na_ontap_vserver_peer_permissions:
    state: present
    vserver: ansible
    cluster_peer: test_cluster
    applications: ['snapmirror']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify vserver peer permission for an SVM
  netapp.ontap.na_ontap_vserver_peer_permissions:
    state: present
    vserver: ansible
    cluster_peer: test_cluster
    applications: ['snapmirror', 'flexcache']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete vserver peer permission for an SVM
  netapp.ontap.na_ontap_vserver_peer_permissions:
    state: absent
    vserver: ansible
    cluster_peer: test_cluster
    applications: ['snapmirror']
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPVserverPeerPermissions:
    """
    Class with vserver peer permission methods
    """

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            applications=dict(required=True, type='list', elements='str'),
            cluster_peer=dict(required=True, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_vserver_peer_permissions', 9, 6)
        self.input_validation()
        self.svm_uuid = None
        self.cluster_peer_uuid = None

    def input_validation(self):
        if self.parameters.get('vserver') == '*':
            self.module.fail_json(msg='As svm name * represents all svms and created by default, please provide a specific SVM name')
        if self.parameters.get('applications') == [''] and self.parameters.get('state') == 'present':
            self.module.fail_json(msg='Applications field cannot be empty, at least one application must be specified')

    def get_vserver_peer_permission_rest(self):
        """
        Retrieves SVM peer permissions.
        """
        api = "svm/peer-permissions"
        query = {
            'svm.name': self.parameters['vserver'],
            "cluster_peer.name": self.parameters['cluster_peer'],
            'fields': 'svm.uuid,cluster_peer.uuid,applications'
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg="Error on fetching vserver peer permissions: %s" % error)
        if record:
            self.svm_uuid = self.na_helper.safe_get(record, ['svm', 'uuid'])
            self.cluster_peer_uuid = self.na_helper.safe_get(record, ['cluster_peer', 'uuid'])
            return {
                'applications': self.na_helper.safe_get(record, ['applications']),
            }
        return None

    def create_vserver_peer_permission_rest(self):
        """
        Creates an SVM peer permission.
        """
        api = "svm/peer-permissions"
        body = {
            'svm.name': self.parameters['vserver'],
            'cluster_peer.name': self.parameters['cluster_peer'],
            'applications': self.parameters['applications']
        }
        record, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error on creating vserver peer permissions: %s" % error)

    def delete_vserver_peer_permission_rest(self):
        """
        Deletes the SVM peer permissions.
        """
        api = "svm/peer-permissions/%s/%s" % (self.cluster_peer_uuid, self.svm_uuid)
        record, error = rest_generic.delete_async(self.rest_api, api, None)
        if error:
            self.module.fail_json(msg="Error on deleting vserver peer permissions: %s" % error)

    def modify_vserver_peer_permission_rest(self, modify):
        """
        Updates the SVM peer permissions.
        """
        body = {}
        if 'applications' in modify:
            body['applications'] = self.parameters['applications']
        api = "svm/peer-permissions/%s/%s" % (self.cluster_peer_uuid, self.svm_uuid)
        record, error = rest_generic.patch_async(self.rest_api, api, None, body)
        if error:
            self.module.fail_json(msg="Error on modifying vserver peer permissions: %s" % error)

    def apply(self):
        current = self.get_vserver_peer_permission_rest()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_vserver_peer_permission_rest()
            elif cd_action == 'delete':
                self.delete_vserver_peer_permission_rest()
            elif modify:
                self.modify_vserver_peer_permission_rest(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp Ontap vserver peer permission object and runs the correct play task
    """
    obj = NetAppONTAPVserverPeerPermissions()
    obj.apply()


if __name__ == '__main__':
    main()
