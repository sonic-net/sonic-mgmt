#!/usr/bin/python
''' This is an Ansible module for ONTAP, to manage initiators in an Igroup

 (c) 2019-2025, NetApp, Inc
 # GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''

module: na_ontap_igroup_initiator
short_description: NetApp ONTAP igroup initiator configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
    - Add/Remove initiators from an igroup

options:
  state:
    description:
      - Whether the specified initiator should exist or not in an igroup.
    choices: ['present', 'absent']
    type: str
    default: present

  names:
    description:
      - List of initiators to manage.
    required: true
    aliases:
      - name
    type: list
    elements: str

  initiator_group:
    description:
      - Name of the initiator group to which the initiator belongs.
    required: true
    type: str

  force_remove:
    description:
      - Forcibly remove the initiators even if there are existing LUNs mapped to the initiator group.
    type: bool
    default: false
    version_added: '20.1.0'

  vserver:
    description:
      - The name of the vserver to use.
    required: true
    type: str

'''

EXAMPLES = '''
- name: Add initiators to an igroup
  netapp.ontap.na_ontap_igroup_initiator:
    names: abc.test:def.com,def.test:efg.com
    initiator_group: test_group
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Remove an initiator from an igroup
  netapp.ontap.na_ontap_igroup_initiator:
    state: absent
    names: abc.test:def.com
    initiator_group: test_group
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
'''

RETURN = '''
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapIgroupInitiator(object):

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            names=dict(required=True, type='list', elements='str', aliases=['name']),
            initiator_group=dict(required=True, type='str'),
            force_remove=dict(required=False, type='bool', default=False),
            vserver=dict(required=True, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.uuid = None

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_initiators(self):
        """
        Get the existing list of initiators from an igroup
        :rtype: list() or None
        """
        if self.use_rest:
            return self.get_initiators_rest()
        igroup_info = netapp_utils.zapi.NaElement('igroup-get-iter')
        attributes = dict(query={'initiator-group-info': {'initiator-group-name': self.parameters['initiator_group'],
                                                          'vserver': self.parameters['vserver']}})
        igroup_info.translate_struct(attributes)
        result, current = None, []

        try:
            result = self.server.invoke_successfully(igroup_info, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching igroup info %s: %s' % (self.parameters['initiator_group'],
                                                                             to_native(error)),
                                  exception=traceback.format_exc())

        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            igroup_info = result.get_child_by_name('attributes-list').get_child_by_name('initiator-group-info')
            if igroup_info.get_child_by_name('initiators') is not None:
                current = [initiator['initiator-name'] for initiator in igroup_info['initiators'].get_children()]
        return current

    def modify_initiator(self, initiator_name, zapi):
        """
        Add or remove an initiator to/from an igroup
        """
        if self.use_rest:
            return self.modify_initiator_rest(initiator_name, zapi)
        options = {'initiator-group-name': self.parameters['initiator_group'],
                   'initiator': initiator_name,
                   'force': 'true' if zapi == 'igroup-remove' and self.parameters['force_remove'] else 'false'}
        initiator_modify = netapp_utils.zapi.NaElement.create_node_with_children(zapi, **options)

        try:
            self.server.invoke_successfully(initiator_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying igroup initiator %s: %s' % (initiator_name,
                                                                                   to_native(error)),
                                  exception=traceback.format_exc())

    def get_initiators_rest(self):
        api = 'protocols/san/igroups'
        query = {'name': self.parameters['initiator_group'], 'svm.name': self.parameters['vserver']}
        fields = 'initiators,uuid'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg="Error fetching igroup info %s: %s" % (self.parameters['initiator_group'], error))
        current = []
        if record:
            self.uuid = record['uuid']
            # igroup may have 0 initiators.
            if 'initiators' in record:
                current = [initiator['name'] for initiator in record['initiators']]
        return current

    def modify_initiator_rest(self, initiator_name, modify_action):
        if self.uuid is None:
            self.module.fail_json(msg="Error modifying igroup initiator %s: igroup not found" % initiator_name)
        api = 'protocols/san/igroups/%s/initiators' % self.uuid
        if modify_action == 'igroup-add':
            body = {"name": initiator_name}
            dummy, error = rest_generic.post_async(self.rest_api, api, body)
        else:
            query = {'allow_delete_while_mapped': self.parameters['force_remove']}
            dummy, error = rest_generic.delete_async(self.rest_api, api, initiator_name.lower(), query)
        if error:
            self.module.fail_json(msg="Error modifying igroup initiator %s: %s" % (initiator_name, error))

    def apply(self):
        initiators = self.get_initiators()
        for initiator in self.parameters['names']:
            present = None
            initiator = self.na_helper.sanitize_wwn(initiator)
            if initiator.lower() in initiators:
                present = True
            cd_action = self.na_helper.get_cd_action(present, self.parameters)
            if self.na_helper.changed and not self.module.check_mode:
                if cd_action == 'create':
                    self.modify_initiator(initiator, 'igroup-add')
                elif cd_action == 'delete':
                    self.modify_initiator(initiator, 'igroup-remove')
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapIgroupInitiator()
    obj.apply()


if __name__ == '__main__':
    main()
