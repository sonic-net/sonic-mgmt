#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''

module: na_ontap_lun_copy

short_description: NetApp ONTAP copy LUNs
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
version_added: 2.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Copy LUNs on NetApp ONTAP.

options:

  state:
    description:
      - Whether the specified LUN should exist or not.
    choices: ['present']
    type: str
    default: present

  destination_vserver:
    description:
      - the name of the Vserver that will host the new LUN.
    required: true
    type: str
    aliases: ['vserver']

  destination_path:
    description:
      - Specifies the full path to the new LUN.
    required: true
    type: str

  source_path:
    description:
      - Specifies the full path to the source LUN.
    required: true
    type: str

  source_vserver:
    description:
      - Specifies the name of the vserver hosting the LUN to be copied.
      - If not provided, C(destination_vserver) value is set as default.
      - with REST, this option value must match C(destination_vserver) when present.
    type: str

notes:
  - supports ZAPI and REST. REST requires ONTAP 9.10.1 or later.
  - supports check mode.
  - REST supports intra-Vserver lun copy only.
  - Thie module is not compatibile with ASA R2 systems.
  '''
EXAMPLES = """
- name: Copy LUN
  netapp.ontap.na_ontap_lun_copy:
    destination_vserver: ansible
    destination_path: /vol/test/test_copy_dest_dest_new
    source_path: /vol/test/test_copy_1
    source_vserver: ansible
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_ontap_personality


class NetAppOntapLUNCopy:

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            destination_vserver=dict(required=True, type='str', aliases=['vserver']),
            destination_path=dict(required=True, type='str'),
            source_path=dict(required=True, type='str'),
            source_vserver=dict(required=False, type='str'),

        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        # if source_vserver not present, set destination_vserver value for intra-vserver copy operation.
        if not self.parameters.get('source_vserver'):
            self.parameters['source_vserver'] = self.parameters['destination_vserver']
        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            msg = 'REST requires ONTAP 9.10.1 or later for na_ontap_lun_copy'
            self.use_rest = self.na_helper.fall_back_to_zapi(self.module, msg, self.parameters)
        self.asa_r2_system = False
        if self.use_rest:
            if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 0):
                self.asa_r2_system = rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)
                if self.asa_r2_system:
                    self.module.fail_json(msg='na_ontap_lun_copy operation is not compatibile with ASA R2 systems')
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module,
                                                           vserver=self.parameters['destination_vserver'])

    def get_lun(self):
        """
           Check if the LUN exists

        :return: true is it exists, false otherwise
        :rtype: bool
        """

        if self.use_rest:
            return self.get_lun_rest()
        return_value = False
        lun_info = netapp_utils.zapi.NaElement('lun-get-iter')
        query_details = netapp_utils.zapi.NaElement('lun-info')

        query_details.add_new_child('path', self.parameters['destination_path'])
        query_details.add_new_child('vserver', self.parameters['destination_vserver'])

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)

        lun_info.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(lun_info, True)

        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error getting lun info %s for  verver %s: %s" %
                                      (self.parameters['destination_path'], self.parameters['destination_vserver'], to_native(e)),
                                  exception=traceback.format_exc())

        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            return_value = True
        return return_value

    def copy_lun(self):
        """
        Copy LUN with requested path and vserver
        """
        if self.use_rest:
            return self.copy_lun_rest()
        lun_copy = netapp_utils.zapi.NaElement.create_node_with_children(
            'lun-copy-start', **{'source-vserver': self.parameters['source_vserver']})
        path_obj = netapp_utils.zapi.NaElement('paths')
        pair = netapp_utils.zapi.NaElement('lun-path-pair')
        pair.add_new_child('destination-path', self.parameters['destination_path'])
        pair.add_new_child('source-path', self.parameters['source_path'])
        path_obj.add_child_elem(pair)
        lun_copy.add_child_elem(path_obj)

        try:
            self.server.invoke_successfully(lun_copy, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error copying lun from %s to  vserver %s: %s" %
                                      (self.parameters['source_vserver'], self.parameters['destination_vserver'], to_native(e)),
                                  exception=traceback.format_exc())

    def get_lun_rest(self):
        api = 'storage/luns'
        params = {
            'svm.name': self.parameters['destination_vserver'],
            'name': self.parameters['destination_path']
        }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error getting lun info %s for  verver %s: %s" %
                                      (self.parameters['destination_path'], self.parameters['destination_vserver'], to_native(error)))
        return True if record else False

    def copy_lun_rest(self):
        api = 'storage/luns'
        body = {
            'copy': {'source': {'name': self.parameters['source_path']}},
            'name': self.parameters['destination_path'],
            'svm.name': self.parameters['destination_vserver']
        }
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error copying lun from %s to  vserver %s: %s" %
                                      (self.parameters['source_vserver'], self.parameters['destination_vserver'], to_native(error)))

    def apply(self):
        if self.get_lun():  # lun already exists at destination
            changed = False
        else:
            if self.use_rest and self.parameters['source_vserver'] != self.parameters['destination_vserver']:
                self.module.fail_json(msg="Error: REST does not supports inter-Vserver lun copy.")
            changed = True
            if not self.module.check_mode:
                # need to copy lun
                if self.parameters['state'] == 'present':
                    self.copy_lun()

        self.module.exit_json(changed=changed)


def main():
    v = NetAppOntapLUNCopy()
    v.apply()


if __name__ == '__main__':
    main()
