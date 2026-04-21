#!/usr/bin/python

""" this is lun mapping module

 (c) 2018-2025, NetApp, Inc
 # GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_lun_map
short_description: NetApp ONTAP LUN maps
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Map and unmap LUNs on NetApp ONTAP.

options:

  state:
    description:
    - Whether the specified LUN should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present

  initiator_group_name:
    description:
    - Initiator group to map to the given LUN.
    required: true
    type: str

  path:
    description:
    - Path of the LUN.
    - For ASA R2 systems, The path should match the format <name>[@<snapshot-name>].
    required: true
    type: str

  vserver:
    required: true
    description:
    - The name of the vserver to use.
    type: str

  lun_id:
    description:
    - LUN ID assigned for the map.
    type: str
"""

EXAMPLES = """
- name: Create LUN mapping
  netapp.ontap.na_ontap_lun_map:
    state: present
    initiator_group_name: ansibleIgroup3234
    path: /vol/iscsi_path/iscsi_lun
    vserver: ci_dev
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Unmap LUN
  netapp.ontap.na_ontap_lun_map:
    state: absent
    initiator_group_name: ansibleIgroup3234
    path: /vol/iscsi_path/iscsi_lun
    vserver: ci_dev
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
lun_node:
    description: NetApp controller that is hosting the LUN. (Note Not returned with REST)
    returned: success
    type: str
    sample: node01
lun_ostype:
    description: Specifies the OS of the host accessing the LUN.
    returned: success
    type: str
    sample: vmware
lun_serial:
    description: A unique, 12-byte, ASCII string used to identify the LUN.
    returned: success
    type: str
    sample: 80E7/]LZp1Tt
lun_naa_id:
    description: The Network Address Authority (NAA) identifier for the LUN.
    returned: success
    type: str
    sample: 600a0980383045372f5d4c5a70315474
lun_state:
    description: Online or offline status of the LUN.
    returned: success
    type: str
    sample: online
lun_size:
    description: Size of the LUN in bytes.
    returned: success
    type: int
    sample: 2199023255552
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
import codecs
from ansible.module_utils._text import to_text, to_bytes
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_ontap_personality

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapLUNMap:
    """
    Class with LUN map methods
    """

    def __init__(self):
        self.lun_uuid, self.igroup_uuid = None, None
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            initiator_group_name=dict(required=True, type='str'),
            path=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            lun_id=dict(required=False, type='str', default=None),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['path'])
            ],
            supports_check_mode=True
        )
        self.lun_info = dict()

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.asa_r2_system = False
        if self.use_rest:
            if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 16, 0):
                self.asa_r2_system = rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)
                if self.asa_r2_system:
                    # If the path is passed as vol/vol1/lun_map it will be converted to lun_map for asa r2 systems.
                    if 'path' in self.parameters:
                        self.module.warn('For ASA R2 systems, The path should match the format <name>[@<snapshot-name>].'
                                         'The name must begin with a letter or \"_\" and contain only \"_\" and alphanumeric character')
                        self.parameters['path'] = self.parameters.get('path').split("/")[-1]
        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_lun_map(self):
        """
        Return details about the LUN map

        :return: Details about the lun map
        :rtype: dict
        """
        if self.use_rest:
            return self.get_lun_map_rest()
        lun_info = netapp_utils.zapi.NaElement('lun-map-list-info')
        lun_info.add_new_child('path', self.parameters['path'])
        result = self.server.invoke_successfully(lun_info, True)
        return_value = None
        igroups = result.get_child_by_name('initiator-groups')
        if igroups:
            for igroup_info in igroups.get_children():
                initiator_group_name = igroup_info.get_child_content('initiator-group-name')
                lun_id = igroup_info.get_child_content('lun-id')
                if initiator_group_name == self.parameters['initiator_group_name']:
                    return_value = {
                        'lun_id': lun_id
                    }
                    break

        return return_value

    def get_lun(self):
        """
        Return details about the LUN

        :return: Details about the lun
        :rtype: dict
        """
        if self.use_rest:
            return self.get_lun_rest()
        # build the lun query
        query_details = netapp_utils.zapi.NaElement('lun-info')
        query_details.add_new_child('path', self.parameters['path'])

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)

        lun_query = netapp_utils.zapi.NaElement('lun-get-iter')
        lun_query.add_child_elem(query)

        # find lun using query
        result = self.server.invoke_successfully(lun_query, True)
        return_value = None
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            lun = result.get_child_by_name('attributes-list').get_child_by_name('lun-info')

            return_value = {
                'lun_node': lun.get_child_content('node'),
                'lun_ostype': lun.get_child_content('multiprotocol-type'),
                'lun_serial': lun.get_child_content('serial-number'),
                'lun_naa_id': self.return_naa_id(lun.get_child_content('serial-number')),
                'lun_state': lun.get_child_content('state'),
                'lun_size': lun.get_child_content('size'),
            }

        return return_value

    def return_naa_id(self, serial_number):
        hexlify = codecs.getencoder('hex')
        return '600a0980' + to_text(hexlify(to_bytes(serial_number))[0])

    def create_lun_map(self):
        """
        Create LUN map
        """
        if self.use_rest:
            return self.create_lun_map_rest()
        options = {'path': self.parameters['path'], 'initiator-group': self.parameters['initiator_group_name']}
        if self.parameters['lun_id'] is not None:
            options['lun-id'] = self.parameters['lun_id']
        lun_map_create = netapp_utils.zapi.NaElement.create_node_with_children('lun-map', **options)

        try:
            self.server.invoke_successfully(lun_map_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error mapping lun %s of initiator_group_name %s: %s" %
                                      (self.parameters['path'], self.parameters['initiator_group_name'], to_native(e)),
                                  exception=traceback.format_exc())

    def delete_lun_map(self):
        """
        Unmap LUN map
        """
        if self.use_rest:
            return self.delete_lun_map_rest()
        lun_map_delete = netapp_utils.zapi.NaElement.create_node_with_children('lun-unmap', **{
            'path': self.parameters['path'], 'initiator-group': self.parameters['initiator_group_name']})

        try:
            self.server.invoke_successfully(lun_map_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error unmapping lun %s of initiator_group_name %s: %s" %
                                      (self.parameters['path'], self.parameters['initiator_group_name'], to_native(e)),
                                  exception=traceback.format_exc())

    def get_lun_rest(self):
        api = 'storage/luns'
        params = {'name': self.parameters['path'],
                  'svm.name': self.parameters['vserver'],
                  'fields': 'name,'
                            'os_type,'
                            'serial_number,'
                            'status.state,'
                            'space.size,'
                            'uuid,'
                            'lun_maps'
                  }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error getting lun %s: %s' % (self.parameters['path'], error))
        if record:
            return {'lun_ostype': self.na_helper.safe_get(record, ['os_type']),
                    'lun_serial': self.na_helper.safe_get(record, ['serial_number']),
                    'lun_naa_id': self.return_naa_id(self.na_helper.safe_get(record, ['serial_number'])),
                    'lun_state': self.na_helper.safe_get(record, ['status', 'state']),
                    'lun_size': self.na_helper.safe_get(record, ['space', 'size']),
                    }
        return None

    def get_lun_map_rest(self):
        api = 'protocols/san/lun-maps'
        params = {'lun.name': self.parameters['path'],
                  'svm.name': self.parameters['vserver'],
                  'igroup.name': self.parameters['initiator_group_name'],
                  'fields': 'logical_unit_number,igroup.uuid,lun.uuid,lun.name,igroup.name'
                  }
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error getting lun_map %s: %s' % (self.parameters['path'], error))
        if record:
            return {'lun_id': str(self.na_helper.safe_get(record, ['logical_unit_number'])),
                    'igroup_uuid': self.na_helper.safe_get(record, ['igroup', 'uuid']),
                    'initiator_group_name': self.na_helper.safe_get(record, ['igroup', 'name']),
                    'lun_uuid': self.na_helper.safe_get(record, ['lun', 'uuid']),
                    'path': self.na_helper.safe_get(record, ['lun', 'name']),
                    }
        return None

    def create_lun_map_rest(self):
        api = 'protocols/san/lun-maps'
        body = {'svm.name': self.parameters['vserver'],
                'igroup.name': self.parameters['initiator_group_name'],
                'lun.name': self.parameters['path']}
        if self.parameters.get('lun_id') is not None:
            body['logical_unit_number'] = self.parameters['lun_id']
        dummy, error = rest_generic.post_async(self.rest_api, api, body, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error creating lun_map %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_lun_map_rest(self):
        api = 'protocols/san/lun-maps'
        both_uuids = '%s/%s' % (self.lun_uuid, self.igroup_uuid)
        dummy, error = rest_generic.delete_async(self.rest_api, api, both_uuids, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error deleting lun_map %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        lun_details = self.get_lun()
        # why do we do this, it never used in the module, and has nothing to do with lun_map (it probably should be in
        # the lun module
        current = self.get_lun_map()
        if self.use_rest and current:
            self.lun_uuid = current.get('lun_uuid', None)
            self.igroup_uuid = current.get('igroup_uuid', None)
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if modify:
                self.module.fail_json(msg="Modification of lun_map not allowed")
        if self.parameters['state'] == 'present' and lun_details:
            self.lun_info.update(lun_details)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_lun_map()
            if cd_action == 'delete':
                self.delete_lun_map()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, extra_responses=self.lun_info)
        self.module.exit_json(**result)


def main():
    lun_mapping = NetAppOntapLUNMap()
    lun_mapping.apply()


if __name__ == '__main__':
    main()
