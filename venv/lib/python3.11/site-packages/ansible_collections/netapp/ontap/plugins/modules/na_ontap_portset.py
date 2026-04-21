#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = '''
short_description: NetApp ONTAP Create/Delete portset
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete ONTAP portset, modify ports in a portset.
  - Modify type(protocol) is not supported in ONTAP.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_portset
options:
  state:
    description:
      - If you want to create a portset.
    default: present
    type: str
  vserver:
    required: true
    description:
      - Name of the SVM.
    type: str
  name:
    required: true
    description:
      - Name of the port set to create.
    type: str
  type:
    description:
      - Required for create in ZAPI.
      - Default value is mixed if not specified at the time of creation in REST.
      - Protocols accepted for this portset.
    choices: ['fcp', 'iscsi', 'mixed']
    type: str
  force:
    description:
      - If 'false' or not specified, the request will fail if there are any igroups bound to this portset.
      - If 'true', forcibly destroy the portset, even if there are existing igroup bindings.
    type: bool
    default: False
  ports:
    description:
      - Specify the ports associated with this portset. Should be comma separated.
      - It represents the expected state of a list of ports at any time, and replaces the current value of ports.
      - Adds a port if it is specified in expected state but not in current state.
      - Deletes a port if it is in current state but not in expected state.
    type: list
    elements: str
version_added: 2.8.0

'''

EXAMPLES = """
- name: Create Portset
  netapp.ontap.na_ontap_portset:
    state: present
    vserver: vserver_name
    name: portset_name
    ports: a1
    type: "{{ protocol type }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify ports in portset
  netapp.ontap.na_ontap_portset:
    state: present
    vserver: vserver_name
    name: portset_name
    ports: a1,a2
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete Portset
  netapp.ontap.na_ontap_portset:
    state: absent
    vserver: vserver_name
    name: portset_name
    force: true
    type: "{{ protocol type }}"
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
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPPortset:
    """
    Methods to create or delete portset
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            type=dict(required=False, type='str', choices=[
                'fcp', 'iscsi', 'mixed']),
            force=dict(required=False, type='bool', default=False),
            ports=dict(required=False, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if 'ports' in self.parameters:
            self.parameters['ports'] = list(set([port.strip() for port in self.parameters['ports']]))
            if '' in self.parameters['ports'] and self.parameters['state'] == 'present':
                self.module.fail_json(msg="Error: invalid value specified for ports")

        # Setup REST API.
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.uuid, self.lifs_info = None, {}
        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            msg = 'REST requires ONTAP 9.9.1 or later for portset APIs.'
            if self.parameters['use_rest'].lower() == 'always':
                self.module.fail_json(msg='Error: %s' % msg)
            if self.parameters['use_rest'].lower() == 'auto':
                self.module.warn('Falling back to ZAPI: %s' % msg)
                self.use_rest = False

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def portset_get_iter(self):
        """
        Compose NaElement object to query current portset using vserver, portset-name and portset-type parameters
        :return: NaElement object for portset-get-iter with query
        """
        portset_get = netapp_utils.zapi.NaElement('portset-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        portset_info = netapp_utils.zapi.NaElement('portset-info')
        portset_info.add_new_child('vserver', self.parameters['vserver'])
        portset_info.add_new_child('portset-name', self.parameters['name'])
        query.add_child_elem(portset_info)
        portset_get.add_child_elem(query)
        return portset_get

    def portset_get(self):
        """
        Get current portset info
        :return: Dictionary of current portset details if query successful, else return None
        """
        if self.use_rest:
            return self.portset_get_rest()
        portset_get_iter = self.portset_get_iter()
        result, portset_info = None, dict()
        try:
            result = self.server.invoke_successfully(portset_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching portset %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        # return portset details
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            portset_get_info = result.get_child_by_name('attributes-list').get_child_by_name('portset-info')
            portset_info['type'] = portset_get_info.get_child_content('portset-type')
            if int(portset_get_info.get_child_content('portset-port-total')) > 0:
                ports = portset_get_info.get_child_by_name('portset-port-info')
                portset_info['ports'] = [port.get_content() for port in ports.get_children()]
            else:
                portset_info['ports'] = []
            return portset_info
        return None

    def create_portset(self):
        """
        Create a portset
        """
        if self.use_rest:
            return self.create_portset_rest()
        if self.parameters.get('type') is None:
            self.module.fail_json(msg='Error: Missing required parameter for create (type)')
        portset_info = netapp_utils.zapi.NaElement("portset-create")
        portset_info.add_new_child("portset-name", self.parameters['name'])
        portset_info.add_new_child("portset-type", self.parameters['type'])
        try:
            self.server.invoke_successfully(
                portset_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error creating portset %s: %s" %
                                      (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_portset(self):
        """
        Delete a portset
        """
        if self.use_rest:
            return self.delete_portset_rest()
        portset_info = netapp_utils.zapi.NaElement("portset-destroy")
        portset_info.add_new_child("portset-name", self.parameters['name'])
        if self.parameters.get('force'):
            portset_info.add_new_child("force", str(self.parameters['force']))
        try:
            self.server.invoke_successfully(
                portset_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error deleting portset %s: %s" %
                                      (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def remove_ports(self, ports):
        """
        Removes all existing ports from portset
        :return: None
        """
        for port in ports:
            self.modify_port(port, 'portset-remove', 'removing')

    def add_ports(self, ports=None):
        """
        Add the list of ports to portset
        :return: None
        """
        if ports is None:
            ports = self.parameters.get('ports')
        # don't add if ports is None
        if ports is None:
            return
        for port in ports:
            self.modify_port(port, 'portset-add', 'adding')

    def modify_port(self, port, zapi, action):
        """
        Add or remove an port to/from a portset
        """
        options = {'portset-name': self.parameters['name'],
                   'portset-port-name': port}

        portset_modify = netapp_utils.zapi.NaElement.create_node_with_children(zapi, **options)

        try:
            self.server.invoke_successfully(portset_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error %s port in portset %s: %s' % (action, self.parameters['name'],
                                                                           to_native(error)),
                                  exception=traceback.format_exc())

    def portset_get_rest(self):
        api = "protocols/san/portsets"
        query = {'name': self.parameters['name'], 'svm.name': self.parameters['vserver']}
        fields = 'uuid,protocol,interfaces'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg='Error fetching portset %s: %s'
                                      % (self.parameters['name'], to_native(error)))
        portset_info = None
        if record:
            portset_info = self.form_portset_info(record)
        return portset_info

    def form_portset_info(self, record):
        self.uuid = record['uuid']
        # if type is not set, assign current type
        # for avoiding incompatible network interface error in modify portset.
        if self.parameters.get('type') is None:
            self.parameters['type'] = record['protocol']
        portset_info = {
            'type': record['protocol'],
            'ports': []
        }
        if 'interfaces' in record:
            for lif in record['interfaces']:
                for key, value in lif.items():
                    if key in ['fc', 'ip']:
                        # add current lifs type and uuid to self.lifs for modify and delete purpose.
                        self.lifs_info[value['name']] = {'lif_type': key, 'uuid': value['uuid']}
                        # This will form ports list for fcp, iscsi and mixed protocols.
                        portset_info['ports'].append(value['name'])
        return portset_info

    def create_portset_rest(self):
        api = "protocols/san/portsets"
        body = {'name': self.parameters['name'], 'svm.name': self.parameters['vserver']}
        if 'type' in self.parameters:
            body['protocol'] = self.parameters['type']
        if self.lifs_info:
            body['interfaces'] = [{self.lifs_info[lif]['lif_type']: {'name': lif}} for lif in self.lifs_info]
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating portset %s: %s" %
                                      (self.parameters['name'], to_native(error)))

    def delete_portset_rest(self):
        api = "protocols/san/portsets"
        # Default value is False if 'force' not in parameters.
        query = {'allow_delete_while_bound': self.parameters.get('force', False)}
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid, query)
        if error:
            self.module.fail_json(msg="Error deleting portset %s: %s" %
                                      (self.parameters['name'], to_native(error)))

    def modify_portset_rest(self, ports_to_add, ports_to_remove):
        if ports_to_add:
            self.add_ports_to_portset(ports_to_add)
        for port in ports_to_remove:
            self.remove_port_from_portset(port)

    def add_ports_to_portset(self, ports_to_add):
        api = 'protocols/san/portsets/%s/interfaces' % self.uuid
        body = {'records': [{self.lifs_info[port]['lif_type']: {'name': port}} for port in ports_to_add]}
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error adding port in portset %s: %s' % (self.parameters['name'],
                                                                               to_native(error)))

    def remove_port_from_portset(self, port_to_remove):
        api = 'protocols/san/portsets/%s/interfaces' % self.uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.lifs_info[port_to_remove]['uuid'])
        if error:
            self.module.fail_json(msg='Error removing port in portset %s: %s' % (self.parameters['name'],
                                                                                 to_native(error)))

    def get_san_lifs_rest(self, san_lifs):
        # list of lifs not present in the vserver
        missing_lifs = []
        record, record2, error, error2 = None, None, None, None
        for lif in san_lifs:
            if self.parameters.get('type') in [None, 'mixed', 'iscsi']:
                record, error = self.get_san_lif_type_uuid(lif, 'ip')
            if self.parameters.get('type') in [None, 'mixed', 'fcp']:
                record2, error2 = self.get_san_lif_type_uuid(lif, 'fc')
            if error is None and error2 is not None and record:
                # ignore error on fc if ip interface is found
                error2 = None
            if error2 is None and error is not None and record2:
                # ignore error on ip if fc interface is found
                error = None
            if error or error2:
                errors = [to_native(err) for err in (error, error2) if err]
                self.module.fail_json(msg='Error fetching lifs details for %s: %s' % (lif, ' - '.join(errors)),
                                      exception=traceback.format_exc())
            if record:
                self.lifs_info[lif] = {'lif_type': 'ip', 'uuid': record['uuid']}
            if record2:
                self.lifs_info[lif] = {'lif_type': 'fc', 'uuid': record2['uuid']}
            if record is None and record2 is None:
                missing_lifs.append(lif)
        if missing_lifs and self.parameters['state'] == 'present':
            error_msg = 'Error: lifs: %s of type %s not found in vserver %s' % \
                        (', '.join(missing_lifs), self.parameters.get('type', 'fcp or iscsi'), self.parameters['vserver'])
            self.module.fail_json(msg=error_msg)

    def get_san_lif_type_uuid(self, lif, portset_type):
        api = 'network/%s/interfaces' % portset_type
        query = {'name': lif, 'svm.name': self.parameters['vserver']}
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        return record, error

    def apply(self):
        """
        Applies action from playbook
        """
        current, modify = self.portset_get(), None
        # get lifs type and uuid which is not present in current.
        if self.use_rest and self.parameters['state'] == 'present':
            self.get_san_lifs_rest([port for port in self.parameters['ports'] if port not in self.lifs_info])
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            if self.parameters.get('type') and self.parameters['type'] != current['type']:
                self.module.fail_json(msg="modify protocol(type) not supported and %s already exists in vserver %s under different type" %
                                          (self.parameters['name'], self.parameters['vserver']))
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_portset()
                # REST handles create and add ports in create api call itself.
                if not self.use_rest:
                    self.add_ports()
            elif cd_action == 'delete':
                self.delete_portset()
            elif modify:
                add_ports = set(self.parameters['ports']) - set(current['ports'])
                remove_ports = set(current['ports']) - set(self.parameters['ports'])
                if self.use_rest:
                    self.modify_portset_rest(add_ports, remove_ports)
                else:
                    self.add_ports(add_ports)
                    self.remove_ports(remove_ports)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    portset_obj = NetAppONTAPPortset()
    portset_obj.apply()


if __name__ == '__main__':
    main()
