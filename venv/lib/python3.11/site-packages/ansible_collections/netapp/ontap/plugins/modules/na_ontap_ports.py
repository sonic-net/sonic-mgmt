#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_ports
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_ports
short_description: NetApp ONTAP add/remove ports
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
    - Add or remove ports for broadcast domain and portset.

options:
  state:
    description:
      - Whether the specified port should be added or removed.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
      - Name of the SVM.
      - Specify this option when operating on portset.
    type: str

  names:
    description:
      - List of ports.
    type: list
    elements: str
    required: true

  resource_name:
    description:
      - name of the portset or broadcast domain.
    type: str
    required: true

  resource_type:
    description:
      - type of the resource to add a port to or remove a port from.
      - adding or removing ports in portset requires ONTAP version 9.9 or later in REST
    choices: ['broadcast_domain', 'portset']
    required: true
    type: str

  ipspace:
    description:
      - Specify the required ipspace for the broadcast domain.
      - A domain ipspace can not be modified after the domain has been created.
    type: str

  portset_type:
    description:
      - Protocols accepted for portset.
    choices: ['fcp', 'iscsi', 'mixed']
    type: str

'''

EXAMPLES = '''
- name: Broadcast domain remove port
  netapp.ontap.na_ontap_ports:
    state: absent
    names: test-vsim1:e0d-1,test-vsim1:e0d-2
    resource_type: broadcast_domain
    resource_name: ansible_domain
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true

- name: Broadcast domain add port
  netapp.ontap.na_ontap_ports:
    state: present
    names: test-vsim1:e0d-1,test-vsim1:e0d-2
    resource_type: broadcast_domain
    resource_name: ansible_domain
    ipspace: Default
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true

- name: Portset remove port
  netapp.ontap.na_ontap_ports:
    state: absent
    names: lif_2
    resource_type: portset
    resource_name: portset_1
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true

- name: Portset add port
  netapp.ontap.na_ontap_ports:
    state: present
    names: lif_2
    resource_type: portset
    resource_name: portset_1
    portset_type: iscsi
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
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


class NetAppOntapPorts:

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=False, type='str'),
            names=dict(required=True, type='list', elements='str'),
            resource_name=dict(required=True, type='str'),
            resource_type=dict(required=True, type='str', choices=['broadcast_domain', 'portset']),
            ipspace=dict(required=False, type='str'),
            portset_type=dict(required=False, type='str', choices=['fcp', 'iscsi', 'mixed']),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('resource_type', 'portset', ['vserver']),
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.desired_ports = None
        self.desired_lifs = None

        if self.use_rest and 'ipspace' not in self.parameters and self.parameters['resource_type'] == 'broadcast_domain':
            error_msg = "Error: ipspace space is a required option with REST"
            self.module.fail_json(msg=error_msg)

        if self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9) and self.parameters['resource_type'] == 'portset':
            self.module.fail_json(msg='Error: adding or removing ports in portset requires ONTAP version 9.9 or later in REST')

        if 'names' in self.parameters:
            self.parameters['names'] = list(set([port.strip() for port in self.parameters['names']]))
            if self.use_rest and self.parameters['resource_type'] == 'broadcast_domain':
                self.desired_ports = self.get_ports_rest(self.parameters['names'])
            if self.use_rest and self.parameters['resource_type'] == 'portset':
                self.desired_lifs = self.get_san_lifs_rest(self.parameters['names'])

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            if self.parameters['resource_type'] == 'broadcast_domain':
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
            elif self.parameters['resource_type'] == 'portset':
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def add_broadcast_domain_ports(self, ports):
        """
        Add broadcast domain ports
        :param: ports to be added.
        """
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-add-ports')
        domain_obj.add_new_child("broadcast-domain", self.parameters['resource_name'])
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        ports_obj = netapp_utils.zapi.NaElement('ports')
        domain_obj.add_child_elem(ports_obj)
        for port in ports:
            ports_obj.add_new_child('net-qualified-port-name', port)
        try:
            self.server.invoke_successfully(domain_obj, True)
            return True
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error adding port for broadcast domain %s: %s' %
                                  (self.parameters['resource_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def add_broadcast_domain_ports_rest(self, ports):
        """
        Add broadcast domain ports in rest.
        :param: ports to be added or moved.
        """
        api = 'network/ethernet/ports'
        body = {
            'broadcast_domain': {
                'name': self.parameters['resource_name'],
                'ipspace': {'name': self.parameters['ipspace']}
            }
        }
        for port in ports:
            dummy, error = rest_generic.patch_async(self.rest_api, api, port['uuid'], body)
            if error:
                self.module.fail_json(msg=error)

    def remove_broadcast_domain_ports(self, ports):
        """
        Deletes broadcast domain ports
        :param: ports to be removed.
        """
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-remove-ports')
        domain_obj.add_new_child("broadcast-domain", self.parameters['resource_name'])
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        ports_obj = netapp_utils.zapi.NaElement('ports')
        domain_obj.add_child_elem(ports_obj)
        for port in ports:
            ports_obj.add_new_child('net-qualified-port-name', port)
        try:
            self.server.invoke_successfully(domain_obj, True)
            return True
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error removing port for broadcast domain %s: %s' %
                                  (self.parameters['resource_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def remove_broadcast_domain_ports_rest(self, ports, ipspace):
        body = {'ports': ports}
        api = "private/cli/network/port/broadcast-domain/remove-ports"
        query = {'broadcast-domain': self.parameters['resource_name'], 'ipspace': ipspace}
        response, error = rest_generic.patch_async(self.rest_api, api, None, body, query)
        if error:
            self.module.fail_json(msg='Error removing ports: %s' % error)

    def get_broadcast_domain_ports(self):
        """
        Return details about the broadcast domain ports.
        :return: Details about the broadcast domain ports. [] if not found.
        :rtype: list
        """
        if self.use_rest:
            return self.get_broadcast_domain_ports_rest()
        domain_get_iter = netapp_utils.zapi.NaElement('net-port-broadcast-domain-get-iter')
        broadcast_domain_info = netapp_utils.zapi.NaElement('net-port-broadcast-domain-info')
        broadcast_domain_info.add_new_child('broadcast-domain', self.parameters['resource_name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(broadcast_domain_info)
        domain_get_iter.add_child_elem(query)
        result = self.server.invoke_successfully(domain_get_iter, True)
        ports = []
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:
            domain_info = result.get_child_by_name('attributes-list').get_child_by_name('net-port-broadcast-domain-info')
            domain_ports = domain_info.get_child_by_name('ports')
            if domain_ports is not None:
                ports = [port.get_child_content('port') for port in domain_ports.get_children()]
        return ports

    def get_broadcast_domain_ports_rest(self):
        """
        Return details about the broadcast domain ports.
        :return: Details about the broadcast domain ports. [] if not found.
        :rtype: list
        """
        api = 'network/ethernet/broadcast-domains'
        query = {'name': self.parameters['resource_name'], 'ipspace.name': self.parameters['ipspace']}
        fields = 'ports'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        ports = []
        if record and 'ports' in record:
            ports = ['%s:%s' % (port['node']['name'], port['name']) for port in record['ports']]
        return ports

    def remove_portset_ports(self, port, portset_uuid=None):
        """
        Removes all existing ports from portset
        :return: None
        """
        if self.use_rest:
            return self.remove_portset_ports_rest(port, portset_uuid)
        options = {'portset-name': self.parameters['resource_name'],
                   'portset-port-name': port.strip()}

        portset_modify = netapp_utils.zapi.NaElement.create_node_with_children('portset-remove', **options)

        try:
            self.server.invoke_successfully(portset_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error removing port in portset %s: %s' %
                                      (self.parameters['resource_name'], to_native(error)), exception=traceback.format_exc())

    def remove_portset_ports_rest(self, port, portset_uuid):
        """
        Removes all existing ports from portset
        :return: None
        """
        api = 'protocols/san/portsets/%s/interfaces' % portset_uuid
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.desired_lifs[port]['uuid'])
        if error:
            self.module.fail_json(msg=error)

    def add_portset_ports(self, port):
        """
        Add the list of ports to portset
        :return: None
        """
        options = {'portset-name': self.parameters['resource_name'],
                   'portset-port-name': port.strip()}

        portset_modify = netapp_utils.zapi.NaElement.create_node_with_children('portset-add', **options)

        try:
            self.server.invoke_successfully(portset_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error adding port in portset %s: %s' %
                                      (self.parameters['resource_name'], to_native(error)), exception=traceback.format_exc())

    def add_portset_ports_rest(self, portset_uuid, ports_to_add):
        """
        Add the list of ports to portset
        :return: None
        """
        api = 'protocols/san/portsets/%s/interfaces' % portset_uuid
        body = {'records': []}
        for port in ports_to_add:
            body['records'].append({self.desired_lifs[port]['lif_type']: {'name': port}})
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg=error)

    def portset_get_iter(self):
        """
        Compose NaElement object to query current portset using vserver, portset-name and portset-type parameters
        :return: NaElement object for portset-get-iter with query
        """
        portset_get = netapp_utils.zapi.NaElement('portset-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        portset_info = netapp_utils.zapi.NaElement('portset-info')
        portset_info.add_new_child('vserver', self.parameters['vserver'])
        portset_info.add_new_child('portset-name', self.parameters['resource_name'])
        if self.parameters.get('portset_type'):
            portset_info.add_new_child('portset-type', self.parameters['portset_type'])
        query.add_child_elem(portset_info)
        portset_get.add_child_elem(query)
        return portset_get

    def portset_get(self):
        """
        Get current portset info
        :return: List of current ports if query successful, else return []
        """
        portset_get_iter = self.portset_get_iter()
        result, ports = None, []
        try:
            result = self.server.invoke_successfully(portset_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching portset %s: %s'
                                      % (self.parameters['resource_name'], to_native(error)),
                                  exception=traceback.format_exc())
        # return portset details
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            portset_get_info = result.get_child_by_name('attributes-list').get_child_by_name('portset-info')
            if int(portset_get_info.get_child_content('portset-port-total')) > 0:
                port_info = portset_get_info.get_child_by_name('portset-port-info')
                ports = [port.get_content() for port in port_info.get_children()]
        return ports

    def portset_get_rest(self):
        """
        Get current portset info
        :return: List of current ports if query successful, else return {}
        """
        api = 'protocols/san/portsets'
        query = {
            'svm.name': self.parameters['vserver'],
            'name': self.parameters['resource_name']
        }
        if self.parameters.get('portset_type'):
            query['protocol'] = self.parameters['portset_type']
        fields = 'interfaces'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        current = {}
        if record:
            current['uuid'] = record['uuid']
            if 'interfaces' in record:
                # This will form ports list for fcp, iscsi and mixed protocols.
                ports = [lif.get('ip', lif.get('fc'))['name'] for lif in record['interfaces']]
                current['ports'] = ports
        if not current and self.parameters['state'] == 'present':
            error_msg = "Error: Portset '%s' does not exist" % self.parameters['resource_name']
            self.module.fail_json(msg=error_msg)
        return current

    def modify_broadcast_domain_ports(self):
        """
        compare current and desire ports. Call add or remove ports methods if needed.
        :return: None.
        """
        current_ports = self.get_broadcast_domain_ports()
        cd_ports = self.parameters['names']
        if self.parameters['state'] == 'present':
            ports_to_add = [port for port in cd_ports if port not in current_ports]
            if len(ports_to_add) > 0:
                if not self.module.check_mode:
                    if self.use_rest:
                        self.add_broadcast_domain_ports_rest(self.ports_to_add_from_desired(ports_to_add))
                    else:
                        self.add_broadcast_domain_ports(ports_to_add)
                self.na_helper.changed = True

        if self.parameters['state'] == 'absent':
            ports_to_remove = [port for port in cd_ports if port in current_ports]
            if len(ports_to_remove) > 0:
                if not self.module.check_mode:
                    if self.use_rest:
                        self.remove_broadcast_domain_ports_rest(ports_to_remove, self.parameters['ipspace'])
                    else:
                        self.remove_broadcast_domain_ports(ports_to_remove)
                self.na_helper.changed = True

    def modify_portset_ports(self):
        uuid = None
        if self.use_rest:
            current = self.portset_get_rest()
            if 'uuid' in current:
                uuid = current['uuid']
            current_ports = current['ports'] if 'ports' in current else []
        else:
            current_ports = self.portset_get()
        cd_ports = self.parameters['names']
        if self.parameters['state'] == 'present':
            ports_to_add = [port for port in cd_ports if port not in current_ports]
            if len(ports_to_add) > 0:
                if not self.module.check_mode:
                    if self.use_rest:
                        self.add_portset_ports_rest(uuid, ports_to_add)
                    else:
                        for port in ports_to_add:
                            self.add_portset_ports(port)
                self.na_helper.changed = True

        if self.parameters['state'] == 'absent':
            ports_to_remove = [port for port in cd_ports if port in current_ports]
            if len(ports_to_remove) > 0:
                if not self.module.check_mode:
                    for port in ports_to_remove:
                        self.remove_portset_ports(port, uuid)
                self.na_helper.changed = True

    def get_ports_rest(self, ports):
        # list of desired ports not present in the node.
        missing_ports = []
        # list of uuid information of each desired port should present in broadcast domain.
        desired_ports = []
        for port in ports:
            current = self.get_net_port_rest(port)
            if current is None:
                missing_ports.append(port)
            else:
                desired_ports.append(current)
        # Error if any of provided ports are not found.
        if missing_ports and self.parameters['state'] == 'present':
            self.module.fail_json(msg='Error: ports: %s not found' % ', '.join(missing_ports))
        return desired_ports

    def get_net_port_rest(self, port):
        if ':' not in port:
            error_msg = "Error: Invalid value specified for port: %s, provide port name as node_name:port_name" % port
            self.module.fail_json(msg=error_msg)
        node_name, port_name = port.split(':')
        api = 'network/ethernet/ports'
        query = {
            'name': port_name,
            'node.name': node_name,
        }
        fields = 'name,uuid'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        if record:
            current = {'uuid': record['uuid'], 'name': '%s:%s' % (record['node']['name'], record['name'])}
            return current
        return None

    def ports_to_add_from_desired(self, ports):
        ports_to_add = []
        for port in ports:
            for port_to_add in self.desired_ports:
                if port == port_to_add['name']:
                    ports_to_add.append({'uuid': port_to_add['uuid']})
        return ports_to_add

    def get_san_lifs_rest(self, san_lifs):
        # list of lifs not present in the vserver
        missing_lifs = []
        # dict with each key is lif name, value contains lif type - fc or ip and uuid.
        desired_lifs = {}
        record, record2, error, error2 = None, None, None, None
        for lif in san_lifs:
            if self.parameters.get('portset_type') in [None, 'mixed', 'iscsi']:
                record, error = self.get_san_lif_type(lif, 'ip')
            if self.parameters.get('portset_type') in [None, 'mixed', 'fcp']:
                record2, error2 = self.get_san_lif_type(lif, 'fc')
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
                desired_lifs[lif] = {'lif_type': 'ip', 'uuid': record['uuid']}
            if record2:
                desired_lifs[lif] = {'lif_type': 'fc', 'uuid': record2['uuid']}
            if record is None and record2 is None:
                missing_lifs.append(lif)
        if missing_lifs and self.parameters['state'] == 'present':
            error_msg = 'Error: lifs: %s of type %s not found in vserver %s' % \
                        (', '.join(missing_lifs), self.parameters.get('portset_type', 'fcp or iscsi'), self.parameters['vserver'])
            self.module.fail_json(msg=error_msg)
        return desired_lifs

    def get_san_lif_type(self, lif, portset_type):
        api = 'network/%s/interfaces' % portset_type
        query = {'name': lif, 'svm.name': self.parameters['vserver']}
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        return record, error

    def apply(self):
        if self.parameters['resource_type'] == 'broadcast_domain':
            self.modify_broadcast_domain_ports()
        elif self.parameters['resource_type'] == 'portset':
            self.modify_portset_ports()
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    portset_obj = NetAppOntapPorts()
    portset_obj.apply()


if __name__ == '__main__':
    main()
