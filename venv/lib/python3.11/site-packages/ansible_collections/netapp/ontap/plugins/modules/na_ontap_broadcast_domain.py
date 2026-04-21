#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_broadcast_domain
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_broadcast_domain
short_description: NetApp ONTAP manage broadcast domains.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Modify a ONTAP broadcast domain.
options:
  state:
    description:
      - Whether the specified broadcast domain should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present
  name:
    description:
      - Specify the broadcast domain name.
    required: true
    aliases:
      - broadcast_domain
    type: str
  from_name:
    description:
      - Specify the broadcast domain name to be split into new broadcast domain.
    version_added: 2.8.0
    type: str
  mtu:
    description:
      - Specify the required mtu for the broadcast domain.
    type: int
  ipspace:
    description:
      - Specify the required ipspace for the broadcast domain.
      - With ZAPI, a domain ipspace cannot be modified after the domain has been created.
      - With REST, a domain ipspace can be modified.
      - This option is required while using REST.
    type: str
  from_ipspace:
    description:
      - if used with C(from_name), it will try to find broadcast domain C(from_name) in C(from_ipspace), split action either rename broadcast_domain and
        ipspace or create a new broadcast domain.
      - If not C(from_name) present, it will try to find C(name) broadcast domain in C(from_ipspace) and modify ipspace using C(ipspace).
      - Only supported with REST.
    version_added: 2.15.0
    type: str
  ports:
    description:
      - Specify the ports associated with this broadcast domain. Should be comma separated.
      - It represents the expected state of a list of ports at any time.
      - Add a port if it is specified in expected state but not in current state.
      - Delete a port if it is specified in current state but not in expected state.
      - For split action, it represents the ports to be split from current broadcast domain and added to the new broadcast domain.
      - If all ports are removed or split from a broadcast domain, the broadcast domain will be deleted automatically.
      - With REST, if exact match of ports found with C(from_name), split action will rename the broadcast domain using C(name).
      - With REST, if partial match of ports with C(from_name), split action will create a new broadcast domain using C(name) and
        move partial matched ports from C(from_name) to C(name).
      - With REST, if C(ports) not in C(from_name), split action will create a new broadcast domain using C(name) with C(ports).
    type: list
    elements: str
'''

EXAMPLES = """
- name: Create broadcast domain
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    name: ansible_domain
    mtu: 1000
    ipspace: Default
    ports: ["khutton-vsim1:e0d-12", "khutton-vsim1:e0d-13"]
- name: Modify broadcast domain
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    name: ansible_domain
    mtu: 1100
    ipspace: Default
    ports: ["khutton-vsim1:e0d-12", "khutton-vsim1:e0d-13"]
- name: Split broadcast domain
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    from_name: ansible_domain
    name: new_ansible_domain
    mtu: 1200
    ipspace: Default
    ports: khutton-vsim1:e0d-12
- name: Delete broadcast domain
  netapp.ontap.na_ontap_broadcast_domain:
    state: absent
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    name: ansible_domain
    ipspace: Default
- name: Create broadcast domain REST
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    name: ansible_domain
    mtu: 1200
    ipspace: Default
    ports: ["khutton-vsim1:e0d-12", "khutton-vsim1:e0d-13", "khutton-vsim1:e0d-14"]
- name: Rename broadcast domain if exact match of ports REST
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    from_name: ansible_domain
    name: new_ansible_domain
    mtu: 1200
    ipspace: Default
    ports: ["khutton-vsim1:e0d-12", "khutton-vsim1:e0d-13", "khutton-vsim1:e0d-14"]
- name: If partial match, remove e0d-12 from new_ansible_domain & create new domain ansible_domain with port e0d-12 REST
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    from_name: new_ansible_domain
    name: ansible_domain
    mtu: 1200
    ipspace: Default
    ports: ["khutton-vsim1:e0d-12"]
- name: Modify both broadcast domain and ipspace REST.
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    from_name: ansible_domain
    from_ipspace: Default
    name: ansible_domain_ip1
    ipspace: ipspace_1
    mtu: 1200
    ports: ["khutton-vsim1:e0d-12"]
- name: Modify ipspace only REST.
  netapp.ontap.na_ontap_broadcast_domain:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    from_ipspace: ipspace_1
    name: ansible_domain_ip1
    ipspace: Default
    mtu: 1200
    ports: ["khutton-vsim1:e0d-12"]
- name: Delete broadcast domain new_ansible_domain.
  netapp.ontap.na_ontap_broadcast_domain:
    state: absent
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    name: new_ansible_domain
    mtu: 1200
    ipspace: Default
    ports: ["khutton-vsim1:e0d-13", "khutton-vsim1:e0d-14"]
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


class NetAppOntapBroadcastDomain(object):
    """
        Create, Modifies and Destroys a Broadcast domain
    """
    def __init__(self):
        """
            Initialize the ONTAP Broadcast Domain class
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str', aliases=["broadcast_domain"]),
            ipspace=dict(required=False, type='str'),
            mtu=dict(required=False, type='int'),
            ports=dict(required=False, type='list', elements='str'),
            from_name=dict(required=False, type='str'),
            from_ipspace=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.desired_ports = None

        if self.use_rest and 'ipspace' not in self.parameters:
            error_msg = "Error: ipspace space is a required option with REST"
            self.module.fail_json(msg=error_msg)

        if 'ports' in self.parameters:
            self.parameters['ports'] = list(set([port.strip() for port in self.parameters['ports']]))
            if self.use_rest:
                self.desired_ports = self.get_ports_rest(self.parameters['ports'])

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
                if 'from_ipspace' in self.parameters:
                    self.parameters.pop('from_ipspace')
                    self.module.warn("from_ipspace is ignored when ZAPI is used.")

    def get_broadcast_domain(self, broadcast_domain=None, ipspace=None):
        """
        Return details about the broadcast domain
        :param broadcast_domain: specific broadcast domain to get.
        :return: Details about the broadcast domain. None if not found.
        :rtype: dict
        """
        if broadcast_domain is None:
            broadcast_domain = self.parameters['name']
        if ipspace is None:
            # unlike rest, ipspace is not mandatory field for zapi.
            ipspace = self.parameters.get('ipspace')
        if self.use_rest:
            return self.get_broadcast_domain_rest(broadcast_domain, ipspace)
        domain_get_iter = netapp_utils.zapi.NaElement('net-port-broadcast-domain-get-iter')
        broadcast_domain_info = netapp_utils.zapi.NaElement('net-port-broadcast-domain-info')
        broadcast_domain_info.add_new_child('broadcast-domain', broadcast_domain)
        if ipspace:
            broadcast_domain_info.add_new_child('ipspace', ipspace)
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(broadcast_domain_info)
        domain_get_iter.add_child_elem(query)
        result = self.server.invoke_successfully(domain_get_iter, True)
        domain_exists = None
        # check if broadcast_domain exists
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:
            domain_info = result.get_child_by_name('attributes-list').\
                get_child_by_name('net-port-broadcast-domain-info')
            domain_name = domain_info.get_child_content('broadcast-domain')
            domain_mtu = domain_info.get_child_content('mtu')
            domain_ipspace = domain_info.get_child_content('ipspace')
            domain_ports = domain_info.get_child_by_name('ports')
            if domain_ports is not None:
                ports = [port.get_child_content('port') for port in domain_ports.get_children()]
            else:
                ports = []
            domain_exists = {
                'domain-name': domain_name,
                'mtu': int(domain_mtu),
                'ipspace': domain_ipspace,
                'ports': ports
            }
        return domain_exists

    def get_broadcast_domain_rest(self, broadcast_domain, ipspace):
        api = 'network/ethernet/broadcast-domains'
        query = {'name': broadcast_domain, 'ipspace.name': ipspace}
        fields = 'uuid,name,ipspace,ports,mtu'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        if record:
            current = {
                'name': record['name'],
                'mtu': record['mtu'],
                'ipspace': record['ipspace']['name'],
                'uuid': record['uuid'],
                'ports': []
            }
            if 'ports' in record:
                current['ports'] = ['%s:%s' % (port['node']['name'], port['name']) for port in record['ports']]
            return current
        return None

    def create_broadcast_domain(self, ports=None):
        """
        Creates a new broadcast domain
        """
        if self.use_rest:
            return self.create_broadcast_domain_rest(ports)
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-create')
        domain_obj.add_new_child("broadcast-domain", self.parameters['name'])
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        if self.parameters.get('mtu'):
            domain_obj.add_new_child("mtu", str(self.parameters['mtu']))
        if self.parameters.get('ports'):
            ports_obj = netapp_utils.zapi.NaElement('ports')
            domain_obj.add_child_elem(ports_obj)
            for port in self.parameters['ports']:
                ports_obj.add_new_child('net-qualified-port-name', port)
        try:
            self.server.invoke_successfully(domain_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating broadcast domain %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_broadcast_domain_rest(self, ports=None):
        api = 'network/ethernet/broadcast-domains'
        body = {
            'name': self.parameters['name'],
            'mtu': self.parameters['mtu'],
            'ipspace': self.parameters['ipspace']
        }
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg=error)
        if ports:
            self.add_or_move_broadcast_domain_ports_rest(ports)

    def delete_broadcast_domain(self, broadcast_domain=None, current=None):
        """
        Deletes a broadcast domain
        """
        if self.use_rest:
            # all ports should be removed to delete broadcast domain in rest.
            if 'ports' in current:
                self.remove_broadcast_domain_ports_rest(current['ports'], current['ipspace'])
            api = 'network/ethernet/broadcast-domains'
            dummy, error = rest_generic.delete_async(self.rest_api, api, current['uuid'])
            if error:
                self.module.fail_json(msg=error)
        else:
            if broadcast_domain is None:
                broadcast_domain = self.parameters['name']
            domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-destroy')
            domain_obj.add_new_child("broadcast-domain", broadcast_domain)
            if self.parameters.get('ipspace'):
                domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
            try:
                self.server.invoke_successfully(domain_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error deleting broadcast domain %s: %s' %
                                      (broadcast_domain, to_native(error)),
                                      exception=traceback.format_exc())

    def modify_broadcast_domain(self):
        """
        Modifies ipspace and mtu options of a broadcast domain
        """
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-modify')
        domain_obj.add_new_child("broadcast-domain", self.parameters['name'])
        if self.parameters.get('mtu'):
            domain_obj.add_new_child("mtu", str(self.parameters['mtu']))
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        try:
            self.server.invoke_successfully(domain_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying broadcast domain %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def split_broadcast_domain(self):
        """
        split broadcast domain
        """
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-split')
        domain_obj.add_new_child("broadcast-domain", self.parameters['from_name'])
        domain_obj.add_new_child("new-broadcast-domain", self.parameters['name'])
        if self.parameters.get('ports'):
            ports_obj = netapp_utils.zapi.NaElement('ports')
            domain_obj.add_child_elem(ports_obj)
            for port in self.parameters['ports']:
                ports_obj.add_new_child('net-qualified-port-name', port)
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        try:
            self.server.invoke_successfully(domain_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error splitting broadcast domain %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if len(self.get_broadcast_domain_ports(self.parameters['from_name'])) == 0:
            self.delete_broadcast_domain(self.parameters['from_name'])

    def modify_broadcast_domain_or_ports(self, modify, current=None):
        """
        :param modify: modify attributes.
        """
        modify_keys = list(modify.keys())
        domain_modify_options = ['mtu', 'name', 'ipspace']
        if any(x in modify_keys for x in domain_modify_options):
            if self.use_rest:
                if modify.get('ports'):
                    del modify['ports']
                self.modify_broadcast_domain_rest(current['uuid'], modify)
                # update current ipspace as it required in modifying ports later.
                if modify.get('ipspace'):
                    current['ipspace'] = modify['ipspace']
            else:
                self.modify_broadcast_domain()
        if 'ports' in modify_keys:
            self.modify_broadcast_domain_ports(current)

    def get_modify_attributes(self, current, split):
        """
        :param current: current state.
        :param split: True or False of split action.
        :return: list of modified attributes.
        """
        modify = None
        if self.parameters['state'] == 'present':
            # split already handled ipspace and ports.
            if self.parameters.get('from_name'):
                if split:
                    modify = self.na_helper.get_modified_attributes(current, self.parameters)
                    if modify.get('ports'):
                        del modify['ports']
            else:
                modify = self.na_helper.get_modified_attributes(current, self.parameters)
        return modify

    def modify_broadcast_domain_ports(self, current=None):
        """
        compare current and desired ports. Call add or remove ports methods if needed.
        :return: None.
        """
        if self.use_rest:
            current_ports = current['ports']
        else:
            current_ports = self.get_broadcast_domain_ports()
        expect_ports = self.parameters['ports']
        # if want to remove all ports, simply delete the broadcast domain.
        if len(expect_ports) == 0:
            self.delete_broadcast_domain(current=current)
            return
        ports_to_remove = list(set(current_ports) - set(expect_ports))
        ports_to_add = list(set(expect_ports) - set(current_ports))

        if len(ports_to_add) > 0:
            if self.use_rest:
                ports = self.get_ports_rest(ports_to_add)
                if ports:
                    self.add_or_move_broadcast_domain_ports_rest(ports)
            else:
                self.add_broadcast_domain_ports(ports_to_add)

        if len(ports_to_remove) > 0:
            if self.use_rest:
                self.remove_broadcast_domain_ports_rest(ports_to_remove, current['ipspace'])
            else:
                self.delete_broadcast_domain_ports(ports_to_remove)

    def add_broadcast_domain_ports(self, ports):
        """
        Creates new broadcast domain ports
        """
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-add-ports')
        domain_obj.add_new_child("broadcast-domain", self.parameters['name'])
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        if ports:
            ports_obj = netapp_utils.zapi.NaElement('ports')
            domain_obj.add_child_elem(ports_obj)
            for port in ports:
                ports_obj.add_new_child('net-qualified-port-name', port)
        try:
            self.server.invoke_successfully(domain_obj, True)
            return True
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating port for broadcast domain %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_broadcast_domain_ports(self, ports):
        """
        Deletes broadcast domain ports
        :param: ports to be deleted.
        """
        domain_obj = netapp_utils.zapi.NaElement('net-port-broadcast-domain-remove-ports')
        domain_obj.add_new_child("broadcast-domain", self.parameters['name'])
        if self.parameters.get('ipspace'):
            domain_obj.add_new_child("ipspace", self.parameters['ipspace'])
        if ports:
            ports_obj = netapp_utils.zapi.NaElement('ports')
            domain_obj.add_child_elem(ports_obj)
            for port in ports:
                ports_obj.add_new_child('net-qualified-port-name', port)
        try:
            self.server.invoke_successfully(domain_obj, True)
            return True
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting port for broadcast domain %s: %s' %
                                  (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_broadcast_domain_ports(self, broadcast_domain=None):
        """
        Return details about the broadcast domain ports.
        :return: Details about the broadcast domain ports. None if not found.
        :rtype: list
        """
        if broadcast_domain is None:
            broadcast_domain = self.parameters['name']
        domain_get_iter = netapp_utils.zapi.NaElement('net-port-broadcast-domain-get-iter')
        broadcast_domain_info = netapp_utils.zapi.NaElement('net-port-broadcast-domain-info')
        broadcast_domain_info.add_new_child('broadcast-domain', broadcast_domain)
        if self.parameters.get('ipspace'):
            broadcast_domain_info.add_new_child('ipspace', self.parameters['ipspace'])
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

    def modify_broadcast_domain_rest(self, uuid, modify):
        api = 'network/ethernet/broadcast-domains'
        body = {}
        # rename broadcast domain.
        if 'name' in modify:
            body['name'] = modify['name']
        if 'ipspace' in modify:
            body['ipspace.name'] = modify['ipspace']
        if 'mtu' in modify:
            body['mtu'] = modify['mtu']
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid, body)
        if error:
            self.module.fail_json(msg=error)

    def add_or_move_broadcast_domain_ports_rest(self, ports):
        api = 'network/ethernet/ports'
        body = {
            'broadcast_domain': {
                'name': self.parameters['name'],
                'ipspace': {'name': self.parameters['ipspace']}
            }
        }
        for port in ports:
            dummy, error = rest_generic.patch_async(self.rest_api, api, port['uuid'], body)
            if error:
                self.module.fail_json(msg=error)

    def remove_broadcast_domain_ports_rest(self, ports, ipspace):
        body = {'ports': ports}
        api = "private/cli/network/port/broadcast-domain/remove-ports"
        query = {'broadcast-domain': self.parameters['name'], 'ipspace': ipspace}
        response, error = rest_generic.patch_async(self.rest_api, api, None, body, query)
        if error:
            self.module.fail_json(msg='Error removing ports: %s' % error)

    def get_ports_rest(self, ports):
        # if desired ports with uuid present then return only the ports to add or move.
        if self.desired_ports:
            return self.ports_to_add_move_from_desired(ports)
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
        port_name = port.split(':')[1]
        node = port.split(':')[0]
        api = 'network/ethernet/ports'
        query = {
            'name': port_name,
            'node.name': node,
        }
        fields = 'name,uuid'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        if record:
            current = {'uuid': record['uuid'], 'name': record['name'], 'node': record['node']}
            return current
        return None

    def ports_to_add_move_from_desired(self, ports):
        ports_to_add_move = []
        for port in ports:
            for port_to_add_or_move in self.desired_ports:
                if port == port_to_add_or_move['node']['name'] + ':' + port_to_add_or_move['name']:
                    ports_to_add_move.append({'uuid': port_to_add_or_move['uuid']})
        return ports_to_add_move

    def apply(self):
        """
        Run Module based on play book
        """
        current = self.get_broadcast_domain()
        cd_action, split = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and any(self.parameters.get(attr) is not None for attr in ('from_name', 'from_ipspace')):
            # either create new domain or split domain, also ipspace can be modified.
            from_name = self.parameters.get('from_name', self.parameters['name'])
            from_ipspace = self.parameters.get('from_ipspace', self.parameters.get('ipspace'))
            from_current = self.get_broadcast_domain(from_name, from_ipspace)
            split = self.na_helper.is_rename_action(from_current, current)
            if split is None:
                self.module.fail_json(msg='A domain cannot be split if it does not exist.',
                                      exception=traceback.format_exc())
            if split:
                cd_action = None
                current = from_current
                if self.use_rest:
                    split = False
                    # check for exact match of ports only if from_name present.
                    if self.parameters.get('from_name'):
                        # rename with no change in ports.
                        if 'ports' not in self.parameters:
                            self.parameters['ports'] = from_current['ports']
                        partial_match = set(from_current['ports']) - set(self.parameters['ports'])
                        # create new broadcast domain with desired ports (REST will move them over from the other domain if necessary)
                        if partial_match:
                            cd_action = 'create'
                            current = None
                        # rename with no change in ports.
                        else:
                            self.parameters.pop('from_name')
        modify = self.get_modify_attributes(current, split) if cd_action is None else {}
        if self.na_helper.changed and not self.module.check_mode:
            if split:
                self.split_broadcast_domain()
            if cd_action == 'create':
                self.create_broadcast_domain(self.desired_ports)
            elif cd_action == 'delete':
                self.delete_broadcast_domain(current=current)
            elif modify:
                self.modify_broadcast_domain_or_ports(modify, current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp ONTAP Broadcast Domain Object that can be created, deleted and modified.
    """
    obj = NetAppOntapBroadcastDomain()
    obj.apply()


if __name__ == '__main__':
    main()
