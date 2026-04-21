#!/usr/bin/python

# (c) 2017-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_cluster
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_cluster
short_description: NetApp ONTAP cluster - create a cluster and add/remove nodes.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create ONTAP cluster.
  - Add or remove cluster nodes using cluster_ip_address.
  - Adding a node requires ONTAP 9.3 or better.
  - Removing a node requires ONTAP 9.4 or better.
options:
  state:
    description:
      - Whether the specified cluster should exist (deleting a cluster is not supported).
      - Whether the node identified by its cluster_ip_address should be in the cluster or not.
    choices: ['present', 'absent']
    type: str
    default: present
  cluster_name:
    description:
      - The name of the cluster to manage.
    type: str
  cluster_ip_address:
    description:
      - intra cluster IP address of the node to be added or removed.
    type: str
  single_node_cluster:
    description:
      - Whether the cluster is a single node cluster.  Ignored for 9.3 or older versions.
      - If present, it was observed that 'Cluster' interfaces were deleted, whatever the value with ZAPI.
    version_added: 19.11.0
    type: bool
  cluster_location:
    description:
      - Cluster location, only relevant if performing a modify action.
    version_added: 19.11.0
    type: str
  cluster_contact:
    description:
      - Cluster contact, only relevant if performing a modify action.
    version_added: 19.11.0
    type: str
  node_name:
    description:
      - Name of the node to be added or removed from the cluster.
      - Be aware that when adding a node, '-' are converted to '_' by the ONTAP backend.
      - When creating a cluster, C(node_name) is ignored.
      - When adding a node using C(cluster_ip_address), C(node_name) is optional.
      - When used to remove a node, C(cluster_ip_address) and C(node_name) are mutually exclusive.
    version_added: 20.9.0
    type: str
  time_out:
    description:
      - time to wait for cluster creation in seconds.
      - Error out if task is not completed in defined time.
      - if 0, the request is asynchronous.
      - default is set to 3 minutes.
    default: 180
    type: int
    version_added: 21.1.0
  force:
    description:
      - forcibly remove a node that is down and cannot be brought online to remove its shared resources.
    default: false
    type: bool
    version_added: 21.13.0
  timezone:
    description: timezone for the cluster. Only supported by REST.
    type: dict
    version_added: 21.24.0
    suboptions:
      name:
        type: str
        description:
          - The timezone name must be
          - A geographic region, usually expressed as area/location
          - Greenwich Mean Time (GMT) or the difference in hours from GMT
          - A valid alias; that is, a term defined by the standard to refer to a geographic region or GMT
          - A system-specific or other term not associated with a geographic region or GMT
          - "full list of supported alias can be found here: https://library.netapp.com/ecmdocs/ECMP1155590/html/GUID-D3B8A525-67A2-4BEE-99DB-EF52D6744B5F.html"
          - Only supported by REST
  certificate:
    description:
      - Certificate used by cluster and node management interfaces for TLS connection requests.
      - Only supported with REST and requires ONTAP 9.10 or later.
    type: dict
    version_added: 22.9.0
    suboptions:
      uuid:
        type: str
        description:
          - Certificate UUID.
notes:
  - supports REST and ZAPI
'''

EXAMPLES = """
- name: Create cluster
  netapp.ontap.na_ontap_cluster:
    state: present
    cluster_name: new_cluster
    time_out: 0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Add node to cluster (Join cluster)
  netapp.ontap.na_ontap_cluster:
    state: present
    cluster_ip_address: 10.10.10.10
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Add node to cluster (Join cluster)
  netapp.ontap.na_ontap_cluster:
    state: present
    cluster_ip_address: 10.10.10.10
    node_name: my_preferred_node_name
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create a 2 node cluster in one call
  netapp.ontap.na_ontap_cluster:
    state: present
    cluster_name: new_cluster
    cluster_ip_address: 10.10.10.10
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Remove node from cluster
  netapp.ontap.na_ontap_cluster:
    state: absent
    cluster_ip_address: 10.10.10.10
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Remove node from cluster
  netapp.ontap.na_ontap_cluster:
    state: absent
    node_name: node002
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify cluster
  netapp.ontap.na_ontap_cluster:
    state: present
    cluster_contact: testing
    cluster_location: testing
    cluster_name: "{{ netapp_cluster}}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Updating the cluster-wide web services configuration
  netapp.ontap.na_ontap_cluster:
    state: present
    cluster_contact: testing
    cluster_location: testing
    certificate:
      uuid: 7f2f332c-933e-11ee-ab1c-005056b397ff
    cluster_name: "{{ netapp_cluster}}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import time
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPCluster:
    """
    object initialize and class methods
    """
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            cluster_name=dict(required=False, type='str'),
            cluster_ip_address=dict(required=False, type='str'),
            cluster_location=dict(required=False, type='str'),
            cluster_contact=dict(required=False, type='str'),
            certificate=dict(required=False, type='dict', options=dict(
                uuid=dict(required=False, type='str')
            )),
            force=dict(required=False, type='bool', default=False),
            single_node_cluster=dict(required=False, type='bool'),
            node_name=dict(required=False, type='str'),
            time_out=dict(required=False, type='int', default=180),
            timezone=dict(required=False, type='dict', options=dict(
                name=dict(type='str')
            ))
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.warnings = []
        # cached, so that we don't call the REST API more than once
        self.node_records = None

        self.rest_api = OntapRestAPI(self.module)
        partially_supported_rest_properties = [['certificate', (9, 10, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)

        if self.parameters['state'] == 'absent' and self.parameters.get('node_name') is not None and self.parameters.get('cluster_ip_address') is not None:
            msg = 'when state is "absent", parameters are mutually exclusive: cluster_ip_address|node_name'
            self.module.fail_json(msg=msg)

        if self.parameters.get('node_name') is not None and '-' in self.parameters.get('node_name'):
            self.warnings.append('ONTAP ZAPI converts "-" to "_", node_name: %s may be changed or not matched' % self.parameters.get('node_name'))

        if self.use_rest and self.parameters['state'] == 'absent' and not self.rest_api.meets_rest_minimum_version(True, 9, 7, 0):
            self.module.warn('switching back to ZAPI as DELETE is not supported on 9.6')
            self.use_rest = False
        if not self.use_rest:
            if self.na_helper.safe_get(self.parameters, ['timezone', 'name']):
                self.module.fail_json(msg='Timezone is only supported with REST')
            if self.na_helper.safe_get(self.parameters, ['certificate', 'uuid']):
                self.module.fail_json(msg='Certificate is only supported with REST')
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_cluster_identity_rest(self):
        ''' get cluster information, but the cluster may not exist yet
            return:
                None if the cluster cannot be reached
                a dictionary of attributes
        '''
        record, error = rest_generic.get_one_record(self.rest_api, 'cluster', fields='contact,location,name,timezone')
        if error:
            if 'are available in precluster.' in error:
                # assuming precluster state
                return None
            self.module.fail_json(msg='Error fetching cluster identity info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if record:
            cluster_info = {
                'cluster_contact': record.get('contact'),
                'cluster_location': record.get('location'),
                'cluster_name': record.get('name'),
                'timezone': self.na_helper.safe_get(record, ['timezone'])
            }
        if self.parameters.get('certificate') is not None:
            web_service_record = self.get_web_services()
            cluster_info.update(web_service_record)
        if cluster_info:
            return cluster_info
        return None

    def get_cluster_identity(self, ignore_error=True):
        ''' get cluster information, but the cluster may not exist yet
            return:
                None if the cluster cannot be reached
                a dictionary of attributes
        '''
        if self.use_rest:
            return self.get_cluster_identity_rest()

        zapi = netapp_utils.zapi.NaElement('cluster-identity-get')
        try:
            result = self.server.invoke_successfully(zapi, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if ignore_error:
                return None
            self.module.fail_json(msg='Error fetching cluster identity info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        cluster_identity = {}
        if result.get_child_by_name('attributes'):
            identity_info = result.get_child_by_name('attributes').get_child_by_name('cluster-identity-info')
            if identity_info:
                cluster_identity['cluster_contact'] = identity_info.get_child_content('cluster-contact')
                cluster_identity['cluster_location'] = identity_info.get_child_content('cluster-location')
                cluster_identity['cluster_name'] = identity_info.get_child_content('cluster-name')
            return cluster_identity
        return None

    def get_cluster_nodes_rest(self):
        ''' get cluster node names, but the cluster may not exist yet
            return:
                None if the cluster cannot be reached
                a list of nodes
        '''
        if self.node_records is None:
            records, error = rest_generic.get_0_or_more_records(self.rest_api, 'cluster/nodes', fields='name,uuid,cluster_interfaces')
            if error:
                self.module.fail_json(msg='Error fetching cluster node info: %s' % to_native(error),
                                      exception=traceback.format_exc())
            self.node_records = records or []
        return self.node_records

    def get_cluster_node_names_rest(self):
        ''' get cluster node names, but the cluster may not exist yet
            return:
                None if the cluster cannot be reached
                a list of nodes
        '''
        records = self.get_cluster_nodes_rest()
        return [record['name'] for record in records]

    def get_cluster_nodes(self, ignore_error=True):
        ''' get cluster node names, but the cluster may not exist yet
            return:
                None if the cluster cannot be reached
                a list of nodes
        '''
        if self.use_rest:
            return self.get_cluster_node_names_rest()

        zapi = netapp_utils.zapi.NaElement('cluster-node-get-iter')
        try:
            result = self.server.invoke_successfully(zapi, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if ignore_error:
                return None
            self.module.fail_json(msg='Error fetching cluster node info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('attributes-list'):
            cluster_nodes = []
            for node_info in result.get_child_by_name('attributes-list').get_children():
                node_name = node_info.get_child_content('node-name')
                if node_name is not None:
                    cluster_nodes.append(node_name)
            return cluster_nodes
        return None

    def get_cluster_ip_addresses_rest(self, cluster_ip_address):
        ''' get list of IP addresses for this cluster
            return:
                a list of dictionaries
        '''
        if_infos = []
        records = self.get_cluster_nodes_rest()
        for record in records:
            for interface in record.get('cluster_interfaces', []):
                ip_address = self.na_helper.safe_get(interface, ['ip', 'address'])
                if cluster_ip_address is None or ip_address == cluster_ip_address:
                    if_info = {
                        'address': ip_address,
                        'home_node': record['name'],
                    }
                    if_infos.append(if_info)
        return if_infos

    def get_cluster_ip_addresses(self, cluster_ip_address, ignore_error=True):
        ''' get list of IP addresses for this cluster
            return:
                a list of dictionaries
        '''
        if_infos = []
        zapi = netapp_utils.zapi.NaElement('net-interface-get-iter')
        if cluster_ip_address is not None:
            query = netapp_utils.zapi.NaElement('query')
            net_info = netapp_utils.zapi.NaElement('net-interface-info')
            net_info.add_new_child('address', cluster_ip_address)
            query.add_child_elem(net_info)
            zapi.add_child_elem(query)

        try:
            result = self.server.invoke_successfully(zapi, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if ignore_error:
                return if_infos
            self.module.fail_json(msg='Error getting IP addresses: %s' % to_native(error),
                                  exception=traceback.format_exc())

        if result.get_child_by_name('attributes-list'):
            for net_info in result.get_child_by_name('attributes-list').get_children():
                if net_info:
                    if_info = {'address': net_info.get_child_content('address')}
                    if_info['home_node'] = net_info.get_child_content('home-node')
                if_infos.append(if_info)
        return if_infos

    def get_cluster_ip_address(self, cluster_ip_address, ignore_error=True):
        ''' get node information if it is discoverable
            return:
                None if the cluster cannot be reached
                a dictionary of attributes
        '''
        if cluster_ip_address is None:
            return None
        if self.use_rest:
            nodes = self.get_cluster_ip_addresses_rest(cluster_ip_address)
        else:
            nodes = self.get_cluster_ip_addresses(cluster_ip_address, ignore_error=ignore_error)
        return nodes if len(nodes) > 0 else None

    def create_cluster_body(self, modify=None, nodes=None):
        body = {}
        params = modify if modify is not None else self.parameters
        for (param_key, rest_key) in {
            'cluster_contact': 'contact',
            'cluster_location': 'location',
            'cluster_name': 'name',
            'single_node_cluster': 'single_node_cluster',
            'timezone': 'timezone'
        }.items():
            if param_key in params:
                body[rest_key] = params[param_key]
        if nodes:
            body['nodes'] = nodes
        return body

    def create_node_body(self):
        node = {}
        for (param_key, rest_key) in {
            'cluster_ip_address': 'cluster_interface.ip.address',
            'cluster_location': 'location',
            'node_name': 'name'
        }.items():
            if param_key in self.parameters:
                node[rest_key] = self.parameters[param_key]
        return node

    def create_nodes(self):
        node = self.create_node_body()
        return [node] if node else None

    def create_cluster_rest(self, older_api=False):
        """
        Create a cluster
        """
        query = None
        body = self.create_cluster_body(nodes=self.create_nodes())
        if 'single_node_cluster' in body:
            query = {'single_node_cluster': body.pop('single_node_cluster')}
        dummy, error = rest_generic.post_async(self.rest_api, 'cluster', body, query, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error creating cluster %s: %s'
                                  % (self.parameters['cluster_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_cluster(self, older_api=False):
        """
        Create a cluster
        """
        if self.use_rest:
            return self.create_cluster_rest()

        # Note: cannot use node_name here:
        # 13001:The "-node-names" parameter must be used with either the "-node-uuids" or the "-cluster-ips" parameters.
        options = {'cluster-name': self.parameters['cluster_name']}
        if not older_api and self.parameters.get('single_node_cluster') is not None:
            options['single-node-cluster'] = str(self.parameters['single_node_cluster']).lower()
        cluster_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'cluster-create', **options)
        try:
            self.server.invoke_successfully(cluster_create,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if error.message == "Extra input: single-node-cluster" and not older_api:
                return self.create_cluster(older_api=True)
            # Error 36503 denotes node already being used.
            if to_native(error.code) == "36503":
                return False
            self.module.fail_json(msg='Error creating cluster %s: %s'
                                  % (self.parameters['cluster_name'], to_native(error)),
                                  exception=traceback.format_exc())
        return True

    def add_node_rest(self):
        """
        Add a node to an existing cluster
        """
        body = self.create_node_body()
        dummy, error = rest_generic.post_async(self.rest_api, 'cluster/nodes', body, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error adding node with ip %s: %s'
                                  % (self.parameters.get('cluster_ip_address'), to_native(error)),
                                  exception=traceback.format_exc())

    def add_node(self, older_api=False):
        """
        Add a node to an existing cluster
        9.2 and 9.3 do not support cluster-ips so fallback to node-ip
        """
        if self.use_rest:
            return self.add_node_rest()

        if self.parameters.get('cluster_ip_address') is None:
            return False
        cluster_add_node = netapp_utils.zapi.NaElement('cluster-add-node')
        if older_api:
            cluster_add_node.add_new_child('node-ip', self.parameters.get('cluster_ip_address'))
        else:
            cluster_ips = netapp_utils.zapi.NaElement.create_node_with_children('cluster-ips', **{'ip-address': self.parameters.get('cluster_ip_address')})
            cluster_add_node.add_child_elem(cluster_ips)
            if self.parameters.get('node_name') is not None:
                node_names = netapp_utils.zapi.NaElement.create_node_with_children('node-names', **{'string': self.parameters.get('node_name')})
                cluster_add_node.add_child_elem(node_names)

        try:
            self.server.invoke_successfully(cluster_add_node, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if error.message == "Extra input: cluster-ips" and not older_api:
                return self.add_node(older_api=True)
            # skip if error says no failed operations to retry.
            if to_native(error) == "NetApp API failed. Reason - 13001:There are no failed \"cluster create\" or \"cluster add-node\" operations to retry.":
                return False
            self.module.fail_json(msg='Error adding node with ip %s: %s'
                                  % (self.parameters.get('cluster_ip_address'), to_native(error)),
                                  exception=traceback.format_exc())
        return True

    def get_uuid_from_ip(self, ip_address):
        for node in self.get_cluster_nodes_rest():
            if ip_address in (interface['ip']['address'] for interface in node['cluster_interfaces']):
                return node['uuid']
        return None

    def get_uuid_from_name(self, node_name):
        for node in self.get_cluster_nodes_rest():
            if node_name == node['name']:
                return node['uuid']
        return None

    def get_uuid(self):
        if self.parameters.get('cluster_ip_address') is not None:
            from_node = self.parameters['cluster_ip_address']
            uuid = self.get_uuid_from_ip(from_node)
        elif self.parameters.get('node_name') is not None:
            from_node = self.parameters['node_name']
            uuid = self.get_uuid_from_name(from_node)
        else:
            # Unexpected, for delete one of cluster_ip_address, node_name is required.
            uuid = None
        if uuid is None:
            self.module.fail_json(msg='Internal error, cannot find UUID in %s: for %s or %s'
                                  % (self.get_cluster_nodes_rest(), self.parameters['cluster_ip_address'], self.parameters.get('node_name') is not None),
                                  exception=traceback.format_exc())
        return uuid, from_node

    def get_web_services(self):
        record, error = rest_generic.get_one_record(self.rest_api, 'cluster/web', fields='certificate')
        if error:
            self.module.fail_json(msg='Error fetching cluster web service config: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if record:
            return record
        return None

    def modify_web_services(self):
        body = {
            'certificate': {
                'uuid': self.parameters['certificate']['uuid']
            }
        }
        dummy, error = rest_generic.patch_async(self.rest_api, 'cluster/web', None, body)
        if error:
            self.module.fail_json(msg='Error modifying cluster web service config for %s: %s'
                                  % (self.parameters['cluster_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def remove_node_rest(self):
        """
        Remove a node from an existing cluster
        """
        uuid, from_node = self.get_uuid()
        query = {'force': True} if self.parameters.get('force') else None
        dummy, error = rest_generic.delete_async(self.rest_api, 'cluster/nodes', uuid, query, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error removing node with %s: %s'
                                  % (from_node, to_native(error)), exception=traceback.format_exc())

    def remove_node(self):
        """
        Remove a node from an existing cluster
        """
        if self.use_rest:
            return self.remove_node_rest()

        cluster_remove_node = netapp_utils.zapi.NaElement('cluster-remove-node')
        from_node = ''
        # cluster-ip and node-name are mutually exclusive:
        # 13115:Element "cluster-ip" within "cluster-remove-node" has been excluded by another element.
        if self.parameters.get('cluster_ip_address') is not None:
            cluster_remove_node.add_new_child('cluster-ip', self.parameters.get('cluster_ip_address'))
            from_node = 'IP: %s' % self.parameters.get('cluster_ip_address')
        elif self.parameters.get('node_name') is not None:
            cluster_remove_node.add_new_child('node', self.parameters.get('node_name'))
            from_node = 'name: %s' % self.parameters.get('node_name')
        if self.parameters.get('force'):
            cluster_remove_node.add_new_child('force', 'true')

        try:
            self.server.invoke_successfully(cluster_remove_node, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if error.message == "Unable to find API: cluster-remove-node":
                msg = 'Error: ZAPI is not available.  Removing a node requires ONTAP 9.4 or newer.'
                self.module.fail_json(msg=msg)
            self.module.fail_json(msg='Error removing node with %s: %s'
                                  % (from_node, to_native(error)), exception=traceback.format_exc())

    def modify_cluster_identity_rest(self, modify):
        """
        Modifies the cluster identity
        """
        if 'certificate' in modify:
            self.modify_web_services()
        body = self.create_cluster_body(modify)
        dummy, error = rest_generic.patch_async(self.rest_api, 'cluster', None, body)
        if error:
            self.module.fail_json(msg='Error modifying cluster identity details %s: %s'
                                  % (self.parameters['cluster_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_cluster_identity(self, modify):
        """
        Modifies the cluster identity
        """
        if self.use_rest:
            return self.modify_cluster_identity_rest(modify)

        cluster_modify = netapp_utils.zapi.NaElement('cluster-identity-modify')
        if modify.get('cluster_name') is not None:
            cluster_modify.add_new_child("cluster-name", modify.get('cluster_name'))
        if modify.get('cluster_location') is not None:
            cluster_modify.add_new_child("cluster-location", modify.get('cluster_location'))
        if modify.get('cluster_contact') is not None:
            cluster_modify.add_new_child("cluster-contact", modify.get('cluster_contact'))

        try:
            self.server.invoke_successfully(cluster_modify,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying cluster idetity details %s: %s'
                                  % (self.parameters['cluster_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def cluster_create_wait(self):
        """
        Wait whilst cluster creation completes
        """
        if self.use_rest:
            # wait is part of post_async for REST
            return

        cluster_wait = netapp_utils.zapi.NaElement('cluster-create-join-progress-get')
        is_complete = False
        status = ''
        retries = self.parameters['time_out']
        errors = []
        while not is_complete and status not in ('failed', 'success') and retries > 0:
            retries = retries - 10
            time.sleep(10)
            try:
                result = self.server.invoke_successfully(cluster_wait, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                # collecting errors, and retrying
                errors.append(repr(error))
                continue

            clus_progress = result.get_child_by_name('attributes')
            result = clus_progress.get_child_by_name('cluster-create-join-progress-info')
            is_complete = self.na_helper.get_value_for_bool(from_zapi=True,
                                                            value=result.get_child_content('is-complete'))
            status = result.get_child_content('status')

        if self.parameters['time_out'] == 0:
            is_complete = True
        if not is_complete and status != 'success':
            current_status_message = result.get_child_content('current-status-message')
            errors.append('Failed to confirm cluster creation %s: %s' % (self.parameters.get('cluster_name'), current_status_message))
            if retries <= 0:
                errors.append("Timeout after %s seconds" % self.parameters['time_out'])
            self.module.fail_json(msg='Error creating cluster %s: %s'
                                  % (self.parameters['cluster_name'], str(errors)))

        return is_complete

    def node_add_wait(self):
        """
        Wait whilst node is being added to the existing cluster
        """
        if self.use_rest:
            # wait is part of post_async for REST
            return

        cluster_node_status = netapp_utils.zapi.NaElement('cluster-add-node-status-get-iter')
        node_status_info = netapp_utils.zapi.NaElement('cluster-create-add-node-status-info')
        node_status_info.add_new_child('cluster-ip', self.parameters.get('cluster_ip_address'))
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(node_status_info)
        cluster_node_status.add_child_elem(query)

        is_complete = None
        failure_msg = None
        retries = self.parameters['time_out']
        errors = []
        while is_complete != 'success' and is_complete != 'failure' and retries > 0:
            retries = retries - 10
            time.sleep(10)
            try:
                result = self.server.invoke_successfully(cluster_node_status, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                if error.message == "Unable to find API: cluster-add-node-status-get-iter":
                    # This API is not supported for 9.3 or earlier releases, just wait a bit
                    time.sleep(60)
                    return
                # collecting errors, and retrying
                errors.append(repr(error))
                continue

            attributes_list = result.get_child_by_name('attributes-list')
            join_progress = attributes_list.get_child_by_name('cluster-create-add-node-status-info')
            is_complete = join_progress.get_child_content('status')
            failure_msg = join_progress.get_child_content('failure-msg')

        if self.parameters['time_out'] == 0:
            is_complete = 'success'
        if is_complete != 'success':
            if 'Node is already in a cluster' in failure_msg:
                return
            elif retries <= 0:
                errors.append("Timeout after %s seconds" % self.parameters['time_out'])
            if failure_msg:
                errors.append(failure_msg)
            self.module.fail_json(msg='Error adding node with ip address %s: %s'
                                  % (self.parameters['cluster_ip_address'], str(errors)))

    def node_remove_wait(self):
        ''' wait for node name or clister IP address to disappear '''
        if self.use_rest:
            # wait is part of delete_async for REST
            return

        node_name = self.parameters.get('node_name')
        node_ip = self.parameters.get('cluster_ip_address')
        retries = self.parameters['time_out']
        while retries > 0:
            retries = retries - 10
            if node_name is not None and node_name not in self.get_cluster_nodes():
                return
            if node_ip is not None and self.get_cluster_ip_address(node_ip) is None:
                return
            time.sleep(10)
        self.module.fail_json(msg='Timeout waiting for node to be removed from cluster.')

    def get_cluster_action(self, cluster_identity):
        cluster_action = None
        if self.parameters.get('cluster_name') is not None:
            cluster_action = self.na_helper.get_cd_action(cluster_identity, self.parameters)
            if cluster_action == 'delete':
                # delete only applies to node
                cluster_action = None
                self.na_helper.changed = False
        return cluster_action

    def get_node_action(self):
        node_action = None
        if self.parameters.get('cluster_ip_address') is not None:
            existing_interfaces = self.get_cluster_ip_address(self.parameters.get('cluster_ip_address'))
            if self.parameters.get('state') == 'present':
                node_action = 'add_node' if existing_interfaces is None else None
            else:
                node_action = 'remove_node' if existing_interfaces is not None else None
        if self.parameters.get('node_name') is not None and self.parameters['state'] == 'absent':
            nodes = self.get_cluster_nodes()
            if self.parameters.get('node_name') in nodes:
                node_action = 'remove_node'
        if node_action is not None:
            self.na_helper.changed = True
        return node_action

    def apply(self):
        """
        Apply action to cluster
        """
        cluster_identity = self.get_cluster_identity(ignore_error=True)
        cluster_action = self.get_cluster_action(cluster_identity)
        node_action = self.get_node_action()
        modify = self.na_helper.get_modified_attributes(cluster_identity, self.parameters)

        if not self.module.check_mode:
            if cluster_action == 'create' and self.create_cluster():
                self.cluster_create_wait()
            if node_action == 'add_node':
                if self.add_node():
                    self.node_add_wait()
            elif node_action == 'remove_node':
                self.remove_node()
                self.node_remove_wait()
            if modify:
                self.modify_cluster_identity(modify)

        results = {'changed': self.na_helper.changed}
        if self.warnings:
            results['warnings'] = self.warnings
        if netapp_utils.has_feature(self.module, 'show_modified'):
            results['modify'] = modify
        self.module.exit_json(**results)


def main():
    """
    Create object and call apply
    """
    cluster_obj = NetAppONTAPCluster()
    cluster_obj.apply()


if __name__ == '__main__':
    main()
