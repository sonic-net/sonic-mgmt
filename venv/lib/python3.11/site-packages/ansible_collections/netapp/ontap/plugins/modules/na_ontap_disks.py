#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_disks

short_description: NetApp ONTAP Assign disks to nodes
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Assign disks to a node.
- Disk autoassign must be turned off before using this module to prevent the disks being reassigned automatically by the cluster.
- This can be done through na_ontap_disk_options or via the cli "disk option modify -node <node_name> -autoassign off".
- If min_spares is not specified min_spares default is 1 if SSD or 2 for any other disk type.
- If disk_count is not specified all unassigned disks will be assigned to the node specified.

options:
  node:
    required: true
    type: str
    description:
    - The node that we want to assign/unassign disks.

  disk_count:
    description:
    - Total number of disks a node should own.
    type: int
    version_added: 2.9.0

  disk_type:
    description:
    - Assign specified type of disk (or set of disks).
    type: str
    choices: ['ATA', 'BSAS', 'FCAL', 'FSAS', 'LUN', 'MSATA', 'SAS', 'SSD', 'SSD_NVM', 'VMDISK', 'unknown']
    version_added: 20.6.0

  min_spares:
    description:
    - Minimum spares required per type for the node.
    type: int
    version_added: 21.7.0

'''

EXAMPLES = """
- name: Assign specified total disks to node
  netapp.ontap.na_ontap_disks:
    node: node1
    disk_count: 56
    disk_type: VMDISK
    min_spares: 2
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Assign all unassigned disks to node1
  netapp.ontap.na_ontap_disks:
    node: node1
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
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapDisks():
    ''' object initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            node=dict(required=True, type='str'),
            disk_count=dict(required=False, type='int'),
            disk_type=dict(required=False, type='str', choices=['ATA', 'BSAS', 'FCAL', 'FSAS', 'LUN', 'MSATA', 'SAS', 'SSD', 'SSD_NVM', 'VMDISK', 'unknown']),
            min_spares=dict(required=False, type='int')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # If min_spares is not specified min_spares is 1 if SSD, min_spares is 2 for any other disk type.
        self.parameters['min_spares'] = 1 if self.parameters.get('disk_type') in ('SSD', 'SSD_NVM') else 2

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    def get_disks(self, container_type, node=None):
        """
        Check for owned disks, unassigned disks or spare disks.
        Return: list of disks or an empty list
        """
        if self.use_rest:
            api = "storage/disks"
            if container_type == 'owned':
                query = {
                    'home_node.name': node,
                    'container_type': '!unassigned',
                    'fields': 'name'
                }
            if container_type == 'unassigned':
                query = {
                    'container_type': 'unassigned',
                    'fields': 'name'
                }
            if container_type == 'spare':
                query = {
                    'home_node.name': node,
                    'container_type': 'spare',
                    'fields': 'name'
                }
            if 'disk_type' in self.parameters:
                query['type'] = self.parameters['disk_type']

            message, error = self.rest_api.get(api, query)
            records, error = rrh.check_for_0_or_more_records(api, message, error)

            if error:
                self.module.fail_json(msg=error)

            return records if records else list()

        else:
            disk_iter = netapp_utils.zapi.NaElement('storage-disk-get-iter')
            disk_storage_info = netapp_utils.zapi.NaElement('storage-disk-info')

            if container_type == 'owned':
                disk_ownership_info = netapp_utils.zapi.NaElement('disk-ownership-info')
                disk_ownership_info.add_new_child('home-node-name', self.parameters['node'])
                disk_storage_info.add_child_elem(disk_ownership_info)
            if container_type == 'unassigned':
                disk_raid_info = netapp_utils.zapi.NaElement('disk-raid-info')
                disk_raid_info.add_new_child('container-type', 'unassigned')
                disk_storage_info.add_child_elem(disk_raid_info)

            disk_query = netapp_utils.zapi.NaElement('query')

            if 'disk_type' in self.parameters and container_type in ('unassigned', 'owned'):
                disk_inventory_info = netapp_utils.zapi.NaElement('disk-inventory-info')
                disk_inventory_info.add_new_child('disk-type', self.parameters['disk_type'])
                disk_query.add_child_elem(disk_inventory_info)

            if container_type == 'spare':
                disk_ownership_info = netapp_utils.zapi.NaElement('disk-ownership-info')
                disk_raid_info = netapp_utils.zapi.NaElement('disk-raid-info')
                disk_ownership_info.add_new_child('owner-node-name', node)
                if 'disk_type' in self.parameters:
                    disk_inventory_info = netapp_utils.zapi.NaElement('disk-inventory-info')
                    disk_inventory_info.add_new_child('disk-type', self.parameters['disk_type'])
                    disk_storage_info.add_child_elem(disk_inventory_info)

                disk_raid_info.add_new_child('container-type', 'spare')
                disk_storage_info.add_child_elem(disk_ownership_info)
                disk_storage_info.add_child_elem(disk_raid_info)

            disk_query.add_child_elem(disk_storage_info)
            disk_iter.add_child_elem(disk_query)

            try:
                result = self.server.invoke_successfully(disk_iter, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error getting disk information: %s' % (to_native(error)),
                                      exception=traceback.format_exc())

            disks = []

            if result.get_child_by_name('attributes-list'):
                attributes_list = result.get_child_by_name('attributes-list')
                storage_disk_info_attributes = attributes_list.get_children()

                for disk in storage_disk_info_attributes:
                    disk_inventory_info = disk.get_child_by_name('disk-inventory-info')
                    disk_name = disk_inventory_info.get_child_content('disk-cluster-name')
                    disks.append(disk_name)

            return disks

    def get_partner_node_name(self):
        """
        return: partner_node_name, str
        """
        if self.use_rest:
            api = "/cluster/nodes"
            query = {
                'ha.partners.name': self.parameters['node']
            }
            message, error = self.rest_api.get(api, query)
            records, error = rrh.check_for_0_or_more_records(api, message, error)
            if error:
                self.module.fail_json(msg=error)

            return records[0]['name'] if records else None

        else:
            partner_name = None
            cf_status = netapp_utils.zapi.NaElement('cf-status')
            cf_status.add_new_child('node', self.parameters['node'])

            try:
                result = self.server.invoke_successfully(cf_status, True)

                if result.get_child_by_name('partner-name'):
                    partner_name = result.get_child_content('partner-name')

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error getting partner name for node %s: %s' % (self.parameters['node'], to_native(error)),
                                      exception=traceback.format_exc())

            return partner_name

    def disk_assign(self, needed_disks):
        """
        Assign disks to node
        """
        if self.use_rest:
            api = "private/cli/storage/disk/assign"
            if needed_disks > 0:
                body = {
                    'owner': self.parameters['node'],
                    'count': needed_disks
                }
                if 'disk_type' in self.parameters:
                    body['type'] = self.parameters['disk_type']
            else:
                body = {
                    'node': self.parameters['node'],
                    'all': True
                }

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

        else:
            if needed_disks > 0:
                assign_disk = netapp_utils.zapi.NaElement.create_node_with_children(
                    'disk-sanown-assign', **{'owner': self.parameters['node'],
                                             'disk-count': str(needed_disks)})
                if 'disk_type' in self.parameters:
                    assign_disk.add_new_child('disk-type', self.parameters['disk_type'])
            else:
                assign_disk = netapp_utils.zapi.NaElement.create_node_with_children(
                    'disk-sanown-assign', **{'node-name': self.parameters['node'],
                                             'all': 'true'})

            try:
                self.server.invoke_successfully(assign_disk,
                                                enable_tunneling=True)
                return True
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error assigning disks %s' % (to_native(error)),
                                      exception=traceback.format_exc())

    def disk_unassign(self, disks):
        """
        Unassign disks.
        Disk autoassign must be turned off when removing ownership of a disk
        """
        if self.use_rest:
            api = "private/cli/storage/disk/removeowner"
            for disk in disks:  # api requires 1 disk to be removed at a time.
                body = {
                    'disk': disk['name']
                }
                dummy, error = self.rest_api.post(api, body)
                if error:
                    self.module.fail_json(msg=error)

        else:
            unassign_partitions = netapp_utils.zapi.NaElement('disk-sanown-remove-ownership')
            disk_list = netapp_utils.zapi.NaElement('disk-list')

            for disk in disks:
                disk_list.add_new_child('disk-name', disk)

            unassign_partitions.add_child_elem(disk_list)

            try:
                self.server.invoke_successfully(unassign_partitions, enable_tunneling=True)

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error unassigning disks %s' % to_native(error))
            return True

    def apply(self):
        '''Apply action to disks'''
        changed = False

        owned_disks = self.get_disks(container_type='owned', node=self.parameters['node'])
        owned_disks_count = len(owned_disks)
        unassigned_disks = self.get_disks(container_type='unassigned')
        owned_spare_disks = self.get_disks(container_type='spare', node=self.parameters['node'])

        needed_disks = None
        unassign = {
            'spare_disks': None,
            'unassign_disks': None
        }

        # unassign disks if more disks are currently owned than requested.
        if 'disk_count' in self.parameters:
            if self.parameters['disk_count'] < owned_disks_count:
                unassign_disks_count = owned_disks_count - self.parameters['disk_count']
                # check to make sure we will have sufficient spares after the removal.
                if unassign_disks_count > (len(owned_spare_disks) - self.parameters['min_spares']):
                    self.module.fail_json(msg="disk removal would leave less than %s spares" % self.parameters['min_spares'])
                # unassign disks.
                unassign = {
                    'spare_disks': owned_spare_disks,
                    'unassign_disks': unassign_disks_count
                }

            # take spare disks from partner so they can be reassigned to the desired node.
            elif self.parameters['disk_count'] > (owned_disks_count + len(unassigned_disks)):
                required_disks_count = self.parameters['disk_count'] - (owned_disks_count + len(unassigned_disks))
                partner_node_name = self.get_partner_node_name()
                partner_spare_disks = self.get_disks(container_type='spare', node=partner_node_name)

                if required_disks_count > (len(partner_spare_disks) - self.parameters['min_spares']):
                    self.module.fail_json(msg="not enough disks available")
                else:
                    unassign = {
                        'spare_disks': partner_spare_disks,
                        'unassign_disks': required_disks_count
                    }

            # assign disks to node.
            if self.parameters['disk_count'] > owned_disks_count:
                needed_disks = self.parameters['disk_count'] - owned_disks_count

        else:
            if len(unassigned_disks) >= 1:
                # assign all unassigned disks to node
                needed_disks = 0

        # unassign
        if unassign['spare_disks'] and unassign['unassign_disks']:
            if not self.module.check_mode:
                self.disk_unassign(unassign['spare_disks'][0:unassign['unassign_disks']])
            changed = True
        # assign
        if needed_disks is not None:
            if not self.module.check_mode:
                self.disk_assign(needed_disks)
            changed = True

        self.module.exit_json(changed=changed)


def main():
    ''' Create object and call apply '''
    obj_aggr = NetAppOntapDisks()
    obj_aggr.apply()


if __name__ == '__main__':
    main()
