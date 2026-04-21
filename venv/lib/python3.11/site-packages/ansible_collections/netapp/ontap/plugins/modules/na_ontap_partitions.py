#!/usr/bin/python

# (c) 2021-2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_partitions

short_description: NetApp ONTAP Assign partitions and disks to nodes.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Assign the specified number of partitions or disks eligible for partitioning to a node.
- There is some overlap between this module and the na_ontap_disks module.
- If you don't have ADP v1 or v2 then you should be using the na_ontap_disks module to assign whole disks.
- Partitions/disks are added in the following order
- 1.    Any unassigned partitions are added.
- 2.    Any unassigned disks of the correct type are added and will be partitioned when added to an aggregate if required.
- 3.    Any spare partner partitions will be re-assigned.
- 4.    Any partner spare disks will be re-assigned and be partitioned when added to an aggregate.
- If you specify a partition_count less than the current number of partitions, then spare partitions will be unassigned.
- If a previously partitioned disk has the partitions removed, and even if it is "slow zeroed" the system \
  will consider it a shared partitioned disk rather than a spare.
- In a root-data-data configuration (ADPv2) if you specify data1 as the partition_type then only P1 partitions will be counted.
- Disk autoassign must be turned off before using this module to prevent the disks being reassigned automatically by the cluster.
- This can be done through na_ontap_disk_options or via the cli "disk option modify -node <node_name> -autoassign off".

options:
  node:
    required: true
    type: str
    description:
    - Specifies the node that the partitions and disks should be assigned to.

  partition_count:
    required: true
    type: int
    description:
    - Total number of partitions that should be assigned to the owner.

  disk_type:
    required: true
    choices: ["ATA", "BSAS", "FCAL", "FSAS", "LUN", "MSATA", "SAS", "SSD", "SSD_NVM", "VMDISK", "unknown"]
    type: str
    description:
    - The type of disk that the partitions that should use.

  partition_type:
    required: true
    choices: ["data", "root", "data1", "data2"]
    type: str
    description:
    - The type of partiton being assigned either root, data, data1 or data2,

  partitioning_method:
    required: true
    choices: ["root_data", "root_data1_data2"]
    type: str
    description:
    - The type of partiton method being used, either root_data or root_data1_data2.

  min_spares:
    description:
    - Minimum spares disks or partitions required per type for the node.
    type: int

'''

EXAMPLES = """
- name: Assign specified total partitions to node cluster-01
  netapp.ontap.na_ontap_partitions:
    node: cluster-01
    partition_count: 56
    disk_type: SSD
    partition_type: data1
    partition_method: root_data1_data2
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapPartitions():
    ''' object initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            node=dict(required=True, type='str'),
            partition_count=dict(required=True, type='int'),
            disk_type=dict(required=True, type='str', choices=['ATA', 'BSAS', 'FCAL', 'FSAS', 'LUN', 'MSATA', 'SAS', 'SSD', 'SSD_NVM', 'VMDISK', 'unknown']),
            partition_type=dict(required=True, type='str', choices=['data1', 'data2', 'data', 'root']),
            partitioning_method=dict(required=True, type='str', choices=['root_data1_data2', 'root_data']),
            min_spares=dict(required=False, type='int')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # If min_spares is not specified min_spares is 1 if SSD, min_spares is 2 for any other disk type.
        if 'min_spares' not in self.parameters:
            if self.parameters['disk_type'] in ('SSD', 'SSD_NVM'):
                self.parameters['min_spares'] = 1
            else:
                self.parameters['min_spares'] = 2

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            self.module.fail_json(msg=self.rest_api.requires_ontap_version('na_ontap_partitions', '9.6'))

    def get_disks(self, container_type, node=None):
        """
        Check for owned disks, unassigned disks or spare disks.
        Return: list of disks or an empty list
        """
        api = 'storage/disks'

        if container_type == 'unassigned':
            query = {
                'container_type': 'unassigned',
                'type': self.parameters['disk_type'],
                'fields': 'name'
            }
        if container_type == 'spare':
            query = {
                'home_node.name': node,
                'container_type': 'spare',
                'type': self.parameters['disk_type'],
                'fields': 'name'
            }
        message, error = self.rest_api.get(api, query)
        records, error = rrh.check_for_0_or_more_records(api, message, error)

        if error:
            self.module.fail_json(msg=error)

        return records if records else list()

    def get_partitions(self, container_type, node=None):
        """
        Get partitions info
        Return: list of partitions of a specified container type or None.
        """
        api = 'private/cli/storage/disk/partition'

        query = {}

        if container_type == 'spare':
            query = {
                'fields': 'partition,container-type,disk-type,partitioning-method,home-node-name,is-root,owner-node-name',
                'home-node-name': node,
                'disk-type': self.parameters['disk_type'],
                'container-type': 'spare',
                'partitioning-method': self.parameters['partitioning_method']
            }
        if container_type == 'unassigned':
            query = {
                'fields': 'partition,container-type,disk-type,partitioning-method,home-node-name,is-root,owner-node-name',
                'nodelist': node,
                'disk-type': self.parameters['disk_type'],
                'container-type': 'unassigned'
            }
        if container_type == 'owner':
            query = {
                'fields': 'partition,container-type,disk-type,partitioning-method,home-node-name,is-root,owner-node-name',
                'home-node-name': node,
                'disk-type': self.parameters['disk_type'],
                'partitioning-method': self.parameters['partitioning_method']
            }

        if self.parameters['partition_type'] == 'root':
            query['is-root'] = True
        else:
            query['is-root'] = False

        message, error = self.rest_api.get(api, query)
        records, error = rrh.check_for_0_or_more_records(api, message, error)
        if error:
            self.module.fail_json(msg=error)

        if records:
            if self.parameters['partitioning_method'] == 'root_data1_data2':
                # get just the P1 or P2 partitions
                data_partitions = []
                for record in records:
                    if self.parameters['partition_type'] == 'data1' and record['partition'].endswith('P1'):
                        data_partitions.append(record)
                    elif self.parameters['partition_type'] == 'data2' and record['partition'].endswith('P2'):
                        data_partitions.append(record)
                return data_partitions

            return records
        else:
            return list()

    def get_partner_node_name(self):
        """
        return: partner_node_name, str
        """
        api = 'cluster/nodes'
        query = {
            'ha.partners.name': self.parameters['node']
        }
        message, error = self.rest_api.get(api, query)
        records, error = rrh.check_for_0_or_more_records(api, message, error)

        if error:
            self.module.fail_json(msg=error)

        return records[0]['name'] if records else None

    def assign_disks(self, disks):
        """
        Assign disks to node
        """
        api = 'private/cli/storage/disk/assign'
        for disk in disks:
            body = {
                'owner': self.parameters['node'],
                'disk': disk['name']
            }

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

    def unassign_disks(self, disks):
        """
        Unassign disks.
        Disk autoassign must be turned off when removing ownership of a disk
        """
        api = 'private/cli/storage/disk/removeowner'
        for disk in disks:  # api requires 1 disk to be removed at a time.
            body = {
                'disk': disk['name']
            }
            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

    def assign_partitions(self, required_partitions):
        """
        Assign partitions to node
        """
        api = 'private/cli/storage/disk/partition/assign'
        for required_partition in required_partitions:
            body = {
                'owner': self.parameters['node'],
                'partition': required_partition['partition']
            }

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

    def unassign_partitions(self, required_partitions):
        """
        Unassign partitions from node
        """
        api = 'private/cli/storage/disk/partition/removeowner'
        for required_partition in required_partitions:
            body = {
                'partition': required_partition['partition']
            }

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)

    def determine_assignment(self, owned_partitions, own_spare_disks):
        """
        Determine which action to take
        return: dict containing lists of the disks/partitions to be assigned/reassigned
        """
        # build dict of partitions and disks to be unassigned/assigned
        assignment = {
            'required_unassigned_partitions': [],
            'required_partner_spare_disks': [],
            'required_partner_spare_partitions': [],
            'required_unassigned_disks': []
        }

        unassigned_partitions = self.get_partitions(container_type='owned', node=self.parameters['node'])
        required_partitions = self.parameters['partition_count'] - (len(owned_partitions) + len(own_spare_disks))

        # are there enough unassigned partitions to meet the requirement?
        if required_partitions > len(unassigned_partitions):
            assignment['required_unassigned_partitions'] = unassigned_partitions
            # check for unassigned disks
            unassigned_disks = self.get_disks(container_type='spare')
            required_unassigned_disks = required_partitions - len(unassigned_partitions)
            if required_unassigned_disks > len(unassigned_disks):
                assignment['required_unassigned_disks'] = unassigned_disks
                # not enough unassigned disks
                required_partner_spare_partitions = required_unassigned_disks - len(unassigned_disks)
                partner_node_name = self.get_partner_node_name()
                if partner_node_name:
                    partner_spare_partitions = self.get_partitions(container_type='spare', node=partner_node_name)
                    partner_spare_disks = self.get_disks(container_type='spare', node=partner_node_name)
                else:
                    partner_spare_partitions = []
                    partner_spare_disks = []
                # check for partner spare partitions
                if required_partner_spare_partitions <= (len(partner_spare_partitions) - self.parameters['min_spares']):
                    # we have enough spare partitions and dont need any disks
                    assignment['required_partner_spare_partitions'] = partner_spare_partitions[0:required_partner_spare_partitions]
                else:
                    # we don't know if we can take all of the spare partitions as we don't know how many spare disks there are
                    # spare partions != spare disks
                    if len(partner_spare_disks) >= self.parameters['min_spares']:
                        # we have enough spare disks so can use all spare partitions if required
                        if required_partner_spare_partitions <= len(partner_spare_partitions):
                            # now we know we have spare disks we can take as may spare partitions as we need
                            assignment['required_partner_spare_partitions'] = partner_spare_partitions[0:required_partner_spare_partitions]
                        else:
                            # we need to take some spare disks as well as using any spare partitions
                            required_partner_spare_disks = required_partner_spare_partitions - len(partner_spare_partitions)
                            required_partner_spare_partitions_count = required_partner_spare_partitions - required_partner_spare_disks
                            assignment['required_partner_spare_partitions'] = partner_spare_partitions[0:required_partner_spare_partitions_count]
                            if required_partner_spare_disks > len(partner_spare_disks) - self.parameters['min_spares']:
                                self.module.fail_json(msg='Not enough partner spare disks or partner spare partitions remain to fulfill the request')
                            else:
                                assignment['required_partner_spare_disks'] = partner_spare_disks[0:required_partner_spare_disks]
                    else:
                        self.module.fail_json(msg='Not enough partner spare disks or partner spare partitions remain to fulfill the request')
            else:
                assignment['required_unassigned_disks'] = unassigned_disks[0:required_unassigned_disks]
        else:
            assignment['required_unassigned_partitions'] = unassigned_partitions[0:required_partitions]

        return assignment

    def apply(self):
        '''Apply action to partitions'''
        changed = False

        owned_partitions = self.get_partitions(container_type='owned', node=self.parameters['node'])
        own_spare_disks = self.get_disks(container_type='spare', node=self.parameters['node'])

        # are the required partitions more than the currently owned partitions and spare disks, if so we need to assign
        if self.parameters['partition_count'] > (len(own_spare_disks) + len(owned_partitions)):
            # which action needs to be taken
            assignment = self.determine_assignment(owned_partitions=owned_partitions, own_spare_disks=own_spare_disks)

            # now that we have calculated where the partitions and disks come from we can take action
            if len(assignment['required_unassigned_partitions']) > 0:
                changed = True
                if not self.module.check_mode:
                    self.assign_partitions(assignment['required_unassigned_partitions'])

            if len(assignment['required_unassigned_disks']) > 0:
                changed = True
                if not self.module.check_mode:
                    self.assign_disks(assignment['required_unassigned_disks'])

            if len(assignment['required_partner_spare_partitions']) > 0:
                changed = True
                if not self.module.check_mode:
                    self.unassign_partitions(assignment['required_partner_spare_partitions'])
                    self.assign_partitions(assignment['required_partner_spare_partitions'])

            if len(assignment['required_partner_spare_disks']) > 0:
                changed = True
                if not self.module.check_mode:
                    self.unassign_disks(assignment['required_partner_spare_disks'])
                    self.assign_disks(assignment['required_partner_spare_disks'])

        # unassign
        elif self.parameters['partition_count'] < len(owned_partitions):
            spare_partitions = self.get_partitions(container_type='spare', node=self.parameters['node'])
            unassign_partitions = len(owned_partitions) - self.parameters['partition_count']

            if unassign_partitions > len(spare_partitions):
                self.module.fail_json(msg='Not enough spare partitions exist fulfill the partition unassignment request')
            elif (len(spare_partitions) - unassign_partitions + len(own_spare_disks)) < self.parameters['min_spares']:
                self.module.fail_json(msg='Unassignment of specified partitions would leave node with less than the minimum number of spares')
            else:
                changed = True
                if not self.module.check_mode:
                    self.unassign_partitions(spare_partitions[0:unassign_partitions])

        self.module.exit_json(changed=changed)


def main():
    ''' Create object and call apply '''
    obj_aggr = NetAppOntapPartitions()
    obj_aggr.apply()


if __name__ == '__main__':
    main()
