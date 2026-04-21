#!/usr/bin/python

# Copyright: (c) 2024, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing Fault Sets on Dell Technologies (Dell) PowerFlex"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
module: fault_set
version_added: '2.2.0'
short_description: Manage Fault Sets on Dell PowerFlex
description:
- Managing fault sets on PowerFlex storage system includes creating,
  getting details, renaming and deleting a fault set.
author:
- Carlos Tronco (@ctronco) <ansible.team@dell.com>
- Trisha Datta (@trisha-dell) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  fault_set_name:
    description:
    - Name of the Fault Set.
    - Mutually exclusive with I(fault_set_id).
    type: str
  fault_set_id:
    description:
    - ID of the Fault Set.
    - Mutually exclusive with I(fault_set_name).
    type: str
  protection_domain_name:
    description:
    - Name of protection domain.
    - Mutually exclusive with I(protection_domain_id).
    type: str
  protection_domain_id:
    description:
    - ID of the protection domain.
    - Mutually exclusive with I(protection_domain_name).
    type: str
  fault_set_new_name:
    description:
    - New name of the fault set.
    type: str
  state:
    description:
    - State of the Fault Set.
    choices: ['present', 'absent']
    default: 'present'
    type: str
notes:
  - The I(check_mode) is supported.
  - When I(fault_set_name) is provided, I(protection_domain_name)
    or I(protection_domain_id) must be provided.
'''


EXAMPLES = r'''

- name: Create Fault Set on Protection Domain
  dellemc.powerflex.fault_set:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    fault_set_name: "{{ fault_set_name }}"
    protection_domain_name: "{{ pd_name }}"
    state: present

- name: Rename Fault Set
  dellemc.powerflex.fault_set:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    fault_set_name: "{{ fault_set_name }}"
    fault_set_new_name: "{{ fault_set_new_name }}"
    state: present

- name: Get details of a Fault Set
  dellemc.powerflex.fault_set:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    fault_set_id: "{{ fault_set_id }}"
    state: present

- name: Delete Fault Set
  dellemc.powerflex.fault_set:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    fault_set_id: "{{ fault_set_id }}"
    state: absent
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'

fault_set_details:
    description: Details of fault set.
    returned: always
    type: dict
    contains:
        protectionDomainId:
            description: Unique identifier of the protection domain.
            type: str
        protectionDomainName:
            description: Name of the protection domain.
            type: str
        name:
            description: Name of the fault set.
            type: str
        id:
            description: Unique identifier of the fault set.
            type: str
        SDS:
            description: List of SDS associated to the fault set.
            type: list
            elements: dict
        links:
            description: Fault set links.
            type: list
            contains:
                href:
                    description: Fault Set instance URL.
                    type: str
                rel:
                    description: Relationship of fault set with different
                                 entities.
                    type: str
    sample: {
        "protectionDomainId": "da721a8300000000",
        "protectionDomainName": "sample-pd",
        "name": "fs_001",
        "id": "eb44b70500000000",
        "links": []
        }

'''


from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell import (
    utils,
)
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.powerflex_base \
    import PowerFlexBase
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.configuration \
    import Configuration
from ansible.module_utils.basic import AnsibleModule


LOG = utils.get_logger("fault_set")


class PowerFlexFaultSet(PowerFlexBase):
    """Class with FaultSet operations"""

    def __init__(self):
        """Define all parameters required by this module"""

        mutually_exclusive = [
            ["fault_set_name", "fault_set_id"],
            ["protection_domain_name", "protection_domain_id"],
        ]
        required_one_of = [["fault_set_name", "fault_set_id"]]

        ansible_module_params = {
            'argument_spec': get_powerflex_fault_set_parameters(),
            'supports_check_mode': True,
            'mutually_exclusive': mutually_exclusive,
            'required_one_of': required_one_of
        }
        super().__init__(AnsibleModule, ansible_module_params)

        self.result = dict(
            changed=False,
            fault_set_details={}
        )

    def get_protection_domain(
        self, protection_domain_name=None, protection_domain_id=None
    ):
        """Get the details of a protection domain in a given PowerFlex storage
        system"""
        return Configuration(self.powerflex_conn, self.module).get_protection_domain(
            protection_domain_name=protection_domain_name, protection_domain_id=protection_domain_id)

    def get_associated_sds(
        self, fault_set_id=None
    ):
        """Get the details of SDS associated to given fault set in a given PowerFlex storage
        system"""
        return Configuration(self.powerflex_conn, self.module).get_associated_sds(
            fault_set_id=fault_set_id)

    def create_fault_set(self, fault_set_name, protection_domain_id):
        """
        Create Fault Set
        :param fault_set_name: Name of the fault set
        :type fault_set_name: str
        :param protection_domain_id: ID of the protection domain
        :type protection_domain_id: str
        :return: Boolean indicating if create operation is successful
        """
        try:
            if not self.module.check_mode:
                msg = (f"Creating fault set with name: {fault_set_name} on "
                       f"protection domain with id: {protection_domain_id}")
                LOG.info(msg)
                self.powerflex_conn.fault_set.create(
                    name=fault_set_name, protection_domain_id=protection_domain_id
                )
            return self.get_fault_set(
                fault_set_name=fault_set_name,
                protection_domain_id=protection_domain_id)

        except Exception as e:
            error_msg = (f"Create fault set {fault_set_name} operation failed "
                         f"with error {str(e)}")
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_fault_set(self, fault_set_name=None, fault_set_id=None, protection_domain_id=None):
        """Get fault set details
            :param fault_set_name: Name of the fault set
            :param fault_set_id: Id of the fault set
            :param protection_domain_id: ID of the protection domain
            :return: Fault set details
            :rtype: dict
        """
        return Configuration(self.powerflex_conn, self.module).get_fault_set(
            fault_set_name=fault_set_name, fault_set_id=fault_set_id, protection_domain_id=protection_domain_id)

    def is_rename_required(self, fault_set_details, fault_set_params):
        """To get the details of the fields to be modified."""

        if fault_set_params['fault_set_new_name'] is not None and \
                fault_set_params['fault_set_new_name'] != fault_set_details['name']:
            return True

        return False

    def rename_fault_set(self, fault_set_id,
                         new_name):
        """Perform rename operation on a fault set"""

        try:
            if not self.module.check_mode:
                self.powerflex_conn.fault_set.rename(
                    fault_set_id=fault_set_id,
                    name=new_name)
            return self.get_fault_set(
                fault_set_id=fault_set_id)
        except Exception as e:
            msg = (f'Failed to rename the fault set instance '
                   f'with error {str(e)}')
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def delete_fault_set(self, fault_set_id):
        """Delete the Fault Set"""
        try:
            if not self.module.check_mode:
                LOG.info(msg=f"Removing Fault Set {fault_set_id}")
                self.powerflex_conn.fault_set.delete(fault_set_id)
                LOG.info("returning None")
                return None
            return self.get_fault_set(
                fault_set_id=fault_set_id)
        except Exception as e:
            errormsg = f"Removing Fault Set {fault_set_id} failed with error {str(e)}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_parameters(self, fault_set_params):
        params = [fault_set_params['fault_set_name'], fault_set_params['fault_set_new_name']]
        for param in params:
            if param is not None and len(param.strip()) == 0:
                error_msg = "Provide valid value for name for the " \
                            "creation/modification of the fault set."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        if fault_set_params['fault_set_name'] is not None and \
                fault_set_params['protection_domain_id'] is None and fault_set_params['protection_domain_name'] is None:
            error_msg = "Provide protection_domain_id/protection_domain_name with fault_set_name."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)


def get_powerflex_fault_set_parameters():
    """This method provide parameter required for the Ansible Fault Set module on
    PowerFlex"""
    return dict(
        fault_set_name=dict(),
        fault_set_id=dict(),
        protection_domain_name=dict(),
        protection_domain_id=dict(),
        fault_set_new_name=dict(),
        state=dict(default='present', choices=['present', 'absent'])
    )


class FaultSetExitHandler():
    def handle(self, fault_set_obj, fault_set_details):
        fault_set_obj.result["fault_set_details"] = fault_set_details
        if fault_set_details:
            fault_set_obj.result["fault_set_details"]["protectionDomainName"] = \
                fault_set_obj.get_protection_domain(
                    protection_domain_id=fault_set_details["protectionDomainId"])["name"]
            fault_set_obj.result["fault_set_details"]["SDS"] = \
                fault_set_obj.get_associated_sds(
                    fault_set_id=fault_set_details['id'])
        fault_set_obj.module.exit_json(**fault_set_obj.result)


class FaultSetDeleteHandler():
    def handle(self, fault_set_obj, fault_set_params, fault_set_details):
        if fault_set_params['state'] == 'absent' and fault_set_details:
            fault_set_details = fault_set_obj.delete_fault_set(fault_set_details['id'])
            fault_set_obj.result['changed'] = True

        FaultSetExitHandler().handle(fault_set_obj, fault_set_details)


class FaultSetRenameHandler():
    def handle(self, fault_set_obj, fault_set_params, fault_set_details):
        if fault_set_params['state'] == 'present' and fault_set_details:
            is_rename_required = fault_set_obj.is_rename_required(fault_set_details, fault_set_params)
            if is_rename_required:
                fault_set_details = fault_set_obj.rename_fault_set(fault_set_id=fault_set_details['id'],
                                                                   new_name=fault_set_params['fault_set_new_name'])
                fault_set_obj.result['changed'] = True

        FaultSetDeleteHandler().handle(fault_set_obj, fault_set_params, fault_set_details)


class FaultSetCreateHandler():
    def handle(self, fault_set_obj, fault_set_params, fault_set_details, pd_id):
        if fault_set_params['state'] == 'present' and not fault_set_details:
            fault_set_details = fault_set_obj.create_fault_set(fault_set_name=fault_set_params['fault_set_name'],
                                                               protection_domain_id=pd_id)
            fault_set_obj.result['changed'] = True

        FaultSetRenameHandler().handle(fault_set_obj, fault_set_params, fault_set_details)


class FaultSetHandler():
    def handle(self, fault_set_obj, fault_set_params):
        fault_set_obj.validate_parameters(fault_set_params=fault_set_params)
        pd_id = None
        if fault_set_params['protection_domain_id'] or fault_set_params['protection_domain_name']:
            pd_id = fault_set_obj.get_protection_domain(
                protection_domain_id=fault_set_params['protection_domain_id'],
                protection_domain_name=fault_set_params['protection_domain_name'])['id']
        fault_set_details = fault_set_obj.get_fault_set(fault_set_id=fault_set_params['fault_set_id'],
                                                        fault_set_name=fault_set_params['fault_set_name'],
                                                        protection_domain_id=pd_id)
        FaultSetCreateHandler().handle(fault_set_obj, fault_set_params, fault_set_details, pd_id)


def main():
    """ Create PowerFlex fault set object and perform action on it
        based on user input from playbook."""
    obj = PowerFlexFaultSet()
    FaultSetHandler().handle(obj, obj.module.params)


if __name__ == '__main__':
    main()
