#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#            Sudheesh Reddy Satti<Sudheesh.Reddy.Satti@ibm.com>
#            Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#            Rahul Pawar <rahul.p@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_portset
short_description: This module manages portset configuration on IBM Storage Virtualize family systems
version_added: "1.8.0"
description:
  - Ansible interface to manage IP and Fibre Channel (FC) portsets using 'mkportset', 'chportset', and 'rmportset' commands.
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        required: true
        type: str
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize system.
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    log_path:
        description:
            - Path of debug log file.
        type: str
    state:
        description:
            - Creates (C(present)) or Deletes (C(absent)) the IP portset.
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of portset.
        type: str
        required: true
    porttype:
        description:
            - Specifies the type of port that can be mapped to the portset.
            - Applies when I(state=present).
            - If not specified, I(porttype=ethernet) will be used to manage IP portset.
        choices: [ fc, ethernet ]
        type: str
        version_added: '1.12.0'
    portset_type:
        description:
            - Specifies the type for the portset.
            - Applies only during creation of portset.
            - If not specified, I(portset_type=host) will be used.
        choices: [ host, replication, highspeedreplication ]
        type: str
    ownershipgroup:
        description:
            - The name of the ownership group to which the portset object is being mapped.
            - Parameters I(ownershipgroup) and I(noownershipgroup) are mutually exclusive.
            - Applies when I(state=present).
        type: str
    noownershipgroup:
        description:
            - Specify to remove the ownership group from portset.
            - Parameters I(ownershipgroup) and I(noownershipgroup) are mutually exclusive.
            - Applies only during updation of portset.
        type: bool
    old_name:
        description:
            - Specifies the old name of the portset while renaming.
            - Valid when I(state=present), to rename an existing host.
        type: str
        version_added: '1.12.0'
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    replicationportsetlinkuid:
        description:
            - Change the replication_portset_link_uid parameter of the portset.
        type: str
        version_added: '2.6.0'
    resetreplicationportsetlinkuid:
        description:
            - Reset the replication_portset_link_uid parameter to a newly generated portset link UID.
        type: bool
        version_added: '2.6.0'
author:
    - Sanjaikumaar M (@sanjaikumaar)
    - Sudheesh Reddy Satti (@sudheeshreddy)
    - Sumit Kumar Gupta (@sumitguptaibm)
    - Rahul Pawar (@rahul-p)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create a portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset1
   portset_type: host
   ownershipgroup: owner1
   state: present
- name: Update a portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset1
   noownershipgroup: true
   state: present
- name: Create an FC portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: fcportset1
   porttype: fc
   portset_type: host
   ownershipgroup: owner1
   state: present
- name: Create an highspeedreplication portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: fcportset1
   porttype: ethernet
   portset_type: highspeedreplication
   state: present
- name: Rename the portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset2
   old_name: portset1
   state: present
- name: Create an FC portset specifying a replicationportsetlinkuid
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: fcportset1
   porttype: fc
   portset_type: host
   ownershipgroup: owner1
   replicationportsetlinkuid: F8C5C02FC24F019154B57B59DD753BFF
   state: present
- name: Modify replication_portset_link_uid parameter of portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset1
   replicationportsetlinkuid: 3A05584AC8EEA48B514F9C4F14A03540
   state: present
- name: Reset replication portset link uid of an existing FC portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: ffcportset1
   resetreplicationportsetlinkuid: true
   state: present
- name: Delete a portset
  ibm.storage_virtualize.ibm_svc_manage_portset:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset1
   state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVCPortset:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(
                    type='str',
                    required=True,
                    choices=['present', 'absent']
                ),
                name=dict(
                    type='str',
                    required=True,
                ),
                portset_type=dict(
                    type='str',
                    choices=['host', 'replication', 'highspeedreplication']
                ),
                ownershipgroup=dict(
                    type='str',
                ),
                noownershipgroup=dict(
                    type='bool',
                ),
                porttype=dict(
                    type='str',
                    choices=['fc', 'ethernet']
                ),
                old_name=dict(
                    type='str',
                ),
                replicationportsetlinkuid=dict(
                    type='str',
                ),
                resetreplicationportsetlinkuid=dict(
                    type='bool',
                )
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']
        # Optional parameters
        self.portset_type = self.module.params.get('portset_type', '')
        self.ownershipgroup = self.module.params.get('ownershipgroup', '')
        self.noownershipgroup = self.module.params.get('noownershipgroup', '')
        self.porttype = self.module.params.get('porttype', '')
        self.old_name = self.module.params.get('old_name', '')
        self.replicationportsetlinkuid = self.module.params.get('replicationportsetlinkuid')
        self.resetreplicationportsetlinkuid = self.module.params.get('resetreplicationportsetlinkuid')

        self.basic_checks()

        # Varialbe to cache data
        self.portset_details = None

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info
        self.changed = False
        self.msg = ''

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=self.log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        if self.state == 'present':
            if not self.name:
                self.module.fail_json(msg='Missing mandatory parameter: name')

            if self.ownershipgroup and self.noownershipgroup:
                self.module.fail_json(msg='Mutually exclusive parameter: ownershipgroup, noownershipgroup')

            if self.replicationportsetlinkuid and self.resetreplicationportsetlinkuid:
                self.module.fail_json(msg='Mutually exclusive parameters: replicationportsetlinkuid, resetreplicationportsetlinkuid')

        else:
            if not self.name:
                self.module.fail_json(msg='Missing mandatory parameter: name')

            fields = [f for f in ['ownershipgroup', 'noownershipgroup', 'porttype', 'portset_type', 'old_name', 'replicationportsetlinkuid',
                                  'resetreplicationportsetlinkuid'] if getattr(self, f)]

            if any(fields):
                self.module.fail_json(msg='Parameters {0} not supported while deleting a porset'.format(', '.join(fields)))

    # for validating parameter while renaming a portset
    def parameter_handling_while_renaming(self):
        parameters = {
            "ownershipgroup": self.ownershipgroup,
            "noownershipgroup": self.noownershipgroup,
            "porttype": self.porttype,
            "portset_type": self.portset_type,
            "replicationportsetlinkuid": self.replicationportsetlinkuid,
            "resetreplicationportsetlinkuid": self.resetreplicationportsetlinkuid
        }
        parameters_exists = [parameter for parameter, value in parameters.items() if value]
        if parameters_exists:
            self.module.fail_json(msg="Parameters {0} not supported while renaming a portset.".format(', '.join(parameters_exists)))

    def is_portset_exists(self, portset_name):
        merged_result = {}
        data = self.restapi.svc_obj_info(
            cmd='lsportset',
            cmdopts=None,
            cmdargs=['-gui', portset_name]
        )

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        self.portset_details = merged_result
        self.log("Existing portset data: %s", self.portset_details)
        return merged_result

    def create_validation(self):
        if self.resetreplicationportsetlinkuid:
            self.module.fail_json(msg="Parameter resetreplicationportsetlinkuid is not supported while creating portset.")

    def create_portset(self):
        self.create_validation()
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mkportset'
        cmdopts = {
            'name': self.name,
            'type': self.portset_type if self.portset_type else 'host',
            'porttype': self.porttype if self.porttype else 'ethernet'
        }

        if self.ownershipgroup:
            cmdopts['ownershipgroup'] = self.ownershipgroup
        if self.replicationportsetlinkuid:
            cmdopts['replicationportsetlinkuid'] = self.replicationportsetlinkuid

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('Portset (%s) created', self.name)
        self.changed = True

    def portset_probe(self):
        updates = []

        if self.portset_type and self.portset_type != self.portset_details['type']:
            self.module.fail_json(msg="portset_type can't be updated for portset")
        if self.porttype and self.porttype != self.portset_details['port_type']:
            self.module.fail_json(msg="porttype can't be updated for portset")
        if self.ownershipgroup and self.ownershipgroup != self.portset_details['owner_name']:
            updates.append('ownershipgroup')
        if self.noownershipgroup:
            updates.append('noownershipgroup')
        if self.replicationportsetlinkuid and (self.replicationportsetlinkuid != self.portset_details['replication_portset_link_uid']):
            updates.append('replicationportsetlinkuid')
        if self.resetreplicationportsetlinkuid:
            updates.append('resetreplicationportsetlinkuid')

        self.log("Modifications to be done: %s", updates)
        return updates

    def update_portset(self, updates):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chportset'
        cmdopts = dict((k, getattr(self, k)) for k in updates)
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts=cmdopts, cmdargs=cmdargs)
        self.log('Portset (%s) updated', self.name)
        self.changed = True

    def delete_portset(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmportset'
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts=None, cmdargs=cmdargs)
        self.log('Portset (%s) deleted', self.name)
        self.changed = True

    # function for renaming an existing portset with a new name
    def portset_rename(self, portset_data):
        msg = ''
        self.parameter_handling_while_renaming()
        old_portset_data = self.is_portset_exists(self.old_name)
        if not old_portset_data and not portset_data:
            self.module.fail_json(msg="Portset with old name {0} doesn't exist.".format(self.old_name))
        elif old_portset_data and portset_data:
            self.module.fail_json(msg="Portset [{0}] already exists.".format(self.name))
        elif not old_portset_data and portset_data:
            msg = "Portset with name [{0}] already exists.".format(self.name)
        elif old_portset_data and not portset_data:
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chportset', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "Portset [{0}] has been successfully rename to [{1}].".format(self.old_name, self.name)
        return msg

    def apply(self):

        portset_data = self.is_portset_exists(self.name)

        if self.state == 'present' and self.old_name:
            self.msg = self.portset_rename(portset_data)
        elif self.state == 'absent' and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")
        else:
            if portset_data:
                if self.state == 'present':
                    modifications = self.portset_probe()
                    if any(modifications):
                        self.update_portset(modifications)
                        self.msg = 'Portset ({0}) updated.'.format(self.name)
                    else:
                        self.msg = 'Portset ({0}) already exists. No modifications done.'.format(self.name)
                else:
                    self.delete_portset()
                    self.msg = 'Portset ({0}) deleted successfully.'.format(self.name)
            else:
                if self.state == 'absent':
                    self.msg = 'Portset ({0}) does not exist. No modifications done.'.format(self.name)
                else:
                    self.create_portset()
                    self.msg = 'Portset ({0}) created successfully.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVCPortset()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
