#!/usr/bin/python
# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_mdisk
short_description: This module manages MDisks on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkarray' and 'rmmdisk' MDisk commands.
version_added: "1.0.0"
options:
  name:
    description:
      - The MDisk name.
    required: true
    type: str
  state:
    description:
      - Creates (C(present)) or removes (C(absent)) the MDisk.
    choices: [ absent, present ]
    required: true
    type: str
  clustername:
    description:
      - The hostname or management IP of the Storage Virtualize system.
    type: str
    required: true
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
    - To generate a token, use the ibm_svc_auth module.
    type: str
    version_added: '1.5.0'
  drive:
    description:
      - Drive(s) to use as members of the RAID array.
      - Required when I(state=present), to create an MDisk array.
    type: str
  mdiskgrp:
    description:
      - The storage pool (mdiskgrp) to which you want to add the MDisk.
    type: str
  log_path:
    description:
      - Path of debug log file.
    type: str
  validate_certs:
    description:
      - Validates certification.
    default: false
    type: bool
  level:
    description:
      - Specifies the RAID level.
      - Required when I(state=present), to create an MDisk array.
    type: str
    choices: ['raid0', 'raid1', 'raid5', 'raid6', 'raid10']
  encrypt:
    description:
      - Defines use of encryption with the MDisk group.
      - Applies when I(state=present).
    type: str
    default: 'no'
    choices: ['yes', 'no']
  driveclass:
    description:
      - Specifies the class that is being used to create the array.
      - Applies when I(state=present).
    type: str
    version_added: '2.0.0'
  drivecount:
    description:
      - Specifies the number of the drives.
      - The value must be a number in the range 2 - 128.
      - Applies when I(state=present).
    type: str
    version_added: '2.0.0'
  stripewidth:
    description:
      - Specifies the width of a single unit of redundancy within a distributed set of drives
      - The value must be a number in the range 2 - 16.
      - Applies when I(state=present).
    type: str
    version_added: '2.0.0'
  tier:
    description:
      - Specifies the new tier of the MDisk.
    type: str
    choices: ['tier0_flash', 'tier1_flash', 'tier_enterprise', 'tier_nearline', 'tier_scm']
    version_added: '2.7.0'
  old_name:
    description:
      - Specifies the old name of an existing pool.
      - Applies when I(state=present), to rename the existing pool.
    type: str
    version_added: '2.0.0'
author:
    - Peng Wang(@wangpww)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create MDisk and name as mdisk20
  ibm.storage_virtualize.ibm_svc_mdisk:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: mdisk20
    state: present
    level: raid0
    drive: '5:6'
    encrypt: 'no'
    mdiskgrp: pool20
- name: Change tier of MDisk to tier1_flash
  ibm.storage_virtualize.ibm_svc_mdisk:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: mdisk20
    state: present
    mdiskgrp: pool20
    tier: tier1_flash
- name: Delete MDisk named mdisk20
  ibm.storage_virtualize.ibm_svc_mdisk:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: mdisk20
    state: absent
    mdiskgrp: pool20
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger


class IBMSVCmdisk(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                level=dict(type='str', choices=['raid0', 'raid1', 'raid5',
                                                'raid6', 'raid10']),
                drive=dict(type='str', default=None),
                encrypt=dict(type='str', default='no', choices=['yes', 'no']),
                mdiskgrp=dict(type='str'),
                driveclass=dict(type='str'),
                drivecount=dict(type='str'),
                stripewidth=dict(type='str'),
                tier=dict(type='str', choices=['tier0_flash', 'tier1_flash', 'tier_enterprise', 'tier_nearline', 'tier_scm']),
                old_name=dict(type='str')
            )
        )

        mutually_exclusive = []
        self.module = AnsibleModule(argument_spec=argument_spec,
                                    mutually_exclusive=mutually_exclusive,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional
        self.level = self.module.params.get('level', None)
        self.drive = self.module.params.get('drive', None)
        self.encrypt = self.module.params.get('encrypt', None)
        self.mdiskgrp = self.module.params.get('mdiskgrp', None)
        self.driveclass = self.module.params.get('driveclass', '')
        self.drivecount = self.module.params.get('drivecount', '')
        self.stripewidth = self.module.params.get('stripewidth', '')
        self.tier = self.module.params.get('tier', '')
        self.old_name = self.module.params.get('old_name', '')

        # internal variable
        self.changed = False

        self.basic_checks()

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        # Handling missing mandatory parameters name
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if self.state == 'present':
            if self.drive and (self.drivecount or self.driveclass or self.stripewidth):
                self.module.fail_json(msg="The parameters 'drive' and "
                                      "'driveclass, drivecount, stripewidth' are mutually exclusive.")
        elif self.state == 'absent':
            if not self.mdiskgrp:
                self.module.fail_json(msg="Parameter [mdiskgrp] is required when deleting an MDisk.")
            invalids = ('drive', 'driveclass', 'level', 'drivecount', 'old_name', 'stripewidth', 'tier')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))

            if invalid_exists:
                self.module.fail_json(
                    msg='Following parameters are not applicable while deleting: {0}'.format(invalid_exists))

    def mdisk_exists(self, name):
        merged_result = {}
        data = self.restapi.svc_obj_info(
            cmd='lsmdisk',
            cmdopts={},
            cmdargs=['-gui', name]
        )

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    def mdisk_rename(self, mdisk_data):
        msg = None
        old_mdisk_data = self.mdisk_exists(self.old_name)
        if not old_mdisk_data and not mdisk_data:
            self.module.fail_json(msg="mdisk [{0}] does not exists.".format(self.old_name))
        elif old_mdisk_data and mdisk_data:
            self.module.fail_json(msg="mdisk with name [{0}] already exists.".format(self.name))
        elif not old_mdisk_data and mdisk_data:
            msg = "mdisk [{0}] already renamed.".format(self.name)
        elif old_mdisk_data and not mdisk_data:
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chmdisk', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "mdisk [{0}] has been successfully rename to [{1}].".format(self.old_name, self.name)
        return msg

    def mdisk_create(self):
        if self.drive:
            if self.drivecount or self.driveclass or self.stripewidth:
                self.module.fail_json(msg="The parameters 'drive' and "
                                      "'driveclass, drivecount, stripewidth' are mutually exclusive.")
        elif self.drivecount and self.driveclass:
            if self.drivecount and not (2 <= int(self.drivecount) <= 128):
                self.module.fail_json(msg="You must pass drivecount value in the range 2 - 128 only.")

            if self.stripewidth and not (2 <= int(self.stripewidth) <= 16):
                self.module.fail_json(msg="You must pass stripewidth value in the range 2 - 16 only.")
        else:
            self.module.fail_json(msg="You must pass any one of the following two: "
                                  "(1) 'drive' for RAID array "
                                  "(2) 'driveclass and drivecount' for DRAID array.")

        if not self.level:
            self.module.fail_json(msg="You must pass in level to the module.")
        if not self.mdiskgrp:
            self.module.fail_json(msg="You must pass in mdiskgrp to the module.")

        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating mdisk '%s'", self.name)

        # Make command
        cmdopts = {}
        if self.drive:
            cmd = 'mkarray'
            cmdopts['drive'] = self.drive
        elif self.driveclass and self.drivecount:
            cmd = 'mkdistributedarray'
            cmdopts['driveclass'] = self.driveclass
            cmdopts['drivecount'] = self.drivecount
            cmdopts['allowsuperior'] = True
            if self.stripewidth:
                cmdopts['stripewidth'] = self.stripewidth

        if self.encrypt:
            cmdopts['encrypt'] = self.encrypt

        cmdopts['level'] = self.level
        cmdopts['strip'] = 256
        cmdopts['name'] = self.name
        cmdargs = [self.mdiskgrp]
        self.log("creating mdisk command=%s opts=%s args=%s",
                 cmd, cmdopts, cmdargs)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.log("create mdisk result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create mdisk result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create mdisk [%s]" % self.name)

    def mdisk_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting mdisk '%s'", self.name)
        cmd = 'rmmdisk'
        cmdopts = {}
        cmdopts['mdisk'] = self.name
        cmdargs = [self.mdiskgrp]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmkdiskgrp does not output anything when successful.
        self.changed = True

    def mdisk_update(self, modify):
        cmd = 'chmdisk'
        cmdopts = {}

        if 'tier' in modify:
            cmdopts['tier'] = self.tier

        if cmdopts:
            cmdargs = [self.name]
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
            # Any error will have been raised in svc_run_command
            # chhost does not output anything when successful.
            self.changed = True

    # TBD: Implement a more generic way to check for properties to modify.
    def mdisk_probe(self, data):
        props = []

        field_mappings = (
            ('drivecount', data.get('drive_count')),
            ('level', data.get('raid_level')),
            ('encrypt', data.get('encrypt')),
            ('tier', data.get('tier'))
        )

        for field, existing_value in field_mappings:
            new_value = getattr(self, field, None)
            if new_value is not None and new_value != existing_value:
                props.append(field)

        self.log("mdisk_probe props='%s'", props)
        return props

    def apply(self):
        changed = False
        msg = None
        modify = []

        mdisk_data = self.mdisk_exists(self.name)
        if self.state == 'present' and self.old_name:
            msg = self.mdisk_rename(mdisk_data)
        elif self.state == 'absent' and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")
        else:
            if mdisk_data:
                if self.state == 'absent':
                    self.log("CHANGED: mdisk exists, but "
                             "requested state is 'absent'")
                    changed = True
                elif self.state == 'present':
                    # This is where we detect if chmdisk should be called.
                    modify = self.mdisk_probe(mdisk_data)
                    if modify:
                        changed = True

            else:
                if self.state == 'present':
                    self.log("CHANGED: mdisk does not exist, "
                             "but requested state is 'present'")
                    changed = True

            if changed:
                if self.state == 'present':
                    if not mdisk_data:
                        self.mdisk_create()
                        self.changed = True
                        msg = "Mdisk [%s] has been created." % self.name
                    else:
                        # This is where we would modify
                        self.mdisk_update(modify)
                        msg = "Mdisk [%s] has been modified." % self.name
                        self.changed = True
                elif self.state == 'absent':
                    self.mdisk_delete()
                    msg = "Mdisk [%s] has been deleted." % self.name
                    self.changed = True
            else:
                self.log("exiting with no changes")
                if self.state == 'absent':
                    msg = "Mdisk [%s] did not exist." % self.name
                else:
                    msg = "Mdisk [%s] already exists. No modifications done" % self.name

            if self.module.check_mode:
                msg = 'skipping changes due to check mode'

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCmdisk()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
