#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#            Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#            Shilpi Jain <shilpi.jain1@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_vol_map
short_description: This module manages volume mapping on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage volume mapping commands
    'mkvdiskhostmap', 'rmvdiskhostmap', 'mkvolumehostclustermap', and 'rmvolumehostclustermap'.
version_added: "1.0.0"
options:
  volname:
    description:
      - Specifies the volume name for host or hostcluster mapping.
    required: true
    type: str
  host:
    description:
      - Specifies the host name for host mapping.
      - This parameter is required to create or delete a volume-to-host mapping.
    type: str
  hostcluster:
    description:
      - Specifies the name of the host cluster for host mapping.
      - This parameter is required to create or delete a volume-to-hostcluster mapping.
    type: str
  scsi:
    description:
      - Specifies the SCSI logical unit number (LUN) ID to assign to a volume on the specified host or host cluster.
      - Applies when I(state=present).
    type: int
  state:
    description:
      - Creates (C(present)) or removes (C(absent)) a volume mapping.
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
  log_path:
    description:
    - Path of debug log file.
    type: str
  validate_certs:
    description:
    - Validates certification.
    default: false
    type: bool
author:
    - Peng Wang(@wangpww)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Map a volume to a host
  ibm.storage_virtualize.ibm_svc_vol_map:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    volname: volume0
    host: host4test
    scsi: 1
    state: present
- name: Unmap a volume from a host
  ibm.storage_virtualize.ibm_svc_vol_map:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    volname: volume0
    host: host4test
    state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCvdiskhostmap(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                volname=dict(type='str', required=True),
                host=dict(type='str', required=False),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                scsi=dict(type='int', required=False),
                hostcluster=dict(type='str', required=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.volname = self.module.params['volname']
        self.state = self.module.params['state']

        # Optional
        self.host = self.module.params['host']
        self.hostcluster = self.module.params['hostcluster']
        self.scsi = self.module.params['scsi']

        # Handline for mandatory parameter volname
        if not self.volname:
            self.module.fail_json(msg="Missing mandatory parameter: volname")

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

    def get_existing_vdiskhostmap(self):
        merged_result = []

        data = self.restapi.svc_obj_info(cmd='lsvdiskhostmap', cmdopts=None,
                                         cmdargs=[self.volname])

        if isinstance(data, list):
            for d in data:
                merged_result.append(d)
        elif data:
            merged_result = [data]

        return merged_result

    # TBD: Implement a more generic way to check for properties to modify.
    def vdiskhostmap_probe(self, mdata):
        props = []
        self.log("vdiskhostmap_probe props='%s'", mdata)
        mapping_exist = False
        for data in mdata:
            if self.host:
                if (self.host == data['host_name']) and (self.volname == data['name']):
                    if self.scsi and (self.scsi != int(data['SCSI_id'])):
                        self.module.fail_json(msg="Update not supported for parameter: scsi")
                    mapping_exist = True
            elif self.hostcluster:
                if (self.hostcluster == data['host_cluster_name']) and (self.volname == data['name']):
                    if self.scsi and (self.scsi != int(data['SCSI_id'])):
                        self.module.fail_json(msg="Update not supported for parameter: scsi")
                    mapping_exist = True

        if not mapping_exist:
            props += ["map"]

        if props is []:
            props = None

        self.log("vdiskhostmap_probe props='%s'", props)
        return props

    def vdiskhostmap_create(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating vdiskhostmap '%s' '%s'", self.volname, self.host)

        # Make command
        cmd = 'mkvdiskhostmap'
        cmdopts = {'force': True}
        cmdopts['host'] = self.host
        cmdopts['scsi'] = self.scsi
        cmdargs = [self.volname]

        self.log("creating vdiskhostmap command %s opts %s args %s",
                 cmd, cmdopts, cmdargs)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.log("create vdiskhostmap result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create vdiskhostmap result message %s",
                     result['message'])
        else:
            self.module.fail_json(msg="Failed to create vdiskhostmap.")

    def vdiskhostmap_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting vdiskhostmap '%s'", self.volname)

        cmd = 'rmvdiskhostmap'
        cmdopts = {}
        cmdopts['host'] = self.host
        cmdargs = [self.volname]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmvdisk does not output anything when successful.
        self.changed = True

    def vdiskhostclustermap_create(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating mkvolumehostclustermap '%s' '%s'", self.volname, self.hostcluster)

        # Make command
        cmd = 'mkvolumehostclustermap'
        cmdopts = {'force': True}
        cmdopts['hostcluster'] = self.hostcluster
        cmdopts['scsi'] = self.scsi
        cmdargs = [self.volname]

        self.log("creating vdiskhostmap command %s opts %s args %s",
                 cmd, cmdopts, cmdargs)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.log("create vdiskhostmap result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create vdiskhostmap result message %s",
                     result['message'])
        else:
            self.module.fail_json(msg="Failed to create vdiskhostmap.")

    def vdiskhostclustermap_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting vdiskhostclustermap '%s'", self.volname)

        cmd = 'rmvolumehostclustermap'
        cmdopts = {}
        cmdopts['hostcluster'] = self.hostcluster
        cmdargs = [self.volname]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmvdisk does not output anything when successful.
        self.changed = True

    def apply(self):
        changed = False
        msg = None

        # Handling for volume
        if not self.volname:
            self.module.fail_json(msg="You must pass in "
                                      "volname to the module.")

        # Handling for host and hostcluster
        if (self.host and self.hostcluster):
            self.module.fail_json(msg="Either use host or hostcluster")
        elif (not self.host and not self.hostcluster):
            self.module.fail_json(msg="Missing parameter: host or hostcluster")

        vdiskmap_data = self.get_existing_vdiskhostmap()
        self.log("volume mapping data is : '%s'", vdiskmap_data)

        if vdiskmap_data:
            if self.state == 'absent':
                self.log("vdiskmap exists, "
                         "and requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                probe_data = self.vdiskhostmap_probe(vdiskmap_data)
                if probe_data:
                    self.log("vdiskmap does not exist, but requested state is 'present'")
                    changed = True
        else:
            if self.state == 'present':
                self.log("vdiskmap does not exist, "
                         "but requested state is 'present'")
                changed = True

        if changed:
            if self.state == 'present':
                if self.host:
                    self.vdiskhostmap_create()
                    msg = "Vdiskhostmap %s %s has been created." % (
                        self.volname, self.host)
                elif self.hostcluster:
                    self.vdiskhostclustermap_create()
                    msg = "Vdiskhostclustermap %s %s has been created." % (
                        self.volname, self.hostcluster)
            elif self.state == 'absent':
                if self.host:
                    self.vdiskhostmap_delete()
                    msg = "vdiskhostmap [%s] has been deleted." % self.volname
                elif self.hostcluster:
                    self.vdiskhostclustermap_delete()
                    msg = "vdiskhostclustermap [%s] has been deleted." % self.volname

            if self.module.check_mode:
                msg = 'skipping changes due to check mode'
        else:
            self.log("exiting with no changes")
            if self.state == 'absent':
                msg = "Volume mapping [%s] did not exist." % self.volname
            else:
                msg = "Volume mapping [%s] already exists." % self.volname

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCvdiskhostmap()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
