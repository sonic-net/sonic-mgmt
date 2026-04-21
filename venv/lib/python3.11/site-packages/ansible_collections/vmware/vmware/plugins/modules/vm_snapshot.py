#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Ansible Project
# This module is also sponsored by E.T.A.I. (www.etai.fr)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_snapshot
short_description: Manages virtual machines snapshots in vCenter
description:
    - This module can be used to create, delete and update snapshot(s) of the given virtual machine.
author:
    - Ansible Cloud Team (@ansible-collections)
options:
    state:
        description:
        - Manage snapshot(s) attached to a specific virtual machine.
        - If set to V(present) and the snapshot absent, a new snapshot will be created with the given name.
        - If set to V(present), the snapshot is present, and O(new_snapshot_name) or O(description) are set, the snapshot name or description is updated.
        - If set to V(absent) and snapshot present, then the snapshot with the given name is removed.
        choices: ['present', 'absent']
        default: 'present'
        type: str
    name:
        description:
        - Name of the virtual machine to work with.
        - This is required parameter, if O(uuid) or O(moid) is not supplied.
        type: str
    name_match:
        description:
        - If multiple VMs with the same name exist, use the first or last found.
        default: 'first'
        choices: ['first', 'last']
        type: str
    uuid:
        description:
        - UUID of the instance to manage. This is VMware's BIOS UUID by default.
        - This is required if O(name) or O(moid) parameter is not supplied.
        type: str
    moid:
        description:
        - Managed Object ID of the virtual machine to manage.
        - This is required if O(name) or O(uuid) is not supplied.
        type: str
    use_instance_uuid:
        description:
        - Whether to use the VMware instance UUID rather than the BIOS UUID.
        default: false
        type: bool
    remove_all:
        description:
        - Removes all snapshots in VM if set to true.
        - Allowed only when O(state) is C(absent)
        default: false
        type: bool
    folder:
        description:
        - Absolute or relative folder path to search for the virtual machine.
        - This parameter is required if O(name) is supplied.
        - For example 'datacenter name/vm/path/to/folder' or 'path/to/folder'
        type: str
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute
              or relative.
            - This option is useful when your environment has a complex folder structure. By default,
              modules will try to intelligently determine if the path is absolute or relative.
              They may mistakenly prepend the datacenter name or other folder names, and this option
              can be used to avoid this.
        type: bool
        required: false
        default: false
    datacenter:
        description:
        - Datacenter to search for the virtual machine.
        type: str
    snapshot_name:
        description:
        - The name of the snapshot to manage.
        - Either this parameter or O(snapshot_id) is required if O(remove_all) is set to False.
        type: str
    snapshot_id:
        description:
        - The ID of the snapshot to manage. This option cannot be used when creating a new snapshot.
        - Either this parameter or O(snapshot_name) is required if O(remove_all) is set to False.
        type: int
    description:
        description:
        - Define an arbitrary description to attach to snapshot.
        default: ''
        type: str
    quiesce:
        description:
        - If set to V(true) and virtual machine is powered on, it will quiesce the file system in virtual machine.
        - Note that VMware Tools are required for this flag.
        - If virtual machine is powered off or VMware Tools are not available, then this flag is set to V(false).
        - If virtual machine does not provide capability to take quiesce snapshot, then this flag is set to V(false).
        type: bool
        default: false
    memory_dump:
        description:
        - If set to V(true), memory dump of virtual machine is also included in snapshot.
        - Note that memory snapshots take time and resources, this will take longer time to create.
        - If virtual machine does not provide capability to take memory snapshot, then this flag is set to V(false).
        type: bool
        default: false
    remove_children:
        description:
        - If set to V(true) and O(state=absent), then the entire snapshot subtree will be removed.
        type: bool
        default: false
    new_snapshot_name:
        description:
        - If the snapshot already exists, it will be renamed to this value.
        type: str



extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Create a snapshot
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    state: present
    snapshot_name: snap1
    description: snap1_description

- name: Remove a snapshot
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    state: absent
    snapshot_name: snap1

- name: Remove all snapshots of a VM
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    state: absent
    remove_all: true

- name: Remove all snapshots of a VM using MoID
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    moid: vm-42
    state: absent
    remove_all: true

- name: Take snapshot of a VM using quiesce and memory flag on
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    state: present
    snapshot_name: dummy_vm_snap_0001
    quiesce: true
    memory_dump: true

- name: Remove a snapshot and snapshot subtree
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    state: absent
    remove_children: true
    snapshot_name: snap1

- name: Remove a snapshot with a snapshot id
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    snapshot_id: 10
    state: absent

- name: Rename a snapshot
  vmware.vmware.vm_snapshot:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    state: present
    snapshot_name: current_snap_name
    new_snapshot_name: im_renamed
    description: "{{ new_snapshot_description }}"
'''

RETURN = r'''
vm:
    description:
        - Information about the target VM
    returned: Always
    type: dict
    sample:
        moid: vm-79828,
        name: test-d9c1-vm

snapshot:
    description:
        - Metadata about the affected virtual machine snapshot
    returned: When state is present
    type: dict
    sample:
        creation_time: "2024-12-24T15:27:37.041577+00:00"
        description: "Snapshot 4 example"
        id: 4
        name: "snapshot4"
        state: "poweredOff"

result:
    description:
        - Information about the vCenter task, if one was run
    returned: On change
    type: dict
    sample:
        completion_time: "2025-04-15T23:29:47.435215+00:00"
        entity_name: "test-e7e0-vm"
        error: null
        state: "success"

'''

try:
    from pyVmomi import vim
except ImportError:
    pass

from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import RunningTaskMonitor
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text, to_native


class VmSnapshotModule(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmSnapshotModule, self).__init__(module)
        self.result = dict(
            changed=False,
            renamed=False,
            vm=dict(
                name=None,
                moid=None
            )
        )

        vm_list = self.get_vms_using_params(fail_on_missing=True)
        self.vm = vm_list[0]
        self.result["vm"]['moid'] = self.vm._GetMoId()
        self.result["vm"]['name'] = self.vm.name
        self._snap_object = None

    @property
    def snap_object(self):
        if not self._snap_object:
            if not self.vm.snapshot:
                self._snap_object = None

            else:
                self._snap_object = self.get_snapshot_by_identifier_recursively(
                    self.vm.snapshot.rootSnapshotList,
                    self.params["snapshot_name"] or self.params["snapshot_id"]
                )

        return self._snap_object

    def serialize_snapshot_obj_to_json(self, obj):
        if not obj:
            return dict()
        return {'id': obj.id,
                'name': obj.name,
                'description': obj.description,
                'creation_time': obj.createTime,
                'state': obj.state,
                'quiesced': obj.quiesced}

    def get_snapshot_by_identifier_recursively(self, snapshots, snapidentifier):
        for snapshot in snapshots:
            if snapidentifier == snapshot.id or snapidentifier == snapshot.name:
                return snapshot
            else:
                return self.get_snapshot_by_identifier_recursively(snapshot.childSnapshotList, snapidentifier)
        return None

    def snapshot_vm(self):
        if self.snap_object:
            if ((not self.params['new_snapshot_name'] or self.params['new_snapshot_name'] == self.snap_object.name) and
               (not self.params['description'] or self.params['description'] == self.snap_object.description)):
                return
            return self.rename_snapshot()

        memory_dump = self.params['memory_dump'] and self.vm.capability.memorySnapshotsSupported
        quiesce = self.params['quiesce'] and self.vm.capability.quiescedSnapshotsSupported
        try:
            self.changed_check_mode_exit()
            snapshot = self.vm.CreateSnapshot_Task(self.params["snapshot_name"],
                                                   self.params["description"],
                                                   memory_dump,
                                                   quiesce)
            self.result['changed'] = True
            return snapshot
        except vim.fault.RestrictedVersion as e:
            self.module.fail_json(msg="Failed to take snapshot due to VMware Licence"
                                      " restriction : %s" % to_native(e.msg))
        except Exception as e:
            self.module.fail_json(msg="Failed to create snapshot of virtual machine"
                                      " %s due to %s" % (self.params['name'], to_native(e)))

    def rename_snapshot(self):
        self.changed_check_mode_exit()
        self.result['changed'] = True
        self.result['renamed'] = True
        return self.snap_object.snapshot.RenameSnapshot(name=self.params["new_snapshot_name"],
                                                        description=self.params["description"])

    def remove_snapshot(self):
        if self.params['remove_all']:
            self.changed_check_mode_exit()
            self.result['changed'] = True
            return self.vm.RemoveAllSnapshots_Task()
        else:
            if self.snap_object:
                self.changed_check_mode_exit()
                self.result['changed'] = True
                return self.snap_object.snapshot.RemoveSnapshot_Task(self.params.get('remove_children', False))

    def apply_snapshot_op(self):
        try:
            if (self.params['state'] == 'present'):
                task = self.snapshot_vm()
            elif (self.params['state'] == 'absent'):
                task = self.remove_snapshot()
            else:
                task = None

            if task:
                success, task_result = RunningTaskMonitor(task).wait_for_completion()
                del task_result['result']
                self.result['result'] = task_result

        except Exception as e:
            self.module.fail_json(msg=to_text(e))

        if self.params['state'] == 'present':
            self.result['snapshot'] = self.serialize_snapshot_obj_to_json(self.snap_object)

    def changed_check_mode_exit(self):
        if self.module.check_mode:
            self.result['changed'] = True
            self.module.exit_json(**self.result)


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                state=dict(default='present', choices=['present', 'absent']),
                name=dict(type='str'),
                name_match=dict(type='str', choices=['first', 'last'], default='first'),
                uuid=dict(type='str'),
                moid=dict(type='str'),
                use_instance_uuid=dict(type='bool', default=False),
                remove_all=dict(type='bool', default=False),
                folder=dict(type='str'),
                folder_paths_are_absolute=dict(type='bool', required=False, default=False),
                datacenter=dict(type='str'),
                snapshot_name=dict(type='str'),
                snapshot_id=dict(type='int'),
                description=dict(type='str', default=''),
                quiesce=dict(type='bool', default=False),
                memory_dump=dict(type='bool', default=False),
                remove_children=dict(type='bool', default=False),
                new_snapshot_name=dict(type='str'),
            )
        },
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('snapshot_name',)),
            ('remove_all', False, ('snapshot_name', 'snapshot_id'), True)
        ],
        required_together=[
            ['name', 'folder']
        ],
        required_one_of=[
            ['name', 'uuid', 'moid']
        ],
        mutually_exclusive=[
            ('name', 'uuid', 'moid'),
            ('snapshot_name', 'snapshot_id')
        ]
    )

    vm_snapshot = VmSnapshotModule(module)
    vm_snapshot.apply_snapshot_op()
    module.exit_json(**vm_snapshot.result)


if __name__ == '__main__':
    main()
