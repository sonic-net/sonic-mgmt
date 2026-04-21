#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_powerstate
short_description: Manages power states of virtual machines in vCenter
description:
    - Manages power states of virtual machines in vCenter, e.g., Power on / Power off / Restart.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    datacenter:
        description:
            - The datacenter where the VM you'd like to operate the power.
        type: str
        required: true
    state:
        description:
            - Set the state of the virtual machine.
        choices: [ powered-off, powered-on, reboot-guest, restarted, shutdown-guest, suspended]
        default: powered-on
        type: str
    name:
        description:
            - Name of the virtual machine to work with.
            - Virtual machine names in vCenter are not necessarily unique, which may be problematic, see O(name_match).
            - This is required if O(moid) or O(uuid) is not supplied.
        type: str
    name_match:
        description:
            - If multiple virtual machines matching the name, use the first or last found.
        default: first
        choices: [ first, last ]
        type: str
    uuid:
        description:
            - UUID of the instance to manage if known, this is VMware's unique identifier.
            - This is required if O(name) or O(moid) is not supplied.
        type: str
    moid:
        description:
            - Managed Object ID of the instance to manage if known, this is a unique identifier only within a single vCenter instance.
            - This is required if O(name) or O(uuid) is not supplied.
        type: str
    use_instance_uuid:
        description:
            - Whether to use the VMware instance UUID rather than the BIOS UUID.
        default: false
        type: bool
    folder:
        description:
            - Destination folder, absolute or relative path to find an existing guest.
            - Should be the full folder path, with or without the 'datacenter/vm/' prefix
            - For example 'datacenter_name/vm/path/to/folder' or 'path/to/folder'
        type: str
        required: false
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
    scheduled_at:
        description:
            - Date and time in string format at which specified task needs to be performed.
            - "The required format for date and time - 'dd/mm/yyyy hh:mm'."
            - Scheduling task requires vCenter server. A standalone ESXi server does not support this option.
        type: str
        required: false
    scheduled_task_name:
        description:
            - Name of scheduled task.
            - Valid only if O(scheduled_at) is specified.
        type: str
        required: false
    scheduled_task_description:
        description:
            - Description of scheduled task.
            - Valid only if O(scheduled_at) is specified.
        type: str
        required: false
    scheduled_task_enabled:
        description:
            - Flag to indicate whether the scheduled task is enabled or disabled.
        type: bool
        default: true
    force:
        description:
            - Ignore warnings and complete the actions.
            - This parameter is useful while forcing virtual machine state.
        default: false
        type: bool
    timeout:
        description:
            - If this argument is set to a positive integer, the module will wait for the VM to reach the poweredoff state.
            - The value sets a timeout in seconds for the module to wait for the state change.
            - This value is ignored if the desired state is V(reboot-guest).
        default: 3600
        type: int
    question_answers:
        description:
            - A list of questions to answer, should one or more arise while waiting for the task to complete.
            - Some common uses are to allow a cdrom to be changed even if locked, or to answer the question as to whether a VM was copied or moved.
            - Can be used if O(state) is V(powered-on).
        suboptions:
            question:
                description:
                    - The message id, for example C(msg.uuid.altered).
                type: str
                required: true
            response:
                description:
                    - The choice key, for example C(button.uuid.copiedTheVM).
                type: str
                required: true
        type: list
        elements: dict
        required: false


extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Set the state of a virtual machine to poweroff
  vmware.vmware.vm_powerstate:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ vm_datacenter }}"
    folder: "/{{ datacenter_name }}/vm/my_folder"
    name: "{{ guest_name }}"
    state: powered-off
  register: deploy

- name: Set the state of a virtual machine to poweron using MoID
  vmware.vmware.vm_powerstate:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ vm_datacenter }}"
    folder: "/{{ datacenter_name }}/vm/my_folder"
    moid: vm-42
    state: powered-on
  register: deploy

- name: Set the state of a virtual machine to poweroff at given scheduled time
  vmware.vmware.vm_powerstate:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ vm_datacenter }}"
    folder: "/{{ datacenter_name }}/vm/my_folder"
    name: "{{ guest_name }}"
    state: powered-off
    scheduled_at: "09/01/2018 10:18"
    scheduled_task_name: "task_00001"
    scheduled_task_description: "Sample task to poweroff VM"
    scheduled_task_enabled: true
  register: deploy_at_scheduled_datetime

- name: Wait for the virtual machine to shutdown
  vmware.vmware.vm_powerstate:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ vm_datacenter }}"
    name: "{{ guest_name }}"
    state: shutdown-guest
  register: deploy

- name: Automatically answer if a question locked a virtual machine
  block:
    - name: Power on a virtual machine without the answer param
      vmware.vmware.vm_powerstate:
        hostname: "{{ vcenter_hostname }}"
        username: "{{ vcenter_username }}"
        password: "{{ vcenter_password }}"
        datacenter: "{{ vm_datacenter }}"
        validate_certs: false
        folder: "{{ f1 }}"
        name: "{{ vm_name }}"
        state: powered-on
  rescue:
    - name: Power on a virtual machine with the answer param
      vmware.vmware.vm_powerstate:
        hostname: "{{ vcenter_hostname }}"
        username: "{{ vcenter_username }}"
        password: "{{ vcenter_password }}"
        datacenter: "{{ vm_datacenter }}"
        validate_certs: false
        folder: "{{ f1 }}"
        name: "{{ vm_name }}"
        question_answers:
          - question: "msg.uuid.altered"
            response: "button.uuid.copiedTheVM"
        state: powered-on
'''

RETURN = r'''
vm:
    description:
        - Information about the target VM
    returned: On success
    type: dict
    sample:
        moid: vm-79828,
        name: test-d9c1-vm
'''

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from random import randint
from datetime import datetime, timedelta
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text, to_native

from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import TaskError, RunningTaskMonitor, VmQuestionHandler


class VmPowerstateModule(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmPowerstateModule, self).__init__(module)

        self.result = dict(
            changed=False,
            vm=dict(
                name=None,
                moid=None
            )
        )

        vm_list = self.get_vms_using_params(fail_on_missing=True)
        self.vm = vm_list[0]
        state = self.params['state']
        self.desired_state = state.replace('_', '').replace('-', '').lower()
        self.current_state = self.vm.summary.runtime.powerState.lower()
        self.result["vm"]['moid'] = self.vm._GetMoId()
        self.result["vm"]['name'] = self.vm.name

    def run_vm_configuration_task(self, task):
        if not task:
            return
        try:
            succeeded, task_result = RunningTaskMonitor(task).wait_for_completion(
                vm=self.vm, timeout=self.params['timeout'], answers=self.params.get('question_answers', None))
        except TaskError as e:
            self.module.fail_json(msg=to_text(e))
        finally:
            self.result['changed'] = True

    def _poll_vm_state_for_shutdown(self):
        """
        Since the shutdown guest state is triggered through VMware tools, we cannot tell when the task ends. So
        instead we will poll the VM state over and over again, until the timeout is met.
        """
        timeout = self.params['timeout']
        if not timeout:
            return

        end_time = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end_time:
            if self.vm.summary.runtime.powerState.lower() == 'poweredoff':
                break
            time.sleep(5)

        else:
            self.module.fail_json(msg="Timeout limit reached while waiting for VM to enter a powered off state.")

    def reset_vm(self):
        if self.current_state not in ('poweredon', 'poweringon', 'resetting', 'poweredoff'):
            self.module.fail_json(msg="Cannot restart virtual machine in the current state %s" % self.current_state)
        return self.vm.Reset()

    def suspend_vm(self):
        if self.current_state not in ('poweredon', 'poweringon'):
            self.module.fail_json(msg='Cannot suspend virtual machine in the current state %s' % self.current_state)
        return self.vm.Suspend()

    def set_vm_state_using_vmtools(self):
        task = None
        if self.current_state == 'poweredon':
            if self.vm.guest.toolsRunningStatus == 'guestToolsRunning':
                if self.desired_state == 'shutdownguest':
                    task = self.vm.ShutdownGuest()
                else:
                    task = self.vm.RebootGuest()
                # Set result['changed'] immediately because
                # shutdown and reboot return None.
                self.result['changed'] = True
            else:
                self.module.fail_json(msg="VMware tools should be installed for guest shutdown/reboot")
        elif self.current_state == 'poweredoff' and self.desired_state == 'shutdownguest':
            self.result['changed'] = False
        else:
            self.module.fail_json(msg="Virtual machine %s must be in poweredon state for guest reboot" % self.vm.name)
        return task

    def set_vm_powerstate(self):
        """
        Set the power status for a VM determined by the current and
        requested states. force is forceful
        """
        # Need Force
        if not self.params['force'] and self.current_state not in ['poweredon', 'poweredoff']:
            self.module.fail_json(msg="Virtual Machine is in %s power state. Force is required!" % self.current_state)

        task = None
        desired_powerstate = {
            'poweredoff': self.vm.PowerOff,
            'poweredon': self.vm.PowerOn,
            'rebootguest': self.set_vm_state_using_vmtools,
            'restarted': self.reset_vm,
            'shutdownguest': self.set_vm_state_using_vmtools,
            'suspended': self.suspend_vm,
        }
        try:
            if self.desired_state in desired_powerstate:
                task = desired_powerstate[self.desired_state]()
            else:
                self.module.fail_json(msg="Unsupported expected state provided: %s" % self.desired_state)

        except Exception as e:
            self.module.fail_json(msg=to_text(e))

        self.run_vm_configuration_task(task)
        if self.desired_state == 'shutdownguest':
            self._poll_vm_state_for_shutdown()

    def configure_vm_powerstate(self):
        """
        Configures a VMs powerstate
        """
        scheduled_at = self.params.get('scheduled_at', None)
        if scheduled_at:
            scheduled_task_spec = self.configure_scheduled_task_spec(scheduled_at)
            self.configure_vm_scheduled_powerstate(scheduled_task_spec)
        else:
            self.set_vm_powerstate()

    def configure_scheduled_task_spec(self, scheduled_at):
        """
        Returns:
            ScheduledTaskSpec, object that contains all specifications regarding the scheduled task
        """
        if not self.is_vcenter():
            self.module.fail_json(msg="Scheduling task requires vCenter, hostname %s "
                                  "is an ESXi server." % self.params.get('hostname'))
        powerstate = {
            'powered-off': vim.VirtualMachine.PowerOff,
            'powered-on': vim.VirtualMachine.PowerOn,
            'reboot-guest': vim.VirtualMachine.RebootGuest,
            'restarted': vim.VirtualMachine.Reset,
            'shutdown-guest': vim.VirtualMachine.ShutdownGuest,
            'suspended': vim.VirtualMachine.Suspend,
        }
        try:
            scheduled_date = datetime.strptime(scheduled_at, '%d/%m/%Y %H:%M')
        except ValueError as e:
            self.module.fail_json(msg="Failed to convert given date and time string to Python datetime object,"
                                  "please specify string in 'dd/mm/yyyy hh:mm' format: %s" % to_native(e))
        scheduled_task_spec = vim.scheduler.ScheduledTaskSpec()
        scheduled_task_spec.name = self.params['scheduled_task_name'] or 'task_%s' % str(randint(10000, 99999))
        default_desciption = 'Scheduled task for vm %s for operation %s at %s' % (self.vm.name, self.params['state'],
                                                                                  scheduled_at)
        scheduled_task_spec.scheduler = vim.scheduler.OnceTaskScheduler()
        scheduled_task_spec.description = self.params['scheduled_task_description'] or default_desciption
        scheduled_task_spec.scheduler.runAt = scheduled_date
        scheduled_task_spec.action = vim.action.MethodAction()
        scheduled_task_spec.action.name = powerstate[self.params['state']]
        scheduled_task_spec.enabled = self.params['scheduled_task_enabled']

        return scheduled_task_spec

    def configure_vm_scheduled_powerstate(self, scheduled_task_spec):
        """
        Configures a VM powerstate when scheduled task option is set
        """
        try:
            self.content.scheduledTaskManager.CreateScheduledTask(self.vm, scheduled_task_spec)
            # As this is async task, we create scheduled task and mark state to changed.
            self.result['changed'] = True
        except vim.fault.InvalidName as e:
            self.module.fail_json(msg="Failed to create scheduled task %s for %s : %s" % (self.params.get('state'),
                                                                                          self.vm.name,
                                                                                          to_native(e.msg)))
        except vim.fault.DuplicateName as e:
            self.module.fail_json(msg="Failed to create scheduled task %s as specified task "
                                  "name is invalid: %s" % (self.params.get('state'),
                                                           to_native(e.msg)))
        except vmodl.fault.InvalidArgument as e:
            err_msg = "Failed to create scheduled task %s as specifications given are invalid: " % self.params.get('state')
            if scheduled_task_spec.scheduler.runAt < datetime.now():
                err_msg += "the specified time has already passed"
            else:
                err_msg += to_native(e.msg)
            self.module.fail_json(msg=err_msg)

    def answer_questions(self):
        if not self.vm.runtime.question:
            return
        if not self.params['question_answers']:
            self.module.fail_json(msg="No answers provided for question %s, set answers using the question_answers option"
                                  % self.vm.runtime.question.text)
        self.result['changed'] = True
        if self.module.check_mode:
            return
        try:
            VmQuestionHandler(vm=self.vm, answers=self.params.get('question_answers', None)).handle_vm_questions()
        except TaskError as e:
            self.module.fail_json(msg=to_text(e))


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                datacenter=dict(type='str', required=True),
                state=dict(type='str', default='powered-on',
                                choices=['powered-off', 'powered-on', 'reboot-guest', 'restarted', 'shutdown-guest', 'suspended']),
                name=dict(type='str'),
                name_match=dict(type='str', choices=['first', 'last'], default='first'),
                uuid=dict(type='str'),
                moid=dict(type='str'),
                use_instance_uuid=dict(type='bool', default=False),
                folder=dict(type='str', required=False),
                folder_paths_are_absolute=dict(type='bool', required=False, default=False),
                force=dict(type='bool', default=False),
                scheduled_at=dict(type='str', required=False),
                scheduled_task_name=dict(type='str', required=False),
                scheduled_task_description=dict(type='str', required=False),
                scheduled_task_enabled=dict(type='bool', default=True),
                timeout=dict(type='int', default=3600),
                question_answers=dict(type='list',
                                      required=False,
                                      elements='dict',
                                      options=dict(
                                          question=dict(type='str', required=True),
                                          response=dict(type='str', required=True)
                                      ))
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ['name', 'uuid', 'moid'],
            ['scheduled_at', 'question_answers']
        ],
        required_one_of=[
            ['name', 'uuid', 'moid']
        ],
    )

    vm_powerstate = VmPowerstateModule(module)
    vm_powerstate.answer_questions()
    if vm_powerstate.current_state == vm_powerstate.desired_state:
        module.exit_json(**vm_powerstate.result)

    if module.check_mode:
        vm_powerstate.result['changed'] = True
        module.exit_json(**vm_powerstate.result)

    vm_powerstate.configure_vm_powerstate()

    module.exit_json(**vm_powerstate.result)


if __name__ == '__main__':
    main()
