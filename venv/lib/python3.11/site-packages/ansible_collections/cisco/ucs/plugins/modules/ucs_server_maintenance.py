#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ucs_server_maintenance
short_description: Creates Server Maintenance Policy on Cisco UCS Manager
description:
- Configures Server Maintenance Policy on Cisco UCS Manager.
extends_documentation_fragment: cisco.ucs.ucs
options:
  state:
    description:
    - If C(present), will verify Server Maintenance Policy is present and will create if needed.
    - If C(absent), will verify Server Maintenance Policy is absent and will delete if needed.
    choices: [present, absent]
    default: present
    type: str
  name:
    description:
    - The name assigned to the Server Maintenance Policy.
    - The Server Maintenance Policy name is case sensitive.
    - This name can be between 1 and 16 alphanumeric characters.
    - "You cannot use spaces or any special characters other than - (hyphen), \"_\" (underscore), : (colon), and . (period)."
    - You cannot change this name after the Server Maintenance Policy is created.
    required: yes
    type: str
  description:
    description:
    - A description of the Server Maintenance Package Policy.
    - Cisco recommends including information about where and when to use the policy.
    - Enter up to 256 characters.
    - "You can use any characters or spaces except the following:"
    - "` (accent mark), \ (backslash), ^ (carat), \" (double quote), = (equal sign), > (greater than), < (less than), or ' (single quote)."
    aliases: [ descr ]
    type: str
  trigger_config:
    description:
    - This option is used in combination with either User Ack (user-ack) or Timer Automatic (timer-automatic).
    - When the On Next Boot option is enabled, the host OS reboot, shutdown, or server reset also triggers the associated FSM to apply the changes.
    - Note that de-selecting the On Next Boot option disables the Maintenance Policy on the BMC.
    choices: [on-next-boot]
    type: str
  uptime_disr:
    description:
    - When a Server profile is associated with a Server, or when changes are made to an associated Server profile, you must reboot the Server.
    - The Reboot Policy field determines when the reboot occurs for Server associated with any Server profiles that include this maintenance policy.
    choices: [immediate, timer-automatic, user-ack]
    required: true
    type: str
requirements:
- ucsmsdk
author:
- Brett Johnson (@brettjohnson008)
'''

EXAMPLES = r'''
- name: Add Server Maintenance Policy
  cisco.ucs.ucs_server_maintenance:
    hostname: 172.16.143.150
    username: admin
    password: password
    name: user-ack
    uptime_disr: user-ack
    trigger_config: on-next-boot
'''

RETURN = r'''
#
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.ucs.plugins.module_utils.ucs import UCSModule, ucs_argument_spec


def main():
    argument_spec = ucs_argument_spec.copy()
    argument_spec.update(
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        trigger_config=dict(type='str', choices=['on-next-boot']),
        uptime_disr=dict(type='str', required=True, choices=['immediate', 'timer-automatic', 'user-ack']),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    ucs = UCSModule(module)

    err = False

    # UCSModule creation above verifies ucsmsdk is present and exits on failure, so additional imports are done below.
    from ucsmsdk.mometa.lsmaint.LsmaintMaintPolicy import LsmaintMaintPolicy

    changed = False
    try:
        mo_exists = False
        props_match = False
        dn_base = 'org-root'
        dn = dn_base + '/maint-' + module.params['name']

        mo = ucs.login_handle.query_dn(dn)
        if mo:
            mo_exists = True

        if module.params['state'] == 'absent':
            # mo must exist but all properties do not have to match
            if mo_exists:
                if not module.check_mode:
                    ucs.login_handle.remove_mo(mo)
                    ucs.login_handle.commit()
                changed = True
        else:
            if mo_exists:
                # check top-level mo props
                kwargs = dict(name=module.params['name'])
                kwargs['descr'] = module.params['description']
                kwargs['trigger_config'] = module.params['trigger_config']
                kwargs['uptime_disr'] = module.params['uptime_disr']
                if mo.check_prop_match(**kwargs):
                    props_match = True

            if not props_match:
                if not module.check_mode:
                    # create if mo does not already exist
                    mo = LsmaintMaintPolicy(
                        parent_mo_or_dn=dn_base,
                        name=module.params['name'],
                        descr=module.params['description'],
                        trigger_config=module.params['trigger_config'],
                        uptime_disr=module.params['uptime_disr'],
                    )

                    ucs.login_handle.add_mo(mo, True)
                    ucs.login_handle.commit()
                changed = True

    except Exception as e:
        err = True
        ucs.result['msg'] = "setup error: %s " % str(e)

    ucs.result['changed'] = changed
    if err:
        module.fail_json(**ucs.result)
    module.exit_json(**ucs.result)


if __name__ == '__main__':
    main()
