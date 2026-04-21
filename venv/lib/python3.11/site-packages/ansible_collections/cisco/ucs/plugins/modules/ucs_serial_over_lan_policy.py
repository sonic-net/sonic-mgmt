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
module: ucs_serial_over_lan_policy

short_description: Manages UCS Serial Over Lan Policies on UCS Manager

description:
  - Manages UCS Serial Over Lan Policies on UCS Manager.

extends_documentation_fragment: cisco.ucs.ucs

options:
    state:
        description:
        - If C(absent), will remove Serial Over Lan Policy.
        - If C(present), will create or update Serial Over Lan Policy.
        choices: [absent, present]
        default: present
        type: str

    name:
        description:
        - The name of the serial over lan policy.
        - Enter up to 16 characters.
        - "You can use any characters or spaces except the following:"
        - "` (accent mark), \ (backslash), ^ (carat), \" (double quote)"
        - "= (equal sign), > (greater than), < (less than), ' (single quote)."
        required: true
        type: str

    description:
        description:
        - A user-defined description of the serial over lan policy.
        - Enter up to 256 characters.
        - "You can use any characters or spaces except the following:"
        - "` (accent mark), \ (backslash), ^ (carat), \" (double quote)"
        - "= (equal sign), > (greater than), < (less than), ' (single quote)."
        aliases: [ descr ]
        type: str

    admin_state:
        description:
        - The administrative state of the serial over lan policy.
        - disable Serial over LAN access is blocked.
        - enable Serial over LAN access is permitted.
        choices: [disable, enable]
        type: str

    speed:
        description:
        - The transmission speed of the serial over lan policy.
        choices: ['9600', '19200', '38400', '57600', '115200']
        type: str

    org_dn:
        description:
        - Org dn (distinguished name) of the serial over lan policy.
        default: org-root
        type: str

requirements:
- ucsmsdk

author:
- John McDonough (@movinalot)
'''

EXAMPLES = r'''
- name: Add UCS Serial Over Lan Policy
  cisco.ucs.ucs_serial_over_lan:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    name: sol_org_root
    description: Serial Over Lan for Org root servers
    admin_state: enable
    speed: 115200
  delegate_to: localhost

- name: Add UCS Serial Over Lan Policy in Organization
  cisco.ucs.ucs_serial_over_lan:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    org_dn: org-root/org-prod
    name: sol_org_prod
    description: Serial Over Lan for Org Prod servers
    admin_state: enable
    speed: 115200
  delegate_to: localhost

- name: Update UCS Serial Over Lan Policy in Organization
  cisco.ucs.ucs_serial_over_lan:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    org_dn: org-root/org-prod
    name: sol_org_prod
    description: Serial Over Lan for Org Prod servers
    admin_state: enable
    speed: 38400
  delegate_to: localhost

- name: Update UCS Serial Over Lan Policy in Organization
  cisco.ucs.ucs_serial_over_lan:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    org_dn: org-root/org-prod
    name: sol_org_prod
    descr: Serial Over Lan for Org Prod servers
    admin_state: enable
    speed: 57600
  delegate_to: localhost

- name: Delete UCS Serial Over Lan Policy in Organization
  cisco.ucs.ucs_serial_over_lan:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: absent
    org_dn: org-root/org-prod
    name: sol_org_prod
  delegate_to: localhost

- name: Delete UCS Serial Over Lan Policy
  cisco.ucs.ucs_serial_over_lan:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: absent
    name: sol_org_root
  delegate_to: localhost
'''

RETURN = r'''
#
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.ucs.plugins.module_utils.ucs import (
    UCSModule,
    ucs_argument_spec
)


def main():
    argument_spec = ucs_argument_spec.copy()
    argument_spec.update(
        org_dn=dict(type='str', default='org-root'),
        name=dict(required=True, type='str'),
        description=dict(type='str', aliases=['descr']),
        admin_state=dict(type='str', choices=['enable', 'disable']),
        speed=dict(type='str', choices=[
            '9600', '19200', '38400', '57600', '115200'
        ]),
        state=dict(
            type='str', default='present',
            choices=['present', 'absent']
        ),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['name']],
        ],
    )

    # UCSModule verifies ucsmsdk is present and exits on failure.
    # Imports are below for UCS object creation.
    ucs = UCSModule(module)
    from importlib import import_module
    from ucsmsdk.ucscoreutils import get_meta_info

    # The Class(es) this module is managing
    module_file = 'ucsmsdk.mometa.sol.SolPolicy'
    module_class = 'SolPolicy'
    mo_module = import_module(module_file)
    mo_class = getattr(mo_module, module_class)

    META = get_meta_info(class_id=module_class)

    err = False
    changed = False
    requested_state = module.params['state']

    kwargs = dict()

    # Manage Attributes
    for attribute in ['admin_state', 'speed']:
        if module.params[attribute] is not None:
            kwargs[attribute] = module.params[attribute]

    kwargs['descr'] = module.params['description']

    try:
        dn = (
            module.params['org_dn'] + '/' +
            META.rn[0:META.rn.index('-') + 1] +
            module.params['name']
        )
        mo = ucs.login_handle.query_dn(dn)

        # Determine state change
        if mo:
            # Object exists, if it should exist has anything changed?
            if requested_state == 'present':
                # Do some or all Object properties not match, that is a change

                if not mo.check_prop_match(**kwargs):
                    changed = True

        # Object does not exist but should, that is a change
        else:
            if requested_state == 'present':
                changed = True

        # Object exists but should not, that is a change
        if mo and requested_state == 'absent':
            changed = True

        # Apply state if not check_mode
        if changed and not module.check_mode:
            if requested_state == 'absent':
                ucs.login_handle.remove_mo(mo)
            else:
                kwargs['parent_mo_or_dn'] = module.params['org_dn']
                kwargs['name'] = module.params['name']

                mo = mo_class(**kwargs)
                ucs.login_handle.add_mo(mo, modify_present=True)
            ucs.login_handle.commit()

    except Exception as e:
        err = True
        ucs.result['msg'] = "setup error: %s " % str(e)

    ucs.result['changed'] = changed
    if err:
        module.fail_json(**ucs.result)

    module.exit_json(**ucs.result)


if __name__ == '__main__':
    main()
