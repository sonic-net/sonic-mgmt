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
module: ucs_graphics_card_policy

short_description: Manages UCS Graphics Card Policies on UCS Manager

description:
  - Manages UCS Graphics Card Policies on UCS Manager.

extends_documentation_fragment: cisco.ucs.ucs

options:
    state:
        description:
        - If C(absent), will remove organization.
        - If C(present), will create or update organization.
        choices: [absent, present]
        default: present
        type: str

    name:
        description:
        - The name of the organization.
        - Enter up to 16 characters.
        - "You can use any characters or spaces except the following:"
        - "` (accent mark), \ (backslash), ^ (carat), \" (double quote)"
        - "= (equal sign), > (greater than), < (less than), ' (single quote)."
        required: true
        type: str

    description:
        description:
        - A user-defined description of the organization.
        - Enter up to 256 characters.
        - "You can use any characters or spaces except the following:"
        - "` (accent mark), \ (backslash), ^ (carat), \" (double quote)"
        - "= (equal sign), > (greater than), < (less than), ' (single quote)."
        aliases: [ descr ]
        type: str

    graphics_card_mode:
        description:
        - Set the Graphics Card Mode.
        choices: [any-configuration, compute, graphics]
        type: str

    org_dn:
        description:
        - Org dn (distinguished name)
        default: org-root
        type: str

requirements:
- ucsmsdk

author:
- John McDonough (@movinalot)
'''

EXAMPLES = r'''
- name: Add UCS Graphics Card Policy
  cisco.ucs.ucs_graphics_card_policy:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    description: Any Graphics Mode Policy
    name: any_graphics
    graphics_card_mode: any-configuration
  delegate_to: localhost

- name: Add UCS Graphics Card Policy in an Organization
  cisco.ucs.ucs_graphics_card_policy:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    org_dn: org-root/org-prod
    description: Any Graphics Mode Policy
    name: prod_graphics
    graphics_card_mode: any-configuration
  delegate_to: localhost

- name: Update UCS Graphics Card Policy in an Organization
  cisco.ucs.ucs_graphics_card_policy:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    org_dn: org-root/org-prod
    description: Graphics Mode Policy
    name: prod_graphics
    graphics_card_mode: graphics
  delegate_to: localhost

- name: Update UCS Graphics Card Policy in an Organization
  cisco.ucs.ucs_graphics_card_policy:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: present
    org_dn: org-root/org-prod
    description: Compute Mode Policy
    name: prod_graphics
    graphics_card_mode: compute
  delegate_to: localhost

- name: Delete UCS Graphics Card Policy in an Organization
  cisco.ucs.ucs_graphics_card_policy:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: absent
    org_dn: org-root/org-prod
    name: prod_graphics
  delegate_to: localhost

- name: Delete UCS Graphics Card Policy
  cisco.ucs.ucs_graphics_card_policy:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    state: absent
    name: any_graphics
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
        graphics_card_mode=dict(type='str', choices=[
            'any-configuration',
            'compute',
            'graphics'
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
    module_file = 'ucsmsdk.mometa.compute.ComputeGraphicsCardPolicy'
    module_class = 'ComputeGraphicsCardPolicy'
    mo_module = import_module(module_file)
    mo_class = getattr(mo_module, module_class)

    META = get_meta_info(class_id=module_class)

    err = False
    changed = False
    requested_state = module.params['state']

    kwargs = dict()

    # Manage Attributes
    for attribute in [
            'graphics_card_mode', 'description']:
        if module.params[attribute] is not None:
            kwargs[attribute] = module.params[attribute]

    try:
        dn = (
            module.params['org_dn'] + '/' +
            META.rn[0:META.rn.rindex('-') + 1] +
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
