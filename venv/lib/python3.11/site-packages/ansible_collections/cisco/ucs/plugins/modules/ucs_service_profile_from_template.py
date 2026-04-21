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
module: ucs_service_profile_from_template
short_description: Configures Service Profiles from templates on Cisco UCS Manager
description:
- Configures Service Profile created from templates on Cisco UCS Manager.
extends_documentation_fragment: cisco.ucs.ucs
options:
  state:
    description:
    - If C(present), will verify Service Profiles are present and will create if needed.
    - If C(absent), will verify Service Profiles are absent and will delete if needed.
    choices: [present, absent]
    default: present
    type: str
  name:
    description:
    - The name of the service profile.
    - This name can be between 2 and 32 alphanumeric characters.
    - "You cannot use spaces or any special characters other than - (hyphen), \"_\" (underscore), : (colon), and . (period)."
    - This name must be unique across all service profiles and service profile templates within the same organization.
    required: true
    type: str
  source_template:
    description:
    - The name of the service profile template used to create this serivce profile.
    required: true
    type: str
  power_state:
    description:
    - The power state to be applied when this service profile is associated with a server.
    - If no value is provided, the power_state for the service profile will not be modified.
    choices: [up, down]
    type: str
  user_label:
    description:
    - The User Label you want to assign to this service profile.
    type: str
  org_dn:
    description:
    - Org dn (distinguished name)
    default: org-root
    type: str
  description:
    description:
    - Optional
    - The Description of the service profile
    type: str
requirements:
- ucsmsdk
author:
- David Soper (@dsoper2)
- CiscoUcs (@CiscoUcs)
'''

EXAMPLES = r'''
- name: Configure Service Profile from Template
  cisco.ucs.ucs_service_profile_from_template:
    hostname: 172.16.143.150
    username: admin
    password: password
    name: test-sp-instance1
    source_template: test-sp
    discription: Created from Ansible

- name: Remove Service Profile
  cisco.ucs.ucs_service_profile_from_template:
    hostname: 172.16.143.150
    username: admin
    password: password
    name: test-sp-instance1
    state: absent
'''

RETURN = r'''
#
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.ucs.plugins.module_utils.ucs import UCSModule, ucs_argument_spec


def main():
    argument_spec = ucs_argument_spec.copy()
    argument_spec.update(
        org_dn=dict(type='str', default='org-root'),
        name=dict(type='str', required=True),
        source_template=dict(type='str', required=True),
        user_label=dict(type='str'),
        power_state=dict(type='str', choices=['up', 'down']),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        description=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    ucs = UCSModule(module)

    err = False

    # UCSModule creation above verifies ucsmsdk is present and exits on failure.  Additional imports are done below.
    from ucsmsdk.mometa.ls.LsServer import LsServer
    from ucsmsdk.mometa.ls.LsPower import LsPower

    changed = False
    try:
        mo_exists = False
        props_match = False
        dn = module.params['org_dn'] + '/ls-' + module.params['name']

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
                kwargs = dict(src_templ_name=module.params['source_template'])
                kwargs['usr_lbl'] = module.params['user_label']
                # service profiles are of type 'instance'
                kwargs['type'] = 'instance'

                if mo.check_prop_match(**kwargs):
                    # top-level props match
                    if module.params.get('power_state'):
                        child_dn = dn + '/power'
                        mo_1 = ucs.login_handle.query_dn(child_dn)
                        if mo_1:
                            kwargs = dict(state=module.params['power_state'])
                            if mo_1.check_prop_match(**kwargs):
                                props_match = True
                    else:
                        # no power state provided, use existing state as match
                        props_match = True

            if not props_match:
                if not module.check_mode:
                    # create if mo does not already exist
                    mo = LsServer(
                        parent_mo_or_dn=module.params['org_dn'],
                        name=module.params['name'],
                        src_templ_name=module.params['source_template'],
                        type='instance',
                        usr_lbl=module.params['user_label'],
                        descr=module.params['description'],
                    )
                    if module.params.get('power_state'):
                        admin_state = 'admin-' + module.params['power_state']
                        mo_1 = LsPower(
                            parent_mo_or_dn=mo,
                            state=admin_state,
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
