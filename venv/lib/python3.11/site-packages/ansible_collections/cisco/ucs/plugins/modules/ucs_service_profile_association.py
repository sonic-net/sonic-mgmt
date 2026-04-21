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
module: ucs_service_profile_association
short_description: Configures Service Profile Association on Cisco UCS Manager
description:
- Configures Service Profile Association (change association or disassociate) on Cisco UCS Manager.
extends_documentation_fragment: cisco.ucs.ucs
options:
  state:
    description:
    - If C(present), will verify service profile association and associate with specified server or server pool if needed.
    - If C(absent), will verify service profile is not associated and will disassociate if needed.  This is the same as specifying Assign Later in the webUI.
    choices: [present, absent]
    default: present
    type: str
  service_profile_name:
    description:
    - The name of the Service Profile being associated or disassociated.
    required: true
    type: str
  server_assignment:
    description:
    - "Specifies how to associate servers with this service profile using the following choices:"
    - "server - Use to pre-provision a slot or select an existing server.  Slot or server is specified by the server_dn option."
    - "pool - Use to select from a server pool.  The server_pool option specifies the name of the server pool to use."
    - Option is not valid if the service profile is bound to a template.
    - Optional if the state is absent.
    choices: [server, pool]
    type: str
  server_dn:
    description:
    - The Distinguished Name (dn) of the server object used for pre-provisioning or selecting an existing server.
    - Required if the server_assignment option is server.
    - Optional if the state is absent.
    type: str
  server_pool_name:
    description:
    - Name of the server pool used for server pool based assignment.
    - Required if the server_assignment option is pool.
    - Optional if the state is absent.
    type: str
  restrict_migration:
    description:
    - Restricts the migration of the service profile after it has been associated with a server.
    - If set to no, Cisco UCS Manager does not perform any compatibility checks on the new server before migrating the existing service profile.
    - If set to no and the hardware of both servers used in migration are not similar, the association might fail.
    choices: ['yes', 'no']
    default: 'no'
    type: str
  org_dn:
    description:
    - The distinguished name (dn) of the organization where the resource is assigned.
    default: org-root
    type: str
requirements:
- ucsmsdk
author:
- David Soper (@dsoper2)
- CiscoUcs (@CiscoUcs)
'''

EXAMPLES = r'''
- name: Change Service Profile Association to server pool Container-Pool and restrict migration
  cisco.ucs.ucs_service_profile_association:
    hostname: 172.16.143.150
    username: admin
    password: password
    service_profile_name: test-sp
    server_assignment: pool
    server_pool_name: Container-Pool
    restrict_migration: 'yes'

- name: Attempt to change association once a minute for up to 10 minutes
  cisco.ucs.ucs_service_profile_association:
    hostname: 172.16.143.150
    username: admin
    password: password
    service_profile_name: test-sp
    server_assignment: server
    server_dn: sys/chassis-2/blade-1
  register: result
  until: result.assign_state == 'assigned' and result.assoc_state == 'associated'
  retries: 10
  delay: 60

- name: Disassociate Service Profile
  cisco.ucs.ucs_service_profile_association:
    hostname: 172.16.143.150
    username: admin
    password: password
    service_profile_name: test-sp
    state: absent
'''

RETURN = r'''
assign_state:
  description: The logical server Assigned State (assigned, unassigned, or failed).
  returned: success
  type: str
  sample: assigned
assoc_state:
  description: The logical server Association State (associated or unassociated).
  returned: success
  type: str
  sample: associated
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.ucs.plugins.module_utils.ucs import UCSModule, ucs_argument_spec


def main():
    argument_spec = ucs_argument_spec.copy()
    argument_spec.update(
        org_dn=dict(type='str', default='org-root'),
        service_profile_name=dict(type='str', required=True),
        server_assignment=dict(type='str', choices=['server', 'pool']),
        server_dn=dict(type='str'),
        server_pool_name=dict(type='str'),
        restrict_migration=dict(type='str', default='no', choices=['yes', 'no']),
        state=dict(default='present', choices=['present', 'absent'], type='str'),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['server_assignment']],
            ['server_assignment', 'server', ['server_dn']],
            ['server_assignment', 'pool', ['server_pool_name']],
        ],
        mutually_exclusive=[
            ['server_dn', 'server_pool_name'],
        ],
    )
    # UCSModule verifies ucsmsdk is present and exits on failure.  Imports are below ucs object creation.
    ucs = UCSModule(module)

    err = False

    from ucsmsdk.mometa.ls.LsRequirement import LsRequirement
    from ucsmsdk.mometa.ls.LsBinding import LsBinding
    from ucsmsdk.mometa.ls.LsServer import LsServer

    changed = False
    ucs.result['assign_state'] = 'unassigned'
    ucs.result['assoc_state'] = 'unassociated'
    try:
        ls_mo_exists = False
        pn_mo_exists = False
        pn_req_mo_exists = False
        props_match = False

        # logical server distinguished name is <org>/ls-<name> and physical node dn appends 'pn' or 'pn-req'
        ls_dn = module.params['org_dn'] + '/ls-' + module.params['service_profile_name']
        ls_mo = ucs.login_handle.query_dn(ls_dn)
        if ls_mo:
            ls_mo_exists = True
            pn_dn = ls_dn + '/pn'
            pn_mo = ucs.login_handle.query_dn(pn_dn)
            if pn_mo:
                pn_mo_exists = True

            pn_req_dn = ls_dn + '/pn-req'
            pn_req_mo = ucs.login_handle.query_dn(pn_req_dn)
            if pn_req_mo:
                pn_req_mo_exists = True

        if module.params['state'] == 'absent':
            if ls_mo_exists and ls_mo.assign_state != 'unassigned':
                if pn_mo_exists:
                    if not module.check_mode:
                        ucs.login_handle.remove_mo(pn_mo)
                        ucs.login_handle.commit()
                    changed = True
                elif pn_req_mo_exists:
                    if not module.check_mode:
                        ucs.login_handle.remove_mo(pn_req_mo)
                        ucs.login_handle.commit()
                    changed = True
        elif ls_mo_exists:
            # check if logical server is assigned and associated
            ucs.result['assign_state'] = ls_mo.assign_state
            ucs.result['assoc_state'] = ls_mo.assoc_state
            if module.params['server_assignment'] == 'pool' and pn_req_mo_exists:
                # check the current pool
                kwargs = dict(name=module.params['server_pool_name'])
                kwargs['restrict_migration'] = module.params['restrict_migration']
                if pn_req_mo.check_prop_match(**kwargs):
                    props_match = True
            elif pn_mo_exists:
                kwargs = dict(pn_dn=module.params['server_dn'])
                kwargs['restrict_migration'] = module.params['restrict_migration']
                if pn_mo.check_prop_match(**kwargs):
                    props_match = True

            if not props_match:
                if not module.check_mode:
                    # create if mo does not already exist in desired state
                    mo = LsServer(
                        parent_mo_or_dn=module.params['org_dn'],
                        name=module.params['service_profile_name'],
                    )
                    if module.params['server_assignment'] == 'pool':
                        if pn_mo_exists:
                            ucs.login_handle.remove_mo(pn_mo)

                        mo_1 = LsRequirement(
                            parent_mo_or_dn=mo,
                            name=module.params['server_pool_name'],
                            restrict_migration=module.params['restrict_migration'],
                        )
                    else:
                        mo_1 = LsBinding(
                            parent_mo_or_dn=mo,
                            pn_dn=module.params['server_dn'],
                            restrict_migration=module.params['restrict_migration'],
                        )
                        ucs.login_handle.add_mo(mo_1, True)
                        ucs.login_handle.commit()

                        pn_req_mo = ucs.login_handle.query_dn(pn_req_dn)
                        if pn_req_mo:
                            # profiles from templates will add a server pool, so remove and add the server again
                            ucs.login_handle.remove_mo(pn_req_mo)

                    ucs.login_handle.add_mo(mo_1, True)
                    ucs.login_handle.commit()
                    ls_mo = ucs.login_handle.query_dn(ls_dn)
                    if ls_mo:
                        ucs.result['assign_state'] = ls_mo.assign_state
                        ucs.result['assoc_state'] = ls_mo.assoc_state
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
