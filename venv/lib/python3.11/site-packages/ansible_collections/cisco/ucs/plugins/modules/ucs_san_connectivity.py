#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: ucs_san_connectivity
short_description: Configures SAN Connectivity Policies on Cisco UCS Manager
description:
- Configures SAN Connectivity Policies on Cisco UCS Manager.
extends_documentation_fragment: cisco.ucs.ucs
options:
  state:
    description:
    - If C(present), will verify SAN Connectivity Policies are present and will create if needed.
    - If C(absent), will verify SAN Connectivity Policies are absent and will delete if needed.
    choices: [present, absent]
    default: present
    type: str
  name:
    description:
    - The name of the SAN Connectivity Policy.
    - This name can be between 1 and 16 alphanumeric characters.
    - "You cannot use spaces or any special characters other than - (hyphen), \"_\" (underscore), : (colon), and . (period)."
    - You cannot change this name after the policy is created.
    type: str
  description:
    description:
    - A description of the policy.
    - Cisco recommends including information about where and when to use the policy.
    - Enter up to 256 characters.
    - "You can use any characters or spaces except the following:"
    - "` (accent mark), \ (backslash), ^ (carat), \" (double quote), = (equal sign), > (greater than), < (less than), or ' (single quote)."
    aliases: [ descr ]
    type: str
  wwnn_pool:
    description:
    - Name of the WWNN pool to use for WWNN assignment.
    default: default
    type: str
  vhba_list:
    description:
    - List of vHBAs used by the SAN Connectivity Policy.
    - vHBAs used by the SAN Connectivity Policy must be created from a vHBA template.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the virtual HBA (required).
        type: str
      vhba_template:
        description:
        - The name of the virtual HBA template (required).
        type: str
      adapter_policy:
        description:
        - The name of the Fibre Channel adapter policy.
        - A user defined policy can be used, or one of the system defined policies (default, Linux, Solaris, VMware, Windows, WindowsBoot)
        default: default
        type: str
      order:
        description:
        - String specifying the vHBA assignment order (e.g., '1', '2').
        default: unspecified
        type: str
  org_dn:
    description:
    - Org dn (distinguished name)
    default: org-root
    type: str
requirements:
- ucsmsdk
author:
- David Soper (@dsoper2)
- John McDonough (@movinalot)
- CiscoUcs (@CiscoUcs)
'''

EXAMPLES = r'''
- name: Configure SAN Connectivity Policy
  cisco.ucs.ucs_san_connectivity:
    hostname: 172.16.143.150
    username: admin
    password: password
    name: Cntr-FC-Boot
    wwnn_pool: WWNN-Pool
    vhba_list:
    - name: Fabric-A
      vhba_template: vHBA-Template-A
      adapter_policy: Linux
    - name: Fabric-B
      vhba_template: vHBA-Template-B
      adapter_policy: Linux

- name: Remove SAN Connectivity Policy
  cisco.ucs.ucs_san_connectivity:
    hostname: 172.16.143.150
    username: admin
    password: password
    name: Cntr-FC-Boot
    state: absent
'''

RETURN = r'''
#
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.ucs.plugins.module_utils.ucs import UCSModule, ucs_argument_spec


def main():
    vhba_list = dict(
        name=dict(type='str'),
        vhba_template=dict(type='str'),
        adapter_policy=dict(type='str', default='default'),
        order=dict(type='str', default='unspecified'),
    )
    argument_spec = ucs_argument_spec.copy()
    argument_spec.update(
        org_dn=dict(type='str', default='org-root'),
        name=dict(type='str'),
        description=dict(type='str', aliases=['descr']),
        wwnn_pool=dict(type='str', default='default'),
        vhba_list=dict(type='list', elements='dict', options=vhba_list),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    ucs = UCSModule(module)

    err = False

    from ucsmsdk.mometa.vnic.VnicSanConnPolicy import VnicSanConnPolicy
    from ucsmsdk.mometa.vnic.VnicFcNode import VnicFcNode
    from ucsmsdk.mometa.vnic.VnicFc import VnicFc
    from ucsmsdk.mometa.vnic.VnicFcIf import VnicFcIf

    changed = False
    try:
        san_connectivity_list = [module.params]
        for san_connectivity in san_connectivity_list:
            mo_exists = False
            props_match = False
            # set default params.  Done here to set values for lists which can't be done in the argument_spec
            if not san_connectivity.get('wwnn_pool'):
                san_connectivity['wwnn_pool'] = 'default'
            if san_connectivity.get('vhba_list'):
                for vhba in san_connectivity['vhba_list']:
                    if not vhba.get('adapter_policy'):
                        vhba['adapter_policy'] = ''
                    if not vhba.get('order'):
                        vhba['order'] = 'unspecified'
            # dn is <org_dn>/san-conn-pol-<name>
            dn = module.params['org_dn'] + '/san-conn-pol-' + san_connectivity['name']

            mo = ucs.login_handle.query_dn(dn)
            if mo:
                mo_exists = True
                # check top-level mo props
                kwargs = dict(descr=san_connectivity['description'])
                if (mo.check_prop_match(**kwargs)):
                    # top-level props match, check next level mo/props
                    # vnicFcNode object
                    child_dn = dn + '/fc-node'
                    mo_1 = ucs.login_handle.query_dn(child_dn)
                    if mo_1:
                        kwargs = dict(ident_pool_name=san_connectivity['wwnn_pool'])
                        if (mo_1.check_prop_match(**kwargs)):
                            if not san_connectivity.get('vhba_list'):
                                props_match = True
                            else:
                                # check vnicFc props
                                for vhba in san_connectivity['vhba_list']:
                                    child_dn = dn + '/fc-' + vhba['name']
                                    mo_2 = ucs.login_handle.query_dn(child_dn)
                                    kwargs = {}
                                    kwargs['adaptor_profile_name'] = vhba['adapter_policy']
                                    kwargs['order'] = vhba['order']
                                    kwargs['nw_templ_name'] = vhba['vhba_template']
                                    if (mo_2.check_prop_match(**kwargs)):
                                        props_match = True

            if module.params['state'] == 'absent':
                # mo must exist but all properties do not have to match
                if mo_exists:
                    if not module.check_mode:
                        ucs.login_handle.remove_mo(mo)
                        ucs.login_handle.commit()
                    changed = True
            else:
                if not props_match:
                    if not module.check_mode:
                        # create if mo does not already exist
                        mo = VnicSanConnPolicy(
                            parent_mo_or_dn=module.params['org_dn'],
                            name=san_connectivity['name'],
                            descr=san_connectivity['description'],
                        )
                        mo_1 = VnicFcNode(
                            parent_mo_or_dn=mo,
                            ident_pool_name=san_connectivity['wwnn_pool'],
                            addr='pool-derived',
                        )
                        if san_connectivity.get('vhba_list'):
                            for vhba in san_connectivity['vhba_list']:
                                mo_2 = VnicFc(
                                    parent_mo_or_dn=mo,
                                    name=vhba['name'],
                                    adaptor_profile_name=vhba['adapter_policy'],
                                    nw_templ_name=vhba['vhba_template'],
                                    order=vhba['order'],
                                )
                                mo_2_1 = VnicFcIf(
                                    parent_mo_or_dn=mo_2,
                                    name='default',
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
