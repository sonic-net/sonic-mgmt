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
module: ucs_ip_pool
short_description: Configures IP address pools on Cisco UCS Manager
description:
- Configures IP address pools and blocks of IP addresses on Cisco UCS Manager.
extends_documentation_fragment: cisco.ucs.ucs
options:
  state:
    description:
    - If C(present), will verify IP pool is present and will create if needed.
    - If C(absent), will verify IP pool is absent and will delete if needed.
    choices: [present, absent]
    default: present
    type: str
  name:
    description:
    - The name of the IP address pool.
    - This name can be between 1 and 32 alphanumeric characters.
    - "You cannot use spaces or any special characters other than - (hyphen), \"_\" (underscore), : (colon), and . (period)."
    - You cannot change this name after the IP address pool is created.
    required: yes
    type: str
  description:
    description:
    - The user-defined description of the IP address pool.
    - Enter up to 256 characters.
    - "You can use any characters or spaces except the following:"
    - "` (accent mark), \ (backslash), ^ (carat), \" (double quote), = (equal sign), > (greater than), < (less than), or ' (single quote)."
    aliases: [ descr ]
    type: str
  order:
    description:
    - The Assignment Order field.
    - "This can be one of the following:"
    - "default - Cisco UCS Manager selects a random identity from the pool."
    - "sequential - Cisco UCS Manager selects the lowest available identity from the pool."
    choices: [default, sequential]
    default: default
    type: str
  ipv4_blocks:
    description:
    - List of IPv4 blocks used by the IP Pool.
    type: list
    elements: dict
    suboptions:
      first_addr:
        description:
        - The first IPv4 address in the IPv4 addresses block.
        - This is the From field in the UCS Manager Add IPv4 Blocks menu.
        type: str
      last_addr:
        description:
        - The last IPv4 address in the IPv4 addresses block.
        - This is the To field in the UCS Manager Add IPv4 Blocks menu.
        type: str
      subnet_mask:
        description:
        - The subnet mask associated with the IPv4 addresses in the block.
        default: 255.255.255.0
        type: str
      default_gw:
        description:
        - The default gateway associated with the IPv4 addresses in the block.
        default: 0.0.0.0
        type: str
      primary_dns:
        description:
        - The primary DNS server that this block of IPv4 addresses should access.
        default: 0.0.0.0
        type: str
      secondary_dns:
        description:
        - The secondary DNS server that this block of IPv4 addresses should access.
        default: 0.0.0.0
        type: str
      state:
        description:
        - If C(present), will verify IP block is present and will create if needed.
        - If C(absent), will verify IP block is absent and will delete if needed.
        choices: [present, absent]
        default: present
        type: str
  ipv6_blocks:
    description:
    - List of IPv6 blocks used by the IP Pool.
    type: list
    elements: dict
    suboptions:
      ipv6_first_addr:
        description:
        - The first IPv6 address in the IPv6 addresses block.
        - This is the From field in the UCS Manager Add IPv6 Blocks menu.
        type: str
      ipv6_last_addr:
        description:
        - The last IPv6 address in the IPv6 addresses block.
        - This is the To field in the UCS Manager Add IPv6 Blocks menu.
        type: str
      ipv6_prefix:
        description:
        - The network address prefix associated with the IPv6 addresses in the block.
        default: '64'
        type: str
      ipv6_default_gw:
        description:
        - The default gateway associated with the IPv6 addresses in the block.
        default: '::'
        type: str
      ipv6_primary_dns:
        description:
        - The primary DNS server that this block of IPv6 addresses should access.
        default: '::'
        type: str
      ipv6_secondary_dns:
        description:
        - The secondary DNS server that this block of IPv6 addresses should access.
        default: '::'
        type: str
      state:
        description:
        - If C(present), will verify IP block is present and will create if needed.
        - If C(absent), will verify IP block is absent and will delete if needed.
        choices: [present, absent]
        default: present
        type: str
  org_dn:
    description:
    - Org dn (distinguished name)
    default: org-root
    type: str
requirements:
- ucsmsdk
author:
  - Brett Johnson (@sdbrett)
  - David Soper (@dsoper2)
  - John McDonough (@movinalot)
  - CiscoUcs (@CiscoUcs)
'''

EXAMPLES = r'''
- name: Configure IPv4 and IPv6 address pool
  cisco.ucs.ucs_ip_pool:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    name: ip-pool-01
    org_dn: org-root/org-level1
    ipv4_blocks:
    - first_addr: 192.168.10.1
      last_addr: 192.168.10.20
      subnet_mask: 255.255.255.128
      default_gw: 192.168.10.2
    - first_addr: 192.168.11.1
      last_addr: 192.168.11.20
      subnet_mask: 255.255.255.128
      default_gw: 192.168.11.2
    ipv6_blocks:
    - ipv6_first_addr: fe80::1cae:7992:d7a1:ed07
      ipv6_last_addr: fe80::1cae:7992:d7a1:edfe
      ipv6_default_gw: fe80::1cae:7992:d7a1:ecff
    - ipv6_first_addr: fe80::1cae:7992:d7a1:ec07
      ipv6_last_addr: fe80::1cae:7992:d7a1:ecfe
      ipv6_default_gw: fe80::1cae:7992:d7a1:ecff

- name: Delete IPv4 and IPv6 address pool blocks
  cisco.ucs.ucs_ip_pool:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    name: ip-pool-01
    org_dn: org-root/org-level1
    ipv4_blocks:
    - first_addr: 192.168.10.1
      last_addr: 192.168.10.20
      state: absent
    ipv6_blocks:
    - ipv6_first_addr: fe80::1cae:7992:d7a1:ec07
      ipv6_last_addr: fe80::1cae:7992:d7a1:ecfe
      state: absent

- name: Remove IPv4 and IPv6 address pool
  cisco.ucs.ucs_ip_pool:
    hostname: "{{ ucs_hostname }}"
    username: "{{ ucs_username }}"
    password: "{{ ucs_password }}"
    name: ip-pool-01
    state: absent
'''

RETURN = r'''
#
'''


def update_ip_pool(ucs, module):
    from ucsmsdk.mometa.ippool.IppoolPool import IppoolPool

    mo = IppoolPool(
        parent_mo_or_dn=module.params['org_dn'],
        name=module.params['name'],
        descr=module.params['descr'],
        assignment_order=module.params['order'],
    )
    ucs.login_handle.add_mo(mo, True)
    ucs.login_handle.commit()

    return mo


def match_existing_ipv4_block(ucs, dn, ipv4_block):
    # ipv4 block specified, check properties
    mo_1 = get_ip_block(ucs, dn, ipv4_block['first_addr'], ipv4_block['last_addr'], 'v4')
    if not mo_1:
        if ipv4_block['state'] == 'absent':
            return True
        return False
    else:
        if ipv4_block['state'] == 'absent':
            return False
        kwargs = dict(subnet=ipv4_block['subnet_mask'])
        kwargs['def_gw'] = ipv4_block['default_gw']
        kwargs['prim_dns'] = ipv4_block['primary_dns']
        kwargs['sec_dns'] = ipv4_block['secondary_dns']
        return mo_1.check_prop_match(**kwargs)


def match_existing_ipv6_block(ucs, dn, ipv6_block):
    # ipv6 block specified, check properties
    mo_1 = get_ip_block(ucs, dn, ipv6_block['ipv6_first_addr'], ipv6_block['ipv6_last_addr'], 'v6')
    if not mo_1:
        if ipv6_block['state'] == 'absent':
            return True
        return False
    else:
        if ipv6_block['state'] == 'absent':
            return False
        kwargs = dict(prefix=ipv6_block['ipv6_prefix'])
        kwargs['def_gw'] = ipv6_block['ipv6_default_gw']
        kwargs['prim_dns'] = ipv6_block['ipv6_primary_dns']
        kwargs['sec_dns'] = ipv6_block['ipv6_secondary_dns']
        return mo_1.check_prop_match(**kwargs)


def remove_ip_block(ucs, dn, ip_block, ip_version):
    if ip_version == 'v6':
        first_addr = ip_block['ipv6_first_addr']
        last_addr = ip_block['ipv6_last_addr']
    else:
        first_addr = ip_block['first_addr']
        last_addr = ip_block['last_addr']

    mo_1 = get_ip_block(ucs, dn, first_addr, last_addr, ip_version)
    if mo_1:
        ucs.login_handle.remove_mo(mo_1)
        ucs.login_handle.commit()


def update_ip_block(ucs, mo, ip_block, ip_version):

    remove_ip_block(ucs, mo.dn, ip_block, ip_version)
    if not ip_block['state'] == 'absent':
        if ip_version == 'v6':
            from ucsmsdk.mometa.ippool.IppoolIpV6Block import IppoolIpV6Block
            IppoolIpV6Block(
                parent_mo_or_dn=mo,
                to=ip_block['ipv6_last_addr'],
                r_from=ip_block['ipv6_first_addr'],
                prefix=ip_block['ipv6_prefix'],
                def_gw=ip_block['ipv6_default_gw'],
                prim_dns=ip_block['ipv6_primary_dns'],
                sec_dns=ip_block['ipv6_secondary_dns']
            )
            ucs.login_handle.add_mo(mo, True)
            ucs.login_handle.commit()
        else:
            from ucsmsdk.mometa.ippool.IppoolBlock import IppoolBlock
            IppoolBlock(
                parent_mo_or_dn=mo,
                to=ip_block['last_addr'],
                r_from=ip_block['first_addr'],
                subnet=ip_block['subnet_mask'],
                def_gw=ip_block['default_gw'],
                prim_dns=ip_block['primary_dns'],
                sec_dns=ip_block['secondary_dns']
            )
            ucs.login_handle.add_mo(mo, True)
            ucs.login_handle.commit()


def get_ip_block(ucs, pool_dn, first_addr, last_addr, ip_version):
    if ip_version == 'v6':
        dn_type = '/v6block-'
    else:
        dn_type = '/block-'

    block_dn = pool_dn + dn_type + first_addr + '-' + last_addr
    return ucs.login_handle.query_dn(block_dn)


def main():
    from ansible.module_utils.basic import AnsibleModule
    from ansible_collections.cisco.ucs.plugins.module_utils.ucs import UCSModule, ucs_argument_spec

    ipv4_configuration_spec = dict(
        first_addr=dict(type='str'),
        last_addr=dict(type='str'),
        subnet_mask=dict(type='str', default='255.255.255.0'),
        default_gw=dict(type='str', default='0.0.0.0'),
        primary_dns=dict(type='str', default='0.0.0.0'),
        secondary_dns=dict(type='str', default='0.0.0.0'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )
    ipv6_configuration_spec = dict(
        ipv6_first_addr=dict(type='str'),
        ipv6_last_addr=dict(type='str'),
        ipv6_prefix=dict(type='str', default='64'),
        ipv6_default_gw=dict(type='str', default='::'),
        ipv6_primary_dns=dict(type='str', default='::'),
        ipv6_secondary_dns=dict(type='str', default='::'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )

    argument_spec = ucs_argument_spec.copy()
    argument_spec.update(
        org_dn=dict(type='str', default='org-root'),
        name=dict(type='str', required=True),
        descr=dict(type='str', aliases=['description']),
        order=dict(type='str', default='default', choices=['default', 'sequential']),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        ipv4_blocks=dict(type='list', default=None, elements='dict', options=ipv4_configuration_spec),
        ipv6_blocks=dict(type='list', default=None, elements='dict', options=ipv6_configuration_spec),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    # UCSModule verifies ucsmsdk is present and exits on failure.  Imports are below ucs object creation.
    ucs = UCSModule(module)

    err = False

    from ucsmsdk.mometa.ippool.IppoolBlock import IppoolBlock
    from ucsmsdk.mometa.ippool.IppoolIpV6Block import IppoolIpV6Block

    changed = False
    try:
        mo_exists = False
        ipv4_props_match = True
        ipv6_props_match = True
        # dn is <org_dn>/ip-pool-<name>
        dn = module.params['org_dn'] + '/ip-pool-' + module.params['name']

        mo = ucs.login_handle.query_dn(dn)
        if mo:
            mo_exists = True
        if module.params['state'] == 'absent':
            if mo_exists:
                if not module.check_mode:
                    ucs.login_handle.remove_mo(mo)
                    ucs.login_handle.commit()
                changed = True
        else:
            if not mo_exists:
                if not module.check_mode:
                    mo = update_ip_pool(ucs, module)
                changed = True
            if mo_exists:
                # check top-level mo props
                kwargs = dict(assignment_order=module.params['order'])
                kwargs['descr'] = module.params['descr']
                if not mo.check_prop_match(**kwargs):
                    if not module.check_mode:
                        mo = update_ip_pool(ucs, module)
                    changed = True
                    # top-level props match, check next level mo/props
            if module.params['ipv4_blocks']:
                for ipv4_block in module.params['ipv4_blocks']:
                    if not match_existing_ipv4_block(ucs, dn, ipv4_block):
                        if not module.check_mode:
                            update_ip_block(ucs, mo, ipv4_block, 'v4')
                        changed = True

            # only check ipv6 props if the top-level and ipv4 props matched
            if module.params['ipv6_blocks']:
                for ipv6_block in module.params['ipv6_blocks']:
                    if not match_existing_ipv6_block(ucs, dn, ipv6_block):
                        if not module.check_mode:
                            update_ip_block(ucs, mo, ipv6_block, 'v6')
                        changed = True

            if not module.check_mode:
                ucs.login_handle.add_mo(mo, True)
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
