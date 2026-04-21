#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein (@felixfontein) <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: api_modify
author:
  - "Felix Fontein (@felixfontein)"
short_description: Modify data at paths with API
version_added: 2.2.0
description:
  - Allows to modify information for a path using the API.
  - Use the M(community.routeros.api_find_and_modify) module to modify one or multiple entries in a controlled way depending
    on some search conditions.
  - To make a backup of a path that can be restored with this module, use the M(community.routeros.api_info) module.
  - The module ignores dynamic and builtin entries.
  - B(Note) that this module is still heavily in development, and only supports B(some) paths. If you want to support new
    paths, or think you found problems with existing paths, please first L(create an issue in the community.routeros Issue
    Tracker,https://github.com/ansible-collections/community.routeros/issues/).
notes:
  - If write-only fields are present in the path, the module is B(not idempotent) in a strict sense, since it is not able
    to verify the current value of these fields. The behavior the module should assume can be controlled with the O(handle_write_only)
    option.
requirements:
  - Needs L(ordereddict,https://pypi.org/project/ordereddict) for Python 2.6
extends_documentation_fragment:
  - community.routeros.api
  - community.routeros.api.restrict
  - community.routeros.attributes
  - community.routeros.attributes.actiongroup_api
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    support: full
    platforms: RouterOS
  idempotent:
    support: full
options:
  path:
    description:
      - Path to query.
      - An example value is V(ip address). This is equivalent to running modification commands in C(/ip address) in the RouterOS
        CLI.
    required: true
    type: str
    choices:
    # BEGIN PATH LIST
      - caps-man aaa
      - caps-man access-list
      - caps-man channel
      - caps-man configuration
      - caps-man datapath
      - caps-man manager
      - caps-man manager interface
      - caps-man provisioning
      - caps-man security
      - certificate settings
      - interface 6to4
      - interface bonding
      - interface bridge
      - interface bridge mlag
      - interface bridge port
      - interface bridge port-controller
      - interface bridge port-extender
      - interface bridge settings
      - interface bridge vlan
      - interface detect-internet
      - interface dot1x client
      - interface dot1x server
      - interface eoip
      - interface ethernet
      - interface ethernet poe
      - interface ethernet switch
      - interface ethernet switch port
      - interface ethernet switch port-isolation
      - interface gre
      - interface gre6
      - interface l2tp-client
      - interface l2tp-server server
      - interface list
      - interface list member
      - interface ovpn-client
      - interface ovpn-server server
      - interface ppp-client
      - interface pppoe-client
      - interface pppoe-server server
      - interface pptp-server server
      - interface sstp-server server
      - interface vlan
      - interface vrrp
      - interface wifi
      - interface wifi aaa
      - interface wifi access-list
      - interface wifi cap
      - interface wifi capsman
      - interface wifi channel
      - interface wifi configuration
      - interface wifi datapath
      - interface wifi interworking
      - interface wifi provisioning
      - interface wifi security
      - interface wifi steering
      - interface wifiwave2
      - interface wifiwave2 aaa
      - interface wifiwave2 access-list
      - interface wifiwave2 cap
      - interface wifiwave2 capsman
      - interface wifiwave2 channel
      - interface wifiwave2 configuration
      - interface wifiwave2 datapath
      - interface wifiwave2 interworking
      - interface wifiwave2 provisioning
      - interface wifiwave2 security
      - interface wifiwave2 steering
      - interface wireguard
      - interface wireguard peers
      - interface wireless
      - interface wireless access-list
      - interface wireless align
      - interface wireless cap
      - interface wireless connect-list
      - interface wireless security-profiles
      - interface wireless sniffer
      - interface wireless snooper
      - iot modbus
      - ip accounting
      - ip accounting web-access
      - ip address
      - ip arp
      - ip cloud
      - ip cloud advanced
      - ip dhcp-client
      - ip dhcp-client option
      - ip dhcp-relay
      - ip dhcp-server
      - ip dhcp-server config
      - ip dhcp-server lease
      - ip dhcp-server matcher
      - ip dhcp-server network
      - ip dhcp-server option
      - ip dhcp-server option sets
      - ip dns
      - ip dns adlist
      - ip dns forwarders
      - ip dns static
      - ip firewall address-list
      - ip firewall connection tracking
      - ip firewall filter
      - ip firewall layer7-protocol
      - ip firewall mangle
      - ip firewall nat
      - ip firewall raw
      - ip firewall service-port
      - ip hotspot
      - ip hotspot profile
      - ip hotspot service-port
      - ip hotspot user
      - ip hotspot user profile
      - ip hotspot walled-garden
      - ip hotspot walled-garden ip
      - ip ipsec identity
      - ip ipsec mode-config
      - ip ipsec peer
      - ip ipsec policy
      - ip ipsec profile
      - ip ipsec proposal
      - ip ipsec settings
      - ip neighbor discovery-settings
      - ip pool
      - ip proxy
      - ip route
      - ip route rule
      - ip route vrf
      - ip service
      - ip settings
      - ip smb
      - ip socks
      - ip ssh
      - ip tftp settings
      - ip traffic-flow
      - ip traffic-flow ipfix
      - ip traffic-flow target
      - ip upnp
      - ip upnp interfaces
      - ip vrf
      - ipv6 address
      - ipv6 dhcp-client
      - ipv6 dhcp-server
      - ipv6 dhcp-server option
      - ipv6 firewall address-list
      - ipv6 firewall filter
      - ipv6 firewall mangle
      - ipv6 firewall nat
      - ipv6 firewall raw
      - ipv6 nd
      - ipv6 nd prefix
      - ipv6 nd prefix default
      - ipv6 route
      - ipv6 settings
      - mpls
      - mpls interface
      - mpls ldp
      - mpls ldp accept-filter
      - mpls ldp advertise-filter
      - mpls ldp interface
      - port firmware
      - port remote-access
      - ppp aaa
      - ppp profile
      - ppp secret
      - queue interface
      - queue simple
      - queue tree
      - queue type
      - radius
      - radius incoming
      - routing bfd configuration
      - routing bgp aggregate
      - routing bgp connection
      - routing bgp instance
      - routing bgp network
      - routing bgp peer
      - routing bgp template
      - routing filter
      - routing filter community-list
      - routing filter num-list
      - routing filter rule
      - routing filter select-rule
      - routing id
      - routing igmp-proxy
      - routing igmp-proxy interface
      - routing mme
      - routing ospf area
      - routing ospf area range
      - routing ospf instance
      - routing ospf interface-template
      - routing ospf static-neighbor
      - routing pimsm instance
      - routing pimsm interface-template
      - routing rip
      - routing ripng
      - routing rule
      - routing table
      - snmp
      - snmp community
      - system clock
      - system clock manual
      - system health settings
      - system identity
      - system leds settings
      - system logging
      - system logging action
      - system note
      - system ntp client
      - system ntp client servers
      - system ntp server
      - system package update
      - system resource irq rps
      - system routerboard settings
      - system scheduler
      - system script
      - system upgrade mirror
      - system ups
      - system watchdog
      - tool bandwidth-server
      - tool e-mail
      - tool graphing
      - tool graphing interface
      - tool graphing resource
      - tool mac-server
      - tool mac-server mac-winbox
      - tool mac-server ping
      - tool netwatch
      - tool romon
      - tool sms
      - tool sniffer
      - tool traffic-generator
      - user
      - user aaa
      - user group
      - user settings
    # END PATH LIST
  data:
    description:
      - Data to ensure that is present for this path.
      - Fields not provided will not be modified.
      - If C(.id) appears in an entry, it will be ignored.
    required: true
    type: list
    elements: dict
  ensure_order:
    description:
      - Whether to ensure the same order of the config as present in O(data).
      - Requires O(handle_absent_entries=remove).
    type: bool
    default: false
  handle_absent_entries:
    description:
      - How to handle entries that are present in the current config, but not in O(data).
      - V(ignore) ignores them.
      - V(remove) removes them.
    type: str
    choices:
      - ignore
      - remove
    default: ignore
  handle_entries_content:
    description:
      - For a single entry in O(data), this describes how to handle fields that are not mentioned in that entry, but appear
        in the actual config.
      - If V(ignore), they are not modified.
      - If V(remove), they are removed. If at least one cannot be removed, the module will fail.
      - If V(remove_as_much_as_possible), all that can be removed will be removed. The ones that cannot be removed will be
        kept.
      - Note that V(remove) and V(remove_as_much_as_possible) do not apply to write-only fields.
    type: str
    choices:
      - ignore
      - remove
      - remove_as_much_as_possible
    default: ignore
  handle_read_only:
    description:
      - How to handle values passed in for read-only fields.
      - If V(ignore), they are not passed to the API.
      - If V(validate), the values are not passed for creation, and for updating they are compared to the value returned for
        the object. If they differ, the module fails.
      - If V(error), the module will fail if read-only fields are provided.
    type: str
    choices:
      - ignore
      - validate
      - error
    default: error
    version_added: 2.10.0
  handle_write_only:
    description:
      - How to handle values passed in for write-only fields.
      - If V(create_only), they are passed on creation, and ignored for updating.
      - If V(always_update), they are always passed to the API. This means that if such a value is present, the module will
        always result in C(changed) since there is no way to validate whether the value actually changed.
      - If V(error), the module will fail if write-only fields are provided.
    type: str
    choices:
      - create_only
      - always_update
      - error
    default: create_only
    version_added: 2.10.0
  restrict:
    description:
      - Restrict operation to entries matching the following criteria.
      - This can be useful together with O(handle_absent_entries=remove) to operate on a subset of the values.
      - For example, for O(path=ip firewall filter), you can set O(restrict[].field=chain) and O(restrict[].values=input)
        to restrict operation to the input chain, and ignore the forward and output chains.
    version_added: 2.18.0
seealso:
  - module: community.routeros.api
  - module: community.routeros.api_facts
  - module: community.routeros.api_find_and_modify
  - module: community.routeros.api_info
"""

EXAMPLES = r"""
---
- name: Setup DHCP server networks
  # Ensures that we have exactly two DHCP server networks (in the specified order)
  community.routeros.api_modify:
    path: ip dhcp-server network
    handle_absent_entries: remove
    handle_entries_content: remove_as_much_as_possible
    ensure_order: true
    data:
      - address: 192.168.88.0/24
        comment: admin network
        dns-server: 192.168.88.1
        gateway: 192.168.88.1
      - address: 192.168.1.0/24
        comment: customer network 1
        dns-server: 192.168.1.1
        gateway: 192.168.1.1
        netmask: 24

- name: Adjust NAT
  community.routeros.api_modify:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: ip firewall nat
    data:
      - action: masquerade
        chain: srcnat
        comment: NAT to WAN
        out-interface-list: WAN
        # Three ways to unset values:
        #   - nothing after `:`
        #   - "empty" value (null/~/None)
        #   - prepend '!'
        out-interface:
        to-addresses: ~
        '!to-ports':

- name: Block all incoming connections
  community.routeros.api_modify:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: ip firewall filter
    handle_absent_entries: remove
    handle_entries_content: remove_as_much_as_possible
    restrict:
      # Do not touch any chain except the input chain
      - field: chain
        values:
          - input
    data:
      - action: drop
        chain: input
"""

RETURN = r"""
old_data:
  description:
    - A list of all elements for the current path before a change was made.
  sample:
    - '.id': '*1'
      actual-interface: bridge
      address: "192.168.88.1/24"
      comment: defconf
      disabled: false
      dynamic: false
      interface: bridge
      invalid: false
      network: 192.168.88.0
  type: list
  elements: dict
  returned: always
new_data:
  description:
    - A list of all elements for the current path after a change was made.
  sample:
    - '.id': '*1'
      actual-interface: bridge
      address: "192.168.1.1/24"
      comment: awesome
      disabled: false
      dynamic: false
      interface: bridge
      invalid: false
      network: 192.168.1.0
  type: list
  elements: dict
  returned: always
"""

from collections import defaultdict

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.routeros.plugins.module_utils.api import (
    api_argument_spec,
    check_has_library,
    create_api,
    get_api_version,
)

from ansible_collections.community.routeros.plugins.module_utils._api_data import (
    PATHS,
    join_path,
    split_path,
)

from ansible_collections.community.routeros.plugins.module_utils._api_helper import (
    restrict_argument_spec,
    restrict_entry_accepted,
    validate_and_prepare_restrict,
    value_to_str,
)

HAS_ORDEREDDICT = True
try:
    from collections import OrderedDict
except ImportError:
    try:
        from ordereddict import OrderedDict
    except ImportError:
        HAS_ORDEREDDICT = False
        OrderedDict = dict

try:
    from librouteros.exceptions import LibRouterosError
except Exception:
    # Handled in api module_utils
    pass


def compose_api_path(api, path):
    api_path = api.path()
    for p in path:
        api_path = api_path.join(p)
    return api_path


def find_modifications(old_entry, new_entry, path_info, module, for_text='', return_none_instead_of_fail=False):
    modifications = OrderedDict()
    updated_entry = old_entry.copy()
    for k, v in new_entry.items():
        if k == '.id':
            continue
        disabled_k = None
        if k.startswith('!'):
            disabled_k = k[1:]
        elif v is None or value_to_str(v) == value_to_str(path_info.fields[k].remove_value):
            disabled_k = k
        if disabled_k is not None:
            if disabled_k in old_entry:
                if path_info.fields[disabled_k].remove_value is not None:
                    modifications[disabled_k] = path_info.fields[disabled_k].remove_value
                else:
                    modifications['!%s' % disabled_k] = ''
                del updated_entry[disabled_k]
            continue
        if k not in old_entry and value_to_str(path_info.fields[k].default) == value_to_str(v) and not path_info.fields[k].can_disable:
            continue
        key_info = path_info.fields[k]
        if key_info.read_only:
            # handle_read_only must be 'validate'
            if old_entry.get(k) != v:
                module.fail_json(
                    msg='Read-only key "{key}" has value "{old_value}", but should have new value "{new_value}"{for_text}.'.format(
                        key=k, old_value=old_entry.get(k), new_value=v, for_text=for_text))
            continue
        if key_info.write_only:
            if module.params['handle_write_only'] == 'create_only':
                # do not update this value
                continue
        if k not in old_entry or value_to_str(old_entry[k]) != value_to_str(v):
            modifications[k] = v
            updated_entry[k] = v
    handle_entries_content = module.params['handle_entries_content']
    if handle_entries_content != 'ignore':
        for k in old_entry:
            if k == '.id' or k in new_entry or ('!%s' % k) in new_entry or k not in path_info.fields:
                continue
            field_info = path_info.fields[k]
            if field_info.default is not None and field_info.default == old_entry[k]:
                continue
            if field_info.remove_value is not None and field_info.remove_value == old_entry[k]:
                continue
            if field_info.can_disable:
                if field_info.default is not None:
                    modifications[k] = field_info.default
                elif field_info.remove_value is not None:
                    modifications[k] = field_info.remove_value
                else:
                    modifications['!%s' % k] = ''
                del updated_entry[k]
            elif field_info.default is not None:
                modifications[k] = field_info.default
                updated_entry[k] = field_info.default
            elif handle_entries_content == 'remove':
                if return_none_instead_of_fail:
                    return None, None
                module.fail_json(msg='Key "{key}" cannot be removed{for_text}.'.format(key=k, for_text=for_text))
        for k in path_info.fields:
            field_info = path_info.fields[k]
            if k not in old_entry and k not in new_entry and field_info.can_disable and field_info.default is not None:
                modifications[k] = field_info.default
                updated_entry[k] = field_info.default
    return modifications, updated_entry


def essentially_same_weight(old_entry, new_entry, path_info, module):
    for k, v in new_entry.items():
        if k == '.id':
            continue
        disabled_k = None
        if k.startswith('!'):
            disabled_k = k[1:]
        elif v is None or value_to_str(v) == value_to_str(path_info.fields[k].remove_value):
            disabled_k = k
        if disabled_k is not None:
            if disabled_k in old_entry:
                return None
            continue
        if k not in old_entry and value_to_str(path_info.fields[k].default) == value_to_str(v):
            continue
        if k not in old_entry or value_to_str(old_entry[k]) != value_to_str(v):
            return None
    handle_entries_content = module.params['handle_entries_content']
    weight = 0
    for k in old_entry:
        if k == '.id' or k in new_entry or ('!%s' % k) in new_entry or k not in path_info.fields:
            continue
        field_info = path_info.fields[k]
        if field_info.default is not None and field_info.default == old_entry[k]:
            continue
        if handle_entries_content != 'ignore':
            return None
        else:
            weight += 1
    return weight


def remove_read_only(entry, path_info):
    to_remove = []
    for real_k, v in entry.items():
        k = real_k
        if k.startswith('!'):
            k = k[1:]
        if path_info.fields[k].read_only:
            to_remove.append(real_k)
    for k in to_remove:
        entry.pop(k)


def format_pk(primary_keys, values):
    return ', '.join('{pk}="{value}"'.format(pk=pk, value=value) for pk, value in zip(primary_keys, values))


def polish_entry(entry, path_info, module, for_text):
    if '.id' in entry:
        entry.pop('.id')
    to_remove = []
    for key, value in entry.items():
        real_key = key
        disabled_key = False
        if key.startswith('!'):
            disabled_key = True
            key = key[1:]
            if key in entry:
                module.fail_json(msg='Not both "{key}" and "!{key}" must appear{for_text}.'.format(key=key, for_text=for_text))
        key_info = path_info.fields.get(key)
        if key_info is None:
            module.fail_json(msg='Unknown key "{key}"{for_text}.'.format(key=real_key, for_text=for_text))
        if disabled_key:
            if not key_info.can_disable:
                module.fail_json(msg='Key "!{key}" must not be disabled (leading "!"){for_text}.'.format(key=key, for_text=for_text))
            if value not in (None, '', key_info.remove_value):
                module.fail_json(msg='Disabled key "!{key}" must not have a value{for_text}.'.format(key=key, for_text=for_text))
        elif value is None:
            if not key_info.can_disable:
                module.fail_json(msg='Key "{key}" must not be disabled (value null/~/None){for_text}.'.format(key=key, for_text=for_text))
        if key_info.read_only:
            if module.params['handle_read_only'] == 'error':
                module.fail_json(msg='Key "{key}" is read-only{for_text}, and handle_read_only=error.'.format(key=key, for_text=for_text))
            if module.params['handle_read_only'] == 'ignore':
                to_remove.append(real_key)
        if key_info.write_only:
            if module.params['handle_write_only'] == 'error':
                module.fail_json(msg='Key "{key}" is write-only{for_text}, and handle_write_only=error.'.format(key=key, for_text=for_text))
    for key in to_remove:
        entry.pop(key)
    for key, field_info in path_info.fields.items():
        if field_info.required and key not in entry:
            module.fail_json(msg='Key "{key}" must be present{for_text}.'.format(key=key, for_text=for_text))
    for require_list in path_info.required_one_of:
        found_req_keys = [rk for rk in require_list if rk in entry]
        if len(require_list) > 0 and not found_req_keys:
            module.fail_json(
                msg='Every element in data must contain one of {required_keys}. For example, the element{for_text} does not provide it.'.format(
                    required_keys=', '.join(['"{k}"'.format(k=k) for k in require_list]),
                    for_text=for_text,
                )
            )
    for exclusive_list in path_info.mutually_exclusive:
        found_ex_keys = [ek for ek in exclusive_list if ek in entry]
        if len(found_ex_keys) > 1:
            module.fail_json(
                msg='Keys {exclusive_keys} cannot be used at the same time{for_text}.'.format(
                    exclusive_keys=', '.join(['"{k}"'.format(k=k) for k in found_ex_keys]),
                    for_text=for_text,
                )
            )


def remove_irrelevant_data(entry, path_info):
    for k, v in list(entry.items()):
        if k == '.id':
            continue
        if k not in path_info.fields or v is None:
            del entry[k]


def match_entries(new_entries, old_entries, path_info, module):
    matching_old_entries = [None for entry in new_entries]
    old_entries = list(old_entries)
    matches = []
    handle_absent_entries = module.params['handle_absent_entries']
    if handle_absent_entries == 'remove':
        for new_index, (unused, new_entry) in enumerate(new_entries):
            for old_index, (unused, old_entry) in enumerate(old_entries):
                modifications, unused = find_modifications(old_entry, new_entry, path_info, module, return_none_instead_of_fail=True)
                if modifications is not None:
                    matches.append((new_index, old_index, len(modifications)))
    else:
        for new_index, (unused, new_entry) in enumerate(new_entries):
            for old_index, (unused, old_entry) in enumerate(old_entries):
                weight = essentially_same_weight(old_entry, new_entry, path_info, module)
                if weight is not None:
                    matches.append((new_index, old_index, weight))
    matches.sort(key=lambda entry: entry[2])
    for new_index, old_index, rating in matches:
        if matching_old_entries[new_index] is not None or old_entries[old_index] is None:
            continue
        matching_old_entries[new_index], old_entries[old_index] = old_entries[old_index], None
    unmatched_old_entries = [index_entry for index_entry in old_entries if index_entry is not None]
    return matching_old_entries, unmatched_old_entries


def remove_dynamic(entries):
    result = []
    for entry in entries:
        if entry.get('dynamic', False) or entry.get('builtin', False):
            continue
        result.append(entry)
    return result


def get_api_data(api_path, path_info):
    entries = list(api_path)
    for entry in entries:
        for k, field_info in path_info.fields.items():
            if field_info.absent_value is not None and k not in entry:
                entry[k] = field_info.absent_value
    return entries


def prepare_for_add(entry, path_info):
    new_entry = {}
    for k, v in entry.items():
        if k.startswith('!'):
            real_k = k[1:]
            remove_value = path_info.fields[real_k].remove_value
            if remove_value is not None:
                k = real_k
                v = remove_value
        else:
            if v is None:
                v = path_info.fields[k].remove_value
        new_entry[k] = v
    return new_entry


def remove_rejected(data, path_info, restrict_data):
    return [
        entry for entry in data
        if restrict_entry_accepted(entry, path_info, restrict_data)
    ]


def sync_list(module, api, path, path_info, restrict_data):
    handle_absent_entries = module.params['handle_absent_entries']
    handle_entries_content = module.params['handle_entries_content']
    if handle_absent_entries == 'remove':
        if handle_entries_content == 'ignore':
            module.fail_json(
                msg='For this path, handle_absent_entries=remove cannot be combined with handle_entries_content=ignore'
            )

    stratify_keys = path_info.stratify_keys or ()

    data = module.params['data']
    stratified_data = defaultdict(list)
    for index, entry in enumerate(data):
        if not restrict_entry_accepted(entry, path_info, restrict_data):
            module.fail_json(msg='The element at index #{index} does not match `restrict`'.format(index=index + 1))
        for stratify_key in stratify_keys:
            if stratify_key not in entry:
                module.fail_json(
                    msg='Every element in data must contain "{stratify_key}". For example, the element at index #{index} does not provide it.'.format(
                        stratify_key=stratify_key,
                        index=index + 1,
                    )
                )
        sks = tuple(entry[stratify_key] for stratify_key in stratify_keys)
        polish_entry(
            entry, path_info, module,
            ' at index {index}'.format(index=index + 1),
        )
        stratified_data[sks].append((index, entry))
    stratified_data = dict(stratified_data)

    api_path = compose_api_path(api, path)

    old_data = get_api_data(api_path, path_info)
    old_data = remove_dynamic(old_data)
    old_data = remove_rejected(old_data, path_info, restrict_data)
    stratified_old_data = defaultdict(list)
    for index, entry in enumerate(old_data):
        sks = tuple(entry[stratify_key] for stratify_key in stratify_keys)
        stratified_old_data[sks].append((index, entry))
    stratified_old_data = dict(stratified_old_data)

    create_list = []
    modify_list = []
    remove_list = []

    new_data = []
    for key, indexed_entries in stratified_data.items():
        old_entries = stratified_old_data.pop(key, [])

        # Try to match indexed_entries with old_entries
        matching_old_entries, unmatched_old_entries = match_entries(indexed_entries, old_entries, path_info, module)

        # Update existing entries
        for (index, new_entry), potential_old_entry in zip(indexed_entries, matching_old_entries):
            if potential_old_entry is not None:
                old_index, old_entry = potential_old_entry
                modifications, updated_entry = find_modifications(
                    old_entry, new_entry, path_info, module,
                    ' at index {index}'.format(index=index + 1),
                )
                # Add to modification list if there are changes
                if modifications:
                    modifications['.id'] = old_entry['.id']
                    modify_list.append(modifications)
                new_data.append((old_index, updated_entry))
                new_entry['.id'] = old_entry['.id']
            else:
                remove_read_only(new_entry, path_info)
                create_list.append(new_entry)

        if handle_absent_entries == 'remove':
            remove_list.extend(entry['.id'] for index, entry in unmatched_old_entries)
        else:
            new_data.extend(unmatched_old_entries)

    for key, entries in stratified_old_data.items():
        if handle_absent_entries == 'remove':
            remove_list.extend(entry['.id'] for index, entry in entries)
        else:
            new_data.extend(entries)

    new_data = [entry for index, entry in sorted(new_data, key=lambda entry: entry[0])]
    new_data.extend(create_list)

    reorder_list = []
    if module.params['ensure_order']:
        for index, entry in enumerate(data):
            if '.id' in entry:
                def match(current_entry):
                    return current_entry['.id'] == entry['.id']

            else:
                def match(current_entry):
                    return current_entry is entry

            current_index = next(current_index + index for current_index, current_entry in enumerate(new_data[index:]) if match(current_entry))
            if current_index != index:
                reorder_list.append((index, new_data[current_index], new_data[index]))
                new_data.insert(index, new_data.pop(current_index))

    if not module.check_mode:
        if remove_list:
            try:
                api_path.remove(*remove_list)
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while removing {remove_list}: {error}'.format(
                        remove_list=', '.join(['ID {id}'.format(id=id) for id in remove_list]),
                        error=to_native(e),
                    )
                )
        for modifications in modify_list:
            try:
                api_path.update(**modifications)
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while modifying for ID {id}: {error}'.format(
                        id=modifications['.id'],
                        error=to_native(e),
                    )
                )
        for entry in create_list:
            try:
                entry['.id'] = api_path.add(**prepare_for_add(entry, path_info))
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while creating entry: {error}'.format(
                        error=to_native(e),
                    )
                )
        for new_index, new_entry, old_entry in reorder_list:
            try:
                for res in api_path('move', numbers=new_entry['.id'], destination=old_entry['.id']):
                    pass
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while moving entry ID {element_id} to position #{new_index} ID ({new_id}): {error}'.format(
                        element_id=new_entry['.id'],
                        new_index=new_index,
                        new_id=old_entry['.id'],
                        error=to_native(e),
                    )
                )

        # For sake of completeness, retrieve the full new data:
        if modify_list or create_list or reorder_list:
            new_data = remove_dynamic(get_api_data(api_path, path_info))
            new_data = remove_rejected(new_data, path_info, restrict_data)

    # Remove 'irrelevant' data
    for entry in old_data:
        remove_irrelevant_data(entry, path_info)
    for entry in new_data:
        remove_irrelevant_data(entry, path_info)

    # Produce return value
    more = {}
    if module._diff:
        more['diff'] = {
            'before': {
                'data': old_data,
            },
            'after': {
                'data': new_data,
            },
        }
    module.exit_json(
        changed=bool(create_list or modify_list or remove_list or reorder_list),
        old_data=old_data,
        new_data=new_data,
        **more
    )


def sync_with_primary_keys(module, api, path, path_info, restrict_data):
    primary_keys = path_info.primary_keys

    if path_info.fixed_entries:
        if module.params['ensure_order']:
            module.fail_json(msg='ensure_order=true cannot be used with this path')
        if module.params['handle_absent_entries'] == 'remove':
            module.fail_json(msg='handle_absent_entries=remove cannot be used with this path')

    data = module.params['data']
    new_data_by_key = OrderedDict()
    for index, entry in enumerate(data):
        if not restrict_entry_accepted(entry, path_info, restrict_data):
            module.fail_json(msg='The element at index #{index} does not match `restrict`'.format(index=index + 1))
        for primary_key in primary_keys:
            if primary_key not in entry:
                module.fail_json(
                    msg='Every element in data must contain "{primary_key}". For example, the element at index #{index} does not provide it.'.format(
                        primary_key=primary_key,
                        index=index + 1,
                    )
                )
        pks = tuple(value_to_str(entry[primary_key]) for primary_key in primary_keys)
        if pks in new_data_by_key:
            module.fail_json(
                msg='Every element in data must contain a unique value for {primary_keys}. The value {value} appears at least twice.'.format(
                    primary_keys=','.join(primary_keys),
                    value=','.join(['"{0}"'.format(pk) for pk in pks]),
                )
            )
        polish_entry(
            entry, path_info, module,
            ' for {values}'.format(
                values=', '.join([
                    '{primary_key}="{value}"'.format(primary_key=primary_key, value=value)
                    for primary_key, value in zip(primary_keys, pks)
                ])
            ),
        )
        new_data_by_key[pks] = entry

    api_path = compose_api_path(api, path)

    old_data = get_api_data(api_path, path_info)
    old_data = remove_dynamic(old_data)
    old_data = remove_rejected(old_data, path_info, restrict_data)
    old_data_by_key = OrderedDict()
    id_by_key = {}
    for entry in old_data:
        pks = tuple(value_to_str(entry[primary_key]) for primary_key in primary_keys)
        old_data_by_key[pks] = entry
        id_by_key[pks] = entry['.id']
    new_data = []

    create_list = []
    modify_list = []
    remove_list = []
    remove_keys = []
    handle_absent_entries = module.params['handle_absent_entries']
    for key, old_entry in old_data_by_key.items():
        new_entry = new_data_by_key.pop(key, None)
        if new_entry is None:
            if handle_absent_entries == 'remove':
                remove_list.append(old_entry['.id'])
                remove_keys.append(key)
            else:
                new_data.append(old_entry)
        else:
            modifications, updated_entry = find_modifications(
                old_entry, new_entry, path_info, module,
                ' for {values}'.format(
                    values=', '.join([
                        '{primary_key}="{value}"'.format(primary_key=primary_key, value=value)
                        for primary_key, value in zip(primary_keys, key)
                    ])
                )
            )
            new_data.append(updated_entry)
            # Add to modification list if there are changes
            if modifications:
                modifications['.id'] = old_entry['.id']
                modify_list.append((key, modifications))
    for new_entry in new_data_by_key.values():
        if path_info.fixed_entries:
            module.fail_json(msg='Cannot add new entry {values} to this path'.format(
                values=', '.join([
                    '{primary_key}="{value}"'.format(primary_key=primary_key, value=new_entry[primary_key])
                    for primary_key in primary_keys
                ]),
            ))
        remove_read_only(new_entry, path_info)
        create_list.append(new_entry)
        new_entry = new_entry.copy()
        for key in list(new_entry):
            if key.startswith('!'):
                new_entry.pop(key)
        new_data.append(new_entry)

    reorder_list = []
    if module.params['ensure_order']:
        index_by_key = dict()
        for index, entry in enumerate(new_data):
            index_by_key[tuple(value_to_str(entry[primary_key]) for primary_key in primary_keys)] = index
        for index, source_entry in enumerate(data):
            source_pks = tuple(value_to_str(source_entry[primary_key]) for primary_key in primary_keys)
            source_index = index_by_key.pop(source_pks)
            if index == source_index:
                continue
            entry = new_data[index]
            pks = tuple(value_to_str(entry[primary_key]) for primary_key in primary_keys)
            reorder_list.append((source_pks, index, pks))
            for k, v in index_by_key.items():
                if v >= index and v < source_index:
                    index_by_key[k] = v + 1
            new_data.insert(index, new_data.pop(source_index))

    if not module.check_mode:
        if remove_list:
            try:
                api_path.remove(*remove_list)
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while removing {remove_list}: {error}'.format(
                        remove_list=', '.join([
                            '{identifier} (ID {id})'.format(identifier=format_pk(primary_keys, key), id=id)
                            for id, key in zip(remove_list, remove_keys)
                        ]),
                        error=to_native(e),
                    )
                )
        for key, modifications in modify_list:
            try:
                api_path.update(**modifications)
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while modifying for {identifier} (ID {id}): {error}'.format(
                        identifier=format_pk(primary_keys, key),
                        id=modifications['.id'],
                        error=to_native(e),
                    )
                )
        for entry in create_list:
            try:
                entry['.id'] = api_path.add(**prepare_for_add(entry, path_info))
                # Store ID for primary keys
                pks = tuple(entry[primary_key] for primary_key in primary_keys)
                id_by_key[pks] = entry['.id']
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while creating entry for {identifier}: {error}'.format(
                        identifier=format_pk(primary_keys, [entry[pk] for pk in primary_keys]),
                        error=to_native(e),
                    )
                )
        for element_pks, new_index, new_pks in reorder_list:
            try:
                element_id = id_by_key[element_pks]
                new_id = id_by_key[new_pks]
                for res in api_path('move', numbers=element_id, destination=new_id):
                    pass
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(
                    msg='Error while moving entry ID {element_id} to position of ID {new_id}: {error}'.format(
                        element_id=element_id,
                        new_id=new_id,
                        error=to_native(e),
                    )
                )

        # For sake of completeness, retrieve the full new data:
        if modify_list or create_list or reorder_list:
            new_data = remove_dynamic(get_api_data(api_path, path_info))
            new_data = remove_rejected(new_data, path_info, restrict_data)

    # Remove 'irrelevant' data
    for entry in old_data:
        remove_irrelevant_data(entry, path_info)
    for entry in new_data:
        remove_irrelevant_data(entry, path_info)

    # Produce return value
    more = {}
    if module._diff:
        more['diff'] = {
            'before': {
                'data': old_data,
            },
            'after': {
                'data': new_data,
            },
        }
    module.exit_json(
        changed=bool(create_list or modify_list or remove_list or reorder_list),
        old_data=old_data,
        new_data=new_data,
        **more
    )


def sync_single_value(module, api, path, path_info, restrict_data):
    if module.params['restrict'] is not None:
        module.fail_json(msg='The restrict option cannot be used with this path, since there is precisely one entry.')
    data = module.params['data']
    if len(data) != 1:
        module.fail_json(msg='Data must be a list with exactly one element.')
    new_entry = data[0]
    polish_entry(new_entry, path_info, module, '')

    api_path = compose_api_path(api, path)

    old_data = get_api_data(api_path, path_info)
    if len(old_data) != 1:
        module.fail_json(
            msg='Internal error: retrieving /{path} resulted in {count} elements. Expected exactly 1.'.format(
                path=join_path(path),
                count=len(old_data)
            )
        )
    old_entry = old_data[0]

    # Determine modifications
    modifications, updated_entry = find_modifications(old_entry, new_entry, path_info, module, '')
    # Do modifications
    if modifications:
        if not module.check_mode:
            # Actually do modification
            try:
                api_path.update(**modifications)
            except (LibRouterosError, UnicodeEncodeError) as e:
                module.fail_json(msg='Error while modifying: {error}'.format(error=to_native(e)))
            # Retrieve latest version
            new_data = get_api_data(api_path, path_info)
            if len(new_data) == 1:
                updated_entry = new_data[0]

    # Remove 'irrelevant' data
    remove_irrelevant_data(old_entry, path_info)
    remove_irrelevant_data(updated_entry, path_info)

    # Produce return value
    more = {}
    if module._diff:
        more['diff'] = {
            'before': old_entry,
            'after': updated_entry,
        }
    module.exit_json(
        changed=bool(modifications),
        old_data=[old_entry],
        new_data=[updated_entry],
        **more
    )


def get_backend(path_info):
    if path_info is None:
        return None
    if not path_info.fully_understood:
        return None

    if path_info.primary_keys:
        return sync_with_primary_keys

    if path_info.single_value:
        return sync_single_value

    if not path_info.has_identifier:
        return sync_list

    return None


def has_backend(versioned_path_info):
    if not versioned_path_info.fully_understood:
        return False

    if versioned_path_info.unversioned is not None:
        return get_backend(versioned_path_info.unversioned) is not None

    if versioned_path_info.versioned is not None:
        for dummy, dummy, unversioned in versioned_path_info.versioned:
            if unversioned and not isinstance(unversioned, str) and get_backend(unversioned) is not None:
                return True

    return False


def main():
    path_choices = sorted([join_path(path) for path, versioned_path_info in PATHS.items() if has_backend(versioned_path_info)])
    module_args = dict(
        path=dict(type='str', required=True, choices=path_choices),
        data=dict(type='list', elements='dict', required=True),
        handle_absent_entries=dict(type='str', choices=['ignore', 'remove'], default='ignore'),
        handle_entries_content=dict(type='str', choices=['ignore', 'remove', 'remove_as_much_as_possible'], default='ignore'),
        ensure_order=dict(type='bool', default=False),
        handle_read_only=dict(type='str', default='error', choices=['ignore', 'validate', 'error']),
        handle_write_only=dict(type='str', default='create_only', choices=['create_only', 'always_update', 'error']),
    )
    module_args.update(api_argument_spec())
    module_args.update(restrict_argument_spec())

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )
    if module.params['ensure_order'] and module.params['handle_absent_entries'] == 'ignore':
        module.fail_json(msg='ensure_order=true requires handle_absent_entries=remove')

    if not HAS_ORDEREDDICT:
        # This should never happen for Python 2.7+
        module.fail_json(msg=missing_required_lib('ordereddict'))

    check_has_library(module)
    api = create_api(module)

    path = split_path(module.params['path'])
    versioned_path_info = PATHS.get(tuple(path))
    if versioned_path_info.needs_version:
        api_version = get_api_version(api)
        supported, not_supported_msg = versioned_path_info.provide_version(api_version)
        if not supported:
            msg = 'Path /{path} is not supported for API version {api_version}'.format(path='/'.join(path), api_version=api_version)
            if not_supported_msg:
                msg = '{0}: {1}'.format(msg, not_supported_msg)
            module.fail_json(msg=msg)
    path_info = versioned_path_info.get_data()

    backend = get_backend(path_info)
    if path_info is None or backend is None:
        module.fail_json(msg='Path /{path} is not yet supported'.format(path='/'.join(path)))

    restrict_data = validate_and_prepare_restrict(module, path_info)

    backend(module, api, path, path_info, restrict_data)


if __name__ == '__main__':
    main()
