#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_firewall
short_description: Manage firewall rules in Proxmox
version_added: "1.4.0"
description:
    - create/update/delete FW rules at cluster/group/vnet/node/vm level
    - Create/delete firewall security groups
    - Create/delete aliases
author: 'Jana Hoch <janahoch91@proton.me> (!UNKNOWN)'
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
options:
  state:
    description:
      - Create/update/delete firewall rules or security group.
    type: str
    choices:
      - present
      - absent
    default: present
  update:
    description:
      - If O(state=present) and if one or more rule/alias/ipset already exists it will update them.
    type: bool
    default: true
  level:
    description:
      - Level at which the firewall rule applies.
    type: str
    choices:
      - cluster
      - group
      - vnet
      - node
      - vm
    default: cluster
  node:
    description:
      - Name of the node.
      - Only needed when O(level=node).
    type: str
  vmid:
    description:
      - ID of the VM to which the rule applies.
      - Only needed when O(level=vm).
    type: int
  vnet:
    description:
      - Name of the virtual network for the rule.
      - Only needed when O(level=vnet).
    type: str
  pos:
    description:
      - Position of the rule in the list.
      - Only needed if O(state=absent).
    type: int
  group_conf:
    description:
      - Whether security group should be created or deleted.
    type: bool
    default: false
  group:
    description:
      - Name of the group to which the rule belongs.
      - Only needed when O(level=group) or O(group_conf=true).
    type: str
  comment:
    description:
      - Comment for security group.
      - Only needed when creating group.
    type: str
  ip_sets:
    description:
      - List of IP set definitions to create, update, or remove.
      - Each IP set is a named collection of CIDRs (with optional negation and comments).
    type: list
    elements: dict
    required: false
    suboptions:
      name:
        description:
          - Unique name of the IP set.
        type: str
        required: true
      comment:
        description:
          - Optional comment for the IP set.
        type: str
      cidrs:
        description:
          - List of CIDR entries in the IP set.
        type: list
        elements: dict
        required: false
        suboptions:
          cidr:
            description:
              - CIDR notation for the entry.
            type: str
            required: true
          nomatch:
            description:
              - When true, this CIDR acts as a negative match (exclusion) within the set.
            type: bool
            default: false
          comment:
            description:
              - Optional comment for this CIDR entry.
            type: str
            required: false
  aliases:
    description:
      - List of aliases.
      - Alias can only be created/updated/deleted at cluster or VM level.
    type: list
    elements: dict
    suboptions:
      name:
        description: Alias name.
        type: str
        required: true
      cidr:
        description:
          - CIDR for alias.
          - Only needed when O(state=present) or O(state=update).
        type: str
        required: false
      comment:
        description: Comment for alias.
        type: str
        required: false
  rules:
    description:
      - List of individual rules to be applied.
    type: list
    elements: dict
    suboptions:
      action:
        description:
          - Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
        type: str
        required: true
      type:
        description:
          - Rule type.
        choices:
          - in
          - out
          - forward
          - group
        type: str
        required: true
      comment:
        description:
          - Optional comment for the specific rule.
        type: str
      dest:
        description:
          - Restrict packet destination address.
          - This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition.
          - You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma).
          - Please do not mix IPv4 and IPv6 addresses inside such lists.
        type: str
      digest:
        description:
          - Prevent changes if current configuration file has a different digest.
          - This can be used to prevent concurrent modifications.
          - If not provided we will calculate at runtime.
        type: str
      dport:
        description:
          - Restrict TCP/UDP destination port.
          - You can use service names or simple numbers (0-65535), as defined in '/etc/services'.
          - Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
        type: str
      enable:
        description:
          - Enable or disable the rule.
        type: bool
      icmp_type:
        description:
          - Specify icmp-type. Only valid if proto equals 'icmp' or 'icmpv6'/'ipv6-icmp'.
        type: str
      iface:
        description:
          - Network interface name. You have to use network configuration key names for VMs and containers ('net\d+').
          - Host related rules can use arbitrary strings.
        type: str
      log:
        description:
          - Logging level for the rule.
        choices:
          - emerg
          - alert
          - crit
          - err
          - warning
          - notice
          - info
          - debug
          - nolog
        type: str
      macro:
        description:
          - Use predefined standard macro.
        type: str
      pos:
        description:
          - Position of the rule in the list.
        type: int
        required: true
      proto:
        description:
          - IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
        type: str
      source:
        description:
          - Restrict packet source address.
          - This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition.
          - You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma).
          - Please do not mix IPv4 and IPv6 addresses inside such lists.
        type: str
      sport:
        description:
          - Restrict TCP/UDP source port.
          - You can use service names or simple numbers (0-65535), as defined in '/etc/services'.
          - Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
        type: str
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Create firewall rules at cluster level
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    level: cluster
    state: present
    rules:
      - type: out
        action: ACCEPT
        source: 1.1.1.1
        log: nolog
        pos: 9
        enable: true
      - type: out
        action: ACCEPT
        source: 1.0.0.1
        pos: 10
        enable: true

- name: Update Cluster level firewall rules
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    level: cluster
    state: present
    update: true
    rules:
      - type: out
        action: ACCEPT
        source: 8.8.8.8
        log: nolog
        pos: 9
        enable: false
      - type: out
        action: ACCEPT
        source: 8.8.4.4
        pos: 10
        enable: false

- name: Delete cluster level firewall rule at pos 10
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    level: cluster
    state: absent
    pos: 10

- name: Create security group
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    group_conf: true
    state: present
    group: test

- name: Delete security group
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    group_conf: true
    state: absent
    group: test

- name: Create FW aliases
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    state: present
    aliases:
      - name: test1
        cidr: '10.10.1.0/24'
      - name: test2
        cidr: '10.10.2.0/24'

- name: Update FW aliases
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    state: present
    update: true
    aliases:
      - name: test1
        cidr: '10.10.1.0/28'
      - name: test2
        cidr: '10.10.2.0/28'

- name: Delete FW aliases
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    state: absent
    aliases:
      - name: test1
      - name: test2

- name: Create IP SET
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    ip_sets:
      - name: hypervisors
        comment: PVE hosts
        cidrs:
          - cidr: 192.168.1.10
            nomatch: false
            comment: Proxmox pve-01
          - cidr: 192.168.1.11
            nomatch: true
            comment: Proxmox pve-02
      - name: test
        comment: PVE hosts
        cidrs:
          - cidr: 10.10.1.0
            comment: Proxmox pve-01

- name: Delete IP SETs
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    state: absent
    ip_sets:
      - name: hypervisors

- name: Delete specific CIDR from IP SET
  community.proxmox.proxmox_firewall:
    api_user: "{{ pc.proxmox.api_user }}"
    api_token_id: "{{ pc.proxmox.api_token_id }}"
    api_token_secret: "{{ vault.proxmox.api_token_secret }}"
    api_host: "{{ pc.proxmox.api_host }}"
    validate_certs: false
    state: absent
    ip_sets:
      - name: test
        cidrs:
          - cidr: 10.10.1.0
"""

RETURN = r"""
group:
    description: group name which was created/deleted
    returned: on success
    type: str
    sample:
      test
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox_sdn import ProxmoxSdnAnsible
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec,
    ansible_to_proxmox_bool,
    compare_list_of_dicts
)


def get_proxmox_args():
    return dict(
        state=dict(type="str", choices=["present", "absent"], default="present"),
        update=dict(type="bool", default=True),
        level=dict(type="str", choices=["cluster", "node", "vm", "vnet", "group"], default="cluster", required=False),
        node=dict(type="str", required=False),
        vmid=dict(type="int", required=False),
        vnet=dict(type="str", required=False),
        pos=dict(type="int", required=False),
        group_conf=dict(type="bool", default=False),
        group=dict(type="str", required=False),
        comment=dict(type="str", required=False),
        ip_sets=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                name=dict(type="str", required=True),
                comment=dict(type="str", required=False),
                cidrs=dict(
                    type="list",
                    elements="dict",
                    required=False,
                    options=dict(
                        cidr=dict(type="str", required=True),
                        nomatch=dict(type="bool", default=False),
                        comment=dict(type="str", required=False)
                    )
                )
            )
        ),
        aliases=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                name=dict(type="str", required=True),
                cidr=dict(type="str", required=False),
                comment=dict(type="str", required=False)
            )
        ),
        rules=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                action=dict(type="str", required=True),
                type=dict(type="str", choices=["in", "out", "forward", "group"], required=True),
                comment=dict(type="str", required=False),
                dest=dict(type="str", required=False),
                digest=dict(type="str", required=False),
                dport=dict(type="str", required=False),
                enable=dict(type="bool", required=False),
                icmp_type=dict(type="str", required=False),
                iface=dict(type="str", required=False),
                log=dict(type="str",
                         choices=["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug", "nolog"],
                         required=False),
                macro=dict(type="str", required=False),
                pos=dict(type="int", required=True),
                proto=dict(type="str", required=False),
                source=dict(type="str", required=False),
                sport=dict(type="str", required=False)
            )
        )
    )


def get_ansible_module():
    module_args = proxmox_auth_argument_spec()
    module_args.update(get_proxmox_args())

    return AnsibleModule(
        argument_spec=module_args,
        required_if=[
            ('group_conf', True, ['group']),
            ('level', 'vm', ['vmid']),
            ('level', 'node', ['node']),
            ('level', 'vnet', ['vnet']),
            ('level', 'group', ['group']),
        ],
        mutually_exclusive=[
            ('aliases', 'rules'),
            ('aliases', 'ip_sets'),
            ('rules', 'ip_sets'),
        ]
    )


class ProxmoxFirewallAnsible(ProxmoxSdnAnsible):
    def __init__(self, module):
        super(ProxmoxFirewallAnsible, self).__init__(module)
        self.params = module.params

    def validate_params(self):
        if self.params.get('state') == 'present':
            if self.params.get('group_conf') != bool(self.params.get('rules') or
                                                     self.params.get('aliases') or
                                                     self.params.get('ip_sets')):
                return True
            else:
                self.module.fail_json(
                    msg="When state is present either group_conf should be true or "
                        "rules/aliases/ip_sets must be present but not both"
                )
        elif self.params.get('state') == 'absent':
            if self.params.get('group_conf') != bool((self.params.get('pos') is not None) or
                                                     self.params.get('aliases') or
                                                     self.params.get('ip_sets')):
                return True
            else:
                self.module.fail_json(
                    msg="When state is absent either group_conf should be true or "
                        "pos/aliases/ip_sets must be present but not both"
                )

    def run(self):
        self.validate_params()

        state = self.params.get("state")
        update = self.params.get("update")
        level = self.params.get("level")
        aliases = self.params.get("aliases")
        rules = self.params.get("rules")
        ip_sets = self.params.get("ip_sets")
        group = self.params.get("group")
        group_conf = self.params.get("group_conf")

        if rules:
            for rule in rules:
                rule['icmp-type'] = rule.get('icmp_type')
                rule['enable'] = ansible_to_proxmox_bool(rule.get('enable'))
                del rule['icmp_type']

        if level == "vm":
            vm = self.get_vm(vmid=self.params.get('vmid'))
            node = self.proxmox_api.nodes(vm['node'])
            virt = node(vm['type'])
            firewall_obj = virt(str(vm['vmid'])).firewall
            rules_obj = firewall_obj().rules

        elif level == "node":
            firewall_obj = self.proxmox_api.nodes(self.params.get('node')).firewall
            rules_obj = firewall_obj().rules

        elif level == "vnet":
            firewall_obj = self.proxmox_api.cluster().sdn().vnets(self.params.get('vnet')).firewall
            rules_obj = firewall_obj().rules

        elif level == "group":
            firewall_obj = None
            rules_obj = self.proxmox_api.cluster().firewall().groups(group)

        else:
            firewall_obj = self.proxmox_api.cluster().firewall
            rules_obj = firewall_obj().rules

        if state == "present":
            if group_conf:
                self.group_present(group=group, comment=self.params.get('comment'))
            if rules:
                self.fw_rules_present(rules_obj=rules_obj, rules=rules, update=update)
            if aliases:
                self.aliases_present(firewall_obj=firewall_obj, level=level, aliases=aliases, update=update)
            if ip_sets:
                self.ip_set_present(ip_sets=ip_sets, update=update)
        elif state == "absent":
            if self.params.get('pos') is not None:
                self.fw_rule_absent(rules_obj=rules_obj, pos=self.params.get('pos'))
            if group_conf:
                self.group_absent(group_name=group)
            if aliases:
                self.aliases_absent(firewall_obj=firewall_obj, aliases=aliases)
            if ip_sets:
                self.ip_set_absent(ip_sets=ip_sets)

    def ip_set_present(self, ip_sets, update):
        existing_ip_sets = self.get_ip_sets()
        existing_ip_set_names = [x['name'] for x in existing_ip_sets]
        changed = False

        try:
            for ip_set in ip_sets:
                ip_set_name = ip_set['name']
                if ip_set_name not in existing_ip_set_names:
                    self.proxmox_api.cluster().firewall().ipset().post(
                        name=ip_set.get('name'),
                        comment=ip_set.get('comment')
                    )
                    cidrs_to_create = ip_set['cidrs']
                    cidrs_to_update = []
                else:
                    existing_ip_set_cidrs = [x['cidrs'] for x in existing_ip_sets if x['name'] == ip_set_name][0]
                    cidrs_to_create, cidrs_to_update = compare_list_of_dicts(
                        existing_list=existing_ip_set_cidrs,
                        new_list=ip_set['cidrs'],
                        uid='cidr',
                        params_to_ignore=['digest'],
                    )

                if cidrs_to_update and not update:
                    self.module.fail_json(f'IP set {ip_set_name} needs to be updated but update is false.')

                for cidr in cidrs_to_update:
                    changed = True
                    proxmoxer_cidr_obj = getattr(self.proxmox_api.cluster().firewall().ipset(ip_set_name), cidr['cidr'])
                    proxmoxer_cidr_obj.put(
                        cidr=cidr['cidr'],
                        name=ip_set_name,
                        comment=cidr['comment'],
                        nomatch=ansible_to_proxmox_bool(cidr.get('nomatch'))
                    )

                for cidr in cidrs_to_create:
                    changed = True
                    self.proxmox_api.cluster().firewall().ipset(ip_set_name).post(
                        cidr=cidr.get('cidr'),
                        nomatch=ansible_to_proxmox_bool(cidr.get('nomatch')),
                        comment=cidr.get('comment')
                    )

            self.module.exit_json(
                changed=changed,
                msg='All ipsets present.'
            )
        except Exception as e:
            self.module.fail_json(f"Failed to create/update ipsets - {e}.")

    def ip_set_absent(self, ip_sets):
        existing_ip_sets = self.get_ip_sets()
        existing_ip_set_names = [x['name'] for x in existing_ip_sets]
        changed = False

        try:
            for ip_set in ip_sets:
                delete_ipset = False
                ip_set_name = ip_set['name']

                if ip_set_name not in existing_ip_set_names:
                    continue

                existing_ip_set_cidrs = [x['cidrs'] for x in existing_ip_sets if x['name'] == ip_set_name][0]

                if not ip_set.get('cidrs'):
                    cidrs_to_delete = existing_ip_set_cidrs
                    delete_ipset = True
                else:
                    cidrs_to_delete = ip_set['cidrs']

                for cidr in cidrs_to_delete:
                    if cidr['cidr'] not in [x['cidr'] for x in existing_ip_set_cidrs]:
                        continue
                    cidr_obj = getattr(self.proxmox_api.cluster().firewall().ipset(ip_set_name), cidr['cidr'])
                    cidr_obj.delete()
                    changed = True

                if delete_ipset:
                    self.proxmox_api.cluster().firewall().ipset(ip_set_name).delete()

            self.module.exit_json(changed=changed, msg='Ipsets are absent.')

        except Exception as e:
            self.module.fail_json(f'Failed to delete ipsets {e}')

    def aliases_present(self, firewall_obj, level, aliases, update):
        if not firewall_obj or level not in ['cluster', 'vm']:
            self.module.fail_json(
                msg='Aliases can only be created at cluster or VM level'
            )

        aliases_to_create, aliases_to_update = compare_list_of_dicts(
            existing_list=self.get_aliases(firewall_obj=firewall_obj),
            new_list=aliases,
            uid='name',
            params_to_ignore=['digest', 'ipversion']
        )

        if len(aliases_to_create) == 0 and len(aliases_to_update) == 0:
            self.module.exit_json(changed=False, msg='No need to create/update any aliases')
        elif len(aliases_to_update) > 0 and not update:
            self.module.fail_json(
                msg=f"Need to update aliases - {[x['name'] for x in aliases_to_update]} but update is false"
            )

        for alias in aliases_to_create:
            try:
                firewall_obj().aliases().post(**alias)
            except Exception as e:
                self.module.fail_json(
                    msg=f"Failed to create Alias {alias['name']} - {e}"
                )
        for alias in aliases_to_update:
            try:
                firewall_obj().aliases(alias['name']).put(**alias)
            except Exception as e:
                self.module.fail_json(
                    msg=f"Failed to update Alias {alias['name']} - {e}"
                )

        self.module.exit_json(changed=True, msg="Aliases created/updated")

    def aliases_absent(self, firewall_obj, aliases):
        existing_aliases = set([x.get('name') for x in self.get_aliases(firewall_obj=firewall_obj)])
        aliases = set([x.get('name') for x in aliases])
        aliases_to_delete = list(existing_aliases.intersection(aliases))

        if len(aliases_to_delete) == 0:
            self.module.exit_json(
                changed=False,
                msg="No need to delete any alias"
            )
        for alias_name in aliases_to_delete:
            try:
                alias_obj = getattr(firewall_obj().aliases(), alias_name)
                alias_obj().delete()
            except Exception as e:
                self.module.fail_json(
                    msg=f"Failed to delete alias {alias_name} - {e}"
                )
        self.module.exit_json(
            changed=True,
            msg="Successfully deleted aliases"
        )

    def group_present(self, group, comment=None):
        if group in self.get_groups():
            self.module.exit_json(
                changed=False, group=group, msg=f"security group {group} already exists"
            )
        try:
            self.proxmox_api.cluster().firewall().groups.post(group=group, comment=comment)
            self.module.exit_json(
                changed=True, group=group, msg=f'successfully created security group {group}'
            )
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to create security group: {e}'
            )

    def group_absent(self, group_name):
        if group_name not in self.get_groups():
            self.module.exit_json(
                changed=False, group=group_name, msg=f"security group {group_name} already doesn't exists"
            )
        try:
            group = getattr(self.proxmox_api.cluster().firewall().groups(), group_name)
            group.delete()
            self.module.exit_json(
                changed=True, group=group_name, msg=f'successfully deleted security group {group_name}'
            )
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to delete security group {group_name}: {e}'
            )

    def fw_rule_absent(self, rules_obj, pos):
        try:
            for item in self.get_fw_rules(rules_obj):
                if item.get('pos') == pos:
                    break
            else:
                self.module.exit_json(
                    changed=False, msg="Firewall rule already doesn't exist"
                )
            rule_obj = getattr(rules_obj(), str(pos))
            digest = rule_obj.get().get('digest')
            rule_obj.delete(pos=pos, digest=digest)

            self.module.exit_json(
                changed=True, msg='successfully deleted firewall rules'
            )
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to delete firewall rule at pos {pos}: {e}'
            )

    def fw_rules_present(self, rules_obj, rules, update):
        existing_rules = self.get_fw_rules(rules_obj=rules_obj)
        rules_to_create, rules_to_update = compare_list_of_dicts(
            existing_list=existing_rules,
            new_list=rules,
            uid='pos',
            params_to_ignore=['digest', 'ipversion']
        )

        if len(rules_to_create) == 0 and len(rules_to_update) == 0:
            self.module.exit_json(changed=False, msg='No need to create/update any rule')
        elif len(rules_to_update) > 0 and not update:
            self.module.fail_json(
                msg=f"Need to update rules at pos - {[x['pos'] for x in rules_to_update]} but update is false"
            )

        for rule in rules_to_update:
            try:
                rule_obj = getattr(rules_obj(), str(rule['pos']))
                rule['digest'] = rule_obj.get().get('digest')  # Avoids concurrent changes
                rule_obj.put(**rule)

            except Exception as e:
                self.module.fail_json(
                    msg=f'Failed to update firewall rule at pos {rule["pos"]}: {e}'
                )
        for rule in rules_to_create:
            try:
                rules_obj().post(**rule)
                self.move_rule_to_correct_pos(rules_obj, rule)

            except Exception as e:
                self.module.fail_json(
                    msg=f'Failed to create firewall rule {rule}: {e}'
                )
        self.module.exit_json(
            changed=True, msg='successfully created/updated firewall rules'
        )

    def move_rule_to_correct_pos(self, rules_obj, rule):
        ##################################################################################################
        # TODO: Once below mentioned issue is fixed. Remove this workaround.                             #
        # Currently Proxmox API doesn't honor pos. All new rules are created at pos 0                    #
        # https://forum.proxmox.com/threads/issue-when-creating-a-firewall-rule.135878/                  #
        # Not able to find it in BUGZILLA. So maybe this is expected behaviour.                          #
        # To workaround this issue we will check rule at pos 0 and if needed move it to correct position #
        ##################################################################################################

        pos = rule.get('pos')
        rule = {k: v for k, v in rule.items() if v is not None}
        if pos is not None and pos != 0:
            try:
                fw_rule_at0 = getattr(rules_obj(), str(0))
                for param, value, in fw_rule_at0.get().items():
                    if param in rule.keys() and param != 'pos' and value != rule.get(param):
                        self.module.warn(
                            msg=f'Skipping workaround for rule placement. '
                                f'Verify rule is at correct pos '
                                f'provided - {rule} rule_at0 - {fw_rule_at0.get()}')
                        break  # No need to move this. Potentially the issue is resolved.
                else:
                    fw_rule_at0.put(moveto=(pos + 1))  # moveto moves rule to one position before the value
            except Exception as e:
                self.module.fail_json(
                    msg=f'Rule created but failed to move it to correct pos. {e}'
                )


def main():
    module = get_ansible_module()
    proxmox = ProxmoxFirewallAnsible(module)

    try:
        proxmox.run()
    except Exception as e:
        module.fail_json(msg=f'An error occurred: {e}')


if __name__ == "__main__":
    main()
