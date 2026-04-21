#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Nikolay Dachev <nikolay@dachev.info>
# GNU General Public License v3.0+ https://www.gnu.org/licenses/gpl-3.0.txt
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: api
author: "Nikolay Dachev (@NikolayDachev)"
short_description: Ansible module for RouterOS API
description:
  - Ansible module for RouterOS API with the Python C(librouteros) library.
  - This module can add, remove, update, query, and execute arbitrary command in RouterOS through the API.
notes:
  - O(add), O(remove), O(update), O(cmd), and O(query) are mutually exclusive.
  - Use the M(community.routeros.api_modify) and M(community.routeros.api_find_and_modify) modules for more specific modifications,
    and the M(community.routeros.api_info) module for a more controlled way of returning all entries for a path.
extends_documentation_fragment:
  - community.routeros.api
  - community.routeros.attributes
  - community.routeros.attributes.actiongroup_api
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  platform:
    support: full
    platforms: RouterOS
  action_group:
    version_added: 2.1.0
  idempotent:
    support: N/A
    details:
      - Whether the executed command is idempotent depends on the operation performed.
options:
  path:
    description:
      - Main path for all other arguments.
      - If other arguments are not set, the module will return all items in selected path.
      - Example V(ip address). Equivalent of RouterOS CLI C(/ip address print).
    required: true
    type: str
  add:
    description:
      - Will add selected arguments in selected path to RouterOS config.
      - Example V(address=1.1.1.1/32 interface=ether1).
      - Equivalent in RouterOS CLI C(/ip address add address=1.1.1.1/32 interface=ether1).
    type: str
  remove:
    description:
      - Remove config/value from RouterOS by '.id'.
      - Example V(*03) will remove config/value with C(id=*03) in selected path.
      - Equivalent in RouterOS CLI C(/ip address remove numbers=1).
      - Note C(number) in RouterOS CLI is different from C(.id).
    type: str
  update:
    description:
      - Update config/value in RouterOS by '.id' in selected path.
      - Example V(.id=*03 address=1.1.1.3/32) and path V(ip address) will replace the existing IP address with C(.id=*03).
      - Equivalent in RouterOS CLI C(/ip address set address=1.1.1.3/32 numbers=1).
      - Note C(number) in RouterOS CLI is different from C(.id).
    type: str
  query:
    description:
      - Query given path for selected query attributes from RouterOS API.
      - WHERE is key word which extend query. WHERE format is key operator value - with spaces.
      - WHERE valid operators are V(==) or V(eq), V(!=) or V(not), V(>) or V(more), V(<) or V(less).
      - Example path V(ip address) and query V(.id address) will return only C(.id) and C(address) for all items in V(ip address)
        path.
      - Example path V(ip address) and query V(.id address WHERE address == 1.1.1.3/32). will return only C(.id) and C(address)
        for items in V(ip address) path, where address is eq to 1.1.1.3/32.
      - Example path V(interface) and query V(mtu name WHERE mut > 1400) will return only interfaces C(mtu,name) where mtu
        is bigger than 1400.
      - Equivalent in RouterOS CLI C(/interface print where mtu > 1400).
    type: str
  extended_query:
    description:
      - Extended query given path for selected query attributes from RouterOS API.
      - Extended query allow conjunctive input. If there is no matching entry, an empty list will be returned.
    type: dict
    suboptions:
      attributes:
        description:
          - The list of attributes to return.
          - Every attribute used in a O(extended_query.where[]) clause need to be listed here.
        type: list
        elements: str
        required: true
      where:
        description:
          - Allows to restrict the objects returned.
          - The conditions here must all match. An O(extended_query.where[].or) condition needs at least one of its conditions
            to match.
        type: list
        elements: dict
        suboptions:
          attribute:
            description:
              - The attribute to match. Must be part of O(extended_query.attributes).
              - Either O(extended_query.where[].or) or all of O(extended_query.where[].attribute), O(extended_query.where[].is),
                and O(extended_query.where[].value) have to be specified.
            type: str
          is:
            description:
              - The operator to use for matching.
              - For equality use V(==) or V(eq). For less use V(<) or V(less). For more use V(>) or V(more).
              - Use V(in) to check whether the value is part of a list. In that case, O(extended_query.where[].value) must
                be a list.
              - Either O(extended_query.where[].or) or all of O(extended_query.where[].attribute), O(extended_query.where[].is),
                and O(extended_query.where[].value) have to be specified.
            type: str
            choices: ["==", "!=", ">", "<", "in", "eq", "not", "more", "less"]
          value:
            description:
              - The value to compare to. Must be a list for O(extended_query.where[].is=in).
              - Either O(extended_query.where[].or) or all of O(extended_query.where[].attribute), O(extended_query.where[].is),
                and O(extended_query.where[].value) have to be specified.
            type: raw
          or:
            description:
              - A list of conditions so that at least one of them has to match.
              - Either O(extended_query.where[].or) or all of O(extended_query.where[].attribute), O(extended_query.where[].is),
                and O(extended_query.where[].value) have to be specified.
            type: list
            elements: dict
            suboptions:
              attribute:
                description:
                  - The attribute to match. Must be part of O(extended_query.attributes).
                type: str
                required: true
              is:
                description:
                  - The operator to use for matching.
                  - For equality use V(==) or V(eq). For less use V(<) or V(less). For more use V(>) or V(more).
                  - Use V(in) to check whether the value is part of a list. In that case, O(extended_query.where[].or[].value)
                    must be a list.
                type: str
                choices: ["==", "!=", ">", "<", "in", "eq", "not", "more", "less"]
                required: true
              value:
                description:
                  - The value to compare to. Must be a list for O(extended_query.where[].or[].is=in).
                type: raw
                required: true
  cmd:
    description:
      - Execute any/arbitrary command in selected path, after the command we can add C(.id).
      - Example path V(system script) and cmd V(run .id=*03) is equivalent in RouterOS CLI C(/system script run number=0).
      - Example path V(ip address) and cmd V(print) is equivalent in RouterOS CLI C(/ip address print).
    type: str
seealso:
  - ref: ansible_collections.community.routeros.docsite.quoting
    description: How to quote and unquote commands and arguments.
  - module: community.routeros.api_facts
  - module: community.routeros.api_find_and_modify
  - module: community.routeros.api_info
  - module: community.routeros.api_modify
"""

EXAMPLES = r"""
---
- name: Get example - ip address print
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "ip address"
  register: ipaddrd_printout

- name: Dump "Get example" output
  ansible.builtin.debug:
    msg: '{{ ipaddrd_printout }}'

- name: Add example - ip address
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "ip address"
    add: "address=192.168.255.10/24 interface=ether2"

- name: Query example - ".id, address" in "ip address WHERE address == 192.168.255.10/24"
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "ip address"
    query: ".id address WHERE address == {{ ip2 }}"
  register: queryout

- name: Dump "Query example" output
  ansible.builtin.debug:
    msg: '{{ queryout }}'

- name: Extended query example - ".id,address,network" where address is not 192.168.255.10/24 or is 10.20.36.20/24
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "ip address"
    extended_query:
      attributes:
        - network
        - address
        - .id
      where:
        - attribute: "network"
          is: "=="
          value: "192.168.255.0"
        - or:
            - attribute: "address"
              is: "!="
              value: "192.168.255.10/24"
            - attribute: "address"
              is: "eq"
              value: "10.20.36.20/24"
        - attribute: "network"
          is: "in"
          value:
            - "10.20.36.0"
            - "192.168.255.0"
  register: extended_queryout

- name: Dump "Extended query example" output
  ansible.builtin.debug:
    msg: '{{ extended_queryout }}'

- name: Update example - ether2 ip address with ".id = *14"
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "ip address"
    update: >-
      .id=*14
      address=192.168.255.20/24
      comment={{ 'Update 192.168.255.10/24 to 192.168.255.20/24 on ether2' | community.routeros.quote_argument_value }}

- name: Remove example - ether2 ip 192.168.255.20/24 with ".id = *14"
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "ip address"
    remove: "*14"

- name: Arbitrary command example "/system identity print"
  community.routeros.api:
    hostname: "{{ hostname }}"
    password: "{{ password }}"
    username: "{{ username }}"
    path: "system identity"
    cmd: "print"
  register: arbitraryout

- name: Dump "Arbitrary command example" output
  ansible.builtin.debug:
    msg: '{{ arbitraryout }}'
"""

RETURN = r"""
message:
  description: All outputs are in list with dictionary elements returned from RouterOS API.
  sample:
    - address: 1.2.3.4
    - address: 2.3.4.5
  type: list
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.routeros.plugins.module_utils.quoting import (
    ParseError,
    convert_list_to_dictionary,
    parse_argument_value,
    split_routeros_command,
)

from ansible_collections.community.routeros.plugins.module_utils.api import (
    api_argument_spec,
    check_has_library,
    create_api,
)

import re

try:
    from librouteros.exceptions import LibRouterosError
    from librouteros.query import Key, Or
except Exception:
    # Handled in api module_utils
    pass


class ROS_api_module:
    def __init__(self):
        module_args = dict(
            path=dict(type='str', required=True),
            add=dict(type='str'),
            remove=dict(type='str'),
            update=dict(type='str'),
            cmd=dict(type='str'),
            query=dict(type='str'),
            extended_query=dict(type='dict', options=dict(
                attributes=dict(type='list', elements='str', required=True),
                where=dict(
                    type='list',
                    elements='dict',
                    options={
                        'attribute': dict(type='str'),
                        'is': dict(type='str', choices=["==", "!=", ">", "<", "in", "eq", "not", "more", "less"]),
                        'value': dict(type='raw'),
                        'or': dict(type='list', elements='dict', options={
                            'attribute': dict(type='str', required=True),
                            'is': dict(type='str', choices=["==", "!=", ">", "<", "in", "eq", "not", "more", "less"], required=True),
                            'value': dict(type='raw', required=True),
                        }),
                    },
                    required_together=[('attribute', 'is', 'value')],
                    mutually_exclusive=[('attribute', 'or')],
                    required_one_of=[('attribute', 'or')],
                ),
            )),
        )
        module_args.update(api_argument_spec())

        self.module = AnsibleModule(argument_spec=module_args,
                                    supports_check_mode=False,
                                    mutually_exclusive=(('add', 'remove', 'update',
                                                         'cmd', 'query', 'extended_query'),),)

        check_has_library(self.module)

        self.api = create_api(self.module)

        self.path = self.module.params['path'].split()
        self.add = self.module.params['add']
        self.remove = self.module.params['remove']
        self.update = self.module.params['update']
        self.arbitrary = self.module.params['cmd']

        self.where = None
        self.query = self.module.params['query']
        self.extended_query = self.module.params['extended_query']

        self.result = dict(
            message=[])

        # create api base path
        self.api_path = self.api_add_path(self.api, self.path)

        # api calls
        try:
            if self.add:
                self.api_add()
            elif self.remove:
                self.api_remove()
            elif self.update:
                self.api_update()
            elif self.query:
                self.check_query()
                self.api_query()
            elif self.extended_query:
                self.check_extended_query()
                self.api_extended_query()
            elif self.arbitrary:
                self.api_arbitrary()
            else:
                self.api_get_all()
        except UnicodeEncodeError as exc:
            self.module.fail_json(msg='Error while encoding text: {error}'.format(error=exc))

    def check_query(self):
        where_index = self.query.find(' WHERE ')
        if where_index < 0:
            self.query = self.split_params(self.query)
        else:
            where = self.query[where_index + len(' WHERE '):]
            self.query = self.split_params(self.query[:where_index])
            # where must be of the format '<attribute> <operator> <value>'
            m = re.match(r'^\s*([^ ]+)\s+([^ ]+)\s+(.*)$', where)
            if not m:
                self.errors("invalid syntax for 'WHERE %s'" % where)
            try:
                self.where = [
                    m.group(1),  # attribute
                    m.group(2),  # operator
                    parse_argument_value(m.group(3).rstrip())[0],  # value
                ]
            except ParseError as exc:
                self.errors("invalid syntax for 'WHERE %s': %s" % (where, exc))
        try:
            idx = self.query.index('WHERE')
            self.where = self.query[idx + 1:]
            self.query = self.query[:idx]
        except ValueError:
            # Raised when WHERE has not been found
            pass

    def check_extended_query_syntax(self, test_atr, or_msg=''):
        if test_atr['is'] == "in" and not isinstance(test_atr['value'], list):
            self.errors("invalid syntax 'extended_query':'where':%s%s 'value' must be a type list" % (or_msg, test_atr))

    def check_extended_query(self):
        if self.extended_query["where"]:
            for i in self.extended_query['where']:
                if i["or"] is not None:
                    if len(i['or']) < 2:
                        self.errors("invalid syntax 'extended_query':'where':'or':%s 'or' requires minimum two items" % i["or"])
                    for orv in i['or']:
                        self.check_extended_query_syntax(orv, ":'or':")
                else:
                    self.check_extended_query_syntax(i)

    def list_to_dic(self, ldict):
        return convert_list_to_dictionary(ldict, skip_empty_values=True, require_assignment=True)

    def split_params(self, params):
        if not isinstance(params, str):
            raise AssertionError('Parameters can only be a string, received %s' % type(params))
        try:
            return split_routeros_command(params)
        except ParseError as e:
            self.module.fail_json(msg=to_native(e))

    def api_add_path(self, api, path):
        api_path = api.path()
        for p in path:
            api_path = api_path.join(p)
        return api_path

    def api_get_all(self):
        try:
            for i in self.api_path:
                self.result['message'].append(i)
            self.return_result(False, True)
        except LibRouterosError as e:
            self.errors(e)

    def api_add(self):
        param = self.list_to_dic(self.split_params(self.add))
        try:
            self.result['message'].append("added: .id= %s"
                                          % self.api_path.add(**param))
            self.return_result(True)
        except LibRouterosError as e:
            self.errors(e)

    def api_remove(self):
        try:
            self.api_path.remove(self.remove)
            self.result['message'].append("removed: .id= %s" % self.remove)
            self.return_result(True)
        except LibRouterosError as e:
            self.errors(e)

    def api_update(self):
        param = self.list_to_dic(self.split_params(self.update))
        if '.id' not in param.keys():
            self.errors("missing '.id' for %s" % param)
        try:
            self.api_path.update(**param)
            self.result['message'].append("updated: %s" % param)
            self.return_result(True)
        except LibRouterosError as e:
            self.errors(e)

    def api_query(self):
        keys = {}
        for k in self.query:
            if k == "id":
                self.errors("'%s' must be '.id'" % k)
            keys[k] = Key(k)
        try:
            if self.where:
                if self.where[1] in ('==', 'eq'):
                    select = self.api_path.select(*keys).where(keys[self.where[0]] == self.where[2])
                elif self.where[1] in ('!=', 'not'):
                    select = self.api_path.select(*keys).where(keys[self.where[0]] != self.where[2])
                elif self.where[1] in ('>', 'more'):
                    select = self.api_path.select(*keys).where(keys[self.where[0]] > self.where[2])
                elif self.where[1] in ('<', 'less'):
                    select = self.api_path.select(*keys).where(keys[self.where[0]] < self.where[2])
                else:
                    self.errors("'%s' is not operator for 'where'"
                                % self.where[1])
            else:
                select = self.api_path.select(*keys)
            for row in select:
                self.result['message'].append(row)
            if len(self.result['message']) < 1:
                msg = "no results for '%s 'query' %s" % (' '.join(self.path),
                                                         ' '.join(self.query))
                if self.where:
                    msg = msg + ' WHERE %s' % ' '.join(self.where)
                self.result['message'].append(msg)
            self.return_result(False)
        except LibRouterosError as e:
            self.errors(e)

    def build_api_extended_query(self, item):
        if item['attribute'] not in self.extended_query['attributes']:
            self.errors("'%s' attribute is not in attributes: %s"
                        % (item, self.extended_query['attributes']))
        if item['is'] in ('eq', '=='):
            return self.query_keys[item['attribute']] == item['value']
        elif item['is'] in ('not', '!='):
            return self.query_keys[item['attribute']] != item['value']
        elif item['is'] in ('less', '<'):
            return self.query_keys[item['attribute']] < item['value']
        elif item['is'] in ('more', '>'):
            return self.query_keys[item['attribute']] > item['value']
        elif item['is'] == 'in':
            return self.query_keys[item['attribute']].In(*item['value'])
        else:
            self.errors("'%s' is not operator for 'is'" % item['is'])

    def api_extended_query(self):
        self.query_keys = {}
        for k in self.extended_query['attributes']:
            if k == 'id':
                self.errors("'extended_query':'attributes':'%s' must be '.id'" % k)
            self.query_keys[k] = Key(k)
        try:
            if self.extended_query['where']:
                where_args = []
                for i in self.extended_query['where']:
                    if i['or']:
                        where_or_args = []
                        for ior in i['or']:
                            where_or_args.append(self.build_api_extended_query(ior))
                        where_args.append(Or(*where_or_args))
                    else:
                        where_args.append(self.build_api_extended_query(i))
                select = self.api_path.select(*self.query_keys).where(*where_args)
            else:
                select = self.api_path.select(*self.extended_query['attributes'])
            for row in select:
                self.result['message'].append(row)
            self.return_result(False)
        except LibRouterosError as e:
            self.errors(e)

    def api_arbitrary(self):
        param = {}
        self.arbitrary = self.split_params(self.arbitrary)
        arb_cmd = self.arbitrary[0]
        if len(self.arbitrary) > 1:
            param = self.list_to_dic(self.arbitrary[1:])
        try:
            arbitrary_result = self.api_path(arb_cmd, **param)
            for i in arbitrary_result:
                self.result['message'].append(i)
            self.return_result(False)
        except LibRouterosError as e:
            self.errors(e)

    def return_result(self, ch_status=False, status=True):
        if not status:
            self.module.fail_json(msg=self.result['message'])
        else:
            self.module.exit_json(changed=ch_status,
                                  msg=self.result['message'])

    def errors(self, e):
        if e.__class__.__name__ == 'TrapError':
            self.result['message'].append("%s" % e)
            self.return_result(False, False)
        self.result['message'].append("%s" % e)
        self.return_result(False, False)


def main():

    ROS_api_module()


if __name__ == '__main__':
    main()
