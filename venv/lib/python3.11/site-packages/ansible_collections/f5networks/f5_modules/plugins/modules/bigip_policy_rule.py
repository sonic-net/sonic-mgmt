#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: bigip_policy_rule
short_description: Manage LTM policy rules on a BIG-IP
description:
  - This module manages LTM policy rules on a BIG-IP.
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the rule.
    type: str
    required: True
  policy:
    description:
      - The name of the policy with which you want to associate this rule.
    type: str
    required: True
  replace_with:
    description:
      - Specifies if the C(conditions)/C(actions) given by the user should overwrite what exists on the device.
      - The option is useful when a subset of C(conditions)/C(actions) needs to be removed. This option is similar to the
        replace-all-with flag available in TMSH commands.
      - Using this option is not idempotent.
    type: bool
    default: false
  rule_order:
    description:
      - Specifies a number that indicates the order of this rule relative to other rules in the policy.
      - When not set, the device sets the parameter to 0.
      - If there are rules with the same rule order number, the device uses rule names
        to determine how the rules are ordered.
      - The lower the number, the lower the rule is in the general order, with the lowest number C(0) being the
        topmost rule.
      - Valid range of values is between C(0) and C(4294967295) inclusive.
    type: int
    version_added: "1.10.0"
  description:
    description:
      - Description of the policy rule.
    type: str
  actions:
    description:
      - The actions you want the policy rule to perform.
      - The available attributes vary by the action, however, each action requires
        you specify a C(type).
      - These conditions can be specified in any order. Despite the fact they are in a list,
        the order in the list does not matter to the BIG-IP.
    type: list
    elements: dict
    suboptions:
      type:
        description:
          - The action type. This value controls which of the following options are required.
          - When C(type) is C(forward), the system associates a given C(pool), or C(virtual),
            or C(node) with this rule.
          - When C(type) is C(enable), the system associates a given C(asm_policy) with
            this rule.
          - When C(type) is C(ignore), the system removes all existing actions from this
            rule.
          - When C(type) is C(redirect), the system redirects an HTTP request to a different URL.
          - When C(type) is C(reset), the system resets the connection upon C(event).
          - When C(type) is C(persist), the system associates C(cookie_insert) and C(cookie_expiry) with this rule.
          - When C(type) is C(set_variable), the system sets a variable based on the evaluated Tcl C(expression) based on C(event).
          - When C(type) is C(remove), the system removes C(http_set_cookie), C(http_referer), C(http_header) or C(http_cookie) with this rule.
          - When C(type) is C(insert), the system inserts C(http_set_cookie), C(http_referer), C(http_header) or C(http_cookie) with this rule.
          - When C(type) is C(replace), the system replaces C(http_connect), C(http_referer), C(http_header), C(http_uri) or C(http_host) with this rule.
          - When C(type) is C(disable), the system disables C(disable_target) with this rule.
        type: str
        required: true
        choices:
          - forward
          - enable
          - ignore
          - redirect
          - reset
          - persist
          - set_variable
          - remove
          - insert
          - replace
          - disable
      pool:
        description:
          - Pool to which you want to forward traffic.
          - This parameter is only valid with the C(forward) type.
        type: str
      virtual:
        description:
          - Virtual server to which you want to forward traffic.
          - This parameter is only valid with the C(forward) type.
        type: str
      node:
        description:
          - Node to which you want to forward traffic.
          - This parameter is only valid with the C(forward) type.
        type: str
        version_added: "1.2.0"
      disable_target:
        description:
          - Target you want to disable.
          - This parameter is only valid with the C(disable) type.
        type: str
        version_added: "1.8.0"
        choices:
          - server_ssl
          - persist
          - asm
      asm_policy:
        description:
          - ASM policy to enable.
          - This parameter is only valid with the C(enable) type.
        type: str
      location:
        description:
          - The new URL for which a redirect response is sent.
          - A Tcl command substitution can be used for this field.
        type: str
      event:
        description:
          - Events on which actions, such as reset and forward, can be triggered.
          - With the C(set_variable) action, it is used for specifying
            an action event, such as request or response.
          - "Valid event choices for C(forward) action type are: client_accepted, proxy_request
            request, ssl_client_hello and ssl_client_server_hello_send."
          - "Valid event choices for C(reset) acton type are: client_accepted, proxy_connect
            proxy_request, proxy_response, request, response, server_connected, ssl_client_hello,
            ssl_client_server_hello_send, ssl_server_handshake, ssl_server_hello, websocket_request,
            websocket_response."
          - "Valid event choices for C(disable) acton type are: client_accepted, proxy_connect
            proxy_request, proxy_response, request, server_connected."
        type: str
      expression:
        description:
          - A Tcl expression used with the C(set_variable) action.
        type: str
      variable_name:
        description:
           - Variable name used with the C(set_variable) action.
        type: str
      cookie_insert:
        description:
          - Cookie name on which you want to persist.
          - This parameter is only valid with the C(persist) type.
        type: str
        version_added: "1.1.0"
      cookie_expiry:
        description:
          - Optional argument, specifying the time for which the session is persisted.
          - This parameter is only valid with the C(persist) type.
        type: int
        version_added: "1.1.0"
      http_header:
        description:
          - HTTP Header that you want to remove or insert.
          - This parameter is only valid with the C(remove), C(insert) and C(replace) type.
        type: dict
        suboptions:
          event:
            description:
              - Type of event when the C(http_header) is removed, replaced, or inserted.
              - The C(request) and C(response) events are only choices with C(remove) and C(insert) type.
              - All of events are valid with C(replace) type action.
            type: str
            required: True
            choices:
              - request
              - response
              - proxy_connect
              - proxy_request
              - proxy_response
          name:
            description:
              - The name of C(http_header).
            type: str
            required: True
          value:
            description:
              - The value of C(http_header).
              - Mandatory parameter when configured with C(insert) or C(replace) type.
            type: str
        version_added: "1.8.0"
      http_referer:
        description:
          - HTTP Referer header you want to remove, replace, or insert.
          - This parameter is only valid with the C(remove), C(insert) and C(replace) type.
        type: dict
        suboptions:
          event:
            description:
              - Type of event when the c(http_referer) is removed, replaced, or inserted.
            required: True
            type: str
            choices:
              - request
              - proxy_connect
              - proxy_request
          value:
            description:
              - The value of C(http_referer).
              - This is a mandatory parameter when configured with C(insert) type action.
              - This parameter is ignored for the C(remove) type.
              - This parameter is optional for the C(replace) type.
            type: str
        version_added: "1.8.0"
      http_set_cookie:
        description:
          - HTTP Set-Cookie header you want to remove or insert.
          - This parameter is only valid with the C(remove) or c(insert) type.
        type: dict
        suboptions:
          name:
            description:
              - The name of C(http_set_cookie).
            type: str
            required: True
          value:
            description:
              - The value of C(http_set_cookie).
              - This is a mandatory parameter when configured with C(insert) type action.
            type: str
        version_added: "1.8.0"
      http_cookie:
        description:
          - HTTP Cookie header you want to remove or insert.
          - This parameter is only valid with the C(remove) and C(insert) type.
        type: dict
        suboptions:
          event:
            description:
              - Type of event when the C(http_cookie) is removed or inserted.
            type: str
            required: True
            choices:
              - request
              - proxy_connect
              - proxy_request
          name:
            description:
              - The name of C(http_cookie).
            type: str
            required: True
          value:
            description:
              - The value of C(http_cookie).
              - This is a mandatory parameter when configured with C(insert) type action.
            type: str
        version_added: "1.8.0"
      http_connect:
        description:
          - HTTP Connect header you want to replace.
          - This parameter is only valid with the C(replace) type.
        type: dict
        suboptions:
          event:
            description:
              - Type of event when the C(http_connect) header is replaced.
            required: True
            type: str
            choices:
              - client_accepted
              - proxy_connect
              - proxy_request
              - proxy_response
              - request
              - server_connected
              - ssl_client_hello
          value:
            description:
              - The value of C(http_connect).
            type: str
            required: True
          port:
            description:
              - The port number.
              - If a port number is not provided, the value is set to 0 by default.
              - Be explicit when defining rules, so the system does not override port values.
            type: int
        version_added: "1.8.0"
      http_host:
        description:
          - HTTP Host header you want to replace.
          - This parameter is only valid with the C(replace) type.
        type: dict
        suboptions:
          event:
            description:
              - Type of event when the C(http_host) is replaced.
            type: str
            required: True
            choices:
              - request
              - proxy_connect
              - proxy_request
          value:
            description:
              - The value of C(http_host).
            type: str
            required: True
        version_added: "1.8.0"
      http_uri:
        description:
          - Replaces HTTP URI, path, or string.
          - This parameter is only valid with the C(replace) type.
        type: dict
        suboptions:
          event:
            description:
              - Type of event when the C(http_uri) is replaced.
            type: str
            required: True
            choices:
              - request
              - proxy_connect
              - proxy_request
          type:
            description:
              - Specifies the part of the C(http_uri) to be replaced.
            type: str
            required: True
            choices:
              - path
              - query_string
              - full_string
          value:
            description:
              - The value of C(http_uri).
            type: str
            required: True
        version_added: "1.8.0"
  conditions:
    description:
      - A list of attributes that describe the condition.
      - See sub-options for details on how to construct each list entry.
      - The ordering of this list is important, the module ensures the order is
        kept when modifying the task.
      - The following sub-options are not required for all condition types,
        read the description for more details.
      - These conditions can be specified in any order. Despite the fact they are in a list,
        the order in the list does not matter to the BIG-IP.
    type: list
    elements: dict
    suboptions:
      type:
        description:
          - The condition type. This value controls which of the following options are required.
          - "When C(type) is C(http_uri), the valid choices are: C(path_begins_with_any), C(path_contains) or
            C(path_is_any)."
          - "When C(type) is C(http_host), the valid choices are: C(host_is_any), C(host_is_not_any), C(host_contains)
            C(host_begins_with_any), C(host_begins_not_with_any), C(host_ends_with_any) or C(host_ends_not_with_any)"
          - "When C(type) is C(http_header), the C(header_name) parameter is mandatory and the valid choice is:
            C(header_is_any)."
          - "When C(type) is C(http_method), the valid choices are: C(method_matches_with_any)."
          - When C(type) is C(all_traffic), the system removes all existing conditions from
            this rule.
        type: str
        required: True
        choices:
          - http_uri
          - all_traffic
          - http_host
          - http_header
          - http_method
          - ssl_extension
          - tcp
      path_begins_with_any:
        description:
          - A list of strings of characters with which the HTTP URI should begin.
          - This parameter is only valid with the C(http_uri) type.
        type: list
        elements: str
      path_contains:
        description:
          - A list of strings of characters the HTTP URI should contain.
          - This parameter is only valid with the C(http_uri) type.
        type: list
        elements: str
        version_added: "1.8.0"
      path_is_any:
        description:
          - A list of strings of characters the HTTP URI should match.
          - This parameter is only valid with the C(http_uri) type.
        type: list
        elements: str
        version_added: "1.8.0"
      host_is_any:
        description:
          - A list of strings of characters the HTTP Host should match.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
      host_is_not_any:
        description:
          - A list of strings of characters the HTTP Host should not match.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
      host_contains:
        description:
          - A list of strings of characters the HTTP Host contain.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
        version_added: "1.23.0"
      host_begins_with_any:
        description:
          - A list of strings of characters with which the HTTP Host should begin.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
      host_begins_not_with_any:
        description:
          - A list of strings of characters with which the HTTP Host should NOT begin.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
        version_added: "1.22.0"
      host_ends_not_with_any:
        description:
          - A list of strings of characters with which the HTTP Host should NOT begin.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
        version_added: "1.22.0"
      host_ends_with_any:
        description:
          - A list of strings of characters with which the HTTP Host should end.
          - This parameter is only valid with the C(http_host) type.
        type: list
        elements: str
        version_added: "1.8.0"
      header_is_any:
        description:
          - A list of strings of characters the HTTP Header value should match.
          - This parameter is only valid with the C(http_header) type.
        type: list
        elements: str
        version_added: "1.8.0"
      header_name:
        description:
          - A name of C(http_header).
          - This parameter is only valid with the C(http_header) type.
        type: str
        version_added: "1.8.0"
      method_matches_with_any:
        description:
          - A list of strings of characters the HTTP Method value should match.
          - This parameter is only valid with the C(http_method) type.
        type: list
        elements: str
        version_added: "1.10.0"
      server_name_is_any:
        description:
          - A list of names that includes the server name.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
      server_name_is_not_any:
        description:
          - A list of names that does NOT include the server name.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
        version_added: "1.27.0"
      server_name_begins_with_any:
        description:
          - A list of names with which the server name should begin.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
        version_added: "1.27.0"
      server_name_begins_not_with_any:
        description:
          - A list of names with which the server name should NOT begin.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
        version_added: "1.27.0"
      server_name_ends_with_any:
        description:
          - A list of names with which the server name should end.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
        version_added: "1.27.0"
      server_name_ends_not_with_any:
        description:
          - A list of names with which the server name should NOT end.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
        version_added: "1.27.0"
      server_name_contains:
        description:
          - A list of names the server name should contain.
          - This parameter is only valid with the C(ssl_extension) type.
        type: list
        elements: str
        version_added: "1.27.0"
      address_matches_with_any:
        description:
          - A list of IP Subnet address strings that the IP address should match.
          - This parameter is only valid with the C(tcp) type.
        type: list
        elements: str
        version_added: "1.8.0"
      address_matches_with_datagroup:
        description:
          - A list of internal data group strings that the IP address should match.
          - This parameter is only valid with the C(tcp) type.
        type: list
        elements: str
        version_added: "1.8.0"
      address_matches_with_external_datagroup:
        description:
          - A list of external data group strings that the IP address should match.
          - This parameter is only valid with the C(tcp) type.
        type: list
        elements: str
        version_added: "1.10.0"
      event:
        description:
          - Events on which conditions type match rules can be triggered.
          - Supported only for C(http_header), C(http_method), C(ssl_extension) and C(tcp).
          - "Valid choices for C(http_header) condition types are: C(proxy_connect),
            C(proxy_request), C(proxy_response), C(request) and C(response)."
          - "Valid choices for C(http_method) condition types are: C(proxy_connect),
            C(proxy_request), C(proxy_response), C(request) and C(response)."
          - "Valid choices for C(tcp) condition types are: C(request), C(client_accepted),
            C(proxy_connect), C(proxy_request), C(proxy_response), C(ssl_client_hello), and
            C(ssl_client_server_hello_send)."
          - "Valid choices for C(ssl_extension) are: C(ssl_client_hello), and C(ssl_client_server_hello_send)."
        type: str
  state:
    description:
      - When C(present), ensures the key is uploaded to the device. When
        C(absent), ensures the key is removed from the device. If the key
        is currently in use, the module will not be able to remove the key.
    type: str
    choices:
      - present
      - absent
    default: present
  partition:
    description:
      - Device partition on which to manage resources.
    type: str
    default: Common
extends_documentation_fragment: f5networks.f5_modules.f5
requirements:
  - BIG-IP >= v12.1.0
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create policies
  bigip_policy:
    name: Policy-Foo
    state: present
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Add a rule to the new policy
  bigip_policy_rule:
    policy: Policy-Foo
    name: rule3
    conditions:
      - type: http_uri
        path_begins_with_any:
          - /ABC
    actions:
      - type: forward
        pool: pool-svrs
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Add multiple rules to the new policy
  bigip_policy_rule:
    policy: Policy-Foo
    name: "{{ item.name }}"
    conditions: "{{ item.conditions }}"
    actions: "{{ item.actions }}"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
  loop:
    - name: rule1
      actions:
        - type: forward
          pool: pool-svrs
      conditions:
        - type: http_uri
          path_begins_with_any:
            - /euro
    - name: rule2
      actions:
        - type: forward
          pool: pool-svrs
      conditions:
        - type: http_uri
          path_begins_with_any:
            - /HomePage/
    - name: rule3
      actions:
        - type: set_variable
          variable_name: user-agent
          expression: tcl:[HTTP::header User-Agent]
          event: request
      conditions:
        - type: http_uri
          path_begins_with_any:
            - /HomePage/

- name: Remove all rules and conditions from the rule
  bigip_policy_rule:
    policy: Policy-Foo
    name: rule1
    conditions:
      - type: all_traffic
    actions:
      - type: ignore
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
actions:
  description: The new list of actions applied to the rule.
  returned: changed
  type: complex
  contains:
    type:
      description: The action type.
      returned: changed
      type: str
      sample: forward
    pool:
      description: Pool for forwarding to.
      returned: changed
      type: str
      sample: foo-pool
  sample: hash/dictionary of values
conditions:
  description: The new list of conditions applied to the rule.
  returned: changed
  type: complex
  contains:
    type:
      description: The condition type.
      returned: changed
      type: str
      sample: http_uri
    path_begins_with_any:
      description: List of strings with which the URI begins.
      returned: changed
      type: list
      sample: [foo, bar]
  sample: hash/dictionary of values
description:
  description: The new description of the rule.
  returned: changed
  type: str
  sample: My rule
rule_order:
  description: Specifies a number that indicates the order of this rule relative to other rules in the policy.
  returned: changed
  type: int
  sample: 10
'''

from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.six import iteritems

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, fq_name
)
from ..module_utils.compare import compare_complex_list
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'actionsReference': 'actions',
        'conditionsReference': 'conditions',
        'ordinal': 'rule_order',
    }
    api_attributes = [
        'description',
        'actions',
        'conditions',
        'ordinal',
    ]

    updatables = [
        'actions',
        'conditions',
        'description',
        'rule_order',
    ]

    returnables = [
        'description',
        'action',
        'conditions',
        'rule_order',
    ]

    @property
    def name(self):
        return self._values.get('name', None)

    @property
    def description(self):
        return self._values.get('description', None)

    @property
    def policy(self):
        if self._values['policy'] is None:
            return None
        return self._values['policy']


class ApiParameters(Parameters):
    def _remove_internal_keywords(self, resource):
        items = [
            'kind', 'generation', 'selfLink', 'poolReference', 'offset', 'datagroupReference'
        ]
        for item in items:
            try:
                del resource[item]
            except KeyError:
                pass

    @property
    def actions(self):
        result = []
        if self._values['actions'] is None or 'items' not in self._values['actions']:
            return [dict(type='ignore')]
        for item in self._values['actions']['items']:
            action = dict()
            self._remove_internal_keywords(item)
            if 'forward' in item:
                action.update(item)
                action['type'] = 'forward'
                del action['forward']
            elif 'enable' in item:
                action.update(item)
                action['type'] = 'enable'
                del action['enable']
            elif 'disable' in item:
                action.update(item)
                action['type'] = 'disable'
                del action['disable']
            elif 'redirect' in item:
                action.update(item)
                action['type'] = 'redirect'
                del action['redirect']
            elif 'setVariable' in item:
                action.update(item)
                action['type'] = 'set_variable'
                del action['fullPath']
                del action['code']
                del action['expirySecs']
                del action['length']
                del action['port']
                del action['status']
                del action['vlanId']
                del action['timeout']
            elif 'shutdown' in item:
                action.update(item)
                action['type'] = 'reset'
                del action['shutdown']
            elif 'persist' in item:
                action.update(item)
                action['type'] = 'persist'
                del action['persist']
            elif 'remove' in item:
                action.update(item)
                action['type'] = 'remove'
                action.pop('fullPath', None)
                action.pop('code', None)
                action.pop('expirySecs', None)
                action.pop('length', None)
                action.pop('port', None)
                action.pop('status', None)
                action.pop('vlanId', None)
                action.pop('timeout', None)
                action.pop('offset', None)
                del action['remove']
            elif 'insert' in item:
                action.update(item)
                action['type'] = 'insert'
                action.pop('fullPath', None)
                action.pop('code', None)
                action.pop('expirySecs', None)
                action.pop('length', None)
                action.pop('port', None)
                action.pop('status', None)
                action.pop('vlanId', None)
                action.pop('timeout', None)
                action.pop('offset', None)
                del action['insert']
            elif 'replace' in item:
                action.update(item)
                action['type'] = 'replace'
                action.pop('fullPath', None)
                action.pop('code', None)
                action.pop('expirySecs', None)
                action.pop('length', None)
                action.pop('status', None)
                action.pop('vlanId', None)
                action.pop('timeout', None)
                action.pop('offset', None)
                if 'httpConnect' not in action:
                    action.pop('port', None)
                del action['replace']
            result.append(action)
        result = sorted(result, key=lambda x: x['name'])
        return result

    @property
    def conditions(self):
        result = []
        if self._values['conditions'] is None or 'items' not in self._values['conditions']:
            return [dict(type='all_traffic')]
        for item in self._values['conditions']['items']:
            action = dict()
            self._remove_internal_keywords(item)
            if 'httpUri' in item:
                action.update(item)
                action['type'] = 'http_uri'
                del action['httpUri']

                # Converts to common stringiness
                #
                # The tuple set "issubset" check that happens in the Difference
                # engine does not recognize that a u'foo' and 'foo' are equal "enough"
                # to consider them a subset. Therefore, we cast everything here to
                # whatever the common stringiness is.
                if 'values' in action:
                    action['values'] = [str(x) for x in action['values']]
            elif 'httpHost' in item:
                action.update(item)
                action['type'] = 'http_host'
                if 'values' in action:
                    action['values'] = [str(x) for x in action['values']]
                del action['httpHost']
            elif 'httpMethod' in item:
                action.update(item)
                action['type'] = 'http_method'
                if 'values' in action:
                    action['values'] = [str(x) for x in action['values']]
                del action['httpMethod']
            elif 'httpHeader' in item:
                action.update(item)
                action['type'] = 'http_header'
                if 'values' in action:
                    action['values'] = [str(x) for x in action['values']]
                del action['httpHeader']
            elif 'sslExtension' in item:
                action.update(item)
                action['type'] = 'ssl_extension'
                if 'values' in action:
                    action['values'] = [str(x) for x in action['values']]
                del action['sslExtension']
            elif 'tcp' in item:
                action.update(item)
                action['type'] = 'tcp'
                if 'values' in action:
                    action['values'] = [str(x) for x in action['values']]
            result.append(action)
        # Names contains the index in which the rule is at.
        result = sorted(result, key=lambda x: x['name'])
        return result


class ModuleParameters(Parameters):
    @property
    def rule_order(self):
        if self._values['rule_order'] is None:
            return None
        if 0 < self._values['rule_order'] > 4294967295:
            raise F5ModuleError(
                "Specified number is out of valid range, correct range is between 0 and 4294967295."
            )
        return self._values['rule_order']

    @property
    def actions(self):
        result = []
        if self._values['actions'] is None:
            return None
        for idx, item in enumerate(self._values['actions']):
            action = dict()
            if 'name' in item:
                action['name'] = str(item['name'])
            else:
                action['name'] = str(idx)
            if item['type'] == 'forward':
                self._handle_forward_action(action, item)
            elif item['type'] == 'set_variable':
                self._handle_set_variable_action(action, item)
            elif item['type'] == 'enable':
                self._handle_enable_action(action, item)
            if item['type'] == 'disable':
                self._handle_disable_action(action, item)
            elif item['type'] == 'ignore':
                return [dict(type='ignore')]
            elif item['type'] == 'redirect':
                self._handle_redirect_action(action, item)
            elif item['type'] == 'reset':
                self._handle_reset_action(action, item)
                del action['shutdown']
            elif item['type'] == 'persist':
                self._handle_persist_action(action, item)
            elif item['type'] == 'remove':
                self._handle_remove_action(action, item)
            elif item['type'] == 'insert':
                self._handle_insert_action(action, item)
            elif item['type'] == 'replace':
                self._handle_replace_action(action, item)
            result.append(action)
        result = sorted(result, key=lambda x: x['name'])
        return result

    @property
    def conditions(self):
        result = []
        if self._values['conditions'] is None:
            return None
        for idx, item in enumerate(self._values['conditions']):
            action = dict()
            if 'name' in item:
                action['name'] = str(item['name'])
            else:
                action['name'] = str(idx)
            if item['type'] == 'http_uri':
                self._handle_http_uri_condition(action, item)
            elif item['type'] == 'http_method':
                self._handle_http_method_condition(action, item)
            elif item['type'] == 'http_host':
                self._handle_http_host_condition(action, item)
            elif item['type'] == 'http_header':
                self._handle_http_header_condition(action, item)
            elif item['type'] == 'ssl_extension':
                self._handle_ssl_extension_condition(action, item)
            elif item['type'] == 'tcp':
                self._handle_tcp_condition(action, item)
            elif item['type'] == 'all_traffic':
                return [dict(type='all_traffic')]
            result.append(action)
        result = sorted(result, key=lambda x: x['name'])
        return result

    def _handle_http_host_condition(self, action, item):
        options = [
            'host_begins_with_any', 'host_begins_not_with_any', 'host_ends_with_any',
            'host_ends_not_with_any', 'host_is_any', 'host_is_not_any', 'host_contains'
        ]
        action['type'] = 'http_host'

        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'host_begins_with_any', 'host_begins_not_with_any', 'host_ends_with_any', 'host_ends_not_with_any',"
                "'host_is_any', 'host_contains, or 'host_is_not_any' must be specified "
                "when the 'http_uri' type is used."
            )

        if 'host_begins_with_any' in item and item['host_begins_with_any'] is not None:
            if isinstance(item['host_begins_with_any'], list):
                values = item['host_begins_with_any']
            else:
                values = [item['host_begins_with_any']]
            action.update(dict(
                host=True,
                startsWith=True,
                values=values
            ))
        elif 'host_begins_not_with_any' in item and item['host_begins_not_with_any'] is not None:
            if isinstance(item['host_begins_not_with_any'], list):
                values = item['host_begins_not_with_any']
            else:
                values = [item['host_begins_not_with_any']]
            action.update({
                'host': True,
                'startsWith': True,
                'not': True,
                'values': values
            })
        elif 'host_ends_not_with_any' in item and item['host_ends_not_with_any'] is not None:
            if isinstance(item['host_ends_not_with_any'], list):
                values = item['host_ends_not_with_any']
            else:
                values = [item['host_ends_not_with_any']]
            action.update({
                'host': True,
                'endsWith': True,
                'not': True,
                'values': values
            })
        elif 'host_ends_with_any' in item and item['host_ends_with_any'] is not None:
            if isinstance(item['host_ends_with_any'], list):
                values = item['host_ends_with_any']
            else:
                values = [item['host_ends_with_any']]
            action.update(dict(
                host=True,
                endsWith=True,
                values=values
            ))
        elif 'host_is_any' in item and item['host_is_any'] is not None:
            if isinstance(item['host_is_any'], list):
                values = item['host_is_any']
            else:
                values = [item['host_is_any']]
            action.update(dict(
                equals=True,
                host=True,
                values=values
            ))
        elif 'host_is_not_any' in item and item['host_is_not_any'] is not None:
            if isinstance(item['host_is_not_any'], list):
                values = item['host_is_not_any']
            else:
                values = [item['host_is_not_any']]
            action.update({
                'equals': True,
                'host': True,
                'not': True,
                'values': values
            })

        elif 'host_contains' in item and item['host_contains'] is not None:
            if isinstance(item['host_contains'], list):
                values = item['host_contains']
            else:
                values = [item['host_contains']]
            action.update(dict(
                host=True,
                contains=True,
                values=values
            ))

    def _handle_http_method_condition(self, action, item):
        options = ['method_matches_with_any']
        action['type'] = 'http_method'
        event_map = dict(
            proxy_connect='proxyConnect',
            proxy_request='proxyRequest',
            proxy_response='proxyResponse',
            request='request',
            response='response',
        )

        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'method_matches_with_any' must be specified when the 'http_method' type is used."
            )

        if 'event' in item and item['event'] is not None:
            event = event_map.get(item['event'], None)
            if event:
                action[event] = True

        if 'method_matches_with_any' in item and item['method_matches_with_any'] is not None:
            if isinstance(item['method_matches_with_any'], list):
                values = item['method_matches_with_any']
            else:
                values = [item['method_matches_with_any']]
            action.update(dict(
                startsWith=True,
                values=values
            ))

    def _handle_http_uri_condition(self, action, item):
        action['type'] = 'http_uri'
        options = ['path_begins_with_any', 'path_contains', 'path_is_any']

        if all(k not in item for k in options):
            raise F5ModuleError(
                "A 'path_begins_with_any', 'path_contains' or 'path_is_any' must be specified "
                "when the 'http_uri' type is used."
            )

        if 'path_begins_with_any' in item and item['path_begins_with_any'] is not None:
            if isinstance(item['path_begins_with_any'], list):
                values = item['path_begins_with_any']
            else:
                values = [item['path_begins_with_any']]
            action.update(dict(
                path=True,
                startsWith=True,
                values=values
            ))
        elif 'path_contains' in item and item['path_contains'] is not None:
            if isinstance(item['path_contains'], list):
                values = item['path_contains']
            else:
                values = [item['path_contains']]
            action.update(dict(
                path=True,
                contains=True,
                values=values
            ))
        elif 'path_is_any' in item and item['path_is_any'] is not None:
            if isinstance(item['path_is_any'], list):
                values = item['path_is_any']
            else:
                values = [item['path_is_any']]
            action.update(dict(
                path=True,
                equals=True,
                values=values
            ))

    def _handle_tcp_condition(self, action, item):
        options = [
            'address_matches_with_any', 'address_matches_with_datagroup', 'address_matches_with_external_datagroup'
        ]
        event_map = dict(
            client_accepted='clientAccepted',
            proxy_connect='proxyConnect',
            proxy_request='proxyRequest',
            proxy_response='proxyResponse',
            request='request',
            ssl_client_hello='sslClientHello',
            ssl_client_server_hello_send='sslClientServerhelloSend'
        )
        action['type'] = 'tcp'
        if all(k not in item for k in options):
            raise F5ModuleError(
                "A 'address_matches_with_any','address_matches_with_datagroup' or"
                "'address_matches_with_external_datagroup' must be specified when the 'tcp' type is used."
            )
        if 'address_matches_with_any' in item and item['address_matches_with_any'] is not None:
            if isinstance(item['address_matches_with_any'], list):
                values = item['address_matches_with_any']
            else:
                values = [item['address_matches_with_any']]
            action.update(dict(
                address=True,
                matches=True,
                values=values
            ))
        if 'address_matches_with_datagroup' in item and item['address_matches_with_datagroup'] is not None:
            if isinstance(item['address_matches_with_datagroup'], list):
                values = item['address_matches_with_datagroup']
            else:
                values = [item['address_matches_with_datagroup']]
            for value in values:
                action.update(dict(
                    address=True,
                    matches=True,
                    datagroup=fq_name(self.partition, value)
                )
                )
        if 'address_matches_with_external_datagroup' in item and \
                item['address_matches_with_external_datagroup'] is not None:
            if isinstance(item['address_matches_with_external_datagroup'], list):
                values = item['address_matches_with_external_datagroup']
            else:
                values = [item['address_matches_with_external_datagroup']]
            for value in values:
                action.update(dict(
                    address=True,
                    matches=True,
                    datagroup=fq_name(self.partition, value)
                )
                )
        if 'event' in item and item['event'] is not None:
            event = event_map.get(item['event'], None)
            if event:
                action[event] = True

    def _handle_ssl_extension_condition(self, action, item):
        options = [
            'server_name_is_any', 'server_name_is_not_any', 'server_name_contains',
            'server_name_begins_with_any', 'server_name_begins_not_with_any',
            'server_name_ends_with_any', 'server_name_ends_not_with_any',
        ]
        action['type'] = 'ssl_extension'
        if 'server_name_is_any' in item and item['server_name_is_any'] is not None:
            if isinstance(item['server_name_is_any'], list):
                values = item['server_name_is_any']
            else:
                values = [item['server_name_is_any']]
            action.update(dict(
                equals=True,
                serverName=True,
                values=values
            ))
        if 'server_name_is_not_any' in item and item['server_name_is_not_any'] is not None:
            if isinstance(item['server_name_is_not_any'], list):
                values = item['server_name_is_not_any']
            else:
                values = [item['server_name_is_not_any']]
            action.update({
                'equals': True,
                'serverName': True,
                'not': True,
                'values': values
            })
        if 'server_name_begins_with_any' in item and item['server_name_begins_with_any'] is not None:
            if isinstance(item['server_name_begins_with_any'], list):
                values = item['server_name_begins_with_any']
            else:
                values = [item['server_name_begins_with_any']]
            action.update(dict(
                serverName=True,
                startsWith=True,
                values=values
            ))
        if 'server_name_begins_not_with_any' in item and item['server_name_begins_not_with_any'] is not None:
            if isinstance(item['server_name_begins_not_with_any'], list):
                values = item['server_name_begins_not_with_any']
            else:
                values = [item['server_name_begins_not_with_any']]
            action.update({
                'serverName': True,
                'startsWith': True,
                'not': True,
                'values': values
            })
        if 'server_name_ends_with_any' in item and item['server_name_ends_with_any'] is not None:
            if isinstance(item['server_name_ends_with_any'], list):
                values = item['server_name_ends_with_any']
            else:
                values = [item['server_name_ends_with_any']]
            action.update(dict(
                serverName=True,
                endsWith=True,
                values=values
            ))
        if 'server_name_ends_not_with_any' in item and item['server_name_ends_not_with_any'] is not None:
            if isinstance(item['server_name_ends_not_with_any'], list):
                values = item['server_name_ends_not_with_any']
            else:
                values = [item['server_name_ends_not_with_any']]
            action.update({
                'serverName': True,
                'endsWith': True,
                'not': True,
                'values': values
            })
        if 'server_name_contains' in item and item['server_name_contains'] is not None:
            if isinstance(item['server_name_contains'], list):
                values = item['server_name_contains']
            else:
                values = [item['server_name_contains']]
            action.update({
                'serverName': True,
                'contains': True,
                'values': values
            })
        if 'event' not in item:
            raise F5ModuleError(
                "An 'event' must be specified when the 'ssl_extension' condition is used."
            )
        elif 'ssl_client_hello' in item['event']:
            action.update(dict(
                sslClientHello=True
            ))
        elif 'ssl_server_hello' in item['event']:
            action.update(dict(
                sslServerHello=True
            ))

    def _handle_http_header_condition(self, action, item):
        action['type'] = 'http_header'
        options = ['header_is_any']
        event_map = dict(
            proxy_connect='proxyConnect',
            proxy_request='proxyRequest',
            proxy_response='proxyResponse',
            request='request',
            response='response',
        )
        if 'header_name' not in item:
            raise F5ModuleError(
                "An 'header_name' must be specified when the 'http_header' condition is used."
            )
        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'header_is_any' must be specified when the 'http_header' type is used."
            )
        if 'event' in item and item['event'] is not None:
            event = event_map.get(item['event'], None)
            if event:
                action[event] = True

        if 'header_is_any' in item:
            if isinstance(item['header_is_any'], list):
                values = item['header_is_any']
            else:
                values = [item['header_is_any']]

            action.update(dict(
                equals=True,
                tmName=item['header_name'],
                values=values
            ))

    def _handle_forward_action(self, action, item):
        """Handle the nuances of the forwarding type

        Right now there is only a single type of forwarding that can be done. As that
        functionality expands, so-to will the behavior of this, and other, methods.
        Therefore, do not be surprised that the logic here is so rigid. It's deliberate.

        :param action:
        :param item:
        :return:
        """

        event_map = dict(
            client_accepted='clientAccepted',
            proxy_request='proxyRequest',
            request='request',
            ssl_client_hello='sslClientHello',
            ssl_client_server_hello_send='sslClientServerhelloSend'
        )

        action['type'] = 'forward'
        options = ['pool', 'virtual', 'node']
        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'pool' or 'virtual' or 'node' must be specified when the 'forward' type is used."
            )
        if item.get('pool', None):
            action['pool'] = fq_name(self.partition, item['pool'])
        elif item.get('virtual', None):
            action['virtual'] = fq_name(self.partition, item['virtual'])
        elif item.get('node', None):
            action['node'] = item['node']

        if 'event' in item and item['event'] is not None:
            event = event_map.get(item['event'], None)
            if event:
                action[event] = True

    def _handle_set_variable_action(self, action, item):
        """Handle the nuances of the set_variable type

        :param action:
        :param item:
        :return:
        """
        if 'expression' not in item and 'variable_name' not in item:
            raise F5ModuleError(
                "A 'variable_name' and 'expression' must be specified when the 'set_variable' type is used."
            )

        if 'event' in item and item['event'] is not None:
            action[item['event']] = True
        else:
            action['request'] = True
        action.update(dict(
            type='set_variable',
            expression=item['expression'],
            tmName=item['variable_name'],
            setVariable=True,
            tcl=True
        ))

    def _handle_enable_action(self, action, item):
        """Handle the nuances of the enable type

        :param action:
        :param item:
        :return:
        """
        action['type'] = 'enable'
        if 'asm_policy' not in item:
            raise F5ModuleError(
                "An 'asm_policy' must be specified when the 'enable' type is used."
            )
        action.update(dict(
            policy=fq_name(self.partition, item['asm_policy']),
            asm=True
        ))

    def _handle_disable_action(self, action, item):
        """Handle the nuances of the disable type

        :param action:
        :param item:
        :return:
        """

        target_map = dict(
            server_ssl='serverSsl',
            persist='persist',
            asm='asm'
        )
        event_map = dict(
            client_accepted='clientAccepted',
            proxy_connect='proxyConnect',
            proxy_request='proxyRequest',
            proxy_response='proxyResponse',
            request='request',
            server_connected='serverConnected',
        )

        action['type'] = 'disable'
        if 'disable_target' not in item:
            raise F5ModuleError(
                "An 'disable_target' must be specified when the 'enable' type is used."
            )
        if 'event' in item and item['event'] is not None:
            event = event_map.get(item['event'], None)
            if event:
                action[event] = True

        action[target_map[item['disable_target']]] = True

    def _handle_redirect_action(self, action, item):
        """Handle the nuances of the redirect type

        :param action:
        :param item:
        :return:
        """
        action['type'] = 'redirect'
        if 'location' not in item:
            raise F5ModuleError(
                "A 'location' must be specified when the 'redirect' type is used."
            )
        action.update(
            location=item['location'],
            httpReply=True,
        )

    def _handle_reset_action(self, action, item):
        """Handle the nuances of the reset type

        :param action:
        :param item:
        :return:
        """
        event_map = dict(
            client_accepted='clientAccepted',
            proxy_connect='proxyConnect',
            proxy_request='proxyRequest',
            proxy_response='proxyResponse',
            request='request',
            response='response',
            server_connected='serverConnected',
            ssl_client_hello='sslClientHello',
            ssl_client_server_hello_send='sslClientServerhelloSend',
            ssl_server_handshake='sslServerHandshake',
            ssl_server_hello='sslServerHello',
            websocket_request='wsRequest',
            websocket_response='wsResponse'
        )

        action['type'] = 'reset'
        if 'event' not in item:
            raise F5ModuleError(
                "An 'event' must be specified when the 'reset' type is used."
            )
        event = event_map.get(item['event'], None)
        if not event:
            raise F5ModuleError(
                "Invalid event type specified for reset action: {0},"
                "check module documentation for valid event types.".format(item['event'])
            )

        action[event] = True
        action.update({
            'connection': True,
            'shutdown': True
        })

    def _handle_persist_action(self, action, item):
        """Handle the nuances of the persist type

        :param action:
        :param item:
        :return:
        """
        action['type'] = 'persist'
        if 'cookie_insert' not in item:
            raise F5ModuleError(
                "A 'cookie_insert' must be specified when the 'persist' type is used."
            )
        elif 'cookie_expiry' in item:
            action.update(
                cookieInsert=True,
                tmName=item['cookie_insert'],
                expiry=str(item['cookie_expiry'])
            )
        else:
            action.update(
                cookieInsert=True,
                tmName=item['cookie_insert']
            )

    def _handle_remove_action(self, action, item):
        """Handle the nuances of the remove type

        :param action:
        :param item:
        :return:
        """

        action['type'] = 'remove'
        options = ['http_header', 'http_referer', 'http_set_cookie', 'http_cookie']
        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'http_header', 'http_referer', 'http_set_cookie' or 'http_cookie' must be specified when "
                "the 'remove' type is used."
            )
        if 'http_header' in item and item['http_header']:
            if item['http_header']['event'] == 'request':
                action.update(
                    httpHeader=True,
                    tmName=item['http_header']['name'],
                    request=True
                )
            elif item['http_header']['event'] == 'response':
                action.update(
                    httpHeader=True,
                    tmName=item['http_header']['name'],
                    response=True
                )
            else:
                action.update(
                    httpHeader=True,
                    tmName=item['http_header']['name']
                )
        if 'http_referer' in item and item['http_referer']:
            if item['http_referer']['event'] == 'request':
                action.update(
                    httpReferer=True,
                    request=True
                )
            if item['http_referer']['event'] == 'proxy_connect':
                action.update(
                    httpReferer=True,
                    proxyConnect=True
                )
            if item['http_referer']['event'] == 'proxy_request':
                action.update(
                    httpReferer=True,
                    proxyRequest=True
                )
        if 'http_cookie' in item and item['http_cookie']:
            if item['http_cookie']['event'] == 'request':
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    request=True
                )
            elif item['http_cookie']['event'] == 'proxy_connect':
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    proxyConnect=True
                )
            elif item['http_cookie']['event'] == 'proxy_request':
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    proxyRequest=True
                )
            else:
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name']
                )
        if 'http_set_cookie' in item and item['http_set_cookie']:
            action.update(
                httpSetCookie=True,
                tmName=item['http_set_cookie']['name'],
                response=True
            )

    def _handle_insert_action(self, action, item):
        """Handle the nuances of the insert type

        :param action:
        :param item:
        :return:
        """

        action['type'] = 'insert'
        options = ['http_header', 'http_referer', 'http_set_cookie', 'http_cookie']
        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'http_header', 'http_referer', 'http_set_cookie' or 'http_cookie' must be specified when "
                "the 'insert' type is used."
            )

        if 'http_header' in item and item['http_header']:
            if item['http_header']['value'] is None:
                raise F5ModuleError(
                    "The http_header value key is required when action is of type 'insert'."
                )
            if item['http_header']['event'] == 'request':
                action.update(
                    httpHeader=True,
                    tmName=item['http_header']['name'],
                    value=item['http_header']['value'],
                    request=True
                )
            elif item['http_header']['event'] == 'response':
                action.update(
                    httpHeader=True,
                    tmName=item['http_header']['name'],
                    value=item['http_header']['value'],
                    response=True
                )
            else:
                action.update(
                    httpHeader=True,
                    tmName=item['http_header']['name'],
                    value=item['http_header']['value']
                )
        if 'http_referer' in item and item['http_referer']:
            if item['http_referer']['value'] is None:
                raise F5ModuleError(
                    "The http_referer value key is required when action is of type 'insert'."
                )
            if item['http_referer']['event'] == 'request':
                action.update(
                    httpReferer=True,
                    value=item['http_referer']['value'],
                    request=True
                )
            if item['http_referer']['event'] == 'proxy_connect':
                action.update(
                    httpReferer=True,
                    value=item['http_referer']['value'],
                    proxyConnect=True
                )
            if item['http_referer']['event'] == 'proxy_request':
                action.update(
                    httpReferer=True,
                    value=item['http_referer']['value'],
                    proxyRequest=True
                )
        if 'http_cookie' in item and item['http_cookie']:
            if item['http_cookie']['value'] is None:
                raise F5ModuleError(
                    "The http_cookie value key is required when action is of type 'insert'."
                )
            if item['http_cookie']['event'] == 'request':
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    value=item['http_cookie']['value'],
                    request=True
                )
            elif item['http_cookie']['event'] == 'proxy_connect':
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    value=item['http_cookie']['value'],
                    proxyConnect=True
                )
            elif item['http_cookie']['event'] == 'proxy_request':
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    value=item['http_cookie']['value'],
                    proxyRequest=True
                )
            else:
                action.update(
                    httpCookie=True,
                    tmName=item['http_cookie']['name'],
                    value=item['http_cookie']['value']
                )
        if 'http_set_cookie' in item and item['http_set_cookie']:
            if item['http_set_cookie']['value'] is None:
                raise F5ModuleError(
                    "The http_set_cookie value key is required when action is of type 'insert'."
                )
            action.update(
                httpSetCookie=True,
                tmName=item['http_set_cookie']['name'],
                value=item['http_set_cookie']['value'],
                response=True
            )

    def _handle_replace_action(self, action, item):
        """Handle the nuances of the replace type

        :param action:
        :param item:
        :return:
        """

        action['type'] = 'replace'
        options = ['http_header', 'http_referer', 'http_host', 'http_connect', 'http_uri']
        if not any(x for x in options if x in item):
            raise F5ModuleError(
                "A 'http_header', 'http_referer', 'http_host', 'http_connect' or 'http_uri' must be specified when "
                "the 'replace' type is used."
            )
        event_map = dict(
            client_accepted='clientAccepted',
            proxy_connect='proxyConnect',
            proxy_request='proxyRequest',
            proxy_response='proxyResponse',
            request='request',
            response='response',
            server_connected='serverConnected',
            ssl_client_hello='sslClientHello'
        )
        type_map = dict(
            path='path',
            query_string='queryString',
            full_string='value'
        )
        if 'http_header' in item and item['http_header']:
            if item['http_header']['value'] is None:
                raise F5ModuleError(
                    "The http_header value key is required when action is of type 'replace'."
                )
            if item['http_header']['event'] is not None:
                action.update({
                    'httpHeader': True,
                    'tmName': item['http_header']['name'],
                    'value': item['http_header']['value'],
                    event_map[item['http_header']['event']]: True
                })
            else:
                action.update({
                    'httpHeader': True,
                    'tmName': item['http_header']['name'],
                    'value': item['http_header']['value']
                })
        if 'http_referer' in item and item['http_referer']:
            if item['http_referer']['value'] is not None:
                action.update({
                    'httpReferer': True,
                    'value': item['http_referer']['value'],
                    event_map[item['http_referer']['event']]: True
                })
            else:
                action.update({
                    'httpReferer': True,
                    event_map[item['http_referer']['event']]: True
                })
        if 'http_connect' in item and item['http_connect']:
            if item['http_connect']['port'] is None:
                action.update({
                    'httpConnect': True,
                    'host': item['http_connect']['value'],
                    'port': 0,
                    event_map[item['http_connect']['event']]: True
                })
            else:
                action.update({
                    'httpConnect': True,
                    'host': item['http_connect']['value'],
                    'port': item['http_connect']['port'],
                    event_map[item['http_connect']['event']]: True
                })
        if 'http_uri' in item and item['http_uri']:
            if item['http_uri']['event'] is not None:
                action.update({
                    'httpUri': True,
                    type_map[item['http_uri']['type']]: item['http_uri']['value'],
                    event_map[item['http_uri']['event']]: True
                })
            else:
                action.update({
                    'httpUri': True,
                    type_map[item['http_uri']['type']]: item['http_uri']['value'],
                })
        if 'http_host' in item and item['http_host']:
            if item['http_host']['event'] is not None:
                action.update({
                    'httpHost': True,
                    'value': item['http_host']['value'],
                    event_map[item['http_host']['event']]: True
                })
            else:
                action.update({
                    'httpHost': True,
                    'value': item['http_host']['value'],
                })


class Changes(Parameters):
    def to_return(self):
        result = {}
        for returnable in self.returnables:
            try:
                result[returnable] = getattr(self, returnable)
                result = self._filter_params(result)
            except Exception:
                raise
        return result


class ReportableChanges(Changes):
    event_map = dict(
        clientAccepted='client_accepted',
        proxyConnect='proxy_connect',
        proxyRequest='proxy_request',
        proxyResponse='proxy_response',
        request='request',
        response='response',
        serverConnected='server_connected',
        sslClientHello='ssl_client_hello'
    )
    uri_type_map = dict(
        path='path',
        queryString='query_string',
        value='full_string'
    )

    returnables = [
        'description', 'actions', 'conditions'
    ]

    def _map_value(self, item, t=False):
        if not t:
            for k in self.event_map.keys():
                if k in item:
                    return k
        else:
            for k in self.uri_type_map.keys():
                if k in item:
                    return k
        return None

    @property
    def actions(self):
        result = []
        if self._values['actions'] is None:
            return [dict(type='ignore')]
        for item in self._values['actions']:
            action = dict()
            if 'forward' in item:
                action.update(item)
                action['type'] = 'forward'
                del action['forward']
            elif 'replace' in item:
                action.update(item)
                action['type'] = 'replace'
                if 'httpHeader' in item:
                    event = self._map_value(item)
                    if event:
                        http_header = dict(event=self.event_map[event], name=action['tmName'], value=action['value'])
                        action['http_header'] = http_header
                        del action[event]
                    else:
                        http_header = dict(name=action['tmName'], value=action['value'])
                        action['http_header'] = http_header
                    del action['httpHeader']
                    del action['value']
                    del action['tmName']
                if 'httpReferer' in item:
                    event = self._map_value(item)
                    if event:
                        if 'value' in item:
                            http_ref = dict(event=self.event_map[event], value=action['value'])
                            action['http_referer'] = http_ref
                            del action['value']
                        else:
                            http_ref = dict(event=self.event_map[event])
                            action['http_referer'] = http_ref
                        del action[event]
                    else:
                        if 'value' in item:
                            http_ref = dict(event=self.event_map[event], value=action['value'])
                            action['http_referer'] = http_ref
                            del action['value']
                    del action['httpReferer']
                if 'httpConnect' in item:
                    event = self._map_value(item)
                    if event:
                        if 'value' in item and 'port' in item:
                            http_con = dict(event=self.event_map[event], value=action['value'], port=action['item'])
                            action['http_connect'] = http_con
                            del action['value']
                            del action['port']
                        elif 'value' in item and 'port' not in item:
                            http_con = dict(event=self.event_map[event], value=action['value'])
                            action['http_connect'] = http_con
                            del action['value']
                        elif 'value' not in item and 'port' in item:
                            http_con = dict(event=self.event_map[event], port=action['port'])
                            action['http_connect'] = http_con
                            del action['port']
                        else:
                            http_con = dict(event=self.event_map[event])
                            action['http_connect'] = http_con
                        del action[event]
                    else:
                        if 'value' in item and 'port' in item:
                            http_con = dict(value=action['value'], port=action['item'])
                            action['http_connect'] = http_con
                            del action['value']
                            del action['port']
                        elif 'value' in item and 'port' not in item:
                            http_con = dict(value=action['value'])
                            action['http_connect'] = http_con
                            del action['value']
                        elif 'value' not in item and 'port' in item:
                            http_con = dict(port=action['port'])
                            action['http_connect'] = http_con
                            del action['port']
                    del action['httpConnect']
                if 'httpUri' in item:
                    event = self._map_value(item)
                    kind = self._map_value(item, True)
                    if event:
                        http_uri = dict(event=self.event_map[event], type=self.uri_type_map[kind], value=action[kind])
                        action['http_uri'] = http_uri
                        del action[event]
                    else:
                        http_uri = dict(type=self.uri_type_map[kind], value=action[kind])
                        action['http_uri'] = http_uri
                    del action[kind]
                    del action['httpUri']
                if 'httpHost' in item:
                    event = self._map_value(item)
                    if event:
                        http_uri = dict(event=self.event_map[event], value=action['value'])
                        action['http_uri'] = http_uri
                        del action[event]
                    else:
                        http_uri = dict(value=action['value'])
                        action['http_uri'] = http_uri
                    del action['value']
                    del action['httpHost']
            elif 'insert' in item:
                action.update(item)
                action['type'] = 'insert'
                if 'httpHeader' in item:
                    if 'response' in item:
                        http_header = dict(event='response', name=action['tmName'], value=action['value'])
                        action['http_header'] = http_header
                        del action['response']
                    if 'request' in item:
                        http_header = dict(event='request', name=action['tmName'], value=action['value'])
                        action['http_header'] = http_header
                        del action['request']
                    del action['httpHeader']
                    del action['tmName']
                if 'httpReferer' in item:
                    if 'request' in item:
                        http_ref = dict(event='request', value=action['value'])
                        action['http_referer'] = http_ref
                        del action['request']
                    if 'proxyConnect' in item:
                        http_ref = dict(event='proxy_connect', value=action['value'])
                        action['http_referer'] = http_ref
                        del action['proxyConnect']
                    if 'proxyRequest' in item:
                        http_ref = dict(event='proxy_request', value=action['value'])
                        action['http_referer'] = http_ref
                        del action['proxyRequest']
                    del action['httpReferer']
                if 'httpCookie' in item:
                    if 'request' in item:
                        http_cookie = dict(event='request', name=action['tmName'], value=action['value'])
                        action['http_cookie'] = http_cookie
                        del action['request']
                    if 'proxyConnect' in item:
                        http_cookie = dict(event='proxy_connect', name=action['tmName'], value=action['value'])
                        action['http_cookie'] = http_cookie
                        del action['proxyConnect']
                    if 'proxyRequest' in item:
                        http_cookie = dict(event='proxy_request', name=action['tmName'], value=action['value'])
                        action['http_cookie'] = http_cookie
                        del action['proxyRequest']
                    del action['httpCookie']
                    del action['tmName']
                if 'httpSetCookie' in item:
                    http_set_cookie = dict(name=action['tmName'], value=action['value'])
                    action['http_set_cookie'] = http_set_cookie
                    del action['response']
                    del action['value']
                    del action['tmName']
                del action['insert']
                del action['value']
            elif 'remove' in item:
                action.update(item)
                action['type'] = 'remove'
                if 'httpHeader' in item:
                    if 'response' in item:
                        http_header = dict(event='response', name=action['tmName'])
                        action['http_header'] = http_header
                        del action['response']
                    if 'request' in item:
                        http_header = dict(event='request', name=action['tmName'])
                        action['http_header'] = http_header
                        del action['request']
                    del action['httpHeader']
                    del action['tmName']
                if 'httpReferer' in item:
                    if 'request' in item:
                        http_ref = dict(event='request')
                        action['http_referer'] = http_ref
                        del action['request']
                    if 'proxyConnect' in item:
                        http_ref = dict(event='proxy_connect')
                        action['http_referer'] = http_ref
                        del action['proxyConnect']
                    if 'proxyRequest' in item:
                        http_ref = dict(event='proxy_request')
                        action['http_referer'] = http_ref
                        del action['proxyRequest']
                    del action['httpReferer']
                if 'httpCookie' in item:
                    if 'request' in item:
                        http_cookie = dict(event='request', name=action['tmName'])
                        action['http_cookie'] = http_cookie
                        del action['request']
                    if 'proxyConnect' in item:
                        http_cookie = dict(event='proxy_connect', name=action['tmName'])
                        action['http_cookie'] = http_cookie
                        del action['proxyConnect']
                    if 'proxyRequest' in item:
                        http_cookie = dict(event='proxy_request', name=action['tmName'])
                        action['http_cookie'] = http_cookie
                        del action['proxyRequest']
                    del action['httpCookie']
                    del action['tmName']
                if 'httpSetCookie' in item:
                    action['http_set_cookie'] = dict(name=action['tmName'])
                    del action['response']
                    del action['tmName']
                del action['remove']
            elif 'set_variable' in item:
                action.update(item)
                action['type'] = 'set_variable'
                del action['set_variable']
            elif 'enable' in item:
                action.update(item)
                action['type'] = 'enable'
                del action['enable']
            elif 'disable' in item:
                action.update(item)
                action['type'] = 'disable'
                if 'serverSsl' in action and action['serverSsl']:
                    action['disable_target'] = 'server_ssl'
                    del action['serverSsl']
                if 'persist' in action and action['persist']:
                    action['disable_target'] = 'persist'
                    del action['persist']
                if 'asm' in action and action['asm']:
                    action['disable_target'] = 'asm'
                    del action['asm']
                del action['enable']
            elif 'redirect' in item:
                action.update(item)
                action['type'] = 'redirect'
                del action['redirect']
                del action['httpReply']
            elif 'reset' in item:
                action.update(item)
                action['type'] = 'reset'
                del action['connection']
                del action['shutdown']
            elif 'persist' in item:
                action.update(item)
                action['type'] = 'persist'
                action['cookie_insert'] = action['tmName']
                if 'expiry' in item:
                    action['cookie_expiry'] = int(action['expiry'])
                    del action['expiry']
                del action['tmName']
                del action['persist']
                del action['cookieInsert']
            result.append(action)
        result = sorted(result, key=lambda x: x['name'])
        return result

    @property
    def conditions(self):
        result = []
        if self._values['conditions'] is None:
            return [dict(type='all_traffic')]
        for item in self._values['conditions']:
            action = dict()
            if 'httpUri' in item:
                action.update(item)
                action['type'] = 'http_uri'
                del action['httpUri']
            elif 'httpMethod' in item:
                action.update(item)
                action['type'] = 'http_method'
                del action['httpMethod']
            elif 'httpHost' in item:
                action.update(item)
                action['type'] = 'http_host'
                del action['httpHost']
            elif 'httpHeader' in item:
                action.update(item)
                action['type'] = 'http_header'
                action['header_name'] = action['tmName']
                del action['httpHeader']
                del action['tmName']
            elif 'tcp' in item:
                action.update(item)
                action['type'] = 'tcp'
                del action['tcp']
            elif 'sslExtension' in item:
                action.update(item)
                action['type'] = 'ssl_extension'
                del action['sslExtension']
            result.append(action)
        # Names contains the index in which the rule is at.
        result = sorted(result, key=lambda x: x['name'])
        return result


class UsableChanges(Changes):
    @property
    def actions(self):
        if self._values['actions'] is None:
            return None
        result = []
        for action in self._values['actions']:
            if 'type' not in action:
                continue
            if action['type'] == 'forward':
                action['forward'] = True
                del action['type']
            elif action['type'] == 'enable':
                action['enable'] = True
                del action['type']
            elif action['type'] == 'disable':
                action['disable'] = True
                del action['type']
            elif action['type'] == 'set_variable':
                action['setVariable'] = True
                action['tcl'] = True
                del action['type']
            elif action['type'] == 'ignore':
                result = []
                break
            elif action['type'] == 'redirect':
                action['httpReply'] = True
                action['redirect'] = True
                del action['type']
            elif action['type'] == 'reset':
                action['shutdown'] = True
                action['connection'] = True
                del action['type']
            elif action['type'] == 'persist':
                action['persist'] = True
                del action['type']
            elif action['type'] == 'remove':
                action['remove'] = True
                del action['type']
            elif action['type'] == 'insert':
                action['insert'] = True
                del action['type']
            elif action['type'] == 'replace':
                action['replace'] = True
                del action['type']
            result.append(action)
        return result

    @property
    def conditions(self):
        if self._values['conditions'] is None:
            return None
        result = []
        for condition in self._values['conditions']:
            if 'type' not in condition:
                continue
            if condition['type'] == 'http_uri':
                condition['httpUri'] = True
                del condition['type']
            elif condition['type'] == 'http_method':
                condition['httpMethod'] = True
                del condition['type']
            elif condition['type'] == 'http_host':
                condition['httpHost'] = True
                del condition['type']
            elif condition['type'] == 'http_header':
                condition['httpHeader'] = True
            elif condition['type'] == 'tcp':
                condition['tcp'] = True
                del condition['type']
            elif condition['type'] == 'ssl_extension':
                condition['sslExtension'] = True
                del condition['type']
            elif condition['type'] == 'all_traffic':
                result = []
                break
            result.append(condition)
        return result


class Difference(object):
    updatables = [
        'actions', 'conditions', 'description'
    ]

    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    def to_tuple(self, items):
        result = []
        for x in items:
            tmp = [(str(k), str(v)) for k, v in iteritems(x)]
            result += tmp
        return result

    def _diff_complex_items(self, want, have):
        if want == [] and have is None:
            return None
        if want is None:
            return None
        w = self.to_tuple(want)
        h = self.to_tuple(have)
        if set(w).issubset(set(h)):
            return None
        else:
            return want

    @property
    def actions(self):
        if self.want.replace_with is True:
            return self.want.actions
        result = self._diff_complex_items(self.want.actions, self.have.actions)
        actioned = self._compare_complex_actions()
        if self._conditions_missing_default_rule_for_asm(result):
            raise F5ModuleError(
                "Valid options when using an ASM policy in a rule's 'enable' "
                "action include all_traffic, http_uri, or http_host."
            )
        if result is None and actioned is True:
            return self.want.actions
        return result

    @property
    def conditions(self):
        if self.want.replace_with is True:
            return self.want.conditions
        result = self._diff_complex_items(self.want.conditions, self.have.conditions)
        return result

    def _conditions_missing_default_rule_for_asm(self, want_actions):
        if want_actions is None:
            actions = self.have.actions
        else:
            actions = want_actions
        if actions is None:
            return False
        if any(x for x in actions if x['type'] == 'enable'):
            conditions = self._diff_complex_items(self.want.conditions, self.have.conditions)
            if conditions is None:
                return False
            if any(y for y in conditions if y['type'] not in ['all_traffic', 'http_uri', 'http_host', 'tcp']):
                return True
        return False

    def _compare_complex_actions(self):
        types = ['insert', 'remove', 'replace']
        if self.want.actions:
            want = [item for item in self.want.actions if item['type'] in types]
            have = [item for item in self.have.actions if item['type'] in types]
            result = compare_complex_list(want, have)
            if result:
                return True
        return False


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()
        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        if self.draft_exists():
            redraft = True
        else:
            redraft = False
            self._create_existing_policy_draft_on_device()
        self.update_on_device()
        if redraft is False:
            self.publish_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        if self.draft_exists():
            redraft = True
        else:
            redraft = False
            self._create_existing_policy_draft_on_device()
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        if redraft is False:
            self.publish_on_device()
        return True

    def create(self):
        self.should_update()
        if self.module.check_mode:
            return True
        if self.draft_exists():
            redraft = True
        else:
            redraft = False
            self._create_existing_policy_draft_on_device()
        self.create_on_device()
        if redraft is False:
            self.publish_on_device()
        return True

    def exists(self):
        if self.draft_exists():
            uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/{3}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self.want.partition, self.want.policy, sub_path='Drafts'),
                self.want.name
            )
        else:
            uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/{3}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self.want.partition, self.want.policy),
                self.want.name
            )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 404 or 'code' in response and response['code'] == 404:
            return False
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def draft_exists(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.policy, sub_path='Drafts')
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 404 or 'code' in response and response['code'] == 404:
            return False
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def _create_existing_policy_draft_on_device(self):
        params = dict(createDraft=True)
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.policy)
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def publish_on_device(self):
        params = dict(
            name=fq_name(self.want.partition,
                         self.want.policy,
                         sub_path='Drafts'
                         ),
            command="publish"

        )
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.policy, sub_path='Drafts'),
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.policy, sub_path='Drafts'),
            self.want.name
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.policy, sub_path='Drafts'),
            self.want.name
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        if self.draft_exists():
            uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/{3}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self.want.partition, self.want.policy, sub_path='Drafts'),
                self.want.name
            )
        else:
            uri = "https://{0}:{1}/mgmt/tm/ltm/policy/{2}/rules/{3}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self.want.partition, self.want.policy),
                self.want.name
            )
        query = "?expandSubcollections=true"
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            description=dict(),
            actions=dict(
                type='list',
                elements='dict',
                options=dict(
                    type=dict(
                        choices=[
                            'forward',
                            'enable',
                            'ignore',
                            'redirect',
                            'reset',
                            'persist',
                            'set_variable',
                            'remove',
                            'insert',
                            'replace',
                            'disable',
                        ],
                        required=True
                    ),
                    pool=dict(),
                    node=dict(),
                    asm_policy=dict(),
                    virtual=dict(),
                    location=dict(),
                    event=dict(),
                    cookie_insert=dict(),
                    cookie_expiry=dict(type='int'),
                    expression=dict(),
                    variable_name=dict(),
                    disable_target=dict(
                        choices=['server_ssl', 'persist', 'asm']
                    ),
                    http_header=dict(
                        type='dict',
                        options=dict(
                            event=dict(
                                choices=[
                                    'request', 'response', 'proxy_connect',
                                    'proxy_request', 'proxy_response'
                                ],
                                required=True
                            ),
                            name=dict(required=True),
                            value=dict()
                        )
                    ),
                    http_referer=dict(
                        type='dict',
                        options=dict(
                            event=dict(
                                choices=['request', 'proxy_connect', 'proxy_request'],
                                required=True
                            ),
                            value=dict()
                        )
                    ),
                    http_set_cookie=dict(
                        type='dict',
                        options=dict(
                            name=dict(required=True),
                            value=dict()
                        )
                    ),
                    http_cookie=dict(
                        type='dict',
                        options=dict(
                            event=dict(
                                choices=['request', 'proxy_connect', 'proxy_request'],
                                required=True

                            ),
                            name=dict(required=True),
                            value=dict()
                        )
                    ),
                    http_connect=dict(
                        type='dict',
                        options=dict(
                            event=dict(
                                choices=[
                                    'client_accepted', 'proxy_connect', 'proxy_request',
                                    'proxy_response', 'request', 'server_connected', 'ssl_client_hello'
                                ],
                                required=True
                            ),
                            value=dict(
                                required=True
                            ),
                            port=dict(type='int'),
                        )
                    ),
                    http_host=dict(
                        type='dict',
                        options=dict(
                            event=dict(
                                choices=['request', 'proxy_connect', 'proxy_request'],
                                required=True
                            ),
                            value=dict(required=True)
                        )
                    ),
                    http_uri=dict(
                        type='dict',
                        options=dict(
                            event=dict(
                                choices=['request', 'proxy_connect', 'proxy_request'],
                                required=True
                            ),
                            type=dict(
                                choices=['path', 'query_string', 'full_string'],
                                required=True
                            ),
                            value=dict(required=True)
                        ),

                    ),
                ),
                mutually_exclusive=[
                    ['pool', 'asm_policy', 'virtual', 'location', 'cookie_insert', 'node', 'http_header',
                     'http_referer', 'http_set_cookie', 'http_cookie', 'http_uri', 'http_host', 'http_connect',
                     'disable_target'
                     ]
                ]
            ),
            conditions=dict(
                type='list',
                elements='dict',
                options=dict(
                    type=dict(
                        choices=[
                            'http_uri',
                            'http_method',
                            'http_host',
                            'http_header',
                            'ssl_extension',
                            'all_traffic',
                            'tcp'
                        ],
                        required=True
                    ),
                    path_begins_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    path_contains=dict(
                        type='list',
                        elements='str',
                    ),
                    path_is_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_begins_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_begins_not_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_ends_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_ends_not_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_is_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_is_not_any=dict(
                        type='list',
                        elements='str',
                    ),
                    host_contains=dict(
                        type='list',
                        elements='str',
                    ),
                    header_name=dict(),
                    header_is_any=dict(
                        type='list',
                        elements='str',
                    ),
                    method_matches_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_is_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_is_not_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_begins_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_begins_not_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_ends_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_ends_not_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    server_name_contains=dict(
                        type='list',
                        elements='str',
                    ),
                    address_matches_with_any=dict(
                        type='list',
                        elements='str',
                    ),
                    address_matches_with_datagroup=dict(
                        type='list',
                        elements='str',
                    ),
                    address_matches_with_external_datagroup=dict(
                        type='list',
                        elements='str',
                    ),
                    event=dict()
                ),
            ),
            name=dict(required=True),
            policy=dict(required=True),
            rule_order=dict(type='int'),
            replace_with=dict(
                type='bool',
                default='no'
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
