#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2013, John Dewey <john@dewey.ws>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: rabbitmq_policy
short_description: Manage the state of policies in RabbitMQ
description:
  - Manage the state of a policy in RabbitMQ using rabbitmqctl or REST APIs.
author: John Dewey (@retr0h)
options:
  name:
    description:
      - The name of the policy to manage.
    type: str
    required: true
  vhost:
    description:
      - The name of the vhost to apply to.
    type: str
    default: /
  apply_to:
    description:
      - What the policy applies to. Requires RabbitMQ 3.2.0 or later. For classic_queues,
        quorum_queues and streams RabbitMQ 3.12 or later is required
    type: str
    default: all
    choices: [all, exchanges, queues, classic_queues, quorum_queues, streams]
  pattern:
    description:
      - A regex of queues to apply the policy to. Required when
        C(state=present). This option is no longer required as of Ansible 2.9.
    type: str
    required: false
    default: null
  tags:
    description:
      - A dict or string describing the policy. Required when
        C(state=present). This option is no longer required as of Ansible 2.9.
    type: dict
    required: false
    default: null
  priority:
    description:
      - The priority of the policy.
    type: str
    default: '0'
  node:
    description:
      - Erlang node name of the rabbit we wish to configure.
    type: str
    default: rabbit
  state:
    description:
      - The state of the policy.
    type: str
    default: present
    choices: [present, absent]
  login_user:
      description:
          - RabbitMQ user for connection.
      type: str
      version_added: '1.6.0'
  login_password:
      description:
          - RabbitMQ password for connection.
      type: str
      version_added: '1.6.0'
  login_host:
      description:
          - RabbitMQ host for connection.
      type: str
      version_added: '1.6.0'
  login_port:
      description:
          - RabbitMQ management API port.
      type: str
      default: '15672'
      version_added: '1.6.0'
  login_protocol:
      description:
          - RabbitMQ management API protocol.
      type: str
      choices: [ http , https ]
      default: http
      version_added: '1.6.0'
  ca_cert:
      description:
          - CA certificate to verify SSL connection to management API.
      type: path
      version_added: '1.6.0'
  client_cert:
      description:
          - Client certificate to send on SSL connections to management API.
      type: path
      version_added: '1.6.0'
  client_key:
      description:
          - Private key matching the client certificate.
      type: path
      version_added: '1.6.0'
'''

EXAMPLES = r'''
- name: Ensure the default vhost contains the HA policy via a dict
  community.rabbitmq.rabbitmq_policy:
    name: HA
    pattern: .*
  args:
    tags:
      ha-mode: all

- name: Ensure the default vhost contains the HA policy
  community.rabbitmq.rabbitmq_policy:
    name: HA
    pattern: .*
    tags:
      ha-mode: all

- name: Ensure the default vhost contains the HA policy using REST APIs.
  community.rabbitmq.rabbitmq_policy:
    name: HA
    pattern: .*
    login_host: localhost
    login_user: admin
    login_password: changeadmin
    tags:
      ha-mode: all
'''

import json
import re
import traceback

from ansible_collections.community.rabbitmq.plugins.module_utils.version import LooseVersion as Version
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.six.moves.urllib import parse as urllib_parse

REQUESTS_IMP_ERR = None
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    REQUESTS_IMP_ERR = traceback.format_exc()
    HAS_REQUESTS = False


class RabbitMqPolicy(object):

    def __init__(self, module, name):
        self._module = module
        self._name = name
        self._vhost = module.params['vhost']
        self._pattern = module.params['pattern']
        self._apply_to = module.params['apply_to']
        self._tags = module.params['tags']
        self._priority = module.params['priority']
        self._node = module.params['node']

        # API parameters.
        self._login_user = module.params['login_user']
        self._login_password = module.params['login_password']
        self._login_host = module.params['login_host']
        self._login_port = module.params['login_port']
        self._login_protocol = module.params['login_protocol']
        self._verify = module.params['ca_cert']
        self._cert = module.params['client_cert']
        self._key = module.params['client_key']

        require_rabbitmqctl = self._login_host is None
        self._rabbitmqctl = module.get_bin_path('rabbitmqctl', require_rabbitmqctl)
        self._version = self._rabbit_version()

    def _exec(self,
              args,
              force_exec_in_check_mode=False,
              split_lines=True,
              add_vhost=True):
        if (not self._module.check_mode
                or (self._module.check_mode and force_exec_in_check_mode)):
            cmd = [self._rabbitmqctl, '-q', '-n', self._node]

            if add_vhost:
                args.insert(1, '-p')
                args.insert(2, self._vhost)

            rc, out, err = self._module.run_command(cmd + args, check_rc=True)
            if split_lines:
                return out.splitlines()

            return out
        return list()

    def _request_policy_api(self, method, vhost=None, name=None, data=None):
        # Check if the vhost and name should be defined.
        if method in ['put', 'delete']:
            if vhost is None:
                msg = "Error in HTTP request (method %s) for (endpoint policies), user %s. vhost must be defined." % (
                    method,
                    self._login_user,
                )
                self._module.fail_json(msg=msg)
                return None
            if name is None:
                msg = "Error in HTTP request (method %s) for (endpoint policies), user %s. name must be defined." % (
                    method,
                    self._login_user,
                )
                self._module.fail_json(msg=msg)
                return None

        policies_endpoint = ['policies']
        if vhost:
            # Ensure provided data is safe to use in a URL.
            # https://docs.python.org/3/library/urllib.parse.html#url-quoting
            # NOTE: This will also encode '/' characters, as they are required
            # to be percent encoded in the RabbitMQ management API.
            policies_endpoint.append(urllib_parse.quote(vhost, safe=''))
            if name:
                policies_endpoint.append(name)
        return self._request_api(method, endpoint='/'.join(policies_endpoint), data=data)

    def _request_overview(self):
        return self._request_api('get', 'overview')

    def _request_api(self, method, endpoint, data=None):
        if self._module.check_mode and method != "get":
            return None

        # TODO: verify the endpoint is supported.
        try:
            url = "%s://%s:%s/api/%s" % (
                self._login_protocol,
                self._login_host,
                self._login_port,
                endpoint,
            )
            response = requests.request(
                method=method,
                url=url,
                auth=(self._login_user, self._login_password),
                verify=self._verify,
                cert=(self._cert, self._key),
                json=data,
            )

        except requests.exceptions.RequestException as exception:
            msg = "Error in HTTP request (method %s) for endpoint %s, user %s in rabbitmq." % (
                method,
                endpoint,
                self._login_user,
            )
            self._module.fail_json(msg=msg, exception=exception)

        return response

    def _rabbit_version(self):
        if self._login_host is not None:
            response = self._request_overview()

            if response is not None and not response.ok:
                msg = (
                    "Error trying to retrieve rabbitmq version. "
                    "Status code '%s'."
                ) % (response.status_code)
                self._module.fail_json(msg=msg)
                return None

            return Version(response.json()['rabbitmq_version'])
        else:
            status = self._exec(['status'], True, False, False)

        # 3.7.x erlang style output
        version_match = re.search('{rabbit,".*","(?P<version>.*)"}', status)
        if version_match:
            return Version(version_match.group('version'))

        # 3.8.x style ouput
        version_match = re.search('RabbitMQ version: (?P<version>.*)', status)
        if version_match:
            return Version(version_match.group('version'))

        return None

    def _list_policies(self):
        if self._login_host is not None:
            response = self._request_policy_api('get', self._vhost)

            if response is not None and not response.ok:
                msg = (
                    "Error trying to retrieve policies on vhost %s in rabbitmq. "
                    "Status code '%s'."
                ) % (self._vhost, response.status_code)
                self._module.fail_json(msg=msg)
                return None

            # PARSE THE RESPONSE DATA.
            # The response data is a json list with field names. The logic of the code expects tab delimited strings.
            policy_response = response.json()
            self._module.debug(f'[list_policies] {json.dumps(policy_response)}')
            policies = []
            if self._version and self._version >= Version('3.7.0'):
                for policy in policy_response:
                    policies.append("%s\t%s\t%s\t%s\t%s\t%s" % (
                        policy['vhost'], policy['name'], policy['pattern'], policy['apply-to'], json.dumps(policy['definition']), policy['priority']))
            else:
                # Prior to 3.7.0, the apply-to & pattern fields were swapped.
                for policy in policy_response:
                    policies.append("%s\t%s\t%s\t%s\t%s\t%s" % (
                        policy['vhost'], policy['name'], policy['apply-to'], policy['pattern'], json.dumps(policy['definition']), policy['priority']))
            return policies

        else:
            if self._version and self._version >= Version('3.7.9'):
                # Remove first header line from policies list for version > 3.7.9
                return self._exec(['list_policies'], True)[1:]

            return self._exec(['list_policies'], True)

    def has_modifications(self):
        if self._pattern is None or self._tags is None:
            self._module.fail_json(
                msg=('pattern and tags are required for '
                     'state=present'))

        if self._version and self._version >= Version('3.7.0'):
            # Change fields order in rabbitmqctl output in version 3.7
            return not any(
                self._policy_check(policy, apply_to_fno=3, pattern_fno=2)
                for policy in self._list_policies())
        else:
            return not any(
                self._policy_check(policy) for policy in self._list_policies())

    def should_be_deleted(self):
        return any(
            self._policy_check_by_name(policy)
            for policy in self._list_policies())

    def set(self):
        if self._login_host is not None:
            policy = {
                "vhost": self._vhost,
                "name": self._name,
                "pattern": self._pattern,
                "apply-to": self._apply_to,
                "definition": self._tags,
                "priority": int(self._priority)  # Priority must be a number.
            }
            self._module.debug(f'[set_policy] {json.dumps(policy)}')
            response = self._request_policy_api('put', self._vhost, self._name, data=policy)

            if response is not None and not response.ok:
                msg = (
                    "Error trying to set policy %s in rabbitmq. "
                    "Response %s\n"
                ) % (self._name, response.text)
                self._module.fail_json(msg=msg)
        else:
            args = ['set_policy']
            args.append(self._name)
            args.append(self._pattern)
            args.append(json.dumps(self._tags))
            args.append('--priority')
            args.append(self._priority)
            if self._apply_to != 'all':
                args.append('--apply-to')
                args.append(self._apply_to)
            return self._exec(args)

    def clear(self):
        if self._login_host is not None:
            response = self._request_policy_api('delete', self._vhost, self._name)

            if response is not None and not response.ok:
                msg = (
                    "Error trying to remove policy %s in rabbitmq. "
                    "Status code '%s'."
                ) % (self._name, response.status_code)
                self._module.fail_json(msg=msg)
        else:
            return self._exec(['clear_policy', self._name])

    def _policy_check(self,
                      policy,
                      name_fno=1,
                      apply_to_fno=2,
                      pattern_fno=3,
                      tags_fno=4,
                      priority_fno=5):
        if not policy:
            return False

        policy_data = policy.split('\t')

        policy_name = policy_data[name_fno]
        apply_to = policy_data[apply_to_fno]
        pattern = policy_data[pattern_fno].replace('\\\\', '\\')

        try:
            tags = json.loads(policy_data[tags_fno])
        except json.decoder.JSONDecodeError:
            tags = policy_data[tags_fno]

        priority = policy_data[priority_fno]

        return (policy_name == self._name and apply_to == self._apply_to
                and tags == self._tags and priority == self._priority
                and pattern == self._pattern)

    def _policy_check_by_name(self, policy):
        if not policy:
            return False

        policy_name = policy.split('\t')[1]

        return policy_name == self._name


def main():
    arg_spec = dict(
        name=dict(required=True),
        vhost=dict(default='/'),
        pattern=dict(required=False, default=None),
        apply_to=dict(default='all', choices=['all', 'exchanges', 'queues', 'classic_queues', 'quorum_queues', 'streams']),
        tags=dict(type='dict', required=False, default=None),
        priority=dict(default='0'),
        node=dict(default='rabbit'),
        state=dict(default='present', choices=['present', 'absent']),
        # API Params.
        login_user=dict(type="str", no_log=True),
        login_password=dict(type="str", no_log=True),
        login_host=dict(type="str"),
        login_port=dict(type="str", default="15672"),
        login_protocol=dict(type="str", default="http", choices=["http", "https"]),
        ca_cert=dict(type="path"),
        client_cert=dict(type="path"),
        client_key=dict(type="path"),
    )

    module = AnsibleModule(
        argument_spec=arg_spec,
        supports_check_mode=True
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMP_ERR)

    name = module.params['name']
    state = module.params['state']
    rabbitmq_policy = RabbitMqPolicy(module, name)

    result = dict(changed=False, name=name, state=state)

    if state == 'present' and rabbitmq_policy.has_modifications():
        rabbitmq_policy.set()
        result['changed'] = True
    elif state == 'absent' and rabbitmq_policy.should_be_deleted():
        rabbitmq_policy.clear()
        result['changed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
