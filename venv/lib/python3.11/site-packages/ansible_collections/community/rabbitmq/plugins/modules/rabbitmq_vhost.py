#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2013, Chatham Financial <oss@chathamfinancial.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rabbitmq_vhost
short_description: Manage the state of a virtual host in RabbitMQ
description:
  - Manage the state of a virtual host in RabbitMQ using rabbitmqctl or REST APIs.
author: Chris Hoffman (@chrishoffman)
options:
  name:
    description:
      - The name of the vhost to manage
    type: str
    required: true
    aliases: [vhost]
  node:
    description:
      - erlang node name of the rabbit we wish to configure
    type: str
    default: rabbit
  tracing:
    description:
      - Enable/disable tracing for a vhost
    type: bool
    default: false
    aliases: [trace]
  state:
    description:
      - The state of vhost
    type: str
    default: present
    choices: [present, absent]
  login_user:
      description:
          - RabbitMQ user for connection.
      type: str
      version_added: '1.5.0'
  login_password:
      description:
          - RabbitMQ password for connection.
      type: str
      version_added: '1.5.0'
  login_host:
      description:
          - RabbitMQ host for connection.
      type: str
      version_added: '1.5.0'
  login_port:
      description:
          - RabbitMQ management API port.
      type: str
      default: '15672'
      version_added: '1.5.0'
  login_protocol:
      description:
          - RabbitMQ management API protocol.
      type: str
      choices: [ http , https ]
      default: http
      version_added: '1.5.0'
  ca_cert:
      description:
          - CA certificate to verify SSL connection to management API.
      type: path
      version_added: '1.5.0'
  client_cert:
      description:
          - Client certificate to send on SSL connections to management API.
      type: path
      version_added: '1.5.0'
  client_key:
      description:
          - Private key matching the client certificate.
      type: path
      version_added: '1.5.0'
"""

EXAMPLES = r"""
- name: Ensure that the vhost /test exists.
  community.rabbitmq.rabbitmq_vhost:
    name: /test
    state: present

- name: Ensure that the vhost /test exists using REST APIs.
  community.rabbitmq.rabbitmq_vhost:
    name: /test
    state: present
    login_host: localhost
    login_user: admin
    login_password: changeadmin
"""

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.six.moves.urllib import parse as urllib_parse

REQUESTS_IMP_ERR = None
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    REQUESTS_IMP_ERR = traceback.format_exc()
    HAS_REQUESTS = False


class RabbitMqVhost(object):
    def __init__(
        self,
        module,
        name,
        tracing,
        node,
        login_user,
        login_password,
        login_host,
        login_port,
        login_protocol,
        ca_cert,
        client_cert,
        client_key,
    ):
        self.module = module
        self.name = name
        self.tracing = tracing
        self.node = node
        self.login_user = login_user
        self.login_password = login_password
        self.login_host = login_host
        self.login_port = login_port
        self.login_protocol = login_protocol
        self.verify = ca_cert
        self.cert = client_cert
        self.key = client_key

        self._tracing = False
        require_rabbitmqctl = self.login_host is None
        self._rabbitmqctl = module.get_bin_path("rabbitmqctl", require_rabbitmqctl)

    def _exec(self, args, force_exec_in_check_mode=False):
        if not self.module.check_mode or (
            self.module.check_mode and force_exec_in_check_mode
        ):
            cmd = [self._rabbitmqctl, "-q", "-n", self.node]
            rc, out, err = self.module.run_command(cmd + args, check_rc=True)
            return out.splitlines()
        return list()

    def get(self):
        if self.login_host is not None:
            response = self._request_vhost_api("get")

            if response.ok:
                self._tracing = response.json()["tracing"]
                return True
            elif response.status_code == 404:
                return False
            else:
                self.module.fail_json(
                    msg="Error getting the vhost",
                    status=response.status_code,
                    details=response.text,
                )
        else:
            vhosts = self._exec(["list_vhosts", "name", "tracing"], True)

            for vhost in vhosts:
                if "\t" not in vhost:
                    continue

                name, tracing = vhost.split("\t")
                if name == self.name:
                    self._tracing = self.module.boolean(tracing)
                    return True
            return False

    def add(self):
        if self.login_host is not None:
            response = self._request_vhost_api("put")

            if response is not None and not response.ok:
                msg = (
                    "Error trying to create vhost %s in rabbitmq. " "Status code '%s'."
                ) % (self.name, response.status_code)
                self.module.fail_json(msg=msg)
        else:
            return self._exec(["add_vhost", self.name])

    def delete(self):
        if self.login_host is not None:
            response = self._request_vhost_api("delete")

            if response is not None and not response.ok:
                msg = (
                    "Error trying to remove vhost %s in rabbitmq. " "Status code '%s'."
                ) % (self.name, response.status_code)
                self.module.fail_json(msg=msg)
        else:
            return self._exec(["delete_vhost", self.name])

    def set_tracing(self):
        if self.tracing != self._tracing:
            if self.tracing:
                self._enable_tracing()
            else:
                self._disable_tracing()
            return True
        return False

    def _enable_tracing(self):
        if self.login_host is not None:
            response = self._request_vhost_api("put", data={"tracing": True})

            if response is not None and not response.ok:
                msg = (
                    "Error trying to enable tracing on vhost %s in rabbitmq. "
                    "Status code '%s'."
                ) % (self.name, response.status_code)
                self.module.fail_json(msg=msg)
        else:
            return self._exec(["trace_on", "-p", self.name])

    def _disable_tracing(self):
        if self.login_host is not None:
            response = self._request_vhost_api("put", data={"tracing": False})

            if response is not None and not response.ok:
                msg = (
                    "Error trying to disable tracing on vhost %s in rabbitmq. "
                    "Status code '%s'."
                ) % (self.name, response.status_code)
                self.module.fail_json(msg=msg)
        else:
            return self._exec(["trace_off", "-p", self.name])

    def _request_vhost_api(self, method, data=None):
        if self.module.check_mode and method != "get":
            return None
        try:
            url = "%s://%s:%s/api/vhosts/%s" % (
                self.login_protocol,
                self.login_host,
                self.login_port,
                # Ensure provided data is safe to use in a URL.
                # https://docs.python.org/3/library/urllib.parse.html#url-quoting
                # NOTE: This will also encode '/' characters, as they are required
                # to be percent encoded in the RabbitMQ management API.
                urllib_parse.quote(self.name, safe=''),
            )
            response = requests.request(
                method=method,
                url=url,
                auth=(self.login_user, self.login_password),
                verify=self.verify,
                cert=(self.cert, self.key),
                json=data,
            )

        except requests.exceptions.RequestException as exception:
            msg = "Error in HTTP request (method %s) for user %s in rabbitmq." % (
                method,
                self.login_user,
            )
            self.module.fail_json(msg=msg, exception=exception)

        return response


def main():
    arg_spec = dict(
        name=dict(required=True, aliases=["vhost"]),
        tracing=dict(default="off", aliases=["trace"], type="bool"),
        state=dict(default="present", choices=["present", "absent"]),
        node=dict(default="rabbit"),
        login_user=dict(type="str", no_log=True),
        login_password=dict(type="str", no_log=True),
        login_host=dict(type="str"),
        login_port=dict(type="str", default="15672"),
        login_protocol=dict(type="str", default="http", choices=["http", "https"]),
        ca_cert=dict(type="path"),
        client_cert=dict(type="path"),
        client_key=dict(type="path"),
    )

    module = AnsibleModule(argument_spec=arg_spec, supports_check_mode=True)

    name = module.params["name"]
    tracing = module.params["tracing"]
    state = module.params["state"]
    node = module.params["node"]
    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    login_host = module.params["login_host"]
    login_port = module.params["login_port"]
    login_protocol = module.params["login_protocol"]
    ca_cert = module.params["ca_cert"]
    client_cert = module.params["client_cert"]
    client_key = module.params["client_key"]

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMP_ERR)

    result = dict(changed=False, name=name, state=state)
    rabbitmq_vhost = RabbitMqVhost(
        module,
        name,
        tracing,
        node,
        login_user,
        login_password,
        login_host,
        login_port,
        login_protocol,
        ca_cert,
        client_cert,
        client_key,
    )

    if rabbitmq_vhost.get():
        if state == "absent":
            rabbitmq_vhost.delete()
            result["changed"] = True
        else:
            if rabbitmq_vhost.set_tracing():
                result["changed"] = True
    elif state == "present":
        rabbitmq_vhost.add()
        rabbitmq_vhost.set_tracing()
        result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
