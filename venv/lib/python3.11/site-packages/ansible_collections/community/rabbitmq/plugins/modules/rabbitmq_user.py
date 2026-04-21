#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2013, Chatham Financial <oss@chathamfinancial.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: rabbitmq_user
short_description: Manage RabbitMQ users
description:
  - Add or remove users to RabbitMQ and assign permissions
author: Chris Hoffman (@chrishoffman)
options:
  user:
    description:
      - Name of user to add
    type: str
    required: true
    aliases: [username, name]
  password:
    description:
      - Password of user to add.
      - To change the password of an existing user, you must also specify
        C(update_password=always).
    type: str
  tags:
    description:
      - User tags specified as comma delimited.
      - The suggested tags to use are management, policymaker, monitoring and administrator.
    type: str
  permissions:
    description:
      - a list of dicts, each dict contains vhost, configure_priv, write_priv, and read_priv,
        and represents a permission rule for that vhost.
      - This option should be preferable when you care about all permissions of the user.
      - You should use vhost, configure_priv, write_priv, and read_priv options instead
        if you care about permissions for just some vhosts.
    type: list
    elements: dict
    default: []
  vhost:
    description:
      - vhost to apply access privileges.
      - This option will be ignored when permissions option is used.
    type: str
    default: /
  node:
    description:
      - erlang node name of the rabbit we wish to configure
    type: str
    default: rabbit
  configure_priv:
    description:
      - Regular expression to restrict configure actions on a resource
        for the specified vhost.
      - By default all actions are restricted.
      - This option will be ignored when permissions option is used.
    type: str
    default: '^$'
  write_priv:
    description:
      - Regular expression to restrict configure actions on a resource
        for the specified vhost.
      - By default all actions are restricted.
      - This option will be ignored when permissions option is used.
    type: str
    default: '^$'
  read_priv:
    description:
      - Regular expression to restrict configure actions on a resource
        for the specified vhost.
      - By default all actions are restricted.
      - This option will be ignored when permissions option is used.
    type: str
    default: '^$'
  topic_permissions:
    description:
      - A list of dicts, each dict contains vhost, exchange, read_priv and write_priv,
        and represents a topic permission rule for that vhost.
      - By default vhost is C(/) and exchange is C(amq.topic).
      - Supported since RabbitMQ 3.7.0. If RabbitMQ is older and topic_permissions are
        set, the module will fail.
    type: list
    elements: dict
    default: []
    version_added: '1.2.0'
  force:
    description:
      - Deletes and recreates the user.
    type: bool
    default: false
  state:
    description:
      - Specify if user is to be added or removed
    type: str
    default: present
    choices: ['present', 'absent']
  update_password:
    description:
      - C(on_create) will only set the password for newly created users.  C(always) will update passwords if they differ.
    type: str
    default: on_create
    choices: ['on_create', 'always']
  login_protocol:
    description:
      - Specify which TCP/IP protocol will be used.
    type: str
    default: http
    choices: ['http', 'https']
    version_added: '1.3.0'
  login_host:
    description:
      - Hostname of API.
    type: str
    version_added: '1.3.0'
  login_port:
    description:
      - login_port of access from API.
    type: str
    default: '15672'
    version_added: '1.3.0'
  login_user:
    description:
      - Administrator's username the management API.
    type: str
    version_added: '1.3.0'
  login_password:
    description:
      - Login password of the management API.
    type: str
    version_added: '1.3.0'
'''

EXAMPLES = r'''
- name: |-
    Add user to server and assign full access control on / vhost.
    The user might have permission rules for other vhost but you don't care.
  community.rabbitmq.rabbitmq_user:
    user: joe
    password: changeme
    vhost: /
    configure_priv: .*
    read_priv: .*
    write_priv: .*
    state: present

- name: |-
    Add user to server and assign full access control on / vhost.
    The user doesn't have permission rules for other vhosts
  community.rabbitmq.rabbitmq_user:
    user: joe
    password: changeme
    permissions:
      - vhost: /
        configure_priv: .*
        read_priv: .*
        write_priv: .*
    state: present

- name: |-
    Add user to server and assign some topic permissions on / vhost.
    The user doesn't have topic permission rules for other vhosts
  community.rabbitmq.rabbitmq_user:
    user: joe
    password: changeme
    topic_permissions:
      - vhost: /
        exchange: amq.topic
        read_priv: .*
        write_priv: 'prod\\.logging\\..*'
    state: present

- name: Add or Update a user using the API
  community.rabbitmq.rabbitmq_user:
    user: joe
    password: changeme
    tags: monitoring
    login_protocol: https
    login_host: localhost
    login_port: 15672
    login_user: admin
    login_password: changeadmin
    permissions:
          - vhost: /
            configure_priv: .*
            read_priv: .*
            write_priv: .*
    topic_permissions:
      - vhost: /
        exchange: amq.topic
        read_priv: .*
        write_priv: 'prod\\.logging\\..*'
    state: present


- name: Remove a user using the API
  community.rabbitmq.rabbitmq_user:
    user: joe
    password: changeme
    tags: monitoring
    login_protocol: https
    login_host: localhost
    login_port: 15672
    login_user: admin
    login_password: changeadmin
    state: absent

'''

import ansible_collections.community.rabbitmq.plugins.module_utils.version as Version  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402

from ansible.module_utils.six.moves.urllib import parse as urllib_parse

import traceback

REQUESTS_IMP_ERR = None
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    REQUESTS_IMP_ERR = traceback.format_exc()
    HAS_REQUESTS = False

from ansible.module_utils.basic import AnsibleModule  # noqa: E402
from ansible.module_utils.common.collections import count


def normalized_permissions(vhost_permission_list):
    """Older versions of RabbitMQ output permissions with slightly different names.

    In older versions of RabbitMQ, the names of the permissions had the `_priv` suffix, which was removed in versions
    >= 3.7.6. For simplicity we only check the `configure` permission. If it's in the old format then all the other
    ones will be wrong too.
    """
    for vhost_permission in vhost_permission_list:
        if 'configure_priv' in vhost_permission:
            yield {
                'configure': vhost_permission['configure_priv'],
                'read': vhost_permission['read_priv'],
                'write': vhost_permission['write_priv'],
                'vhost': vhost_permission['vhost']
            }
        else:
            yield vhost_permission


def as_permission_dict(vhost_permission_list):
    return dict([(vhost_permission['vhost'], vhost_permission) for vhost_permission
                 in normalized_permissions(vhost_permission_list)])


def as_topic_permission_dict(topic_permission_list):
    return dict([((perm['vhost'], perm['exchange']), perm) for perm
                 in topic_permission_list])


def only(vhost, vhost_permissions):
    return {vhost: vhost_permissions.get(vhost, {})}


def first(iterable):
    return next(iter(iterable))


def treat_permissions_for_api(permissions):
    return {
        "configure": permissions.get('configure') if permissions.get('configure') else '^$',
        "write": permissions.get('write') if permissions.get('write') else '^$',
        "read": permissions.get('read') if permissions.get('read') else '^$'
    }


def treat_topic_permissions_for_api(permissions):
    return {"exchange": permissions.get('exchange'), "write": permissions.get('write'),
            "read": permissions.get('read')}


class RabbitMqUser(object):
    def __init__(self, module, username, password, tags, permissions,
                 topic_permissions, node, bulk_permissions=False,
                 login_protocol=None, login_host=None, login_port=None,
                 login_user=None, login_password=None):
        self.module = module
        self.username = username
        self.password = password or ''
        self.node = node
        self.tags = list() if not tags else tags.replace(' ', '').split(',')
        self.permissions = as_permission_dict(permissions)
        self.topic_permissions = as_topic_permission_dict(topic_permissions)
        self.bulk_permissions = bulk_permissions
        self.login_protocol = login_protocol
        self.login_host = login_host
        self.login_port = login_port
        self.login_user = login_user
        self.login_password = login_password

        self.existing_tags = None
        self.existing_permissions = dict()
        self.existing_topic_permissions = dict()
        if self.login_host is not None:
            self._rabbitmqctl = module.get_bin_path('rabbitmqctl', False)
            self._version = None
        else:
            self._rabbitmqctl = module.get_bin_path('rabbitmqctl', True)
            self._version = self._check_version()

    def _check_version(self):
        """Get the version of the RabbitMQ server."""
        version = self._rabbitmq_version_post_3_7(fail_on_error=False)
        if not version:
            version = self._rabbitmq_version_pre_3_7(fail_on_error=False)
        if not version:
            self.module.fail_json(msg="Could not determine the version of the RabbitMQ server.")
        return version

    def _fail(self, msg, stop_execution=False):
        if stop_execution:
            self.module.fail_json(msg=msg)
        # This is a dummy return to prevent linters from throwing errors.
        return None

    def _rabbitmq_version_post_3_7(self, fail_on_error=False):
        """Use the JSON formatter to get a machine readable output of the version.

        At this point we do not know which RabbitMQ server version we are dealing with and which
        version of `rabbitmqctl` we are using, so we will try to use the JSON formatter and see
        what happens. In some versions of
        """

        def int_list_to_str(ints):
            return ''.join([chr(i) for i in ints])

        rc, output, err = self._exec(['status', '--formatter', 'json'], check_rc=False)
        if rc != 0:
            return self._fail(msg="Could not parse the version of the RabbitMQ server, "
                                  "because `rabbitmqctl status` returned no output.",
                              stop_execution=fail_on_error)
        try:
            status_json = json.loads(output)
            if 'rabbitmq_version' in status_json:
                return Version.StrictVersion(status_json['rabbitmq_version'])
            for application in status_json.get('running_applications', list()):
                if application[0] == 'rabbit':
                    if isinstance(application[1][0], int):
                        return Version.StrictVersion(int_list_to_str(application[2]))
                    else:
                        return Version.StrictVersion(application[1])
            return self._fail(msg="Could not find RabbitMQ version of `rabbitmqctl status` command.",
                              stop_execution=fail_on_error)
        except ValueError as e:
            return self._fail(msg="Could not parse output of `rabbitmqctl status` as JSON: {exc}.".format(exc=repr(e)),
                              stop_execution=fail_on_error)

    def _rabbitmq_version_pre_3_7(self, fail_on_error=False):
        """Get the version of the RabbitMQ Server.

        Before version 3.7.6 the `rabbitmqctl` utility did not support the
        `--formatter` flag, so the output has to be parsed using regular expressions.
        """
        version_reg_ex = r"{rabbit,\"RabbitMQ\",\"([0-9]+\.[0-9]+\.[0-9]+)\"}"
        rc, output, err = self._exec(['status'], check_rc=False)
        if rc != 0:
            if fail_on_error:
                self.module.fail_json(msg="Could not parse the version of the RabbitMQ server, because"
                                          " `rabbitmqctl status` returned no output.")
            else:
                return None
        reg_ex_res = re.search(version_reg_ex, output, re.IGNORECASE)
        if not reg_ex_res:
            return self._fail(msg="Could not parse the version of the RabbitMQ server from the output of "
                                  "`rabbitmqctl status` command: {output}.".format(output=output),
                              stop_execution=fail_on_error)
        try:
            return Version.StrictVersion(reg_ex_res.group(1))
        except ValueError as e:
            return self._fail(msg="Could not parse the version of the RabbitMQ server: {exc}.".format(exc=repr(e)),
                              stop_execution=fail_on_error)

    def _exec(self, args, check_rc=True):
        """Execute a command using the `rabbitmqctl` utility.

        By default the _exec call will cause the module to fail, if the error code is non-zero. If the `check_rc`
        flag is set to False, then the exit_code, stdout and stderr will be returned to the calling function to
        perform whatever error handling it needs.

        :param args: the arguments to pass to the `rabbitmqctl` utility
        :param check_rc: when set to True, fail if the utility's exit code is non-zero
        :return: the output of the command or all the outputs plus the error code in case of error
        """
        cmd = [self._rabbitmqctl, '-q']
        if self.node:
            cmd.extend(['-n', self.node])
        rc, out, err = self.module.run_command(cmd + args)
        if check_rc and rc != 0:
            # check_rc is not passed to the `run_command` method directly to allow for more fine grained checking of
            # error messages returned by `rabbitmqctl`.
            user_error_msg_regex = r"(Only root or .* .* run rabbitmqctl)"
            user_error_msg = re.search(user_error_msg_regex, out)
            if user_error_msg:
                self.module.fail_json(msg="Wrong user used to run the `rabbitmqctl` utility: {err}"
                                      .format(err=user_error_msg.group(1)))
            else:
                self.module.fail_json(msg="rabbitmqctl exited with non-zero code: {err}".format(err=err),
                                      rc=rc, stdout=out)
        return out if check_rc else (rc, out, err)

    def get(self):
        """Retrieves the list of registered users from the node.

        If the user is already present, the node will also be queried for the user's permissions and topic
        permissions.
        If the version of the node is >= 3.7.6 the JSON formatter will be used, otherwise the plaintext will be
        parsed.
        """
        users = dict()
        if self.login_host is not None:
            response = self.request_users_api('GET')
            if response.status_code == 200:
                if isinstance(response.json(), list):
                    users = dict([(user_entry['name'], user_entry['tags']) for user_entry in response.json()])
                else:
                    users = {response.json()['name']: response.json()['tags']}
            elif response.status_code == 404:
                return None
            else:
                self.module.fail_json(
                    msg="Error getting the user",
                    status=response.status_code,
                    details=response.text
                )
        else:
            if self._version >= Version.StrictVersion('3.7.6'):
                users = dict([(user_entry['user'], user_entry['tags'])
                              for user_entry in json.loads(self._exec(['list_users', '--formatter', 'json']))])
            else:
                users = self._exec(['list_users'])

                def process_tags(tags):
                    if not tags:
                        return list()
                    return tags.replace('[', '').replace(']', '').replace(' ', '').strip('\t').split(',')

                users_and_tags = [user_entry.split('\t') for user_entry in users.strip().split('\n')]

                users = dict()
                for user_parts in users_and_tags:
                    users[user_parts[0]] = process_tags(user_parts[1]) if len(user_parts) > 1 else []

        self.existing_tags = users.get(self.username, list())
        self.existing_permissions = self._get_permissions() if self.username in users else dict()
        self.existing_topic_permissions = self._get_topic_permissions() if self.username in users else dict()
        return self.username in users

    def _get_permissions(self):
        """Get permissions of the user from RabbitMQ."""
        if self.login_host is not None:
            try:
                response = requests.get(self.get_permissions_api_url_builder(self.username),
                                        auth=(self.login_user,
                                              self.login_password))
            except requests.exceptions.RequestException as exception:
                msg = ("Error trying to request topic permissions "
                       "of the user %s info in rabbitmq.") % (self.username)
                self.module.fail_json(
                    msg=msg,
                    exception=exception,
                )

            if response.ok or (response.status_code == 204):
                permissions = list()
                for permission in response.json():
                    permissions.append({
                        "vhost": permission.get('vhost'),
                        "configure": permission.get('configure'),
                        "write": permission.get('write'),
                        "read": permission.get('read')
                    })
            elif response.status_code == 404:
                return None
            else:
                self.module.fail_json(
                    msg="Error getting the user",
                    status=response.status_code,
                    details=response.text
                )
        else:
            if self._version >= Version.StrictVersion('3.7.6'):
                permissions = json.loads(self._exec(['list_user_permissions', self.username, '--formatter', 'json']))
            else:
                output = self._exec(['list_user_permissions', self.username]).strip().split('\n')
                perms_out = [perm.split('\t') for perm in output if perm.strip()]
                # Filter out headers from the output of the command in case they are still present
                perms_out = [perm for perm in perms_out if perm != ["vhost", "configure", "write", "read"]]

                permissions = list()
                for vhost, configure, write, read in perms_out:
                    permissions.append(dict(vhost=vhost, configure=configure, write=write, read=read))

        if self.bulk_permissions:
            return as_permission_dict(permissions)
        else:
            return only(first(self.permissions.keys()), as_permission_dict(permissions))

    def _get_topic_permissions(self):
        """Get topic permissions of the user from RabbitMQ."""
        if self.login_host is not None:
            try:
                response = requests.get(self.get_topic_permissions_api_url_builder(self.username),
                                        auth=(self.login_user,
                                              self.login_password))
            except requests.exceptions.RequestException as exception:
                msg = ("Error trying to request permissions "
                       "of the user %s info in rabbitmq.") % (self.username)
                self.module.fail_json(
                    msg=msg,
                    exception=exception,
                )

            if response.ok or (response.status_code == 204):
                permissions = list()
                for permission in response.json():
                    permissions.append({
                        "vhost": permission.get('vhost'),
                        "exchange": permission.get('exchange'),
                        "write": permission.get('write'),
                        "read": permission.get('read')
                    })
                return as_topic_permission_dict(permissions)
            elif response.status_code == 404:
                return None
            else:
                self.module.fail_json(
                    msg="Error getting the user",
                    status=response.status_code,
                    details=response.text
                )
        else:
            if self._version < Version.StrictVersion('3.7.0'):
                return dict()
            if self._version >= Version.StrictVersion('3.7.6'):
                permissions = json.loads(
                    self._exec(['list_user_topic_permissions', self.username, '--formatter', 'json']))
            else:
                output = self._exec(['list_user_topic_permissions', self.username]).strip().split('\n')
                perms_out = [perm.split('\t') for perm in output if perm.strip()]
                permissions = list()
                for vhost, exchange, write, read in perms_out:
                    permissions.append(dict(vhost=vhost, exchange=exchange, write=write, read=read))
            return as_topic_permission_dict(permissions)

    def check_password(self):
        """Return `True` if the user can authenticate successfully."""
        if self.login_host is not None:
            url = "%s://%s:%s/api/whoami" % (
                self.login_protocol,
                self.login_host,
                self.login_port)
            try:
                response = requests.get(url, auth=(self.username, self.password))
            except requests.exceptions.RequestException as exception:
                msg = ("Error trying to request permissions "
                       "of the user %s info in rabbitmq.") % (self.username)
                self.module.fail_json(
                    msg=msg,
                    exception=exception,
                )

            if response.ok or response.json().get('reason') == "Not management user":
                return True
            else:
                return False
        else:
            rc, out, err = self._exec(['authenticate_user', self.username, self.password], check_rc=False)
            return rc == 0

    def add(self):
        if self.login_host is not None:
            data = {"password": self.password, "tags": self.treat_tags_for_api() or ""}
            response = self.request_users_api('PUT', data)

            if not response.ok or (response.status_code == 204):
                msg = ("Error trying to create user %s in rabbitmq. "
                       "Status code '%s'.") % (self.username, response.status_code)
                self.module.fail_json(msg=msg)
        else:
            self._exec(['add_user', self.username, self.password or ''])
            if not self.password:
                self._exec(['clear_password', self.username])

    def delete(self):
        if self.login_host is not None:
            response = self.request_users_api('DELETE')
            if response.status_code != 204:
                msg = ("Error trying to remove user %s in rabbitmq. "
                       "Status code '%s'.") % (self.username, response.status_code)
                self.module.fail_json(msg=msg)
        else:
            self._exec(['delete_user', self.username])

    def change_password(self):
        if self.login_host is not None:
            data = {"password": self.password or "", "tags": self.tags or ""}
            response = self.request_users_api('PUT', data)

            if not response.ok or (response.status_code == 204):
                msg = ("Error trying to set tags for the user %s in rabbitmq. "
                       "Status code '%s'.") % (self.username, response.status_code)
                self.module.fail_json(msg=msg)
            else:
                self.module.fail_json(
                    msg="Error setting tags for the user",
                    status=response.status_code,
                    details=response.text
                )
        else:
            if self.password:
                self._exec(['change_password', self.username, self.password])
            else:
                self._exec(['clear_password', self.username])

    def set_tags(self):
        if self.login_host is not None:
            data = {"password": self.password, "tags": self.treat_tags_for_api() or ""}
            response = self.request_users_api('PUT', data)

            if not response.status_code == 204:
                msg = ("Error trying to set tags for the user %s in rabbitmq. "
                       "Status code '%s'.") % (self.username, response.status_code)
                self.module.fail_json(msg=msg)

        else:
            self._exec(['set_user_tags', self.username] + self.tags)

    def set_permissions(self):
        permissions_to_add = list()
        for vhost, permission_dict in self.permissions.items():
            if permission_dict != self.existing_permissions.get(vhost, {}):
                permissions_to_add.append(permission_dict)
        permissions_to_clear = list()
        for vhost in self.existing_permissions.keys():
            if vhost not in self.permissions:
                permissions_to_clear.append(vhost)

        for vhost in permissions_to_clear:
            if self.login_host is not None:
                response = self.request_permissions_api('DELETE', vhost)
                if response.status_code != 204:
                    msg = ("Error trying to remove permission from user %s in rabbitmq. "
                           "Status code '%s'.") % (self.username, response.status_code)
                    self.module.fail_json(msg=msg)
            else:
                cmd = 'clear_permissions -p {vhost} {username}'.format(username=self.username, vhost=vhost)
                self._exec(cmd.split(' '))
        for permissions in permissions_to_add:
            if self.login_host is not None:
                response = self.request_permissions_api('PUT', permissions.get('vhost'),
                                                        data=treat_permissions_for_api(permissions))
                if response.status_code not in (201, 204):
                    msg = ("Error trying to add permission to user %s in rabbitmq. "
                           "Status code '%s'.") % (self.username, response.status_code)
                    self.module.fail_json(msg=msg)
            else:
                cmd = ('set_permissions -p {vhost} {username} {configure} {write} {read}'
                       .format(username=self.username, **permissions))
                self._exec(cmd.split(' '))
        self.existing_permissions = self._get_permissions()

    def set_topic_permissions(self):
        permissions_to_add = list()
        for vhost_exchange, permission_dict in self.topic_permissions.items():
            if permission_dict != self.existing_topic_permissions.get(vhost_exchange, {}):
                permissions_to_add.append(permission_dict)

        permissions_to_clear = list()
        for vhost_exchange in self.existing_topic_permissions.keys():
            if vhost_exchange not in self.topic_permissions:
                permissions_to_clear.append(vhost_exchange)

        for vhost_exchange in permissions_to_clear:
            vhost, exchange = vhost_exchange
            if self.login_host is not None:
                response = self.request_topic_permissions_api('DELETE', vhost)
                if response.status_code != 204:
                    msg = ("Error trying to remove topic permission from user %s in rabbitmq. "
                           "Status code '%s'.") % (self.username, response.status_code)
                    self.module.fail_json(msg=msg)
            else:
                cmd = ('clear_topic_permissions -p {vhost} {username} {exchange}'
                       .format(username=self.username, vhost=vhost, exchange=exchange))
                self._exec(cmd.split(' '))
        for permissions in permissions_to_add:
            if self.login_host is not None:
                response = self.request_topic_permissions_api('PUT', permissions.get('vhost'),
                                                              data=treat_topic_permissions_for_api(permissions))
                if response.status_code not in (201, 204):
                    msg = ("Error trying to add topic permission to user %s in rabbitmq. "
                           "Status code '%s'.") % (self.username, response.status_code)
                    self.module.fail_json(msg=msg)
            else:
                cmd = ('set_topic_permissions -p {vhost} {username} {exchange} {write} {read}'
                       .format(username=self.username, **permissions))
                self._exec(cmd.split(' '))
        self.existing_topic_permissions = self._get_topic_permissions()

    def has_tags_modifications(self):
        return set(self.tags) != set(self.existing_tags)

    def has_permissions_modifications(self):
        return self.existing_permissions != self.permissions

    def has_topic_permissions_modifications(self):
        return self.existing_topic_permissions != self.topic_permissions

    def users_api_url_builder(self, username):
        return "%s://%s:%s/api/users/%s" % (
            self.login_protocol,
            self.login_host,
            self.login_port,
            # Ensure provided data is safe to use in a URL.
            # https://docs.python.org/3/library/urllib.parse.html#url-quoting
            # NOTE: This will also encode '/' characters, as they are required
            # to be percent encoded in the RabbitMQ management API.
            urllib_parse.quote(username, safe=''),
        )

    def get_permissions_api_url_builder(self, username):
        return "%s://%s:%s/api/users/%s/permissions" % (
            self.login_protocol,
            self.login_host,
            self.login_port,
            # Ensure provided data is safe to use in a URL.
            # https://docs.python.org/3/library/urllib.parse.html#url-quoting
            # NOTE: This will also encode '/' characters, as they are required
            # to be percent encoded in the RabbitMQ management API.
            urllib_parse.quote(username, safe=''),
        )

    def get_topic_permissions_api_url_builder(self, username):
        return "%s://%s:%s/api/users/%s/topic-permissions" % (
            self.login_protocol,
            self.login_host,
            self.login_port,
            # Ensure provided data is safe to use in a URL.
            # https://docs.python.org/3/library/urllib.parse.html#url-quoting
            # NOTE: This will also encode '/' characters, as they are required
            # to be percent encoded in the RabbitMQ management API.
            urllib_parse.quote(username, safe=''),
        )

    def permissions_api_url_builder(self, username, vhost):
        if vhost is None:
            vhost = "/"
        return "%s://%s:%s/api/permissions/%s/%s" % (
            self.login_protocol,
            self.login_host,
            self.login_port,
            # Ensure provided data is safe to use in a URL.
            # https://docs.python.org/3/library/urllib.parse.html#url-quoting
            # NOTE: This will also encode '/' characters, as they are required
            # to be percent encoded in the RabbitMQ management API.
            urllib_parse.quote(vhost, safe=''),
            urllib_parse.quote(username, safe=''),
        )

    def topic_permissions_api_url_builder(self, username, vhost):
        if vhost is None:
            vhost = "/"
        return "%s://%s:%s/api/topic-permissions/%s/%s" % (
            self.login_protocol,
            self.login_host,
            self.login_port,
            # Ensure provided data is safe to use in a URL.
            # https://docs.python.org/3/library/urllib.parse.html#url-quoting
            # NOTE: This will also encode '/' characters, as they are required
            # to be percent encoded in the RabbitMQ management API.
            urllib_parse.quote(vhost, safe=''),
            urllib_parse.quote(username, safe=''),
        )

    def treat_tags_for_api(self):
        return ','.join(tag for tag in self.tags)

    def request_users_api(self, method, data=None):
        try:
            response = requests.request(method, self.users_api_url_builder(self.username),
                                        auth=(self.login_user, self.login_password), json=data)
        except requests.exceptions.RequestException as exception:
            msg = "Error in HTTP request (method %s) for user %s in rabbitmq." % (
                method.lower(),
                self.username,
            )
            self.module.fail_json(msg=msg, exception=exception)
        return response

    def request_permissions_api(self, method, vhost=None, data=None):
        try:
            response = requests.request(method, self.permissions_api_url_builder(self.username, vhost),
                                        auth=(self.login_user, self.login_password), json=data)
        except requests.exceptions.RequestException as exception:
            msg = "Error in HTTP request (method %s) for user's permission %s in rabbitmq." % (
                method.lower(),
                self.username,
            )
            self.module.fail_json(msg=msg, exception=exception)
        return response

    def request_topic_permissions_api(self, method, vhost=None, data=None):
        try:
            response = requests.request(method, self.topic_permissions_api_url_builder(self.username, vhost),
                                        auth=(self.login_user, self.login_password), json=data)
        except requests.exceptions.RequestException as exception:
            msg = "Error in HTTP request (method %s) for topic permission for user %s in rabbitmq." % (
                method.lower(),
                self.username,
            )
            self.module.fail_json(msg=msg, exception=exception)
        return response


def main():
    arg_spec = dict(
        user=dict(required=True, aliases=['username', 'name']),
        password=dict(default=None, no_log=True),
        tags=dict(default=None),
        permissions=dict(default=list(), type='list', elements='dict'),
        vhost=dict(default='/'),
        configure_priv=dict(default='^$'),
        write_priv=dict(default='^$'),
        read_priv=dict(default='^$'),
        topic_permissions=dict(default=list(), type='list', elements='dict'),
        force=dict(default='no', type='bool'),
        state=dict(default='present', choices=['present', 'absent']),
        node=dict(default='rabbit'),
        update_password=dict(default='on_create', choices=['on_create', 'always'], no_log=False),
        login_protocol=dict(type="str", default="http", choices=["http", "https"]),
        login_host=dict(type="str"),
        login_port=dict(type="str", default="15672"),
        login_user=dict(type="str", no_log=True),
        login_password=dict(type="str", no_log=True)
    )
    module = AnsibleModule(
        argument_spec=arg_spec,
        supports_check_mode=False
    )

    username = module.params['user']
    password = module.params['password']
    tags = module.params['tags']
    permissions = module.params['permissions']
    vhost = module.params['vhost']
    configure_priv = module.params['configure_priv']
    write_priv = module.params['write_priv']
    read_priv = module.params['read_priv']
    topic_permissions = module.params['topic_permissions']
    force = module.params['force']
    state = module.params['state']
    node = module.params['node']
    update_password = module.params['update_password']
    login_protocol = module.params['login_protocol']
    login_host = module.params['login_host']
    login_port = module.params['login_port']
    login_user = module.params['login_user']
    login_password = module.params['login_password']

    if permissions:
        vhosts = [permission.get('vhost', '/') for permission in permissions]
        if any(vhost_count > 1 for vhost_count in count(vhosts).values()):
            module.fail_json(msg="Error parsing vhost permissions: You can't "
                                 "have two permission dicts for the same vhost")
        bulk_permissions = True
    else:
        perm = {
            'vhost': vhost,
            'configure_priv': configure_priv,
            'write_priv': write_priv,
            'read_priv': read_priv
        }
        permissions.append(perm)
        bulk_permissions = False

    if topic_permissions:
        vhost_exchanges = [
            (permission.get('vhost', '/'), permission.get('exchange'))
            for permission in topic_permissions
        ]
        if any(ve_count > 1 for ve_count in count(vhost_exchanges).values()):
            module.fail_json(msg="Error parsing vhost topic_permissions: You can't "
                                 "have two topic permission dicts for the same vhost "
                                 "and the same exchange")

    for permission in permissions:
        if not permission['vhost']:
            module.fail_json(msg="Error parsing vhost permissions: You can't "
                                 "have an empty vhost when setting permissions")

    for permission in topic_permissions:
        permission.setdefault('vhost', '/')
        permission.setdefault('exchange', 'amq.topic')
        # Normalize the arguments
        for perm_name in ("read", "write"):
            suffixed_perm_name = "{perm_name}_priv".format(perm_name=perm_name)
            if suffixed_perm_name in permission:
                permission[perm_name] = permission.pop(suffixed_perm_name)

    rabbitmq_user = RabbitMqUser(module, username, password, tags, permissions,
                                 topic_permissions, node,
                                 bulk_permissions=bulk_permissions, login_protocol=login_protocol,
                                 login_host=login_host, login_port=login_port, login_user=login_user,
                                 login_password=login_password)

    result = dict(changed=False, user=username, state=state)
    if rabbitmq_user.get():
        if state == 'absent':
            rabbitmq_user.delete()
            result['changed'] = True
        else:
            if force:
                rabbitmq_user.delete()
                rabbitmq_user.add()
                rabbitmq_user.get()
                result['changed'] = True
            elif update_password == 'always':
                if not rabbitmq_user.check_password():
                    rabbitmq_user.change_password()
                    result['changed'] = True

            if rabbitmq_user.has_tags_modifications():
                rabbitmq_user.set_tags()
                result['changed'] = True

            if rabbitmq_user.has_permissions_modifications():
                rabbitmq_user.set_permissions()
                result['changed'] = True

            if rabbitmq_user.has_topic_permissions_modifications():
                rabbitmq_user.set_topic_permissions()
                result['changed'] = True
    elif state == 'present':
        rabbitmq_user.add()
        rabbitmq_user.set_tags()
        rabbitmq_user.set_permissions()
        rabbitmq_user.set_topic_permissions()
        result['changed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
