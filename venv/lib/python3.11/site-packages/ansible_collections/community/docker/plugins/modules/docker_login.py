#!/usr/bin/python
#
# Copyright (c) 2016 Olaf Kilian <olaf.kilian@symanex.com>
#                    Chris Houseknecht, <house@redhat.com>
#                    James Tanner, <jtanner@redhat.com>
#
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_login
short_description: Log into a Docker registry
description:
  - Provides functionality similar to the C(docker login) command.
  - Authenticate with a docker registry and add the credentials to your local Docker config file respectively the credentials
    store associated to the registry. Adding the credentials to the config files resp. the credential store allows future
    connections to the registry using tools such as Ansible's Docker modules, the Docker CLI and Docker SDK for Python without
    needing to provide credentials.
  - Running in check mode will perform the authentication without updating the config file.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  registry_url:
    description:
      - The registry URL.
    type: str
    default: "https://index.docker.io/v1/"
    aliases:
      - registry
      - url
  username:
    description:
      - The username for the registry account.
      - Required when O(state=present).
    type: str
  password:
    description:
      - The plaintext password for the registry account.
      - Required when O(state=present).
    type: str
  reauthorize:
    description:
      - Refresh existing authentication found in the configuration file.
    type: bool
    default: false
    aliases:
      - reauth
  config_path:
    description:
      - Custom path to the Docker CLI configuration file.
    type: path
    default: ~/.docker/config.json
    aliases:
      - dockercfg_path
  state:
    description:
      - This controls the current state of the user. V(present) will login in a user, V(absent) will log them out.
      - To logout you only need the registry server, which defaults to DockerHub.
      - Before 2.1 you could ONLY log in.
      - Docker does not support 'logout' with a custom config file.
    type: str
    default: 'present'
    choices: ['present', 'absent']

requirements:
  - "Docker API >= 1.25"
author:
  - Olaf Kilian (@olsaki) <olaf.kilian@symanex.com>
  - Chris Houseknecht (@chouseknecht)
"""

EXAMPLES = r"""
---
- name: Log into DockerHub
  community.docker.docker_login:
    username: docker
    password: rekcod

- name: Log into private registry and force re-authorization
  community.docker.docker_login:
    registry_url: your.private.registry.io
    username: yourself
    password: secrets3
    reauthorize: true

- name: Log into DockerHub using a custom config file
  community.docker.docker_login:
    username: docker
    password: rekcod
    config_path: /tmp/.mydockercfg

- name: Log out of DockerHub
  community.docker.docker_login:
    state: absent
"""

RETURN = r"""
login_result:
  description: Result from the login.
  returned: when O(state=present)
  type: dict
  sample: {"serveraddress": "localhost:5000", "username": "testuser"}
"""

import base64
import json
import os
import traceback

from ansible.module_utils.common.text.converters import to_bytes, to_text, to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)
from ansible_collections.community.docker.plugins.module_utils.util import (
    DEFAULT_DOCKER_REGISTRY,
    DockerBaseClass,
)

from ansible_collections.community.docker.plugins.module_utils._api import auth
from ansible_collections.community.docker.plugins.module_utils._api.auth import decode_auth
from ansible_collections.community.docker.plugins.module_utils._api.credentials.errors import CredentialsNotFound
from ansible_collections.community.docker.plugins.module_utils._api.credentials.store import Store
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException


class DockerFileStore(object):
    '''
    A custom credential store class that implements only the functionality we need to
    update the docker config file when no credential helpers is provided.
    '''

    program = "<legacy config>"

    def __init__(self, config_path):
        self._config_path = config_path

        # Make sure we have a minimal config if none is available.
        self._config = dict(
            auths=dict()
        )

        try:
            # Attempt to read the existing config.
            with open(self._config_path, "r") as f:
                config = json.load(f)
        except (ValueError, IOError):
            # No config found or an invalid config found so we'll ignore it.
            config = dict()

        # Update our internal config with what ever was loaded.
        self._config.update(config)

    @property
    def config_path(self):
        '''
        Return the config path configured in this DockerFileStore instance.
        '''

        return self._config_path

    def get(self, server):
        '''
        Retrieve credentials for `server` if there are any in the config file.
        Otherwise raise a `StoreError`
        '''

        server_creds = self._config['auths'].get(server)
        if not server_creds:
            raise CredentialsNotFound('No matching credentials')

        (username, password) = decode_auth(server_creds['auth'])

        return dict(
            Username=username,
            Secret=password
        )

    def _write(self):
        '''
        Write config back out to disk.
        '''
        # Make sure directory exists
        dir = os.path.dirname(self._config_path)
        if not os.path.exists(dir):
            os.makedirs(dir)
        # Write config; make sure it has permissions 0x600
        content = json.dumps(self._config, indent=4, sort_keys=True).encode('utf-8')
        f = os.open(self._config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(f, content)
        finally:
            os.close(f)

    def store(self, server, username, password):
        '''
        Add a credentials for `server` to the current configuration.
        '''

        b64auth = base64.b64encode(
            to_bytes(username) + b':' + to_bytes(password)
        )
        auth = to_text(b64auth)

        # build up the auth structure
        if 'auths' not in self._config:
            self._config['auths'] = dict()

        self._config['auths'][server] = dict(
            auth=auth
        )

        self._write()

    def erase(self, server):
        '''
        Remove credentials for the given server from the configuration.
        '''

        if 'auths' in self._config and server in self._config['auths']:
            self._config['auths'].pop(server)
            self._write()


class LoginManager(DockerBaseClass):

    def __init__(self, client, results):

        super(LoginManager, self).__init__()

        self.client = client
        self.results = results
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.registry_url = parameters.get('registry_url')
        self.username = parameters.get('username')
        self.password = parameters.get('password')
        self.reauthorize = parameters.get('reauthorize')
        self.config_path = parameters.get('config_path')
        self.state = parameters.get('state')

    def run(self):
        '''
        Do the actual work of this task here. This allows instantiation for partial
        testing.
        '''

        if self.state == 'present':
            self.login()
        else:
            self.logout()

    def fail(self, msg):
        self.client.fail(msg)

    def _login(self, reauth):
        if self.config_path and os.path.exists(self.config_path):
            self.client._auth_configs = auth.load_config(
                self.config_path, credstore_env=self.client.credstore_env
            )
        elif not self.client._auth_configs or self.client._auth_configs.is_empty:
            self.client._auth_configs = auth.load_config(
                credstore_env=self.client.credstore_env
            )

        authcfg = self.client._auth_configs.resolve_authconfig(self.registry_url)
        # If we found an existing auth config for this registry and username
        # combination, we can return it immediately unless reauth is requested.
        if authcfg and authcfg.get('username') == self.username and not reauth:
            return authcfg

        req_data = {
            'username': self.username,
            'password': self.password,
            'email': None,
            'serveraddress': self.registry_url,
        }

        response = self.client._post_json(self.client._url('/auth'), data=req_data)
        if response.status_code == 200:
            self.client._auth_configs.add_auth(self.registry_url or auth.INDEX_NAME, req_data)
        return self.client._result(response, json=True)

    def login(self):
        '''
        Log into the registry with provided username/password. On success update the config
        file with the new authorization.

        :return: None
        '''

        self.results['actions'].append("Logged into %s" % (self.registry_url))
        self.log("Log into %s with username %s" % (self.registry_url, self.username))
        try:
            response = self._login(self.reauthorize)
        except Exception as exc:
            self.fail("Logging into %s for user %s failed - %s" % (self.registry_url, self.username, to_native(exc)))

        # If user is already logged in, then response contains password for user
        if 'password' in response:
            # This returns correct password if user is logged in and wrong password is given.
            # So if it returns another password as we passed, and the user did not request to
            # reauthorize, still do it.
            if not self.reauthorize and response['password'] != self.password:
                try:
                    response = self._login(True)
                except Exception as exc:
                    self.fail("Logging into %s for user %s failed - %s" % (self.registry_url, self.username, to_native(exc)))
            response.pop('password', None)
        self.results['login_result'] = response

        self.update_credentials()

    def logout(self):
        '''
        Log out of the registry. On success update the config file.

        :return: None
        '''

        # Get the configuration store.
        store = self.get_credential_store_instance(self.registry_url, self.config_path)

        try:
            store.get(self.registry_url)
        except CredentialsNotFound:
            # get raises an exception on not found.
            self.log("Credentials for %s not present, doing nothing." % (self.registry_url))
            self.results['changed'] = False
            return

        if not self.check_mode:
            store.erase(self.registry_url)
        self.results['changed'] = True

    def update_credentials(self):
        '''
        If the authorization is not stored attempt to store authorization values via
        the appropriate credential helper or to the config file.

        :return: None
        '''

        # Check to see if credentials already exist.
        store = self.get_credential_store_instance(self.registry_url, self.config_path)

        try:
            current = store.get(self.registry_url)
        except CredentialsNotFound:
            # get raises an exception on not found.
            current = dict(
                Username='',
                Secret=''
            )

        if current['Username'] != self.username or current['Secret'] != self.password or self.reauthorize:
            if not self.check_mode:
                store.store(self.registry_url, self.username, self.password)
            self.log("Writing credentials to configured helper %s for %s" % (store.program, self.registry_url))
            self.results['actions'].append("Wrote credentials to configured helper %s for %s" % (
                store.program, self.registry_url))
            self.results['changed'] = True

    def get_credential_store_instance(self, registry, dockercfg_path):
        '''
        Return an instance of docker.credentials.Store used by the given registry.

        :return: A Store or None
        :rtype: Union[docker.credentials.Store, NoneType]
        '''

        credstore_env = self.client.credstore_env

        config = auth.load_config(config_path=dockercfg_path)

        store_name = auth.get_credential_store(config, registry)

        # Make sure that there is a credential helper before trying to instantiate a
        # Store object.
        if store_name:
            self.log("Found credential store %s" % store_name)
            return Store(store_name, environment=credstore_env)

        return DockerFileStore(dockercfg_path)


def main():

    argument_spec = dict(
        registry_url=dict(type='str', default=DEFAULT_DOCKER_REGISTRY, aliases=['registry', 'url']),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
        reauthorize=dict(type='bool', default=False, aliases=['reauth']),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        config_path=dict(type='path', default='~/.docker/config.json', aliases=['dockercfg_path']),
    )

    required_if = [
        ('state', 'present', ['username', 'password']),
    ]

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
    )

    try:
        results = dict(
            changed=False,
            actions=[],
            login_result={}
        )

        manager = LoginManager(client, results)
        manager.run()

        if 'actions' in results:
            del results['actions']
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
