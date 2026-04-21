#!/usr/bin/python
# coding: utf-8
#
# Copyright (c) 2021 Red Hat | Ansible Sakar Mehra<@sakarmehra100@gmail.com | @sakar97>
# Copyright (c) 2019, Vladimir Porshkevich (@porshkevich) <neosonic@mail.ru>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_plugin
short_description: Manage Docker plugins
version_added: 1.3.0
description:
  - This module allows to install, delete, enable and disable Docker plugins.
  - Performs largely the same function as the C(docker plugin) CLI subcommand.
notes:
  - The C(--grant-all-permissions) CLI flag is true by default in this module.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  idempotent:
    support: full

options:
  plugin_name:
    description:
      - Name of the plugin to operate on.
    required: true
    type: str

  state:
    description:
      - V(absent) remove the plugin.
      - V(present) install the plugin, if it does not already exist.
      - V(enable) enable the plugin.
      - V(disable) disable the plugin.
    default: present
    choices:
      - absent
      - present
      - enable
      - disable
    type: str

  alias:
    description:
      - Local name for plugin.
    type: str
    version_added: 1.8.0

  plugin_options:
    description:
      - Dictionary of plugin settings.
    type: dict
    default: {}

  force_remove:
    description:
      - Remove even if the plugin is enabled.
    default: false
    type: bool

  enable_timeout:
    description:
      - Timeout in seconds.
    type: int
    default: 0

author:
  - Sakar Mehra (@sakar97)
  - Vladimir Porshkevich (@porshkevich)

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Install a plugin
  community.docker.docker_plugin:
    plugin_name: plugin_one
    state: present

- name: Remove a plugin
  community.docker.docker_plugin:
    plugin_name: plugin_one
    state: absent

- name: Enable the plugin
  community.docker.docker_plugin:
    plugin_name: plugin_one
    state: enable

- name: Disable the plugin
  community.docker.docker_plugin:
    plugin_name: plugin_one
    state: disable

- name: Install a plugin with options
  community.docker.docker_plugin:
    plugin_name: weaveworks/net-plugin:latest_release
    plugin_options:
      IPALLOC_RANGE: "10.32.0.0/12"
      WEAVE_PASSWORD: "PASSWORD"
"""

RETURN = r"""
plugin:
  description:
    - Plugin inspection results for the affected plugin.
  returned: success
  type: dict
  sample: {}
actions:
  description:
    - List of actions performed during task execution.
  returned: when O(state) is not V(absent)
  type: list
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException
)

from ansible_collections.community.docker.plugins.module_utils.util import (
    DockerBaseClass,
    DifferenceTracker,
)

from ansible_collections.community.docker.plugins.module_utils._api import auth
from ansible_collections.community.docker.plugins.module_utils._api.errors import APIError, DockerException, NotFound


class TaskParameters(DockerBaseClass):
    def __init__(self, client):
        super(TaskParameters, self).__init__()
        self.client = client
        self.plugin_name = None
        self.alias = None
        self.plugin_options = None
        self.debug = None
        self.force_remove = None
        self.enable_timeout = None

        for key, value in client.module.params.items():
            setattr(self, key, value)


def prepare_options(options):
    return ['%s=%s' % (k, v if v is not None else "") for k, v in options.items()] if options else []


def parse_options(options_list):
    return dict(x.split('=', 1) for x in options_list) if options_list else {}


class DockerPluginManager(object):

    def __init__(self, client):
        self.client = client

        self.parameters = TaskParameters(client)
        self.preferred_name = self.parameters.alias or self.parameters.plugin_name
        self.check_mode = self.client.check_mode
        self.diff = self.client.module._diff
        self.diff_tracker = DifferenceTracker()
        self.diff_result = dict()

        self.actions = []
        self.changed = False

        self.existing_plugin = self.get_existing_plugin()

        state = self.parameters.state
        if state == 'present':
            self.present()
        elif state == 'absent':
            self.absent()
        elif state == 'enable':
            self.enable()
        elif state == 'disable':
            self.disable()

        if self.diff or self.check_mode or self.parameters.debug:
            if self.diff:
                self.diff_result['before'], self.diff_result['after'] = self.diff_tracker.get_before_after()
            self.diff = self.diff_result

    def get_existing_plugin(self):
        try:
            return self.client.get_json('/plugins/{0}/json', self.preferred_name)
        except NotFound:
            return None
        except APIError as e:
            self.client.fail(to_native(e))

    def has_different_config(self):
        """
        Return the list of differences between the current parameters and the existing plugin.

        :return: list of options that differ
        """
        differences = DifferenceTracker()
        if self.parameters.plugin_options:
            settings = self.existing_plugin.get('Settings')
            if not settings:
                differences.add('plugin_options', parameter=self.parameters.plugin_options, active=settings)
            else:
                existing_options = parse_options(settings.get('Env'))

                for key, value in self.parameters.plugin_options.items():
                    if ((not existing_options.get(key) and value) or
                            not value or
                            value != existing_options[key]):
                        differences.add('plugin_options.%s' % key,
                                        parameter=value,
                                        active=existing_options.get(key))

        return differences

    def install_plugin(self):
        if not self.existing_plugin:
            if not self.check_mode:
                try:
                    # Get privileges
                    headers = {}
                    registry, repo_name = auth.resolve_repository_name(self.parameters.plugin_name)
                    header = auth.get_config_header(self.client, registry)
                    if header:
                        headers['X-Registry-Auth'] = header
                    privileges = self.client.get_json('/plugins/privileges', params={'remote': self.parameters.plugin_name}, headers=headers)
                    # Pull plugin
                    params = {
                        'remote': self.parameters.plugin_name,
                    }
                    if self.parameters.alias:
                        params['name'] = self.parameters.alias
                    response = self.client._post_json(self.client._url('/plugins/pull'), params=params, headers=headers, data=privileges, stream=True)
                    self.client._raise_for_status(response)
                    for data in self.client._stream_helper(response, decode=True):
                        pass
                    # Inspect and configure plugin
                    self.existing_plugin = self.client.get_json('/plugins/{0}/json', self.preferred_name)
                    if self.parameters.plugin_options:
                        data = prepare_options(self.parameters.plugin_options)
                        self.client.post_json('/plugins/{0}/set', self.preferred_name, data=data)
                except APIError as e:
                    self.client.fail(to_native(e))

            self.actions.append("Installed plugin %s" % self.preferred_name)
            self.changed = True

    def remove_plugin(self):
        force = self.parameters.force_remove
        if self.existing_plugin:
            if not self.check_mode:
                try:
                    self.client.delete_call('/plugins/{0}', self.preferred_name, params={'force': force})
                except APIError as e:
                    self.client.fail(to_native(e))

            self.actions.append("Removed plugin %s" % self.preferred_name)
            self.changed = True

    def update_plugin(self):
        if self.existing_plugin:
            differences = self.has_different_config()
            if not differences.empty:
                if not self.check_mode:
                    try:
                        data = prepare_options(self.parameters.plugin_options)
                        self.client.post_json('/plugins/{0}/set', self.preferred_name, data=data)
                    except APIError as e:
                        self.client.fail(to_native(e))
                self.actions.append("Updated plugin %s settings" % self.preferred_name)
                self.changed = True
        else:
            self.client.fail("Cannot update the plugin: Plugin does not exist")

    def present(self):
        differences = DifferenceTracker()
        if self.existing_plugin:
            differences = self.has_different_config()

        self.diff_tracker.add('exists', parameter=True, active=self.existing_plugin is not None)

        if self.existing_plugin:
            self.update_plugin()
        else:
            self.install_plugin()

        if self.diff or self.check_mode or self.parameters.debug:
            self.diff_tracker.merge(differences)

        if not self.check_mode and not self.parameters.debug:
            self.actions = None

    def absent(self):
        self.remove_plugin()

    def enable(self):
        timeout = self.parameters.enable_timeout
        if self.existing_plugin:
            if not self.existing_plugin.get('Enabled'):
                if not self.check_mode:
                    try:
                        self.client.post_json('/plugins/{0}/enable', self.preferred_name, params={'timeout': timeout})
                    except APIError as e:
                        self.client.fail(to_native(e))
                self.actions.append("Enabled plugin %s" % self.preferred_name)
                self.changed = True
        else:
            self.install_plugin()
            if not self.check_mode:
                try:
                    self.client.post_json('/plugins/{0}/enable', self.preferred_name, params={'timeout': timeout})
                except APIError as e:
                    self.client.fail(to_native(e))
            self.actions.append("Enabled plugin %s" % self.preferred_name)
            self.changed = True

    def disable(self):
        if self.existing_plugin:
            if self.existing_plugin.get('Enabled'):
                if not self.check_mode:
                    try:
                        self.client.post_json('/plugins/{0}/disable', self.preferred_name)
                    except APIError as e:
                        self.client.fail(to_native(e))
                self.actions.append("Disable plugin %s" % self.preferred_name)
                self.changed = True
        else:
            self.client.fail("Plugin not found: Plugin does not exist.")

    @property
    def result(self):
        plugin_data = {}
        if self.parameters.state != 'absent':
            try:
                plugin_data = self.client.get_json('/plugins/{0}/json', self.preferred_name)
            except NotFound:
                # This can happen in check mode
                pass
        result = {
            'actions': self.actions,
            'changed': self.changed,
            'diff': self.diff,
            'plugin': plugin_data,
        }
        return dict((k, v) for k, v in result.items() if v is not None)


def main():
    argument_spec = dict(
        alias=dict(type='str'),
        plugin_name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent', 'enable', 'disable']),
        plugin_options=dict(type='dict', default={}),
        debug=dict(type='bool', default=False),
        force_remove=dict(type='bool', default=False),
        enable_timeout=dict(type='int', default=0),
    )
    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        cm = DockerPluginManager(client)
        client.module.exit_json(**cm.result)
    except DockerException as e:
        client.fail('An unexpected docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
