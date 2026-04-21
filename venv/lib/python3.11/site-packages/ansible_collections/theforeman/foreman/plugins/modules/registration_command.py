#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) Evgeni Golov
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: registration_command
version_added: 4.0.0
short_description: Manage Registration Command
description:
  - Manage Registration Command
author:
  - "Evgeni Golov (@evgeni)"
options:
  activation_keys:
    description:
    - Activation keys for subscription-manager client, required for CentOS and Red Hat
      Enterprise Linux.
    - Required only if host group has no activation keys.
    required: false
    type: list
    elements: str
  force:
    description:
    - "Clear any previous registration and run C(subscription-manager) with C(--force)."
    required: false
    type: bool
  hostgroup:
    description:
    - Host group to register the host in.
    required: false
    type: str
  ignore_subman_errors:
    description:
    - Ignore C(subscription-manager) errors for C(subscription-manager register) command.
    required: false
    type: bool
  insecure:
    description:
    - Enable insecure argument for the initial C(curl).
    required: false
    type: bool
  jwt_expiration:
    description:
    - Expiration of the authorization token (in hours).
    required: false
    type: int
  lifecycle_environment:
    description:
    - Lifecycle environment for the host.
    - "Deprecated: The Lifecycle Environment of a Host should be set by the Activation Key."
    - Removed from the API since Katello 4.12.
    required: false
    type: str
  operatingsystem:
    description:
    - Operating System to register the host in.
    - Operating system must have a C(host_init_config) template assigned.
    required: false
    type: str
  packages:
    description:
    - Packages to install on the host when registered.
    - Multiple packages are to be given as a space delimited string.
    required: false
    type: str
  remote_execution_interface:
    description:
    - Identifier of the Host interface for Remote execution.
    required: false
    type: str
  repo:
    description:
    - Repository URL (yum/dnf) or full sources.list entry (apt).
    required: false
    type: str
  repo_gpg_key_url:
    description:
    - URL of the GPG key for the repository.
    required: false
    type: str
  setup_insights:
    description:
    - If this is set to C(true), C(insights-client) will be installed
      and registered on Red Hat family operating systems.
    required: false
    type: bool
  setup_remote_execution:
    description:
    - If this is set to true, SSH keys will be installed on the host.
    required: false
    type: bool
  setup_remote_execution_pull:
    description:
    - If this is set to true, pull provider client will be deployed on the host.
    required: false
    type: bool
  smart_proxy:
    description:
    - Name of Smart Proxy.
    - This Proxy must have both the C(Templates) and C(Registration) features enabled.
    required: false
    type: str
  update_packages:
    description:
    - Update all packages on the host.
    required: false
    type: bool
  organization:
    description:
      - Organization to register the host in.
    required: false
    type: str
  location:
    description:
      - Location to register the host in.
    required: false
    type: str

extends_documentation_fragment:
  - theforeman.foreman.foreman
'''

EXAMPLES = '''
# This needs to run on a host with API access
- name: "Generate registration command"
  theforeman.foreman.registration_command:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
  register: command
  delegate_to: localhost

# This needs to run on the host being registered
- name: "Perform registration"
  ansible.builtin.shell:
    cmd: "{{ command.registration_command }}"
'''

RETURN = '''
registration_command:
  description: The generated registration command.
  returned: success
  type: str
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanAnsibleModule


class ForemanRegistrationCommandModule(ForemanAnsibleModule):
    pass


def main():
    module = ForemanRegistrationCommandModule(
        foreman_spec=dict(
            hostgroup=dict(type='entity'),
            operatingsystem=dict(type='entity'),
            smart_proxy=dict(type='entity'),
            setup_insights=dict(type='bool'),
            setup_remote_execution=dict(type='bool'),
            jwt_expiration=dict(type='int'),
            insecure=dict(type='bool'),
            packages=dict(type='str'),
            update_packages=dict(type='bool'),
            repo=dict(type='str'),
            repo_gpg_key_url=dict(type='str', no_log=False),
            remote_execution_interface=dict(type='str'),
            setup_remote_execution_pull=dict(type='bool'),
            activation_keys=dict(type='list', elements='str', no_log=False),
            lifecycle_environment=dict(type='entity'),
            force=dict(type='bool'),
            ignore_subman_errors=dict(type='bool'),
            organization=dict(type='entity'),
            location=dict(type='entity'),
        ),
        required_plugins=[
            ('katello', ['activation_key', 'activation_keys', 'lifecycle_environment', 'ignore_subman_errors', 'force']),
            ('remote_execution', ['remote_execution_interface', 'setup_remote_execution_pull']),
        ],
    )

    with module.api_connection():
        module.auto_lookup_entities()
        if not module.check_mode:
            command = module.ensure_entity('registration_commands', module.foreman_params, None, state='present')['registration_command']
        else:
            command = "curl | bash"
        module.exit_json(registration_command=command)


if __name__ == '__main__':
    main()
