#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, Gaudenz Steinlin <gaudenz.steinlin@cloudscale.ch>
# Copyright: (c) 2019, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: server
short_description: Manages servers on the cloudscale.ch IaaS service
description:
  - Create, update, start, stop and delete servers on the cloudscale.ch IaaS service.
notes:
  - If I(uuid) option is provided, it takes precedence over I(name) for server selection. This allows to update the server's name.
  - If no I(uuid) option is provided, I(name) is used for server selection. If more than one server with this name exists, execution is aborted.
  - Only the I(name) and I(flavor) are evaluated for the update.
  - The option I(force=true) must be given to allow the reboot of existing running servers for applying the changes.
author:
  - Gaudenz Steinlin (@gaudenz)
  - René Moser (@resmo)
  - Denis Krienbühl (@href)
version_added: "1.0.0"
options:
  state:
    description:
      - State of the server.
    choices: [ running, stopped, absent ]
    default: running
    type: str
  name:
    description:
      - Name of the Server.
      - Either I(name) or I(uuid) are required.
    type: str
  uuid:
    description:
      - UUID of the server.
      - Either I(name) or I(uuid) are required.
    type: str
  flavor:
    description:
      - Flavor of the server.
    type: str
  image:
    description:
      - Image used to create the server.
    type: str
  zone:
    description:
      - Zone in which the server resides (e.g. C(lpg1) or C(rma1)).
    type: str
  volume_size_gb:
    description:
      - Initial size of the root volume in GB.
      - This parameter has no effect on existing servers.
      - Use the volume module to change the size of the root volume.
    default: 10
    type: int
  bulk_volume_size_gb:
    description:
      - Size of the bulk storage volume in GB.
      - No bulk storage volume if not set.
    type: int
  ssh_keys:
    description:
       - List of SSH public keys.
       - Use the full content of your .pub file here.
    type: list
    elements: str
  password:
    description:
       - Password for the server.
    type: str
  use_public_network:
    description:
      - Attach a public network interface to the server.
    type: bool
  use_private_network:
    description:
      - Attach a private network interface to the server.
    type: bool
  use_ipv6:
    description:
      - Enable IPv6 on the public network interface.
    default: true
    type: bool
  interfaces:
    description:
      - List of network interface objects specifying the interfaces to be attached to the server.
        See U(https://www.cloudscale.ch/en/api/v1/#interfaces-attribute-specification) for more details.
    type: list
    elements: dict
    version_added: 1.4.0
    suboptions:
      network:
        description:
          - Create a network interface on the network identified by UUID.
            Use 'public' instead of an UUID to attach a public network interface.
            Can be omitted if a subnet is provided under addresses.
        type: str
      addresses:
        description:
          - Attach a private network interface and configure a subnet and/or an IP address.
        type: list
        elements: dict
        suboptions:
          subnet:
            description:
              - UUID of the subnet from which an address will be assigned.
            type: str
          address:
            description:
              - The static IP address of the interface. Use '[]' to avoid assigning an IP address via DHCP.
            type: str
  server_groups:
    description:
      - List of UUID or names of server groups.
    type: list
    elements: str
  user_data:
    description:
      - Cloud-init configuration (cloud-config) data to use for the server.
    type: str
  force:
    description:
      - Allow to stop the running server for updating if necessary.
    default: false
    type: bool
  tags:
    description:
      - Tags assosiated with the servers. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create and start a server with an existing server group (shiny-group)
- name: Start cloudscale.ch server
  cloudscale_ch.cloud.server:
    name: my-shiny-cloudscale-server
    image: debian-10
    flavor: flex-4-4
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    server_groups: shiny-group
    zone: lpg1
    use_private_network: true
    bulk_volume_size_gb: 100
    api_token: xxxxxx

# Start another server in anti-affinity (server group shiny-group)
- name: Start second cloudscale.ch server
  cloudscale_ch.cloud.server:
    name: my-other-shiny-server
    image: ubuntu-16.04
    flavor: flex-8-2
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    server_groups: shiny-group
    zone: lpg1
    api_token: xxxxxx

# Force to update the flavor of a running server
- name: Start cloudscale.ch server
  cloudscale_ch.cloud.server:
    name: my-shiny-cloudscale-server
    image: debian-10
    flavor: flex-8-2
    force: true
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    use_private_network: true
    bulk_volume_size_gb: 100
    api_token: xxxxxx
  register: server1

# Stop the first server
- name: Stop my first server
  cloudscale_ch.cloud.server:
    uuid: '{{ server1.uuid }}'
    state: stopped
    api_token: xxxxxx

# Delete my second server
- name: Delete my second server
  cloudscale_ch.cloud.server:
    name: my-other-shiny-server
    state: absent
    api_token: xxxxxx

# Start a server and wait for the SSH host keys to be generated
- name: Start server and wait for SSH host keys
  cloudscale_ch.cloud.server:
    name: my-cloudscale-server-with-ssh-key
    image: debian-10
    flavor: flex-4-2
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    api_token: xxxxxx
  register: server
  until: server is not failed
  retries: 5
  delay: 2

# Start a server with two network interfaces:
#
#    A public interface with IPv4/IPv6
#    A private interface on a specific private network with an IPv4 address

- name: Start a server with a public and private network interface
  cloudscale_ch.cloud.server:
    name: my-cloudscale-server-with-two-network-interfaces
    image: debian-10
    flavor: flex-4-2
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    api_token: xxxxxx
    interfaces:
      - network: 'public'
      - addresses:
        - subnet: UUID_of_private_subnet

# Start a server with a specific IPv4 address from subnet range
- name: Start a server with a specific IPv4 address from subnet range
  cloudscale_ch.cloud.server:
    name: my-cloudscale-server-with-specific-address
    image: debian-10
    flavor: flex-4-2
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    api_token: xxxxxx
    interfaces:
      - addresses:
        - subnet: UUID_of_private_subnet
          address: 'A.B.C.D'

# Start a server with two network interfaces:
#
#    A public interface with IPv4/IPv6
#    A private interface on a specific private network with no IPv4 address

- name: Start a server with a private network interface and no IP address
  cloudscale_ch.cloud.server:
    name: my-cloudscale-server-with-specific-address
    image: debian-10
    flavor: flex-4-2
    ssh_keys:
      - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    api_token: xxxxxx
    interfaces:
      - network: 'public'
      - network: UUID_of_private_network
        addresses: []
'''

RETURN = '''
href:
  description: API URL to get details about this server
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/servers/cfde831a-4e87-4a75-960f-89b0148aa2cc
uuid:
  description: The unique identifier for this server
  returned: success
  type: str
  sample: cfde831a-4e87-4a75-960f-89b0148aa2cc
name:
  description: The display name of the server
  returned: success
  type: str
  sample: its-a-me-mario.cloudscale.ch
state:
  description: The current status of the server
  returned: success
  type: str
  sample: running
flavor:
  description: The flavor that has been used for this server
  returned: success when not state == absent
  type: dict
  sample: { "slug": "flex-4-2", "name": "Flex-4-2", "vcpu_count": 2, "memory_gb": 4 }
image:
  description: The image used for booting this server
  returned: success when not state == absent
  type: dict
  sample: { "default_username": "ubuntu", "name": "Ubuntu 18.04 LTS", "operating_system": "Ubuntu", "slug": "ubuntu-18.04" }
zone:
  description: The zone used for booting this server
  returned: success when not state == absent
  type: dict
  sample: { 'slug': 'lpg1' }
volumes:
  description: List of volumes attached to the server
  returned: success when not state == absent
  type: list
  sample: [ {"type": "ssd", "device": "/dev/vda", "size_gb": "50"} ]
interfaces:
  description: List of network ports attached to the server
  returned: success when not state == absent
  type: list
  sample: [ { "type": "public", "addresses": [ ... ] } ]
ssh_fingerprints:
  description: A list of SSH host key fingerprints. Will be null until the host keys could be retrieved from the server.
  returned: success when not state == absent
  type: list
  sample: ["ecdsa-sha2-nistp256 SHA256:XXXX", ... ]
ssh_host_keys:
  description: A list of SSH host keys. Will be null until the host keys could be retrieved from the server.
  returned: success when not state == absent
  type: list
  sample: ["ecdsa-sha2-nistp256 XXXXX", ... ]
server_groups:
  description: List of server groups
  returned: success when not state == absent
  type: list
  sample: [ {"href": "https://api.cloudscale.ch/v1/server-groups/...", "uuid": "...", "name": "db-group"} ]
tags:
  description: Tags assosiated with the server.
  returned: success
  type: dict
  sample: { 'project': 'my project' }
'''

from datetime import datetime, timedelta
from time import sleep
from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import (
    AnsibleCloudscaleBase,
    cloudscale_argument_spec,
)

ALLOWED_STATES = ('running',
                  'stopped',
                  'absent',
                  )


class AnsibleCloudscaleServer(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleServer, self).__init__(module)

        # Initialize server dictionary
        self._info = {}

    def _init_server_container(self):
        return {
            'uuid': self._module.params.get('uuid') or self._info.get('uuid'),
            'name': self._module.params.get('name') or self._info.get('name'),
            'state': 'absent',
        }

    def _get_server_info(self, refresh=False):
        if self._info and not refresh:
            return self._info

        self._info = self._init_server_container()

        uuid = self._info.get('uuid')
        if uuid is not None:
            server_info = self._get('servers/%s' % uuid)
            if server_info:
                self._info = self._transform_state(server_info)

        else:
            name = self._info.get('name')
            if name is not None:
                servers = self._get('servers') or []
                matching_server = []
                for server in servers:
                    if server['name'] == name:
                        matching_server.append(server)

                if len(matching_server) == 1:
                    self._info = self._transform_state(matching_server[0])
                elif len(matching_server) > 1:
                    self._module.fail_json(msg="More than one server with name '%s' exists. "
                                           "Use the 'uuid' parameter to identify the server." % name)

        return self._info

    @staticmethod
    def _transform_state(server):
        if 'status' in server:
            server['state'] = server['status']
            del server['status']
        else:
            server['state'] = 'absent'
        return server

    def _wait_for_state(self, states):
        start = datetime.now()
        timeout = self._module.params['api_timeout'] * 2
        while datetime.now() - start < timedelta(seconds=timeout):
            server_info = self._get_server_info(refresh=True)
            if server_info.get('state') in states:
                return server_info
            sleep(1)

        # Timeout succeeded
        if server_info.get('name') is not None:
            msg = "Timeout while waiting for a state change on server %s to states %s. " \
                  "Current state is %s." % (server_info.get('name'), states, server_info.get('state'))
        else:
            name_uuid = self._module.params.get('name') or self._module.params.get('uuid')
            msg = 'Timeout while waiting to find the server %s' % name_uuid

        self._module.fail_json(msg=msg)

    def _start_stop_server(self, server_info, target_state="running", ignore_diff=False):
        actions = {
            'stopped': 'stop',
            'running': 'start',
        }

        server_state = server_info.get('state')
        if server_state != target_state:
            self._result['changed'] = True

            if not ignore_diff:
                self._result['diff']['before'].update({
                    'state': server_info.get('state'),
                })
                self._result['diff']['after'].update({
                    'state': target_state,
                })
            if not self._module.check_mode:
                self._post('servers/%s/%s' % (server_info['uuid'], actions[target_state]))
                server_info = self._wait_for_state((target_state, ))

        return server_info

    def _update_param(self, param_key, server_info, requires_stop=False):
        param_value = self._module.params.get(param_key)
        if param_value is None:
            return server_info

        if 'slug' in server_info[param_key]:
            server_v = server_info[param_key]['slug']
        else:
            server_v = server_info[param_key]

        if server_v != param_value:
            # Set the diff output
            self._result['diff']['before'].update({param_key: server_v})
            self._result['diff']['after'].update({param_key: param_value})

            if server_info.get('state') == "running":
                if requires_stop and not self._module.params.get('force'):
                    self._module.warn("Some changes won't be applied to running servers. "
                                      "Use force=true to allow the server '%s' to be stopped/started." % server_info['name'])
                    return server_info

            # Either the server is stopped or change is forced
            self._result['changed'] = True
            if not self._module.check_mode:

                if requires_stop:
                    self._start_stop_server(server_info, target_state="stopped", ignore_diff=True)

                patch_data = {
                    param_key: param_value,
                }

                # Response is 204: No Content
                self._patch('servers/%s' % server_info['uuid'], patch_data)

                # State changes to "changing" after update, waiting for stopped/running
                server_info = self._wait_for_state(('stopped', 'running'))

        return server_info

    def _get_server_group_ids(self):
        server_group_params = self._module.params['server_groups']
        if not server_group_params:
            return None

        matching_group_names = []
        results = []
        server_groups = self._get('server-groups')
        for server_group in server_groups:
            if server_group['uuid'] in server_group_params:
                results.append(server_group['uuid'])
                server_group_params.remove(server_group['uuid'])

            elif server_group['name'] in server_group_params:
                results.append(server_group['uuid'])
                server_group_params.remove(server_group['name'])
                # Remember the names found
                matching_group_names.append(server_group['name'])

            # Names are not unique, verify if name already found in previous iterations
            elif server_group['name'] in matching_group_names:
                self._module.fail_json(msg="More than one server group with name exists: '%s'. "
                                       "Use the 'uuid' parameter to identify the server group." % server_group['name'])

        if server_group_params:
            self._module.fail_json(msg="Server group name or UUID not found: %s" % ', '.join(server_group_params))

        return results

    def _create_server(self, server_info):
        self._result['changed'] = True
        self.normalize_interfaces_param()

        data = deepcopy(self._module.params)
        for i in ('uuid', 'state', 'force', 'api_timeout', 'api_token', 'api_url'):
            del data[i]
        data['server_groups'] = self._get_server_group_ids()

        self._result['diff']['before'] = self._init_server_container()
        self._result['diff']['after'] = deepcopy(data)
        if not self._module.check_mode:
            self._post('servers', data)
            server_info = self._wait_for_state(('running', ))
        return server_info

    def _update_server(self, server_info):

        previous_state = server_info.get('state')

        # The API doesn't support to update server groups.
        # Show a warning to the user if the desired state does not match.
        desired_server_group_ids = self._get_server_group_ids()
        if desired_server_group_ids is not None:
            current_server_group_ids = [grp['uuid'] for grp in server_info['server_groups']]
            if desired_server_group_ids != current_server_group_ids:
                self._module.warn("Server groups can not be mutated, server needs redeployment to change groups.")

        # Remove interface properties that were not filled out by the user
        self.normalize_interfaces_param()

        # Compare the interfaces as specified by the user, with the interfaces
        # as received by the API. The structures are somewhat different, so
        # they need to be evaluated in detail
        wanted = self._module.params.get('interfaces')
        actual = server_info.get('interfaces')

        try:
            update_interfaces = not self.has_wanted_interfaces(wanted, actual)
        except KeyError as e:
            self._module.fail_json(
                msg="Error checking 'interfaces', missing key: %s" % e.args[0])

        if update_interfaces:
            server_info = self._update_param('interfaces', server_info)

            if not self._result['changed']:
                self._result['changed'] = server_info['interfaces'] != actual

        server_info = self._update_param('flavor', server_info, requires_stop=True)
        server_info = self._update_param('name', server_info)
        server_info = self._update_param('tags', server_info)

        if previous_state == "running":
            server_info = self._start_stop_server(server_info, target_state="running", ignore_diff=True)

        return server_info

    def present_server(self):
        server_info = self._get_server_info()

        if server_info.get('state') != "absent":

            # If target state is stopped, stop before an potential update and force would not be required
            if self._module.params.get('state') == "stopped":
                server_info = self._start_stop_server(server_info, target_state="stopped")

            server_info = self._update_server(server_info)

            if self._module.params.get('state') == "running":
                server_info = self._start_stop_server(server_info, target_state="running")
        else:
            server_info = self._create_server(server_info)
            server_info = self._start_stop_server(server_info, target_state=self._module.params.get('state'))

        return server_info

    def absent_server(self):
        server_info = self._get_server_info()
        if server_info.get('state') != "absent":
            self._result['changed'] = True
            self._result['diff']['before'] = deepcopy(server_info)
            self._result['diff']['after'] = self._init_server_container()
            if not self._module.check_mode:
                self._delete('servers/%s' % server_info['uuid'])
                server_info = self._wait_for_state(('absent', ))
        return server_info

    def has_wanted_interfaces(self, wanted, actual):
        """ Compares the interfaces as specified by the user, with the
        interfaces as reported by the server.

        """

        if len(wanted or ()) != len(actual or ()):
            return False

        def match_interface(spec):

            # First, find the interface that belongs to the spec
            for interface in actual:

                # If we have a public network, only look for the right type
                if spec.get('network') == 'public':
                    if interface['type'] == 'public':
                        break

                # If we have a private network, check the network's UUID
                if spec.get('network') is not None:
                    if interface['type'] == 'private':
                        if interface['network']['uuid'] == spec['network']:
                            break

                # If we only have an addresses block, match all subnet UUIDs
                wanted_subnet_ids = set(
                    a['subnet'] for a in (spec.get('addresses') or ()))

                actual_subnet_ids = set(
                    a['subnet']['uuid'] for a in interface['addresses'])

                if wanted_subnet_ids == actual_subnet_ids:
                    break
            else:
                return False  # looped through everything without match

            # Fail if any of the addresses don't match
            for wanted_addr in (spec.get('addresses') or ()):

                # Unspecified, skip
                if 'address' not in wanted_addr:
                    continue

                addresses = set(a['address'] for a in interface['addresses'])
                if wanted_addr['address'] not in addresses:
                    return False

            # If the wanted address is an empty list, but the actual list is
            # not, the user wants to remove automatically set addresses
            if spec.get('addresses') == [] and interface['addresses'] != []:
                return False

            if interface['addresses'] == [] and spec.get('addresses') != []:
                return False

            return interface

        for spec in wanted:

            # If there is any interface that does not match, clearly not all
            # wanted interfaces are present
            if not match_interface(spec):
                return False

        return True

    def normalize_interfaces_param(self):
        """ Goes through the interfaces parameter and gets it ready to be
        sent to the API. """

        for spec in (self._module.params.get('interfaces') or ()):
            if spec['addresses'] is None:
                del spec['addresses']
            if spec['network'] is None:
                del spec['network']

            for address in (spec.get('addresses') or ()):
                if address['address'] is None:
                    del address['address']
                if address['subnet'] is None:
                    del address['subnet']


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        state=dict(default='running', choices=ALLOWED_STATES),
        name=dict(),
        uuid=dict(),
        flavor=dict(),
        image=dict(),
        zone=dict(),
        volume_size_gb=dict(type='int', default=10),
        bulk_volume_size_gb=dict(type='int'),
        ssh_keys=dict(type='list', elements='str', no_log=False),
        password=dict(no_log=True),
        use_public_network=dict(type='bool'),
        use_private_network=dict(type='bool'),
        use_ipv6=dict(type='bool', default=True),
        interfaces=dict(
            type='list',
            elements='dict',
            options=dict(
                network=dict(type='str'),
                addresses=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        address=dict(type='str'),
                        subnet=dict(type='str'),
                    ),
                ),
            ),
        ),
        server_groups=dict(type='list', elements='str'),
        user_data=dict(),
        force=dict(type='bool', default=False),
        tags=dict(type='dict'),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(
            ['interfaces', 'use_public_network'],
            ['interfaces', 'use_private_network'],
        ),
        required_one_of=(('name', 'uuid'),),
        supports_check_mode=True,
    )

    cloudscale_server = AnsibleCloudscaleServer(module)
    if module.params['state'] == "absent":
        server = cloudscale_server.absent_server()
    else:
        server = cloudscale_server.present_server()

    result = cloudscale_server.get_result(server)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
