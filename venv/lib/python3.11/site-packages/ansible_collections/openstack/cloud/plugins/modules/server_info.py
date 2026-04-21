#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: server_info
short_description: Retrieve information about one or more compute instances
author: OpenStack Ansible SIG
description:
    - Retrieve information about server instances from OpenStack.
notes:
    - The result contains a list of servers.
options:
  name:
    description:
      - restrict results to servers with names or UUID matching
        this glob expression such as web*.
    aliases: ['server']
    type: str
  detailed:
    description:
      - when true, return additional detail about servers at the expense
        of additional API calls.
    type: bool
    default: 'false'
  filters:
    description: |
      Used for further filtering of results. Either a string containing a
      JMESPath expression or a dictionary of meta data. Elements of the latter
      may, themselves, be dictionaries.
    type: dict
  all_projects:
    description:
      - Whether to list servers from all projects or just the current auth
        scoped project.
    type: bool
    default: 'false'
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Gather information about all 'web*' servers in active state
  openstack.cloud.server_info:
    cloud: devstack
    name: web*
    filters:
      vm_state: active

- name: Filter servers with nested dictionaries
  openstack.cloud.server_info:
    cloud: devstack
    filters:
      metadata:
        key1: value1
        key2: value2
'''

RETURN = '''
servers:
    description: List of servers matching the filters
    elements: dict
    type: list
    returned: always
    contains:
        access_ipv4:
            description: |
                IPv4 address that should be used to access this server.
                May be automatically set by the provider.
            returned: success
            type: str
        access_ipv6:
            description: |
                IPv6 address that should be used to access this
                server. May be automatically set by the provider.
            returned: success
            type: str
        addresses:
            description: |
                A dictionary of addresses this server can be accessed through.
                The dictionary contains keys such as 'private' and 'public',
                each containing a list of dictionaries for addresses of that
                type. The addresses are contained in a dictionary with keys
                'addr' and 'version', which is either 4 or 6 depending on the
                protocol of the IP address.
            returned: success
            type: dict
        admin_password:
            description: |
                When a server is first created, it provides the administrator
                password.
            returned: success
            type: str
        attached_volumes:
            description: |
                A list of an attached volumes. Each item in the list contains
                at least an 'id' key to identify the specific volumes.
            returned: success
            type: list
        availability_zone:
            description: |
                The name of the availability zone this server is a part of.
            returned: success
            type: str
        block_device_mapping:
            description: |
                Enables fine grained control of the block device mapping for an
                instance. This is typically used for booting servers from
                volumes.
            returned: success
            type: str
        compute_host:
            description: |
                The name of the compute host on which this instance is running.
                Appears in the response for administrative users only.
            returned: success
            type: str
        config_drive:
            description: |
                Indicates whether or not a config drive was used for this
                server.
            returned: success
            type: str
        created_at:
            description: Timestamp of when the server was created.
            returned: success
            type: str
        description:
            description: |
                The description of the server. Before microversion
                2.19 this was set to the server name.
            returned: success
            type: str
        disk_config:
            description: The disk configuration. Either AUTO or MANUAL.
            returned: success
            type: str
        flavor:
            description: The flavor property as returned from server.
            returned: success
            type: dict
        flavor_id:
            description: |
                The flavor reference, as a ID or full URL, for the flavor to
                use for this server.
            returned: success
            type: str
        has_config_drive:
            description: |
                Indicates whether a configuration drive enables metadata
                injection. Not all cloud providers enable this feature.
            returned: success
            type: str
        host_id:
            description: An ID representing the host of this server.
            returned: success
            type: str
        host_status:
            description: The host status.
            returned: success
            type: str
        hostname:
            description: |
                The hostname set on the instance when it is booted.
                By default, it appears in the response for administrative users
                only.
            returned: success
            type: str
        hypervisor_hostname:
            description: |
                The hypervisor host name. Appears in the response for
                administrative users only.
            returned: success
            type: str
        id:
            description: ID of the server.
            returned: success
            type: str
        image:
            description: The image property as returned from server.
            returned: success
            type: dict
        image_id:
            description: |
                The image reference, as a ID or full URL, for the image to use
                for this server.
            returned: success
            type: str
        instance_name:
            description: |
                The instance name. The Compute API generates the instance name
                from the instance name template. Appears in the response for
                administrative users only.
            returned: success
            type: str
        is_locked:
            description: The locked status of the server
            returned: success
            type: bool
        kernel_id:
            description: |
                The UUID of the kernel image when using an AMI. Will be null if
                not. By default, it appears in the response for administrative
                users only.
            returned: success
            type: str
        key_name:
            description: The name of an associated keypair.
            returned: success
            type: str
        launch_index:
            description: |
                When servers are launched via multiple create, this is the
                sequence in which the servers were launched. By default, it
                appears in the response for administrative users only.
            returned: success
            type: int
        launched_at:
            description: The timestamp when the server was launched.
            returned: success
            type: str
        links:
            description: |
                A list of dictionaries holding links relevant to this server.
            returned: success
            type: str
        max_count:
            description: The maximum number of servers to create.
            returned: success
            type: str
        metadata:
            description: List of tag strings.
            returned: success
            type: dict
        min_count:
            description: The minimum number of servers to create.
            returned: success
            type: str
        name:
            description: Name of the server
            returned: success
            type: str
        networks:
            description: |
                A networks object. Required parameter when there are multiple
                networks defined for the tenant. When you do not specify the
                networks parameter, the server attaches to the only network
                created for the current tenant.
            returned: success
            type: str
        power_state:
            description: The power state of this server.
            returned: success
            type: str
        progress:
            description: |
                While the server is building, this value represents the
                percentage of completion. Once it is completed, it will be 100.
            returned: success
            type: int
        project_id:
            description: The ID of the project this server is associated with.
            returned: success
            type: str
        ramdisk_id:
            description: |
                The UUID of the ramdisk image when using an AMI. Will be null
                if not. By default, it appears in the response for
                administrative users only.
            returned: success
            type: str
        reservation_id:
            description: |
                The reservation id for the server. This is an id that can be
                useful in tracking groups of servers created with multiple
                create, that will all have the same reservation_id. By default,
                it appears in the response for administrative users only.
            returned: success
            type: str
        root_device_name:
            description: |
                The root device name for the instance By default, it appears in
                the response for administrative users only.
            returned: success
            type: str
        scheduler_hints:
            description: The dictionary of data to send to the scheduler.
            returned: success
            type: dict
        security_groups:
            description: |
                A list of applicable security groups. Each group contains keys
                for: description, name, id, and rules.
            returned: success
            type: list
            elements: dict
        server_groups:
            description: |
                The UUIDs of the server groups to which the server belongs.
                Currently this can contain at most one entry.
            returned: success
            type: list
        status:
            description: |
                The state this server is in. Valid values include 'ACTIVE',
                'BUILDING', 'DELETED', 'ERROR', 'HARD_REBOOT', 'PASSWORD',
                'PAUSED', 'REBOOT', 'REBUILD', 'RESCUED', 'RESIZED',
                'REVERT_RESIZE', 'SHUTOFF', 'SOFT_DELETED', 'STOPPED',
                'SUSPENDED', 'UNKNOWN', or 'VERIFY_RESIZE'.
            returned: success
            type: str
        tags:
            description:  A list of associated tags.
            returned: success
            type: list
        task_state:
            description: The task state of this server.
            returned: success
            type: str
        terminated_at:
            description: |
                The timestamp when the server was terminated (if it has been).
            returned: success
            type: str
        trusted_image_certificates:
            description: |
                A list of trusted certificate IDs, that were used during image
                signature verification to verify the signing certificate.
            returned: success
            type: list
        updated_at:
            description: Timestamp of when this server was last updated.
            returned: success
            type: str
        user_data:
            description: |
                Configuration information or scripts to use upon launch.
                Base64 encoded.
            returned: success
            type: str
        user_id:
            description: The ID of the owners of this server.
            returned: success
            type: str
        vm_state:
            description: The VM state of this server.
            returned: success
            type: str
        volumes:
            description: Same as attached_volumes.
            returned: success
            type: list
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ServerInfoModule(OpenStackModule):

    argument_spec = dict(
        name=dict(aliases=['server']),
        detailed=dict(type='bool', default=False),
        filters=dict(type='dict'),
        all_projects=dict(type='bool', default=False),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['detailed', 'filters', 'all_projects']
                      if self.params[k] is not None)
        kwargs['name_or_id'] = self.params['name']

        self.exit(changed=False,
                  servers=[server.to_dict(computed=False)
                           if hasattr(server, "to_dict") else server
                           for server in
                           self.conn.search_servers(**kwargs)])


def main():
    module = ServerInfoModule()
    module()


if __name__ == '__main__':
    main()
