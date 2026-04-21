#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016, Mario Santos <mario.rf.santos@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: server_metadata
short_description: Add/Update/Delete Metadata in Compute Instances from OpenStack
author: OpenStack Ansible SIG
description:
   - Add, Update or Remove metadata in compute instances from OpenStack.
options:
   name:
     description:
        - Name of the instance to update the metadata
     required: true
     aliases: ['server']
     type: str
   metadata:
     description:
        - 'A list of key value pairs that should be provided as a metadata to
          the instance or a string containing a list of key-value pairs.
          Eg:  meta: "key1=value1,key2=value2"'
        - Note that when I(state) is C(true), metadata already existing on the
          server will not be cleared.
     required: true
     aliases: [meta]
     type: dict
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Creates or updates hostname=test1 as metadata of the server instance vm1
# Note that existing keys will not be cleared
- name: add metadata to instance
  openstack.cloud.server_metadata:
      state: present
      cloud: "{{ cloud }}"
      name: vm1
      metadata:
          hostname: test1
          group: group1

# Removes the keys under meta from the instance named vm1
- name: delete metadata from instance
  openstack.cloud.server_metadata:
        state: absent
        cloud: "{{ cloud }}"
        name: vm1
        meta:
            hostname:
            group:
            public_keys:
'''

RETURN = '''
server:
    description: Dictionary describing the server that was updated.
    type: dict
    returned: On success when I(state) is 'present'.
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


class ServerMetadataModule(OpenStackModule):
    argument_spec = dict(
        name=dict(required=True, aliases=['server']),
        metadata=dict(required=True, type='dict', aliases=['meta']),
        state=dict(default='present', choices=['absent', 'present']),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        state = self.params['state']
        server_name_or_id = self.params['name']
        metadata = self.params['metadata']

        server = self.conn.compute.find_server(server_name_or_id,
                                               ignore_missing=False)
        # openstacksdk will not return details when looking up by name, so we
        # need to refresh the server to get the metadata when updating.
        # Can remove when
        # https://review.opendev.org/c/openstack/openstacksdk/+/857987 merges
        server = self.conn.compute.get_server(server.id)

        if self.ansible.check_mode:
            self.exit_json(**self._check_mode_values(state, server, metadata))

        changed = False
        if state == 'present':
            update = self._build_update(server.metadata, metadata)
            if update:
                # Pass in all metadata keys to set_server_metadata so server
                # object keeps all the keys
                new_metadata = (server.metadata or {})
                new_metadata.update(update)
                self.conn.compute.set_server_metadata(server,
                                                      **new_metadata)
                changed = True
        elif state == 'absent':
            # Only remove keys that exist on the server
            keys_to_delete = self._get_keys_to_delete(server.metadata,
                                                      metadata)
            if keys_to_delete:
                self.conn.compute.delete_server_metadata(server,
                                                         keys_to_delete)
                changed = True

        self.exit_json(changed=changed,
                       server=server.to_dict(computed=False))

    def _build_update(self, current=None, requested=None):
        current = current or {}
        requested = requested or {}
        update = dict(requested.items() - current.items())
        return update

    def _get_keys_to_delete(self, current=None, requested=None):
        current = current or {}
        requested = requested or {}
        return set(current.keys() & requested.keys())

    def _check_mode_values(self, state, server, meta):
        "Builds return values for check mode"
        changed = False
        if state == 'present':
            update = self._build_update(server.metadata, meta)
            if update:
                changed = True
                new_metadata = (server.metadata or {})
                new_metadata.update(update)
                server.metadata = new_metadata
        else:
            keys = self._get_keys_to_delete(server.metadata, meta)
            for k in keys:
                server.meta.pop(k)
        return dict(changed=changed, server=server.to_dict(computed=False))


def main():
    module = ServerMetadataModule()
    module()


if __name__ == '__main__':
    main()
