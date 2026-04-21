#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2019 Red Hat, Inc.
# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# Copyright (c) 2013, John Dewey <john@dewey.ws>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: server
short_description: Create/Delete Compute Instances from OpenStack
author: OpenStack Ansible SIG
description:
   - Create or Remove compute instances from OpenStack.
options:
    auto_ip:
      description:
        - Ensure instance has public ip however the cloud wants to do that.
        - For example, the cloud could add a floating ip for the server or
          attach the server to a public network.
        - Requires I(wait) to be C(True) during server creation.
        - Floating IP support is unstable in this module, use with caution.
        - Options I(auto_ip), I(floating_ip_pools) and I(floating_ips) interact
          in non-obvious ways and undocumentable depth. For explicit and safe
          attaching and detaching of floating ip addresses use module
          I(openstack.cloud.resource) instead.
      type: bool
      default: 'true'
      aliases: ['auto_floating_ip', 'public_ip']
    availability_zone:
      description:
        - Availability zone in which to create the server.
        - This server attribute cannot be updated.
      type: str
    boot_from_volume:
      description:
        - Should the instance boot from a persistent volume created based on
          the image given. Mutually exclusive with boot_volume.
        - This server attribute cannot be updated.
      type: bool
      default: 'false'
    boot_volume:
      description:
        - Volume name or id to use as the volume to boot from. Implies
          boot_from_volume. Mutually exclusive with image and boot_from_volume.
        - This server attribute cannot be updated.
      aliases: ['root_volume']
      type: str
    config_drive:
      description:
        - Whether to boot the server with config drive enabled.
        - This server attribute cannot be updated.
      type: bool
      default: 'false'
    delete_ips:
      description:
        - When I(state) is C(absent) and this option is true, any floating IP
          address associated with this server will be deleted along with it.
        - Floating IP support is unstable in this module, use with caution.
      type: bool
      aliases: ['delete_fip']
      default: 'false'
    description:
      description:
        - Description of the server.
      type: str
    flavor:
      description:
        - The name or id of the flavor in which the new instance has to be
          created.
        - Exactly one of I(flavor) and I(flavor_ram) must be defined when
          I(state=present).
        - This server attribute cannot be updated.
      type: str
    flavor_include:
      description:
        - Text to use to filter flavor names, for the case, such as Rackspace,
          where there are multiple flavors that have the same ram count.
          flavor_include is a positive match filter - it must exist in the
          flavor name.
        - This server attribute cannot be updated.
      type: str
    flavor_ram:
      description:
        - The minimum amount of ram in MB that the flavor in which the new
          instance has to be created must have.
        - Exactly one of I(flavor) and I(flavor_ram) must be defined when
          I(state=present).
        - This server attribute cannot be updated.
      type: int
    floating_ip_pools:
      description:
        - Name of floating IP pool from which to choose a floating IP.
        - Requires I(wait) to be C(True) during server creation.
        - Floating IP support is unstable in this module, use with caution.
        - Options I(auto_ip), I(floating_ip_pools) and I(floating_ips) interact
          in non-obvious ways and undocumentable depth. For explicit and safe
          attaching and detaching of floating ip addresses use module
          I(openstack.cloud.resource) instead.
      type: list
      elements: str
    floating_ips:
      description:
        - list of valid floating IPs that pre-exist to assign to this node.
        - Requires I(wait) to be C(True) during server creation.
        - Floating IP support is unstable in this module, use with caution.
        - Options I(auto_ip), I(floating_ip_pools) and I(floating_ips) interact
          in non-obvious ways and undocumentable depth. For explicit and safe
          attaching and detaching of floating ip addresses use module
          I(openstack.cloud.resource) instead.
      type: list
      elements: str
    image:
      description:
        - The name or id of the base image to boot.
        - Required when I(boot_from_volume=true).
        - This server attribute cannot be updated.
      type: str
    image_exclude:
      description:
        - Text to use to filter image names, for the case, such as HP, where
          there are multiple image names matching the common identifying
          portions. image_exclude is a negative match filter - it is text that
          may not exist in the image name.
        - This server attribute cannot be updated.
      type: str
      default: "(deprecated)"
    key_name:
      description:
        - The key pair name to be used when creating a instance.
        - This server attribute cannot be updated.
      type: str
    metadata:
      description:
        - 'A list of key value pairs that should be provided as a metadata to
          the new instance or a string containing a list of key-value pairs.
          Example:  metadata: "key1=value1,key2=value2"'
      aliases: ['meta']
      type: raw
    name:
      description:
        - Name that has to be given to the instance. It is also possible to
          specify the ID of the instance instead of its name if I(state) is
          I(absent).
        - This server attribute cannot be updated.
      required: true
      type: str
    network:
      description:
        - Name or ID of a network to attach this instance to. A simpler
          version of the I(nics) parameter, only one of I(network) or I(nics)
          should be supplied.
        - This server attribute cannot be updated.
      type: str
    nics:
      description:
        - A list of networks to which the instance's interface should
          be attached. Networks may be referenced by net-id/net-name/port-id
          or port-name.
        - 'Also this accepts a string containing a list of (net/port)-(id/name)
          Example: C(nics: "net-id=uuid-1,port-name=myport")'
        - Only one of I(network) or I(nics) should be supplied.
        - This server attribute cannot be updated.
      type: list
      elements: raw
      default: []
      suboptions:
        tag:
          description:
            - 'A I(tag) for the specific port to be passed via metadata.
              Eg: C(tag: test_tag)'
    reuse_ips:
      description:
        - When I(auto_ip) is true and this option is true, the I(auto_ip) code
          will attempt to re-use unassigned floating ips in the project before
          creating a new one. It is important to note that it is impossible
          to safely do this concurrently, so if your use case involves
          concurrent server creation, it is highly recommended to set this to
          false and to delete the floating ip associated with a server when
          the server is deleted using I(delete_ips).
        - Floating IP support is unstable in this module, use with caution.
        - This server attribute cannot be updated.
      type: bool
      default: 'true'
    scheduler_hints:
      description:
        - Arbitrary key/value pairs to the scheduler for custom use.
        - This server attribute cannot be updated.
      type: dict
    security_groups:
      description:
        - Names or IDs of the security groups to which the instance should be
          added.
        - On server creation, if I(security_groups) is omitted, the API creates
          the server in the default security group.
        - Requested security groups are not applied to pre-existing ports.
      type: list
      elements: str
      default: []
    state:
      description:
        - Should the resource be C(present) or C(absent).
      choices: [present, absent]
      default: present
      type: str
    tags:
      description:
        -  A list of tags should be added to instance
      type: list
      elements: str
      default: []
    terminate_volume:
      description:
        - If C(true), delete volume when deleting the instance and if it has
          been booted from volume(s).
        - This server attribute cannot be updated.
      type: bool
      default: 'false'
    timeout:
      description:
        - The amount of time the module should wait for the instance to get
          into active state.
      default: 180
      type: int
    userdata:
      description:
        - Opaque blob of data which is made available to the instance.
        - This server attribute cannot be updated.
      type: str
    volume_size:
      description:
        - The size of the volume to create in GB if booting from volume based
          on an image.
        - This server attribute cannot be updated.
      type: int
    volumes:
      description:
        - A list of preexisting volumes names or ids to attach to the instance
        - This server attribute cannot be updated.
      default: []
      type: list
      elements: str
    wait:
      description:
        - If the module should wait for the instance to be created.
      type: bool
      default: 'true'
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Create a new instance with metadata and attaches it to a network
  openstack.cloud.server:
       state: present
       auth:
         auth_url: https://identity.example.com
         username: admin
         password: admin
         project_name: admin
       name: vm1
       image: 4f905f38-e52a-43d2-b6ec-754a13ffb529
       key_name: ansible_key
       timeout: 200
       flavor: 4
       nics:
         - net-id: 34605f38-e52a-25d2-b6ec-754a13ffb723
         - net-name: another_network
       meta:
         hostname: test1
         group: uge_master

# Create a new instance in HP Cloud AE1 region availability zone az2 and
# automatically assigns a floating IP
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        state: present
        auth:
          auth_url: https://identity.example.com
          username: username
          password: Equality7-2521
          project_name: username-project1
        name: vm1
        region_name: region-b.geo-1
        availability_zone: az2
        image: 9302692b-b787-4b52-a3a6-daebb79cb498
        key_name: test
        timeout: 200
        flavor: 101
        security_groups:
        - default
        auto_ip: true

# Create a new instance in named cloud mordred availability zone az2
# and assigns a pre-known floating IP
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        state: present
        cloud: mordred
        name: vm1
        availability_zone: az2
        image: 9302692b-b787-4b52-a3a6-daebb79cb498
        key_name: test
        timeout: 200
        flavor: 101
        floating_ips:
          - 12.34.56.79

# Create a new instance with 4G of RAM on Ubuntu Trusty, ignoring
# deprecated images
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        name: vm1
        state: present
        cloud: mordred
        region_name: region-b.geo-1
        image: Ubuntu Server 14.04
        image_exclude: deprecated
        flavor_ram: 4096

# Create a new instance with 4G of RAM on Ubuntu Trusty on a Performance node
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        name: vm1
        cloud: rax-dfw
        state: present
        image: Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)
        flavor_ram: 4096
        flavor_include: Performance

# Creates a new instance and attaches to multiple network
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance with a string
      openstack.cloud.server:
        auth:
           auth_url: https://identity.example.com
           username: admin
           password: admin
           project_name: admin
        name: vm1
        image: 4f905f38-e52a-43d2-b6ec-754a13ffb529
        key_name: ansible_key
        timeout: 200
        flavor: 4
        nics: >-
            net-id=4cb08b20-62fe-11e5-9d70-feff819cdc9f,
            net-id=542f0430-62fe-11e5-9d70-feff819cdc9f

- name: Creates a new instance with metadata and attaches it to a network
  openstack.cloud.server:
       state: present
       auth:
         auth_url: https://identity.example.com
         username: admin
         password: admin
         project_name: admin
       name: vm1
       image: 4f905f38-e52a-43d2-b6ec-754a13ffb529
       key_name: ansible_key
       timeout: 200
       flavor: 4
       nics:
         - net-id: 34605f38-e52a-25d2-b6ec-754a13ffb723
         - net-name: another_network
       meta: "hostname=test1,group=uge_master"

- name:  Creates a new instance and attaches to a specific network
  openstack.cloud.server:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: vm1
    image: 4f905f38-e52a-43d2-b6ec-754a13ffb529
    key_name: ansible_key
    timeout: 200
    flavor: 4
    network: another_network

# Create a new instance with 4G of RAM on a 75G Ubuntu Trusty volume
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        name: vm1
        state: present
        cloud: mordred
        region_name: ams01
        image: Ubuntu Server 14.04
        flavor_ram: 4096
        boot_from_volume: True
        volume_size: 75

# Creates a new instance with 2 volumes attached
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        name: vm1
        state: present
        cloud: mordred
        region_name: ams01
        image: Ubuntu Server 14.04
        flavor_ram: 4096
        volumes:
        - photos
        - music

# Creates a new instance with provisioning userdata using Cloud-Init
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        name: vm1
        state: present
        image: "Ubuntu Server 14.04"
        flavor: "P-1"
        network: "Production"
        userdata: |
          #cloud-config
          chpasswd:
            list: |
              ubuntu:{{ default_password }}
            expire: False
          packages:
            - ansible
          package_upgrade: true

# Creates a new instance with provisioning userdata using Bash Scripts
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        name: vm1
        state: present
        image: "Ubuntu Server 22.04"
        flavor: "P-1"
        network: "Production"
        userdata: |
          #!/bin/sh
          apt update
          apt -y full-upgrade

# Create a new instance with server group for (anti-)affinity
# server group ID is returned from openstack.cloud.server_group module.
- name: launch a compute instance
  hosts: localhost
  tasks:
    - name: launch an instance
      openstack.cloud.server:
        state: present
        name: vm1
        image: 4f905f38-e52a-43d2-b6ec-754a13ffb529
        flavor: 4
        scheduler_hints:
          group: f5c8c61a-9230-400a-8ed2-3b023c190a7f

# Create an instance with "tags" for the nic
- name: Create instance with nics "tags"
  openstack.cloud.server:
    state: present
    auth:
        auth_url: https://identity.example.com
        username: admin
        password: admin
        project_name: admin
    name: vm1
    image: 4f905f38-e52a-43d2-b6ec-754a13ffb529
    key_name: ansible_key
    flavor: 4
    nics:
      - port-name: net1_port1
        tag: test_tag
      - net-name: another_network

# Deletes an instance via its ID
- name: remove an instance
  hosts: localhost
  tasks:
    - name: remove an instance
      openstack.cloud.server:
        name: abcdef01-2345-6789-0abc-def0123456789
        state: absent

'''

RETURN = '''
server:
    description: Dictionary describing the server.
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
            elements: str
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
import copy


class ServerModule(OpenStackModule):

    argument_spec = dict(
        auto_ip=dict(default=True, type='bool',
                     aliases=['auto_floating_ip', 'public_ip']),
        availability_zone=dict(),
        boot_from_volume=dict(default=False, type='bool'),
        boot_volume=dict(aliases=['root_volume']),
        config_drive=dict(default=False, type='bool'),
        delete_ips=dict(default=False, type='bool', aliases=['delete_fip']),
        description=dict(),
        flavor=dict(),
        flavor_include=dict(),
        flavor_ram=dict(type='int'),
        floating_ip_pools=dict(type='list', elements='str'),
        floating_ips=dict(type='list', elements='str'),
        image=dict(),
        image_exclude=dict(default='(deprecated)'),
        key_name=dict(),
        metadata=dict(type='raw', aliases=['meta']),
        name=dict(required=True),
        network=dict(),
        nics=dict(default=[], type='list', elements='raw'),
        reuse_ips=dict(default=True, type='bool'),
        scheduler_hints=dict(type='dict'),
        security_groups=dict(default=[], type='list', elements='str'),
        state=dict(default='present', choices=['absent', 'present']),
        tags=dict(type='list', default=[], elements='str'),
        terminate_volume=dict(default=False, type='bool'),
        userdata=dict(),
        volume_size=dict(type='int'),
        volumes=dict(default=[], type='list', elements='str'),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ['auto_ip', 'floating_ips', 'floating_ip_pools'],
            ['flavor', 'flavor_ram'],
            ['image', 'boot_volume'],
            ['boot_from_volume', 'boot_volume'],
            ['nics', 'network'],
        ],
        required_if=[
            ('boot_from_volume', True, ['volume_size', 'image']),
            ('state', 'present', ('image', 'boot_volume'), True),
            ('state', 'present', ('flavor', 'flavor_ram'), True),
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        server = self.conn.compute.find_server(self.params['name'])
        if server:
            # fetch server details such as server['addresses']
            server = self.conn.compute.get_server(server)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, server))

        if state == 'present' and not server:
            # Create server
            server = self._create()
            self.exit_json(changed=True,
                           server=server.to_dict(computed=False))

        elif state == 'present' and server:
            # Update server
            update = self._build_update(server)
            if update:
                server = self._update(server, update)

            self.exit_json(changed=bool(update),
                           server=server.to_dict(computed=False))

        elif state == 'absent' and server:
            # Delete server
            self._delete(server)
            self.exit_json(changed=True)

        elif state == 'absent' and not server:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, server):
        if server.status not in ('ACTIVE', 'SHUTOFF', 'PAUSED', 'SUSPENDED'):
            self.fail_json(msg="The instance is available but not "
                               "active state: {0}".format(server.status))

        return {
            **self._build_update_ips(server),
            **self._build_update_security_groups(server),
            **self._build_update_server(server),
            **self._build_update_tags(server)}

    def _build_update_ips(self, server):
        auto_ip = self.params['auto_ip']
        floating_ips = self.params['floating_ips']
        floating_ip_pools = self.params['floating_ip_pools']

        if not (auto_ip or floating_ips or floating_ip_pools):
            # No floating ip has been requested, so
            # do not add or remove any floating ip.
            return {}

        # Get floating ip addresses attached to the server
        ips = [interface_spec['addr']
               for v in server['addresses'].values()
               for interface_spec in v
               if interface_spec.get('OS-EXT-IPS:type', None) == 'floating']

        if (auto_ip and ips and not floating_ip_pools and not floating_ips):
            # Server has a floating ip address attached and
            # no specific floating ip has been requested,
            # so nothing to change.
            return {}

        if not ips:
            # One or multiple floating ips have been requested,
            # but none have been attached, so attach them.
            return dict(ips=dict(
                auto_ip=auto_ip,
                ips=floating_ips,
                ip_pool=floating_ip_pools))

        if auto_ip or not floating_ips:
            # Nothing do to because either any floating ip address
            # or no specific floating ips have been requested
            # and any floating ip has been attached.
            return {}

        # A specific set of floating ips has been requested
        update = {}
        add_ips = [ip for ip in floating_ips if ip not in ips]
        if add_ips:
            # add specific ips which have not been added
            update['add_ips'] = add_ips

        remove_ips = [ip for ip in ips if ip not in floating_ips]
        if remove_ips:
            # Detach ips which are not supposed to be attached
            update['remove_ips'] = remove_ips

    def _build_update_security_groups(self, server):
        update = {}

        required_security_groups = dict(
            (sg['id'], sg) for sg in [
                self.conn.network.find_security_group(
                    security_group_name_or_id, ignore_missing=False)
                for security_group_name_or_id in self.params['security_groups']
            ])

        # Retrieve IDs of security groups attached to the server
        server = self.conn.compute.fetch_server_security_groups(server)
        assigned_security_groups = dict(
            (sg['id'], self.conn.network.get_security_group(sg['id']))
            for sg in server.security_groups)

        # openstacksdk adds security groups to server using resources
        add_security_groups = [
            sg for (sg_id, sg) in required_security_groups.items()
            if sg_id not in assigned_security_groups]

        if add_security_groups:
            update['add_security_groups'] = add_security_groups

        # openstacksdk removes security groups from servers using resources
        remove_security_groups = [
            sg for (sg_id, sg) in assigned_security_groups.items()
            if sg_id not in required_security_groups]

        if remove_security_groups:
            update['remove_security_groups'] = remove_security_groups

        return update

    def _build_update_server(self, server):
        update = {}

        # Process metadata
        required_metadata = self._parse_metadata(self.params['metadata'])
        assigned_metadata = server.metadata

        add_metadata = dict()
        for (k, v) in required_metadata.items():
            if k not in assigned_metadata or assigned_metadata[k] != v:
                add_metadata[k] = v

        if add_metadata:
            update['add_metadata'] = add_metadata

        remove_metadata = dict()
        for (k, v) in assigned_metadata.items():
            if k not in required_metadata or required_metadata[k] != v:
                remove_metadata[k] = v

        if remove_metadata:
            update['remove_metadata'] = remove_metadata

        # Process server attributes

        # Updateable server attributes in openstacksdk
        # (OpenStack API names in braces):
        # - access_ipv4 (accessIPv4)
        # - access_ipv6 (accessIPv6)
        # - name (name)
        # - hostname (hostname)
        # - disk_config (OS-DCF:diskConfig)
        # - description (description)
        # Ref.: https://docs.openstack.org/api-ref/compute/#update-server

        # A server's name cannot be updated by this module because
        # it is used to find servers by name or id.
        # If name is an id, then we do not have a name to update.
        # If name is a name actually, then it was used to find a
        # matching server hence the name is the user defined one
        # already.

        # Update all known updateable attributes although
        # our module might not support them yet
        server_attributes = dict(
            (k, self.params[k])
            for k in ['access_ipv4', 'access_ipv6', 'hostname', 'disk_config',
                      'description']
            if k in self.params and self.params[k] is not None
            and self.params[k] != server[k])

        if server_attributes:
            update['server_attributes'] = server_attributes

        return update

    def _build_update_tags(self, server):
        required_tags = self.params.get('tags')
        if set(server["tags"]) == set(required_tags):
            return {}
        update = dict(tags=required_tags)
        return update

    def _create(self):
        for k in ['auto_ip', 'floating_ips', 'floating_ip_pools']:
            if self.params[k] \
               and self.params['wait'] is False:
                # floating ip addresses will only be added if
                # we wait until the server has been created
                # Ref.: https://opendev.org/openstack/openstacksdk/src/commit/3f81d0001dd994cde990d38f6e2671ee0694d7d5/openstack/cloud/_compute.py#L945
                self.fail_json(
                    msg="Option '{0}' requires 'wait: true'".format(k))

        flavor_name_or_id = self.params['flavor']

        image_id = None
        if not self.params['boot_volume']:
            image_id = self.conn.get_image_id(
                self.params['image'], self.params['image_exclude'])
            if not image_id:
                self.fail_json(
                    msg="Could not find image {0} with exclude {1}".format(
                        self.params['image'], self.params['image_exclude']))

        if flavor_name_or_id:
            flavor = self.conn.compute.find_flavor(flavor_name_or_id,
                                                   ignore_missing=False)
        else:
            flavor = self.conn.get_flavor_by_ram(self.params['flavor_ram'],
                                                 self.params['flavor_include'])
            if not flavor:
                self.fail_json(msg="Could not find any matching flavor")

        args = dict(
            flavor=flavor.id,
            image=image_id,
            ip_pool=self.params['floating_ip_pools'],
            ips=self.params['floating_ips'],
            meta=self._parse_metadata(self.params['metadata']),
            nics=self._parse_nics(),
        )

        for k in ['auto_ip', 'availability_zone', 'boot_from_volume',
                  'boot_volume', 'config_drive', 'description', 'key_name',
                  'name', 'network', 'reuse_ips', 'scheduler_hints',
                  'security_groups', 'tags', 'terminate_volume', 'timeout',
                  'userdata', 'volume_size', 'volumes', 'wait']:
            if self.params[k] is not None:
                args[k] = self.params[k]

        server = self.conn.create_server(**args)

        # openstacksdk's create_server() might call meta.add_server_interfaces(
        # ) which alters server attributes such as server['addresses']. So we
        # do an extra call to compute.get_server() to return a clean server
        # resource.
        # Ref.: https://opendev.org/openstack/openstacksdk/src/commit/3f81d0001dd994cde990d38f6e2671ee0694d7d5/openstack/cloud/_compute.py#L942
        return self.conn.compute.get_server(server)

    def _delete(self, server):
        self.conn.delete_server(
            server.id,
            **dict((k, self.params[k])
                   for k in ['wait', 'timeout', 'delete_ips']))
        # Nova returns server for some time with the "DELETED" state. Our tests
        # are not able to handle this, so wait for server to really disappear.
        if self.params['wait']:
            for count in self.sdk.utils.iterate_timeout(
                timeout=self.params['timeout'],
                message="Timeout waiting for server to be absent"
            ):
                if self.conn.compute.find_server(server.id) is None:
                    break

    def _update(self, server, update):
        server = self._update_ips(server, update)
        server = self._update_security_groups(server, update)
        server = self._update_tags(server, update)
        server = self._update_server(server, update)
        # Refresh server attributes after security groups etc. have changed
        #
        # Use compute.get_server() instead of compute.find_server()
        # to include server details
        return self.conn.compute.get_server(server)

    def _update_ips(self, server, update):
        args = dict((k, self.params[k]) for k in ['wait', 'timeout'])
        ips = update.get('ips')
        if ips:
            server = self.conn.add_ips_to_server(server, **ips, **args)

        add_ips = update.get('add_ips')
        if add_ips:
            # Add specific ips which have not been added
            server = self.conn.add_ip_list(server, add_ips, **args)

        remove_ips = update.get('remove_ips')
        if remove_ips:
            # Detach ips which are not supposed to be attached
            for ip in remove_ips:
                ip_id = self.conn.network.find_ip(name_or_id=ip,
                                                  ignore_missing=False).id
                # self.conn.network.update_ip(ip_id, port_id=None) does not
                # handle nova network but self.conn.detach_ip_from_server()
                # does so
                self.conn.detach_ip_from_server(server_id=server.id,
                                                floating_ip_id=ip_id)
        return server

    def _update_security_groups(self, server, update):
        add_security_groups = update.get('add_security_groups')
        if add_security_groups:
            for sg in add_security_groups:
                self.conn.compute.add_security_group_to_server(server, sg)

        remove_security_groups = update.get('remove_security_groups')
        if remove_security_groups:
            for sg in remove_security_groups:
                self.conn.compute.remove_security_group_from_server(server, sg)

        # Whenever security groups of a server have changed,
        # the server object has to be refreshed. This will
        # be postponed until all updates have been applied.
        return server

    def _update_server(self, server, update):
        add_metadata = update.get('add_metadata')
        if add_metadata:
            self.conn.compute.set_server_metadata(server.id,
                                                  **add_metadata)

        remove_metadata = update.get('remove_metadata')
        if remove_metadata:
            self.conn.compute.delete_server_metadata(server.id,
                                                     remove_metadata.keys())

        server_attributes = update.get('server_attributes')
        if server_attributes:
            # Server object cannot passed to self.conn.compute.update_server()
            # entirely because its security_groups attribute was expanded by
            # self.conn.compute.fetch_server_security_groups() previously which
            # thus will no longer have a valid value for OpenStack API.
            server = self.conn.compute.update_server(server['id'],
                                                     **server_attributes)

        # Whenever server attributes such as metadata have changed,
        # the server object has to be refreshed. This will
        # be postponed until all updates have been applied.
        return server

    def _update_tags(self, server, update):
        tags = update.get('tags')

        self.conn.compute.put(
            "/servers/{server_id}/tags".format(server_id=server['id']),
            json={"tags": tags},
            microversion="2.26"
        )
        return server

    def _parse_metadata(self, metadata):
        if not metadata:
            return {}

        if isinstance(metadata, str):
            metas = {}
            for kv_str in metadata.split(","):
                k, v = kv_str.split("=")
                metas[k] = v
            return metas

        return metadata

    def _parse_nics(self):
        nics = []
        stringified_nets = self.params['nics']

        if not isinstance(stringified_nets, list):
            self.fail_json(msg="The 'nics' parameter must be a list.")

        nets = [(dict((nested_net.split('='),))
                for nested_net in net.split(','))
                if isinstance(net, str) else net
                for net in stringified_nets]

        for net in nets:
            if not isinstance(net, dict):
                self.fail_json(
                    msg="Each entry in the 'nics' parameter must be a dict.")

            if net.get('net-id'):
                nics.append(net)
            elif net.get('net-name'):
                network_id = self.conn.network.find_network(
                    net['net-name'], ignore_missing=False).id
                # Replace net-name with net-id and keep optional nic args
                # Ref.: https://github.com/ansible/ansible/pull/20969
                #
                # Delete net-name from a copy else it will
                # disappear from Ansible's debug output
                net = copy.deepcopy(net)
                del net['net-name']
                net['net-id'] = network_id
                nics.append(net)
            elif net.get('port-id'):
                nics.append(net)
            elif net.get('port-name'):
                port_id = self.conn.network.find_port(
                    net['port-name'], ignore_missing=False).id
                # Replace net-name with net-id and keep optional nic args
                # Ref.: https://github.com/ansible/ansible/pull/20969
                #
                # Delete net-name from a copy else it will
                # disappear from Ansible's debug output
                net = copy.deepcopy(net)
                del net['port-name']
                net['port-id'] = port_id
                nics.append(net)

            if 'tag' in net:
                nics[-1]['tag'] = net['tag']
        return nics

    def _will_change(self, state, server):
        if state == 'present' and not server:
            return True
        elif state == 'present' and server:
            return bool(self._build_update(server))
        elif state == 'absent' and server:
            return True
        else:
            # state == 'absent' and not server:
            return False


def main():
    module = ServerModule()
    module()


if __name__ == '__main__':
    main()
