#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: image
short_description: Manage images of OpenStack image (Glance) service.
author: OpenStack Ansible SIG
description:
  - Create or delete images in OpenStack image (Glance) service.
options:
  checksum:
    description:
      - The checksum of the image.
    type: str
  container_format:
    description:
      - The format of the container.
      - This image attribute cannot be changed.
      - Examples are C(ami), C(aki), C(ari), C(bare), C(ovf), C(ova) or
        C(docker).
    default: bare
    type: str
  disk_format:
    description:
      - The format of the disk that is getting uploaded.
      - This image attribute cannot be changed.
      - Examples are C(ami), C(ari), C(aki), C(vhd), C(vmdk), C(raw),
        C(qcow2), C(vdi), c(iso), C(vhdx) or C(ploop).
    default: qcow2
    type: str
  filename:
    description:
      - The path to the file which has to be uploaded.
      - This image attribute cannot be changed.
    type: str
  id:
    description:
      - The ID of the image when uploading an image.
      - This image attribute cannot be changed.
    type: str
  is_protected:
    description:
      - Prevent image from being deleted.
    aliases: ['protected']
    type: bool
  is_public:
    description:
      - Whether the image can be accessed publicly.
      - Setting I(is_public) to C(true) requires admin role by default.
      - I(is_public) has been deprecated. Use I(visibility) instead of
        I(is_public).
    type: bool
    default: false
  kernel:
    description:
      - The name of an existing kernel image that will be associated with this
        image.
    type: str
  min_disk:
    description:
      - The minimum disk space (in GB) required to boot this image.
    type: int
  min_ram:
    description:
      - The minimum ram (in MB) required to boot this image.
    type: int
  name:
    description:
      - The name of the image when uploading - or the name/ID of the image if
        deleting.
      - If provided with the id, it can be used to change the name of existing
        image.
    required: true
    type: str
  owner:
    description:
      - The name or ID of the project owning the image.
    type: str
    aliases: ['project']
  owner_domain:
    description:
      - The name or id of the domain the project owning the image belongs to.
      - May be used to identify a unique project when providing a name to the
        project argument and multiple projects with such name exist.
    type: str
    aliases: ['project_domain']
  properties:
    description:
      - Additional properties to be associated with this image.
    default: {}
    type: dict
  ramdisk:
    description:
      - The name of an existing ramdisk image that will be associated with this
        image.
    type: str
  state:
    description:
      - Should the resource be present, absent or inactive.
    choices: [present, absent, inactive]
    default: present
    type: str
  tags:
    description:
      - List of tags to be applied to the image.
    default: []
    type: list
    elements: str
  visibility:
    description:
      - The image visibility.
    type: str
    choices: [public, private, shared, community]
  volume:
    description:
      - ID of a volume to create an image from.
      - The volume must be in AVAILABLE state.
      - I(volume) has been deprecated. Use module M(openstack.cloud.volume)
        instead.
    type: str
  use_import:
    description:
      - Use the 'glance-direct' method of the interoperable image import mechanism.
      - Should only be used when needed, such as when the user needs the cloud to
        transform image format.
    type: bool
  import_method:
    description:
      - Method to use for importing the image. Not all deployments support all methods.
      - Supports web-download or glance-download.
      - copy-image is not supported with create actions.
      - glance-direct is removed from the import method so use_import can be used in that case.
    type: str
    choices: [web-download, glance-download]
  uri:
    description:
      - Required only if using the web-download import method.
      - This url is where the data is made available to the Image service.
    type: str

extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Upload an image from a local file named cirros-0.3.0-x86_64-disk.img
  openstack.cloud.image:
    cloud: devstack-admin
    name: cirros
    container_format: bare
    disk_format: qcow2
    state: present
    filename: cirros-0.3.0-x86_64-disk.img
    kernel: cirros-vmlinuz
    ramdisk: cirros-initrd
    tags:
      - custom
    properties:
      cpu_arch: x86_64
      distro: ubuntu
'''

RETURN = r'''
image:
  description: Dictionary describing the Glance image.
  returned: On success when I(state) is C(present) or C(inactive).
  type: dict
  contains:
    id:
      description: Unique UUID.
      type: str
    name:
      description: Name given to the image.
      type: str
    status:
      description: Image status.
      type: str
    architecture:
      description: The CPU architecture that must be supported by
                   the hypervisor.
      type: str
    created_at:
      description: Image created at timestamp.
      type: str
    container_format:
      description: Container format of the image.
      type: str
    direct_url:
      description: URL to access the image file kept in external store.
      type: str
    min_ram:
      description: Min amount of RAM required for this image.
      type: int
    disk_format:
      description: Disk format of the image.
      type: str
    file:
      description: The URL for the virtual machine image file.
      type: str
    has_auto_disk_config:
      description: If root partition on disk is automatically resized
                   before the instance boots.
      type: bool
    hash_algo:
      description: The algorithm used to compute a secure hash of the
                   image data.
      type: str
    hash_value:
      description: The hexdigest of the secure hash of the image data
                   computed using the algorithm whose name is the value of the
                   os_hash_algo property.
      type: str
    hw_cpu_cores:
      description: Used to pin the virtual CPUs (vCPUs) of instances to
                   the host's physical CPU cores (pCPUs).
      type: str
    hw_cpu_policy:
      description: The hexdigest of the secure hash of the image data.
      type: str
    hw_cpu_sockets:
      description: Preferred number of sockets to expose to the guest.
      type: str
    hw_cpu_thread_policy:
      description: Defines how hardware CPU threads in a simultaneous
                   multithreading-based (SMT) architecture be used.
      type: str
    hw_cpu_threads:
      description: The preferred number of threads to expose to the guest.
      type: str
    hw_disk_bus:
      description: Specifies the type of disk controller to attach disk
                   devices to.
      type: str
    hw_machine_type:
      description: Enables booting an ARM system using the
                   specified machine type.
      type: str
    hw_qemu_guest_agent:
      description: "A string boolean, which if 'true', QEMU guest agent
                    will be exposed to the instance."
      type: str
    hw_rng_model:
      description: "Adds a random-number generator device to the image's
                   instances."
      type: str
    hw_scsi_model:
      description: Enables the use of VirtIO SCSI (virtio-scsi) to
                   provide block device access for compute instances.
      type: str
    hw_video_model:
      description: The video image driver used.
      type: str
    hw_video_ram:
      description: Maximum RAM for the video image.
      type: str
    hw_vif_model:
      description: Specifies the model of virtual network interface device to
                   use.
      type: str
    hw_watchdog_action:
      description: Enables a virtual hardware watchdog device that
                   carries out the specified action if the server hangs.
      type: str
    hypervisor_type:
      description: The hypervisor type.
      type: str
    instance_type_rxtx_factor:
      description: Optional property allows created servers to have a
                   different bandwidth cap than that defined in the network
                   they are attached to.
      type: str
    instance_uuid:
      description: For snapshot images, this is the UUID of the server
                   used to create this image.
      type: str
    is_hidden:
      description: Controls whether an image is displayed in the default
                   image-list response
      type: bool
    is_hw_boot_menu_enabled:
      description: Enables the BIOS bootmenu.
      type: bool
    is_hw_vif_multiqueue_enabled:
      description: Enables the virtio-net multiqueue feature.
      type: bool
    kernel_id:
      description: The ID of an image stored in the Image service that
                   should be used as the kernel when booting an AMI-style
                   image.
      type: str
    locations:
      description: A list of URLs to access the image file in external store.
      type: str
    metadata:
      description: The location metadata.
      type: str
    needs_config_drive:
      description: Specifies whether the image needs a config drive.
      type: bool
    needs_secure_boot:
      description: Whether Secure Boot is needed.
      type: bool
    os_admin_user:
      description: The operating system admin username.
      type: str
    os_command_line:
      description: The kernel command line to be used by libvirt driver.
      type: str
    os_distro:
      description: The common name of the operating system distribution
                   in lowercase.
      type: str
    os_require_quiesce:
      description: If true, require quiesce on snapshot via
                   QEMU guest agent.
      type: str
    os_shutdown_timeout:
      description: Time for graceful shutdown.
      type: str
    os_type:
      description: The operating system installed on the image.
      type: str
    os_version:
      description: The operating system version as specified by
                   the distributor.
      type: str
    owner_id:
      description: The ID of the owner, or project, of the image.
      type: str
    ramdisk_id:
      description: The ID of image stored in the Image service that should
                   be used as the ramdisk when booting an AMI-style image.
      type: str
    schema:
      description: URL for the schema describing a virtual machine image.
      type: str
    store:
      description: Glance will attempt to store the disk image data in the
                   backing store indicated by the value of the header.
      type: str
    updated_at:
      description: Image updated at timestamp.
      type: str
    url:
      description: URL to access the image file kept in external store.
      type: str
    virtual_size:
      description: The virtual size of the image.
      type: str
    vm_mode:
      description: The virtual machine mode.
      type: str
    vmware_adaptertype:
      description: The virtual SCSI or IDE controller used by the
                   hypervisor.
      type: str
    vmware_ostype:
      description: Operating system installed in the image.
      type: str
    filters:
      description: Additional properties associated with the image.
      type: dict
    min_disk:
      description: Min amount of disk space required for this image.
      type: int
    is_protected:
      description: Image protected flag.
      type: bool
    checksum:
      description: Checksum for the image.
      type: str
    owner:
      description: Owner for the image.
      type: str
    visibility:
      description: Indicates who has access to the image.
      type: str
    size:
      description: Size of the image.
      type: int
    tags:
      description: List of tags assigned to the image
      type: list
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ImageModule(OpenStackModule):

    argument_spec = dict(
        checksum=dict(),
        container_format=dict(default='bare'),
        disk_format=dict(default='qcow2'),
        filename=dict(),
        id=dict(),
        is_protected=dict(type='bool', aliases=['protected']),
        is_public=dict(type='bool', default=False),
        kernel=dict(),
        min_disk=dict(type='int'),
        min_ram=dict(type='int'),
        name=dict(required=True),
        owner=dict(aliases=['project']),
        owner_domain=dict(aliases=['project_domain']),
        properties=dict(type='dict', default={}),
        ramdisk=dict(),
        state=dict(default='present', choices=['absent', 'present', 'inactive']),
        tags=dict(type='list', default=[], elements='str'),
        visibility=dict(choices=['public', 'private', 'shared', 'community']),
        volume=dict(),
        use_import=dict(type='bool'),
        import_method=dict(choices=['web-download', 'glance-download']),
        uri=dict()
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('filename', 'volume', 'uri'),
            ('visibility', 'is_public'),
        ],
    )

    # resource attributes obtainable directly from params
    attr_params = ('id', 'name', 'filename', 'disk_format',
                   'container_format', 'wait', 'timeout', 'is_public',
                   'is_protected', 'min_disk', 'min_ram', 'volume', 'tags',
                   'use_import', 'import_method', 'uri')

    def _resolve_visibility(self):
        """resolve a visibility value to be compatible with older versions"""
        if self.params['visibility']:
            return self.params['visibility']
        if self.params['is_public'] is not None:
            return 'public' if self.params['is_public'] else 'private'
        return None

    def _build_params(self, owner):
        params = {attr: self.params[attr] for attr in self.attr_params}
        if owner:
            params['owner_id'] = owner.id
        params['visibility'] = self._resolve_visibility()
        params = {k: v for k, v in params.items() if v is not None}
        return params

    def _return_value(self, image_name_or_id):
        image = self.conn.image.find_image(image_name_or_id)
        if image:
            image = image.to_dict(computed=False)
        return image

    def _build_update(self, image):
        update_payload = {'visibility': self._resolve_visibility()}

        for k in ('is_protected', 'min_disk', 'min_ram'):
            update_payload[k] = self.params[k]

        for k in ('kernel', 'ramdisk'):
            if not self.params[k]:
                continue
            k_id = '{0}_id'.format(k)
            k_image = self.conn.image.find_image(
                name_or_id=self.params[k], ignore_missing=False)
            update_payload[k_id] = k_image.id

        update_payload = {k: v for k, v in update_payload.items()
                          if v is not None and image[k] != v}

        for p, v in self.params['properties'].items():
            if p not in image or image[p] != v:
                update_payload[p] = v

        if (self.params['tags']
                and set(image['tags']) != set(self.params['tags'])):
            update_payload['tags'] = self.params['tags']

        # If both name and id are defined,then we might change the name
        if self.params['id'] and \
           self.params['name'] and \
           self.params['name'] != image['name']:
            update_payload['name'] = self.params['name']

        return update_payload

    def run(self):
        changed = False
        image_name_or_id = self.params['id'] or self.params['name']
        owner_name_or_id = self.params['owner']
        owner_domain_name_or_id = self.params['owner_domain']
        owner_filters = {}
        if owner_domain_name_or_id:
            owner_domain = self.conn.identity.find_domain(
                owner_domain_name_or_id)
            if owner_domain:
                owner_filters['domain_id'] = owner_domain.id
            else:
                # else user may not be able to enumerate domains
                owner_filters['domain_id'] = owner_domain_name_or_id

        owner = None
        if owner_name_or_id:
            owner = self.conn.identity.find_project(
                owner_name_or_id, ignore_missing=False, **owner_filters)

        image = None
        if image_name_or_id:
            image = self.conn.get_image(
                image_name_or_id,
                filters={k: self.params[k]
                         for k in ['checksum'] if self.params[k] is not None})

        changed = False
        if self.params['state'] == 'present':
            attrs = self._build_params(owner)
            if not image:
                # self.conn.image.create_image() cannot be used because it does
                # not provide self.conn.create_image()'s volume parameter [0].
                # [0] https://opendev.org/openstack/openstacksdk/src/commit/
                #     a41d04ea197439c2f134ce3554995693933a46ac/openstack/cloud/_image.py#L306
                image = self.conn.create_image(**attrs)
                changed = True
                if not self.params['wait']:
                    self.exit_json(changed=changed,
                                   image=self._return_value(image.id))

            if image['status'] == 'deactivated':
                self.conn.image.reactivate_image(image)
                changed = True

            update_payload = self._build_update(image)

            if update_payload:
                self.conn.image.update_image(image.id, **update_payload)
                changed = True

            self.exit_json(changed=changed, image=self._return_value(image.id))

        elif self.params['state'] == 'absent' and image is not None:
            # self.conn.image.delete_image() does not offer a wait parameter
            self.conn.delete_image(
                name_or_id=image['id'],
                wait=self.params['wait'],
                timeout=self.params['timeout'])
            changed = True

        elif self.params['state'] == 'inactive' and image is not None:
            if image['status'] == 'active':
                self.conn.image.deactivate_image(image)
                changed = True

            update_payload = self._build_update(image)

            if update_payload:
                self.conn.image.update_image(image.id, **update_payload)
                changed = True

            self.exit_json(changed=changed, image=self._return_value(image.id))

        self.exit_json(changed=changed)


def main():
    module = ImageModule()
    module()


if __name__ == '__main__':
    main()
