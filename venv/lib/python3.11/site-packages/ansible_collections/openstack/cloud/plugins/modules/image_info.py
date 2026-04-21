#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: image_info
short_description: Fetch images from OpenStack image (Glance) service.
author: OpenStack Ansible SIG
description:
  - Fetch images from OpenStack image (Glance) service.
options:
  name:
    description:
      - Name or ID of the image
    type: str
    aliases: ['image']
  filters:
    description:
      - Dict of properties of the images used for query
    type: dict
    aliases: ['properties']
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather previously created image named image1
  openstack.cloud.image_info:
    cloud: devstack-admin
    image: image1

- name: List all images
  openstack.cloud.image_info:

- name: Retrieve and filter images
  openstack.cloud.image_info:
    filters:
      is_protected: False
'''

RETURN = r'''
images:
  description: List of dictionaries describing matching images.
  returned: always
  type: list
  elements: dict
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


class ImageInfoModule(OpenStackModule):

    argument_spec = dict(
        filters=dict(type='dict', aliases=['properties']),
        name=dict(aliases=['image']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['filters']
                      if self.params[k] is not None)

        name_or_id = self.params['name']
        if name_or_id is not None:
            kwargs['name_or_id'] = name_or_id

        self.exit(changed=False,
                  images=[i.to_dict(computed=False)
                          for i in self.conn.search_images(**kwargs)])


def main():
    module = ImageInfoModule()
    module()


if __name__ == '__main__':
    main()
