#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_disk
short_description: "Module to manage Virtual Machine and floating disks in oVirt/RHV"
version_added: "1.0.0"
author: "oVirt Developers (@oVirt)"
description:
    - "Module to manage Virtual Machine and floating disks in oVirt/RHV."
    - "WARNING: If you are installing the collection from ansible galaxy you need to install 'qemu-img' package."
options:
    id:
        description:
            - "ID of the disk to manage. Either C(id) or C(name)/C(alias) is required."
        type: str
    name:
        description:
            - "Name of the disk to manage. Either C(id) or C(name)/C(alias) is required."
        aliases: ['alias']
        type: str
    description:
        description:
            - "Description of the disk image to manage."
        type: str
    vm_name:
        description:
            - "Name of the Virtual Machine to manage. Either C(vm_id) or C(vm_name) is required if C(state) is I(attached) or I(detached)."
        type: str
    vm_id:
        description:
            - "ID of the Virtual Machine to manage. Either C(vm_id) or C(vm_name) is required if C(state) is I(attached) or I(detached)."
        type: str
    state:
        description:
            - "Should the Virtual Machine disk be present/absent/attached/detached/exported/imported."
        choices: ['present', 'absent', 'attached', 'detached', 'exported', 'imported']
        default: 'present'
        type: str
    download_image_path:
        description:
            - "Path on a file system where disk should be downloaded."
            - "Note that you must have an valid oVirt/RHV engine CA in your system trust store
               or you must provide it in C(ca_file) parameter."
            - "Note that the disk is not downloaded when the file already exists,
               but you can forcibly download the disk when using C(force) I (true)."
        type: str
    upload_image_path:
        description:
            - "Path to disk image, which should be uploaded."
            - "Note if C(size) is not specified the size of the disk will be determined by the size of the specified image."
            - "Note that currently we support only compatibility version 0.10 of the qcow disk."
            - "Note that you must have an valid oVirt/RHV engine CA in your system trust store
               or you must provide it in C(ca_file) parameter."
            - "Note that there is no reliable way to achieve idempotency, so
               if you want to upload the disk even if the disk with C(id) or C(name) exists,
               then please use C(force) I(true). If you will use C(force) I(false), which
               is default, then the disk image won't be uploaded."
            - "Note that in order to upload iso the C(format) should be 'raw'."
        type: str
        aliases: ['image_path']
    size:
        description:
            - "Size of the disk. Size should be specified using IEC standard units.
               For example 10GiB, 1024MiB, etc."
            - "Size can be only increased, not decreased."
            - "If the disk is referenced by C(name) and is attached to a VM, make sure to specify C(vm_name)/C(vm_id)
               to prevent extension of another disk that is not attached to the VM."
        type: str
    interface:
        description:
            - "Driver of the storage interface."
            - "It's required parameter when creating the new disk."
        choices: ['virtio', 'ide', 'sata', 'virtio_scsi']
        type: str
    format:
        description:
            - Specify format of the disk.
            - Note that this option isn't idempotent as it's not currently possible to change format of the disk via API.
        choices: ['raw', 'cow']
        default: 'cow'
        type: str
    content_type:
        description:
            - Specify if the disk is a data disk or ISO image or a one of a the Hosted Engine disk types
            - The Hosted Engine disk content types are available with Engine 4.3+ and Ansible 2.8
        choices: ['data', 'iso', 'hosted_engine', 'hosted_engine_sanlock', 'hosted_engine_metadata', 'hosted_engine_configuration']
        default: 'data'
        type: str
    sparse:
        required: False
        type: bool
        description:
            - "I(True) if the disk should be sparse (also known as I(thin provision)).
              If the parameter is omitted, cow disks will be created as sparse and raw disks as I(preallocated)"
            - Note that this option isn't idempotent as it's not currently possible to change sparseness of the disk via API.
    storage_domain:
        description:
            - "Storage domain name where disk should be created."
        type: str
    storage_domains:
        description:
            - "Storage domain names where disk should be copied."
            - "C(**IMPORTANT**)"
            - "There is no reliable way to achieve idempotency, so every time
               you specify this parameter the disks are copied, so please handle
               your playbook accordingly to not copy the disks all the time. This
               is valid only for VM and floating disks, template disks works
               as expected."
        type: list
        elements: str
    force:
        description:
            - "Please take a look at C(image_path) documentation to see the correct
               usage of this parameter."
        type: bool
        default: false
    profile:
        description:
            - "Disk profile name to be attached to disk. By default profile is chosen by oVirt/RHV engine."
        type: str
    quota_id:
        description:
            - "Disk quota ID to be used for disk. By default quota is chosen by oVirt/RHV engine."
        type: str
    bootable:
        description:
            - "I(True) if the disk should be bootable. By default when disk is created it isn't bootable."
        type: bool
    shareable:
        description:
            - "I(True) if the disk should be shareable. By default when disk is created it isn't shareable."
        type: bool
    read_only:
        description:
            - "I(True) if the disk should be read_only. By default when disk is created it isn't read_only."
        type: bool
    logical_unit:
        description:
            - "Dictionary which describes LUN to be directly attached to VM:"
        suboptions:
            address:
                description:
                    - Address of the storage server. Used by iSCSI.
            port:
                description:
                    - Port of the storage server. Used by iSCSI.
            target:
                description:
                    - iSCSI target.
            id:
                description:
                    - LUN id.
            username:
                description:
                    - CHAP Username to be used to access storage server. Used by iSCSI.
            password:
                description:
                    - CHAP Password of the user to be used to access storage server. Used by iSCSI.
            storage_type:
                description:
                    - Storage type either I(fcp) or I(iscsi).
        type: dict
    sparsify:
        description:
            - "I(True) if the disk should be sparsified."
            - "Sparsification frees space in the disk image that is not used by
               its filesystem. As a result, the image will occupy less space on
               the storage."
            - "Note that this parameter isn't idempotent, as it's not possible
               to check if the disk should be or should not be sparsified."
        type: bool
    openstack_volume_type:
        description:
            - "Name of the openstack volume type. This is valid when working
               with cinder."
        type: str
    image_provider:
        description:
            - "When C(state) is I(exported) disk is exported to given Glance image provider."
            - "When C(state) is I(imported) disk is imported from given Glance image provider."
            - "C(**IMPORTANT**)"
            - "There is no reliable way to achieve idempotency, so every time
               you specify this parameter the disk is exported, so please handle
               your playbook accordingly to not export the disk all the time.
               This option is valid only for template disks."
        type: str
    host:
        description:
            - "When the hypervisor name is specified the newly created disk or
               an existing disk will refresh its information about the
               underlying storage( Disk size, Serial, Product ID, Vendor ID ...)
               The specified host will be used for gathering the storage
               related information. This option is only valid for passthrough
               disks. This option requires at least the logical_unit.id to be
               specified"
        type: str
    wipe_after_delete:
        description:
            - "If the disk's Wipe After Delete is enabled, then the disk is first wiped."
        type: bool
    activate:
        description:
            - I(True) if the disk should be activated.
            - When creating disk of Virtual Machine it is set to I(True).
        type: bool
    backup:
        description:
            - The backup behavior supported by the disk.
        choices: ['incremental']
        version_added: 1.1.0
        type: str
    scsi_passthrough:
        description:
            - Indicates whether SCSI passthrough is enable and its policy.
            - Setting a value of `filtered`/`unfiltered` will enable SCSI passthrough for a LUN disk with unprivileged/privileged SCSI I/O.
            - To disable SCSI passthrough the value should be set to `disabled`
        choices: ['disabled', 'filtered', 'unfiltered']
        type: str
        version_added: 1.2.0
    propagate_errors:
        description:
            - Indicates if disk errors should cause Virtual Machine to be paused or if disk errors should be
            - propagated to the the guest operating system instead.
        type: bool
        version_added: 1.2.0
    pass_discard:
        description:
            - Defines whether the Virtual Machine passes discard commands to the storage.
        type: bool
        version_added: 1.2.0
    uses_scsi_reservation:
        description:
            - Defines whether SCSI reservation is enabled for this disk.
        type: bool
        version_added: 1.2.0
    max_workers:
        description:
            - The number of workers which should be used in the upload/download of the image.
            - The use of multiple workers can speed up the process.
        type: int
        version_added: 1.7.0
extends_documentation_fragment: ovirt.ovirt.ovirt
'''


EXAMPLES = '''
# Examples don't contain auth parameter for simplicity,
# look at ovirt_auth module to see how to reuse authentication:

# Create and attach new disk to VM
- ovirt.ovirt.ovirt_disk:
    name: myvm_disk
    vm_name: rhel7
    size: 10GiB
    format: cow
    interface: virtio
    storage_domain: data

# Attach logical unit to VM rhel7
- ovirt.ovirt.ovirt_disk:
    vm_name: rhel7
    logical_unit:
      target: iqn.2016-08-09.brq.str-01:omachace
      id: 1IET_000d0001
      address: 10.34.63.204
    interface: virtio

# Detach disk from VM
- ovirt.ovirt.ovirt_disk:
    state: detached
    name: myvm_disk
    vm_name: rhel7
    size: 10GiB
    format: cow
    interface: virtio

# Change Disk Name
- ovirt.ovirt.ovirt_disk:
    id: 00000000-0000-0000-0000-000000000000
    storage_domain: data
    name: "new_disk_name"
    vm_name: rhel7

# Upload local image to disk and attach it to vm:
# Since Ansible 2.3
- ovirt.ovirt.ovirt_disk:
    name: mydisk
    vm_name: myvm
    interface: virtio
    size: 10GiB
    format: cow
    image_path: /path/to/mydisk.qcow2
    storage_domain: data

# Download disk to local file system:
# Since Ansible 2.3
- ovirt.ovirt.ovirt_disk:
    id: 7de90f31-222c-436c-a1ca-7e655bd5b60c
    download_image_path: /home/user/mydisk.qcow2

# Export disk as image to Glance domain
# Since Ansible 2.4
- ovirt.ovirt.ovirt_disk:
    id: 7de90f31-222c-436c-a1ca-7e655bd5b60c
    image_provider: myglance
    state: exported

# Defining a specific quota while creating a disk image:
# Since Ansible 2.5
- ovirt.ovirt.ovirt_quotas_info:
    data_center: Default
    name: myquota
  register: quota
- ovirt.ovirt.ovirt_disk:
    name: mydisk
    size: 10GiB
    storage_domain: data
    description: somedescriptionhere
    quota_id: "{{ quota.ovirt_quotas[0]['id'] }}"

# Upload an ISO image
# Since Ansible 2.8
- ovirt.ovirt.ovirt_disk:
    name: myiso
    upload_image_path: /path/to/iso/image
    storage_domain: data
    size: 4 GiB
    wait: true
    bootable: true
    format: raw
    content_type: iso

# Add fiber chanel disk
- name: Create disk
  ovirt.ovirt.ovirt_disk:
    name: fcp_disk
    host: my_host
    logical_unit:
      id: 3600a09803830447a4f244c4657597777
      storage_type: fcp
'''


RETURN = '''
id:
    description: "ID of the managed disk"
    returned: "On success if disk is found."
    type: str
    sample: 7de90f31-222c-436c-a1ca-7e655bd5b60c
disk:
    description: "Dictionary of all the disk attributes. Disk attributes can be found on your oVirt/RHV instance
                  at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/disk."
    returned: "On success if disk is found and C(vm_id) or C(vm_name) wasn't passed."
    type: dict

disk_attachment:
    description: "Dictionary of all the disk attachment attributes. Disk attachment attributes can be found
                  on your oVirt/RHV instance at following url:
                  http://ovirt.github.io/ovirt-engine-api-model/master/#types/disk_attachment."
    returned: "On success if disk is found and C(vm_id) or C(vm_name) was passed and VM was found."
    type: dict
'''

import json
import os
import subprocess
import time
import traceback
import inspect

from ansible.module_utils.six.moves.http_client import HTTPSConnection
from ansible.module_utils.six.moves.urllib.parse import urlparse
try:
    import ovirtsdk4 as sdk
    import ovirtsdk4.types as otypes
    from ovirt_imageio import client
except ImportError:
    pass
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import (
    BaseModule,
    check_sdk,
    check_params,
    create_connection,
    convert_to_bytes,
    equal,
    follow_link,
    get_id_by_name,
    ovirt_full_argument_spec,
    search_by_name,
    wait,
)


def _search_by_lun(disks_service, lun_id):
    """
    Find disk by LUN ID.
    """
    res = [
        disk for disk in disks_service.list(search='disk_type=lun') if (
            disk.lun_storage.id == lun_id
        )
    ]
    return res[0] if res else None


def create_transfer_connection(module, transfer, context, connect_timeout=10, read_timeout=60):
    url = urlparse(transfer.transfer_url)
    connection = HTTPSConnection(
        url.netloc, context=context, timeout=connect_timeout)
    try:
        connection.connect()
    except Exception as e:
        # Typically, "ConnectionRefusedError" or "socket.gaierror".
        module.warn("Cannot connect to %s, trying %s: %s" % (transfer.transfer_url, transfer.proxy_url, e))

        url = urlparse(transfer.proxy_url)
        connection = HTTPSConnection(
            url.netloc, context=context, timeout=connect_timeout)
        connection.connect()

    connection.sock.settimeout(read_timeout)
    return connection, url


def start_transfer(connection, module, direction):
    transfers_service = connection.system_service().image_transfers_service()
    hosts_service = connection.system_service().hosts_service()
    transfer = transfers_service.add(
        otypes.ImageTransfer(
            disk=otypes.Disk(id=module.params.get('id')),
            direction=direction,
            timeout_policy=otypes.ImageTransferTimeoutPolicy.LEGACY,
            host=otypes.Host(
                id=get_id_by_name(hosts_service, module.params.get('host'))
            ) if module.params.get('host') else None,
            # format=raw uses the NBD backend, enabling:
            # - Transfer raw guest data, regardless of the disk format.
            # - Automatic format conversion to remote disk format. For example,
            #   upload qcow2 image to raw disk, or raw image to qcow2 disk.
            # - Collapsed qcow2 chains to single raw file.
            # - Extents reporting for qcow2 images and raw images on file storage,
            #   speeding up downloads.
            format=otypes.DiskFormat.RAW,
        )
    )
    transfer_service = transfers_service.image_transfer_service(transfer.id)

    start = time.time()

    while True:
        time.sleep(1)
        try:
            transfer = transfer_service.get()
        except sdk.NotFoundError:
            # The system has removed the disk and the transfer.
            raise RuntimeError("Transfer {0} was removed".format(transfer.id))

        if transfer.phase == otypes.ImageTransferPhase.FINISHED_FAILURE:
            # The system will remove the disk and the transfer soon.
            raise RuntimeError("Transfer {0} has failed".format(transfer.id))

        if transfer.phase == otypes.ImageTransferPhase.PAUSED_SYSTEM:
            transfer_service.cancel()
            raise RuntimeError(
                "Transfer {0} was paused by system".format(transfer.id))

        if transfer.phase == otypes.ImageTransferPhase.TRANSFERRING:
            break

        if transfer.phase != otypes.ImageTransferPhase.INITIALIZING:
            transfer_service.cancel()
            raise RuntimeError(
                "Unexpected transfer {0} phase {1}"
                .format(transfer.id, transfer.phase))

        if time.time() > start + module.params.get('timeout'):
            transfer_service.cancel()
            raise RuntimeError(
                "Timed out waiting for transfer {0}".format(transfer.id))

    hosts_service = connection.system_service().hosts_service()
    host_service = hosts_service.host_service(transfer.host.id)
    transfer.host = host_service.get()
    return transfer


def cancel_transfer(connection, transfer_id):
    transfer_service = (connection.system_service()
                        .image_transfers_service()
                        .image_transfer_service(transfer_id))
    transfer_service.cancel()


def finalize_transfer(connection, module, transfer_id):
    transfer = None
    transfer_service = (connection.system_service()
                        .image_transfers_service()
                        .image_transfer_service(transfer_id))
    start = time.time()

    transfer_service.finalize()
    while True:
        time.sleep(1)
        try:
            transfer = transfer_service.get()
        except sdk.NotFoundError:
            # Old engine (< 4.4.7): since the transfer was already deleted from
            # the database, we can assume that the disk status is already
            # updated, so we can check it only once.
            disk_service = (connection.system_service()
                            .disks_service()
                            .disk_service(module.params['id']))
            try:
                disk = disk_service.get()
            except sdk.NotFoundError:
                # Disk verification failed and the system removed the disk.
                raise RuntimeError(
                    "Transfer {0} failed: disk {1} was removed"
                    .format(transfer.id, module.params['id']))

            if disk.status == otypes.DiskStatus.OK:
                break

            raise RuntimeError(
                "Transfer {0} failed: disk {1} is '{2}'"
                .format(transfer.id, module.params['id'], disk.status))

        if transfer.phase == otypes.ImageTransferPhase.FINISHED_SUCCESS:
            break

        if transfer.phase == otypes.ImageTransferPhase.FINISHED_FAILURE:
            raise RuntimeError(
                "Transfer {0} failed, phase: {1}"
                .format(transfer.id, transfer.phase))

        if time.time() > start + module.params.get('timeout'):
            raise RuntimeError(
                "Timed out waiting for transfer {0} to finalize, phase: {1}"
                .format(transfer.id, transfer.phase))


def download_disk_image(connection, module):
    transfer = start_transfer(connection, module, otypes.ImageTransferDirection.DOWNLOAD)
    try:
        extra_args = {}
        parameters = inspect.signature(client.download).parameters
        if "proxy_url" in parameters:
            extra_args["proxy_url"] = transfer.proxy_url
        if module.params.get('max_workers') and "max_workers" in parameters:
            extra_args["max_workers"] = module.params.get('max_workers')
        client.download(
            transfer.transfer_url,
            module.params.get('download_image_path'),
            module.params.get('auth').get('ca_file'),
            fmt='qcow2' if module.params.get('format') == 'cow' else 'raw',
            secure=not module.params.get('auth').get('insecure'),
            buffer_size=client.BUFFER_SIZE,
            **extra_args
        )
    except Exception as e:
        cancel_transfer(connection, transfer.id)
        raise e
    finalize_transfer(connection, module, transfer.id)
    return True


def upload_disk_image(connection, module):
    transfer = start_transfer(connection, module, otypes.ImageTransferDirection.UPLOAD)
    try:
        extra_args = {}
        parameters = inspect.signature(client.upload).parameters
        if "proxy_url" in parameters:
            extra_args["proxy_url"] = transfer.proxy_url
        if module.params.get('max_workers') and "max_workers" in parameters:
            extra_args["max_workers"] = module.params.get('max_workers')
        client.upload(
            module.params.get('upload_image_path'),
            transfer.transfer_url,
            module.params.get('auth').get('ca_file'),
            secure=not module.params.get('auth').get('insecure'),
            buffer_size=client.BUFFER_SIZE,
            **extra_args
        )
    except Exception as e:
        cancel_transfer(connection, transfer.id)
        raise e
    finalize_transfer(connection, module, transfer.id)
    return True


class DisksModule(BaseModule):

    def build_entity(self):
        hosts_service = self._connection.system_service().hosts_service()
        logical_unit = self._module.params.get('logical_unit')
        size = convert_to_bytes(self._module.params.get('size'))
        if not size and self._module.params.get('upload_image_path'):
            out = subprocess.check_output(
                ["qemu-img", "info", "--output", "json", self._module.params.get('upload_image_path')])
            image_info = json.loads(out)
            size = image_info["virtual-size"]
        disk = otypes.Disk(
            id=self._module.params.get('id'),
            name=self._module.params.get('name'),
            description=self._module.params.get('description'),
            format=otypes.DiskFormat(
                self._module.params.get('format')
            ) if self._module.params.get('format') else None,
            content_type=otypes.DiskContentType(
                self._module.params.get('content_type')
            ) if self._module.params.get('content_type') else None,
            sparse=self._module.params.get(
                'sparse'
            ) if self._module.params.get(
                'sparse'
            ) is not None else self._module.params.get('format') != 'raw',
            openstack_volume_type=otypes.OpenStackVolumeType(
                name=self.param('openstack_volume_type')
            ) if self.param('openstack_volume_type') else None,
            provisioned_size=size,
            storage_domains=[
                otypes.StorageDomain(
                    name=self._module.params.get('storage_domain'),
                ),
            ],
            disk_profile=otypes.DiskProfile(
                id=get_id_by_name(self._connection.system_service().disk_profiles_service(), self._module.params.get('profile'))
            ) if self._module.params.get('profile') else None,
            quota=otypes.Quota(id=self._module.params.get('quota_id')) if self.param('quota_id') else None,
            shareable=self._module.params.get('shareable'),
            sgio=otypes.ScsiGenericIO(self.param('scsi_passthrough')) if self.param('scsi_passthrough') else None,
            propagate_errors=self.param('propagate_errors'),
            backup=otypes.DiskBackup(self.param('backup')) if self.param('backup') else None,
            wipe_after_delete=self.param('wipe_after_delete'),
            lun_storage=otypes.HostStorage(
                host=otypes.Host(
                    id=get_id_by_name(hosts_service, self._module.params.get('host'))
                ) if self.param('host') else None,
                type=otypes.StorageType(
                    logical_unit.get('storage_type', 'iscsi')
                ),
                logical_units=[
                    otypes.LogicalUnit(
                        address=logical_unit.get('address'),
                        port=logical_unit.get('port', 3260),
                        target=logical_unit.get('target'),
                        id=logical_unit.get('id'),
                        username=logical_unit.get('username'),
                        password=logical_unit.get('password'),
                    )
                ],
            ) if logical_unit else None,
        )
        if hasattr(disk, 'initial_size') and self._module.params['upload_image_path']:
            out = subprocess.check_output([
                'qemu-img',
                'measure',
                '-O', 'qcow2' if self._module.params.get('format') == 'cow' else 'raw',
                '--output', 'json',
                self._module.params['upload_image_path']
            ])
            measure = json.loads(out)
            disk.initial_size = measure["required"]

        return disk

    def update_storage_domains(self, disk_id):
        changed = False
        disk_service = self._service.service(disk_id)
        disk = disk_service.get()
        sds_service = self._connection.system_service().storage_domains_service()

        # We don't support move&copy for non file based storages:
        if disk.storage_type != otypes.DiskStorageType.IMAGE:
            return changed
        if disk.content_type in [
                otypes.DiskContentType(x) for x in ['hosted_engine', 'hosted_engine_sanlock', 'hosted_engine_metadata', 'hosted_engine_configuration']]:
            return changed
        # Initiate move:
        if self._module.params['storage_domain']:
            new_disk_storage_id = get_id_by_name(sds_service, self._module.params['storage_domain'])
            if new_disk_storage_id in [sd.id for sd in disk.storage_domains]:
                return changed
            changed = self.action(
                action='move',
                entity=disk,
                action_condition=lambda d: new_disk_storage_id != d.storage_domains[0].id,
                wait_condition=lambda d: d.status == otypes.DiskStatus.OK,
                storage_domain=otypes.StorageDomain(
                    id=new_disk_storage_id,
                ),
                post_action=lambda _: time.sleep(self._module.params['poll_interval']),
            )['changed']

        if self._module.params['storage_domains']:
            for sd in self._module.params['storage_domains']:
                new_disk_storage = search_by_name(sds_service, sd)
                changed = changed or self.action(
                    action='copy',
                    entity=disk,
                    action_condition=(
                        lambda d: new_disk_storage.id not in [sd.id for sd in d.storage_domains]
                    ),
                    wait_condition=lambda d: d.status == otypes.DiskStatus.OK,
                    storage_domain=otypes.StorageDomain(
                        id=new_disk_storage.id,
                    ),
                )['changed']

        return changed

    def update_check(self, entity):
        return (
            equal(self._module.params.get('name'), entity.name) and
            equal(self._module.params.get('description'), entity.description) and
            equal(self.param('quota_id'), getattr(entity.quota, 'id', None)) and
            equal(convert_to_bytes(self._module.params.get('size')), entity.provisioned_size) and
            equal(self._module.params.get('shareable'), entity.shareable) and
            equal(self.param('propagate_errors'), entity.propagate_errors) and
            equal(otypes.ScsiGenericIO(self.param('scsi_passthrough')) if self.param('scsi_passthrough') else None, entity.sgio) and
            equal(self.param('wipe_after_delete'), entity.wipe_after_delete) and
            equal(self.param('profile'), getattr(follow_link(self._connection, entity.disk_profile), 'name', None))
        )


class DiskAttachmentsModule(DisksModule):

    def build_entity(self):
        return otypes.DiskAttachment(
            disk=super(DiskAttachmentsModule, self).build_entity(),
            interface=otypes.DiskInterface(
                self._module.params.get('interface')
            ) if self._module.params.get('interface') else None,
            bootable=self._module.params.get('bootable'),
            active=self.param('activate'),
            read_only=self.param('read_only'),
            uses_scsi_reservation=self.param('uses_scsi_reservation'),
            pass_discard=self.param('pass_discard'),
        )

    def update_check(self, entity):
        return (
            super(DiskAttachmentsModule, self).update_check(follow_link(self._connection, entity.disk)) and
            equal(self._module.params.get('interface'), str(entity.interface)) and
            equal(self._module.params.get('bootable'), entity.bootable) and
            equal(self._module.params.get('pass_discard'), entity.pass_discard) and
            equal(self._module.params.get('read_only'), entity.read_only) and
            equal(self._module.params.get('uses_scsi_reservation'), entity.uses_scsi_reservation) and
            equal(self.param('activate'), entity.active)
        )


def searchable_attributes(module):
    """
    Return all searchable disk attributes passed to module.
    """
    attributes = {
        'name': module.params.get('name'),
        'Storage.name': module.params.get('storage_domain'),
        'vm_names': module.params.get('vm_name') if module.params.get('state') != 'attached' else None,
    }
    return dict((k, v) for k, v in attributes.items() if v is not None)


def get_vm_service(connection, module):
    if module.params.get('vm_id') is not None or module.params.get('vm_name') is not None and module.params['state'] != 'absent':
        vms_service = connection.system_service().vms_service()

        # If `vm_id` isn't specified, find VM by name:
        vm_id = module.params['vm_id']
        if vm_id is None:
            vm_id = get_id_by_name(vms_service, module.params['vm_name'])

        if vm_id is None:
            module.fail_json(
                msg="VM doesn't exist, please create it first."
            )

        return vms_service.vm_service(vm_id)


def main():
    argument_spec = ovirt_full_argument_spec(
        state=dict(
            choices=['present', 'absent', 'attached', 'detached', 'exported', 'imported'],
            default='present'
        ),
        id=dict(default=None),
        name=dict(default=None, aliases=['alias']),
        description=dict(default=None),
        vm_name=dict(default=None),
        vm_id=dict(default=None),
        size=dict(default=None),
        interface=dict(default=None, choices=['virtio', 'ide', 'sata', 'virtio_scsi']),
        storage_domain=dict(default=None),
        storage_domains=dict(default=None, type='list', elements='str'),
        profile=dict(default=None),
        quota_id=dict(default=None),
        format=dict(default='cow', choices=['raw', 'cow']),
        content_type=dict(
            default='data',
            choices=['data', 'iso', 'hosted_engine', 'hosted_engine_sanlock', 'hosted_engine_metadata', 'hosted_engine_configuration']
        ),
        backup=dict(default=None, type='str', choices=['incremental']),
        sparse=dict(default=None, type='bool'),
        bootable=dict(default=None, type='bool'),
        shareable=dict(default=None, type='bool'),
        scsi_passthrough=dict(default=None, type='str', choices=['disabled', 'filtered', 'unfiltered']),
        uses_scsi_reservation=dict(default=None, type='bool'),
        pass_discard=dict(default=None, type='bool'),
        propagate_errors=dict(default=None, type='bool'),
        logical_unit=dict(default=None, type='dict'),
        read_only=dict(default=None, type='bool'),
        download_image_path=dict(default=None),
        upload_image_path=dict(default=None, aliases=['image_path']),
        force=dict(default=False, type='bool'),
        sparsify=dict(default=None, type='bool'),
        openstack_volume_type=dict(default=None),
        image_provider=dict(default=None),
        host=dict(default=None),
        wipe_after_delete=dict(type='bool', default=None),
        activate=dict(default=None, type='bool'),
        max_workers=dict(default=None, type='int'),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    lun = module.params.get('logical_unit')
    host = module.params['host']
    # Fail when host is specified with the LUN id. LUN id is needed to identify
    # an existing disk if already available in the environment.
    if (host and lun is None) or (host and lun.get("id") is None):
        module.fail_json(
            msg="Can not use parameter host ({0!s}) without "
            "specifying the logical_unit id".format(host)
        )

    check_sdk(module)
    check_params(module)

    try:
        state = module.params['state']
        auth = module.params.get('auth')
        connection = create_connection(auth)
        disks_service = connection.system_service().disks_service()
        disks_module = DisksModule(
            connection=connection,
            module=module,
            service=disks_service,
        )

        force_create = False
        vm_service = get_vm_service(connection, module)
        if lun:
            disk = _search_by_lun(disks_service, lun.get('id'))
        else:
            disk = disks_module.search_entity(search_params=searchable_attributes(module))
            if vm_service and disk and state != 'attached':
                # If the VM doesn't exist in VMs disks, but still it's found it means it was found
                # for template with same name as VM, so we should force create the VM disk.
                force_create = disk.id not in [a.disk.id for a in vm_service.disk_attachments_service().list() if a.disk]

        ret = None
        # First take care of creating the VM, if needed:
        if state in ('present', 'detached', 'attached'):
            # Always activate disk when it is created.
            if vm_service is not None and disk is None:
                module.params['activate'] = module.params['activate'] is None or module.params['activate']
            ret = disks_module.create(
                entity=disk if not force_create else None,
                result_state=otypes.DiskStatus.OK if lun is None else None,
                search_params=searchable_attributes(module),
                fail_condition=lambda d: d.status == otypes.DiskStatus.ILLEGAL if lun is None else False,
                force_create=force_create,
                _wait=True if module.params['upload_image_path'] else module.params['wait'],
            )
            is_new_disk = ret['changed']
            ret['changed'] = ret['changed'] or disks_module.update_storage_domains(ret['id'])
            # We need to pass ID to the module, so in case we want to detach/attach disk
            # we have this ID specified to attach/detach method:
            module.params['id'] = ret['id']

            # Upload disk image in case it is a new disk or force parameter is passed:
            if module.params['upload_image_path'] and (is_new_disk or module.params['force']):
                if module.params['format'] == 'cow' and module.params['content_type'] == 'iso':
                    module.warn("To upload an ISO image 'format' parameter needs to be set to 'raw'.")
                uploaded = upload_disk_image(connection, module)
                ret['changed'] = ret['changed'] or uploaded
            # Download disk image in case the file doesn't exist or force parameter is passed:
            if (
                module.params['download_image_path'] and (not os.path.isfile(module.params['download_image_path']) or module.params['force'])
            ):
                downloaded = download_disk_image(connection, module)
                ret['changed'] = ret['changed'] or downloaded

            # Disk sparsify, only if disk is of image type:
            if not module.check_mode:
                disk = disks_service.disk_service(module.params['id']).get()
                if disk.storage_type == otypes.DiskStorageType.IMAGE:
                    ret = disks_module.action(
                        action='sparsify',
                        action_condition=lambda d: module.params['sparsify'],
                        wait_condition=lambda d: d.status == otypes.DiskStatus.OK,
                    )

        # Export disk as image to glance domain
        elif state == 'exported':
            disk = disks_module.search_entity()
            if disk is None:
                module.fail_json(
                    msg="Can not export given disk '%s', it doesn't exist" %
                        module.params.get('name') or module.params.get('id')
                )
            if disk.storage_type == otypes.DiskStorageType.IMAGE:
                ret = disks_module.action(
                    action='export',
                    action_condition=lambda d: module.params['image_provider'],
                    wait_condition=lambda d: d.status == otypes.DiskStatus.OK,
                    storage_domain=otypes.StorageDomain(name=module.params['image_provider']),
                )
        elif state == 'imported':
            glance_service = connection.system_service().openstack_image_providers_service()
            image_provider = search_by_name(glance_service, module.params['image_provider'])
            images_service = glance_service.service(image_provider.id).images_service()
            entity_id = get_id_by_name(images_service, module.params['name'])
            images_service.service(entity_id).import_(
                storage_domain=otypes.StorageDomain(
                    name=module.params['storage_domain']
                ) if module.params['storage_domain'] else None,
                disk=otypes.Disk(
                    name=module.params['name']
                ),
                import_as_template=False,
            )
            # Wait for disk to appear in system:
            disk = disks_module.wait_for_import(
                condition=lambda t: t.status == otypes.DiskStatus.OK
            )
            ret = disks_module.create(result_state=otypes.DiskStatus.OK)
        elif state == 'absent':
            ret = disks_module.remove()

        # If VM was passed attach/detach disks to/from the VM:
        if vm_service:
            disk_attachments_service = vm_service.disk_attachments_service()
            disk_attachments_module = DiskAttachmentsModule(
                connection=connection,
                module=module,
                service=disk_attachments_service,
                changed=ret['changed'] if ret else False,
            )

            if state == 'present' or state == 'attached':
                ret = disk_attachments_module.create()
                if lun is None:
                    wait(
                        service=disk_attachments_service.service(ret['id']),
                        condition=lambda d: follow_link(connection, d.disk).status == otypes.DiskStatus.OK,
                        wait=module.params['wait'],
                        timeout=module.params['timeout'],
                    )
            elif state == 'detached':
                ret = disk_attachments_module.remove()
        elif any([
                module.params.get('interface'),
                module.params.get('activate'),
                module.params.get('bootable'),
                module.params.get('uses_scsi_reservation'),
                module.params.get('pass_discard'), ]):
            module.warn("Cannot use 'interface', 'activate', 'bootable', 'uses_scsi_reservation' or 'pass_discard' without specifying VM.")

        # When the host parameter is specified and the disk is not being
        # removed, refresh the information about the LUN.
        if state != 'absent' and host:
            hosts_service = connection.system_service().hosts_service()
            host_id = get_id_by_name(hosts_service, host)
            disks_service.disk_service(disk.id).refresh_lun(otypes.Host(id=host_id))

        module.exit_json(**ret)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == "__main__":
    main()
