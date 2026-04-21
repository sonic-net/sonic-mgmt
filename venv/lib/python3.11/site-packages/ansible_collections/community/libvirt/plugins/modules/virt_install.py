#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025, Joey Zhang <thinkdoggie@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: virt_install
version_added: 2.0.0
author: "Joey Zhang (@thinkdoggie)"
short_description: Provision new virtual machines using virt-install tool
description:
  - Create and install virtual machines using C(virt-install) with a declarative configuration.
options:
  name:
    type: str
    description:
      - Name of the new guest virtual machine instance.
    required: true
  state:
    choices: [ present, absent ]
    type: str
    description:
      - If set to V(present), create the VM if it does not exist.
      - If set to V(absent), remove the VM if it exists.
    default: present
  recreate:
    type: bool
    description:
      - Use with present to force the re-creation of an existing VM.
    default: false
  # General options
  memory:
    type: int
    description:
      - Memory to allocate for the guest, in MiB.
  memory_opts:
    type: dict
    description:
      - Additional options for memory allocation.
    suboptions:
      current_memory:
        type: int
        description:
          - The actual allocation of memory for the guest, in MiB.
      max_memory:
        type: int
        description:
          - The run time maximum memory allocation of the guest, in MiB.
      max_memory_opts:
        type: dict
        description:
          - Additional options for maximum memory configuration.
        suboptions:
          slots:
            type: int
            description:
              - The number of slots available for adding memory to the guest.
  memorybacking:
    type: dict
    description:
      - Specify how virtual memory pages are backed by host pages
    suboptions:
      hugepages:
        type: bool
        description:
          - Use huge pages for memory backing.
      hugepage_specs:
        type: list
        elements: dict
        description:
          - Configure hugepage specifications for memory backing.
        suboptions:
          page_size:
            type: int
            description:
              - Specify the hugepage size with a unit suffix.
          nodeset:
            type: str
            description:
              - Specify the guest's NUMA nodes to certain hugepage sizes.
      nosharepages:
        type: bool
        description:
          - Instructs hypervisor to disable shared pages (memory merge, KSM) for this domain.
      locked:
        type: bool
        description:
          - Memory pages will be locked in host's memory and will not be swapped out.
      access:
        type: dict
        description:
          - Configure memory access permissions.
        suboptions:
          mode:
            type: str
            choices: [ shared, private ]
            description:
              - The access mode for the memory.
      allocation:
        type: dict
        description:
          - Configure memory allocation behavior.
        suboptions:
          mode:
            type: str
            choices: [ immediate, ondemand ]
            description:
              - Specify when to allocate the memory by supplying either V(immediate) or V(ondemand).
          threads:
            type: int
            description:
              - The number of threads that hypervisor uses to allocate memory.
      discard:
        type: bool
        description:
          - If set to V(true), the memory content is discarded just before guest shuts down (or when DIMM module is unplugged).
  arch:
    type: str
    description:
      - Request a non-native CPU architecture for the guest virtual machine.
      - If omitted, the host CPU architecture will be used in the guest.
  machine:
    type: str
    description:
      - The machine type to emulate. This will typically not need to be specified for Xen or KVM.
  metadata:
    type: dict
    description:
      - Specify the metadata for the guest virtual machine.
      - The dictionary contains key/value pairs that define individual metadata entries.
      - 'e.g. V({uuid: 4dea22b3-1d52-d8f3-2516-782e98ab3fa0})'
      - Use C(virt-install --metadata=?) to see a list of all available sub options.
  events:
    type: dict
    description:
      - Specify events values for the guest.
    suboptions:
      on_poweroff:
        type: str
        choices: [ destroy, restart, preserve, rename-restart ]
        description:
          - Action to take when the guest requests a poweroff.
      on_reboot:
        type: str
        choices: [ destroy, restart, preserve, rename-restart ]
        description:
          - Action to take when the guest requests a reboot.
      on_crash:
        type: str
        choices: [ destroy, restart, preserve, rename-restart, coredump-destroy, coredump-restart ]
        description:
          - Action to take when the guest crashes.
      on_lockfailure:
        type: str
        choices: [ poweroff, restart, pause, ignore ]
        description:
          - Action to take when when a lock manager loses resource locks.
  resource:
    type: dict
    description:
      - Specify resource partitioning for the guest.
      - The dictionary contains key/value pairs that define individual resource entries.
      - Use C(virt-install --resource=?) to see a list of all available sub options.
  sysinfo:
    type: dict
    description:
      - Configure sysinfo/SMBIOS values exposed to the VM OS.
      - The dictionary contains key/value pairs that define individual sysinfo entries.
      - Use C(virt-install --sysinfo=?) to see a list of all available sub options.
  qemu_commandline:
    type: str
    description:
      - Pass options directly to the qemu emulator. Only works for the libvirt qemu driver.
  vcpus:
    type: int
    description:
      - Number of virtual cpus to configure for the guest.
  vcpus_opts:
    type: dict
    description:
      - Additional options for virtual CPU configuration.
    suboptions:
      maxvcpus:
        type: int
        description:
          - If specified, the guest will be able to hotplug up to MAX vcpus while the guest is running.
      sockets:
        type: int
        description:
          - Total number of CPU sockets
      dies:
        type: int
        description:
          - Number of dies per socket
      clusters:
        type: int
        description:
          - number of clusters per die
      cores:
        type: int
        description:
          - Number of cores per cluster
      threads:
        type: int
        description:
          - Number of threads per core
      current:
        type: int
        description:
          - Specify whether fewer than the maximum number of virtual CPUs should be enabled.
      cpuset:
        type: str
        description:
          - A comma-separated list of physical CPU numbers that domain process and virtual CPUs can be pinned to by default.
      placement:
        type: str
        choices: [ static, auto ]
        description:
          - Indicate the CPU placement mode for domain process
      vcpu_specs:
        type: list
        elements: dict
        description:
          - Configure individual vCPU properties.
          - Each dictionary entry contains a property name and its corresponding value.
  numatune:
    type: dict
    description:
      - Tune NUMA policy for the domain process.
    suboptions:
      memory:
        type: dict
        description:
          - Specifies how to allocate memory for the domain process on a NUMA host.
        suboptions:
          mode:
            type: str
            choices: [ interleave, preferred, strict ]
            description:
              - Can be one of V(interleave), V(preferred), or V(strict) (the default)
          nodeset:
            type: str
            description:
              - Specifies the NUMA nodes to allocate memory from.
          placement:
            type: str
            choices: [ static, auto ]
            description:
              - Indicate the memory placement mode for domain process.
      memnode_specs:
        type: list
        elements: dict
        description:
          - Specify memory allocation policies per each guest NUMA node.
        suboptions:
          cellid:
            type: int
            description:
              - Specify the NUMA node ID.
          mode:
            type: str
            choices: [ interleave, preferred, strict ]
            description:
              - Can be one of V(interleave), V(preferred), or V(strict) (the default)
          nodeset:
            type: str
            description:
              - Specifies the NUMA nodes to allocate memory from.
  memtune:
    type: dict
    description:
      - Tune memory policy for the domain process.
      - The dictionary contains key/value pairs that define individual memtune entries.
  blkiotune:
    type: dict
    description:
      - Tune block I/O policy for the domain process.
    suboptions:
      weight:
        type: int
        description:
          - The overall I/O weight of the guest.
          - The value should be in the range [100, 1000]. After kernel 2.6.39, the value could be in the range [10, 1000].
      devices:
        type: list
        elements: dict
        description:
          - Tune the weights for individual host block device used by the guest.
          - Each dictionary entry contains a property name and its corresponding value.
  cpu:
    type: dict
    description:
      - Configure the CPU model and CPU features exposed to the guest.
    suboptions:
      model:
        type: str
        description:
          - A valid CPU model or configuration mode for the guest.
          - "The possible values include: V(host-model), V(host-passthrough) and V(maximum)."
      model_opts:
        type: dict
        description:
          - Additional options for CPU model configuration.
        suboptions:
          fallback:
            type: str
            choices: [ forbid, allow ]
            description:
              - Specify whether to automatically fall back to the closest model supported by the hypervisor if unable to use the exact CPU model.
          vendor_id:
            type: str
            description:
              - Set the vendor id seen by the guest. It must be exactly 12 characters long.
              - Typical possible values are I(AuthenticAMD) and I(GenuineIntel).
      match:
        type: str
        choices: [ exact, minimum, strict ]
        description:
          - Specify how strictly the CPU model should be matched.
      migratable:
        type: bool
        description:
          - Specify whether this CPU model is migratable.
      vendor:
        type: str
        description:
          - Specify CPU vendor requested by the guest
          - The list of supported vendors can be found in I(cpu_map/*_vendors.xml).
      features:
        type: dict
        description:
          - Fine-tune features provided by the selected CPU model.
          - The value should be a dictionary where each key is a feature name and the value is a dictionary of options for that feature.
          - An empty object V({}) for a feature indicates to enable that feature.
        suboptions:
          policy:
            type: str
            choices: [ force, require, optional, disable, forbid ]
            description:
              - The policy for the CPU feature.
              - If set to V(force), the vCPU will claim the feature is supported regardless of it being supported by host CPU.
              - If set to V(require), guest creation will fail unless the feature is supported by the host CPU or the hypervisor is able to emulate it.
              - If set to V(optional), the feature will be supported by vCPU if and only if it is supported by host CPU.
              - If set to V(disable), the feature will not be supported by virtual CPU.
              - If set to V(forbid), guest creation will fail if the feature is supported by host CPU.
      cache:
        type: dict
        description:
          - vCPU cache configuration for the guest.
        suboptions:
          mode:
            type: str
            choices: [ emulate, passthrough, disable ]
            description:
              - If set to V(emulate), the hypervisor will provide a fake CPU cache data.
              - If set to V(passthrough), the host CPU cache data reported by the host CPU will be passed through to the vCPU.
              - If set to V(disable), the vCPU will report no CPU cache at all.
          level:
            type: int
            description:
              - Specify the level of CPU cache.
      numa:
        type: dict
        description:
          - Configure NUMA topology for the guest.
        suboptions:
          cell_specs:
            type: list
            elements: dict
            description:
              - Specify a NUMA cell configuration.
            suboptions:
              id:
                type: int
                description:
                  - Specify the NUMA node ID.
              cpus:
                type: str
                description:
                  - Specify the CPU or range of CPUs that are part of this node.
              memory:
                type: int
                description:
                  - Specify the node memory size with a unit suffix.
              mem_access:
                type: str
                choices: [ shared, private ]
                description:
                  - Specify the memory access mode for the NUMA node.
                  - This is valid only for hugepages-backed memory and nvdimm modules.
              discard:
                type: bool
                description:
                  - Fine tune the discard feature for given NUMA node.
              distances:
                type: dict
                description:
                  - Define the distance between NUMA cells.
                suboptions:
                  sibling_specs:
                    type: list
                    elements: dict
                    description:
                      - Specify the distance value between sibling NUMA cells.
                      - Each dictionary entry contains a property name and its corresponding value.
              cache_specs:
                type: list
                elements: dict
                description:
                  - Describe memory side cache for memory proximity domains.
                  - Each dictionary entry contains a property name and its corresponding value.
          interconnects:
            type: list
            elements: dict
            description:
              - Describes the normalized memory read/write latency and bandwidth between Initiator Proximity Domains and Target Proximity Domains.
            suboptions:
              bandwidth_specs:
                type: list
                elements: dict
                description:
                  - Describe bandwidth between two memory nodes.
                  - Each dictionary entry contains a property name and its corresponding value.
              latency_specs:
                type: list
                elements: dict
                description:
                  - Describe latency between two memory nodes.
                  - Each dictionary entry contains a property name and its corresponding value.
  cputune:
    type: dict
    description:
      - Tune CPU parameters for the guest.
    suboptions:
      vcpupin_specs:
        type: list
        elements: dict
        description:
          - Specify which of host's physical CPUs the domain vCPU will be pinned to
        suboptions:
          vcpu:
            type: int
            description:
              - Specify the vCPU ID.
          cpuset:
            type: str
            description:
              - A comma-separated list of physical CPU numbers.
      emulatorpin:
        type: dict
        description:
          - Specify which host CPUs the domain emulator will be pinned to.
        suboptions:
          cpuset:
            type: str
            description:
              - Specify which physical CPUs to pin to.
      iothreadpin_specs:
        type: list
        elements: dict
        description:
          - Specify which of host physical CPUs the IOThreads will be pinned to.
        suboptions:
          iothread:
            type: int
            description:
              - Specify the IOThread ID.
          cpuset:
            type: str
            description:
              - Specify which physical CPUs to pin to.
      vcpusched_specs:
        type: list
        elements: dict
        description:
          - Specify the scheduler type for particular vCPUs.
        suboptions:
          vcpus:
            type: str
            description:
              - Select which vCPUs this setting applies to.
          scheduler:
            type: str
            choices: [ batch, idle, fifo, rr ]
            description:
              - The scheduler type.
          priority:
            type: int
            description:
              - For real-time schedulers (fifo, rr), priority must be specified as well (and is ignored for non-real-time ones).
              - The value range for the priority depends on the host kernel (usually 1-99).
      iothreadsched_specs:
        type: list
        elements: dict
        description:
          - Specify the scheduler type for particular IOThreads.
        suboptions:
          iothreads:
            type: str
            description:
              - Select which IOThreads this setting applies to.
          scheduler:
            type: str
            choices: [ batch, idle, fifo, rr ]
            description:
              - The scheduler type.
          priority:
            type: int
            description:
              - For real-time schedulers (fifo, rr), priority must be specified as well (and is ignored for non-real-time ones).
              - The value range for the priority depends on the host kernel (usually 1-99).
      emulatorsched:
        type: dict
        description:
          - Specify the scheduler type for emulator thread.
        suboptions:
          scheduler:
            type: str
            choices: [ batch, idle, fifo, rr ]
            description:
              - The scheduler type.
          priority:
            type: int
            description:
              - For real-time schedulers (fifo, rr), priority must be specified as well (and is ignored for non-real-time ones).
              - The value range for the priority depends on the host kernel (usually 1-99).
      shares:
        type: int
        description:
          - Specify the proportional weighted share for the domain.
      period:
        type: int
        description:
          - "Specify the enforcement interval (unit: microseconds)."
          - The value should be in range [1000, 1000000]. A period with value 0 means no value.
      quota:
        type: int
        description:
          - "Specify the maximum allowed bandwidth (unit: microseconds)."
          - A domain with quota as any negative value indicates that the domain has infinite bandwidth for vCPU threads.
      global_period:
        type: int
        description:
          - "Specify the enforcement CFS scheduler interval (unit: microseconds) for the whole domain."
      global_quota:
        type: int
        description:
          - "Specify the maximum allowed bandwidth (unit: microseconds) within a period for the whole domain."
      emulator_period:
        type: int
        description:
          - "Specify the enforcement interval (unit: microseconds) for domain's emulator threads."
      emulator_quota:
        type: int
        description:
          - "Specify the maximum allowed bandwidth (unit: microseconds) for domain's emulator threads."
      iothread_period:
        type: int
        description:
          - "Specify the enforcement interval (unit: microseconds) for domain's IOThreads."
      iothread_quota:
        type: int
        description:
          - "Specify the maximum allowed bandwidth (unit: microseconds) for domain's IOThreads."
  security:
    type: dict
    description:
      - Configure domain seclabel domain settings.
      - The dictionary contains key/value pairs that define individual security entries.
  keywrap:
    type: dict
    description:
      - Configure domain keywrap settings used for S390 cryptographic key management operations.
    suboptions:
      ciphers:
        type: list
        elements: dict
        description:
          - Specify the cipher settings for the domain.
          - Each dictionary entry contains a property name and its corresponding value.
  iothreads:
    type: int
    description:
      - Number of I/O threads to configure for the guest.
  iothreads_opts:
    type: dict
    description:
      - Additional options for I/O threads configuration.
    suboptions:
      iothread_specs:
        type: list
        elements: dict
        description:
          - Provide the capability to specifically define the IOThread ID's for the domain.
        suboptions:
          id:
            type: int
            description:
              - Define the IOThread ID.
          thread_pool_min:
            type: int
            description:
              - Set lower boundary for number of worker threads for given IOThread.
          thread_pool_max:
            type: int
            description:
              - Set upper boundary for number of worker threads for given IOThread.
      defaultiothread:
        type: dict
        description:
          - Provide the capability to define the default event loop within hypervisor.
        suboptions:
          thread_pool_min:
            type: int
            description:
              - Set lower boundary for number of worker threads for given IOThread.
          thread_pool_max:
            type: int
            description:
              - Set upper boundary for number of worker threads for given IOThread.
  features:
    type: dict
    description:
      - Enable or disable certain machine features.
      - The value should be a dictionary where each key is a feature name and the value is a dictionary of options for that feature.
      - An empty object V({}) for a feature indicates to turn on that feature with default options.
      - 'Example: V(hyperv.spinlocks: {state: off}), V(pvspinlock: {})'
  clock:
    type: dict
    description:
      - Configure the clock for the guest.
    suboptions:
      offset:
        type: str
        description:
          - Set the clock offset, e.g. V(utc) or V(localtime).
      timers:
        type: list
        elements: dict
        description:
          - Tweak the guest's timer settings on the specific hypervisor.
          - Each dictionary entry contains a property name and its corresponding value.
  pm:
    type: dict
    description:
      - Configure the power management for the guest.
    suboptions:
      suspend_to_mem:
        type: dict
        description:
          - Configure BIOS support for S3 (suspend-to-mem) ACPI sleep states.
        suboptions:
          enabled:
            type: bool
            description:
              - Enable or disable this sleep state.
      suspend_to_disk:
        type: dict
        description:
          - Configure BIOS support for S4 (suspend-to-disk) ACPI sleep states.
        suboptions:
          enabled:
            type: bool
            description:
              - Enable or disable this sleep state.
  launch_security:
    type: dict
    description:
      - Enable launch security for the guest.
    suboptions:
      type:
        type: str
        description:
          - The type of launch security to enable, e.g. V(sev).
        required: true
      policy:
        type: str
        description:
          - The guest policy which must be maintained by the SEV firmware, e.g. V(0x01).
      cbitpos:
        type: int
        description:
          - The C-bit (aka encryption bit) location in guest page table entry.
      reduced_phys_bits:
        type: int
        description:
          - The physical address bit reduction, e.g. V(1).
      dh_cert:
        type: str
        description:
          - The guest owners base64 encoded Diffie-Hellman (DH) key.
      session:
        type: str
        description:
          - The guest owners base64 encoded session blob defined in the SEV API spec.
  # Installation options
  cdrom:
    type: str
    description:
      - ISO file or CDROM device to use for VM install media.
  location:
    type: str
    description:
      - The installation source, which can be a URL or a directory path containing the OS distribution installation media.
  location_opts:
    type: dict
    description:
      - Additional options for the installation source.
    suboptions:
      kernel:
        type: str
        description:
          - The kernel path relative to the specified location.
      initrd:
        type: str
        description:
          - The initrd path relative to the specified location.
  pxe:
    type: bool
    description:
      - Install the guest from PXE.
  import:
    type: bool
    description:
      - Skip the OS installation process, and build a guest around an existing disk image.
  extra_args:
    type: str
    description:
      - Additional kernel command line arguments to pass to the installer when performing a guest install with O(location).
  initrd_inject:
    type: str
    description:
      - Add PATH to the root of the initrd fetched with O(location).
  install:
    type: dict
    description:
      - Additional options for the installation.
      - This option is strictly for VM install operations, essentially configuring the first boot.
    suboptions:
      os:
        type: str
        description:
          - The OS name from I(libosinfo), e.g. V(fedora29).
        required: true
      kernel:
        type: str
        description:
          - Specify a kernel and initrd pair to use as install media.
      initrd:
        type: str
        description:
          - Specify a kernel and initrd pair to use as install media.
      kernel_args:
        type: str
        description:
          - Specify the installation-time kernel arguments.
      kernel_args_overwrite:
        type: bool
        description:
          - Override the virt-install default kernel arguments rather than appending to them.
      bootdev:
        type: str
        description:
          - Specify the install bootdev to boot for the install phase.
      no_install:
        type: bool
        description:
          - Tell virt-install that there isn't actually any install happening, and you just want to create the VM.
  unattended:
    type: dict
    description:
      - Perform an unattended install using libosinfo's install script support.
    suboptions:
      profile:
        type: str
        description:
          - Choose which I(libosinfo) unattended profile to use.
      admin_password_file:
        type: str
        description:
          - A file used to set the VM OS admin/root password from.
      user_login:
        type: str
        description:
          - The user login name to be used in the VM.
      user_password_file:
        type: str
        description:
          - A file used to set the VM user password.
      product_key:
        type: str
        description:
          - Set a Windows product key.
  cloud_init:
    type: dict
    description:
      - Pass cloud-init metadata to the VM.
      - A cloud-init NoCloud ISO file is generated, and attached to the VM as a CDROM device.
    suboptions:
      root_password_generate:
        type: bool
        description:
          - Generate a new root password for the VM.
      disable:
        type: bool
        description:
          - Disable cloud-init in the VM for subsequent boots.
          - Without this, cloud-init may reset auth on each boot.
      root_password_file:
        type: str
        description:
          - A file used to set the VM root password from.
      root_ssh_key:
        type: str
        description:
          - Specify a public key file to inject into the guest.
      clouduser_ssh_key:
        type: str
        description:
          - Specify a public key file to inject into the guest, providing ssh access to the default cloud-init user account.
      network_config:
        type: str
        description:
          - Specify a cloud-init network-config file content.
      meta_data:
        type: dict
        description:
          - Specify a cloud-init meta-data file content.
      user_data:
        type: dict
        description:
          - Specify a cloud-init user-data file content.
  boot:
    type: str
    description:
      - Set the boot device priority for post-install configuration.
  boot_opts:
    type: dict
    description:
      - Additional options for boot configuration.
      - The dictionary contains key/value pairs that define individual boot options.
  idmap:
    type: dict
    description:
      - Configure the UID or GID mapping for the guest.
    suboptions:
      uid:
        type: dict
        description:
          - The UID mapping configuration.
        suboptions:
          start:
            type: int
            description:
              - First user ID in container.
          target:
            type: int
            description:
              - The first user ID in container will be mapped to this target user ID in host.
          count:
            type: int
            description:
              - How many users in container are allowed to map to host's user.
      gid:
        type: dict
        description:
          - The GID mapping configuration.
        suboptions:
          start:
            type: int
            description:
              - First group ID in container.
          target:
            type: int
            description:
              - The first group ID in container will be mapped to this target user ID in host.
          count:
            type: int
            description:
              - How many groups in container are allowed to map to host's user.
  # Guest OS options
  osinfo:
    type: dict
    description:
      - Optimize the guest configuration for a specific operating system.
    suboptions:
      name:
        type: str
        aliases: [ short_id ]
        description:
          - The OS name from libosinfo. (e.g. V(fedora32), V(win10))
      id:
        type: str
        description:
          - The full URL style libosinfo ID.
      detect:
        type: bool
        description:
          - Whether C(virt-install) should attempt OS detection from the specified install media.
      require:
        type: bool
        description:
          - Whether C(virt-install) should fail if OS detection fails.
  # Storage Options
  disks:
    type: list
    elements: dict
    description:
      - Specify the storage devices for the guest.
    suboptions:
      path:
        type: str
        description:
          - The path to some storage media to use, existing or not.
      pool:
        type: str
        description:
          - An existing libvirt storage pool name to create new storage on.
      vol:
        type: str
        description:
          - An existing libvirt storage volume to use.
      size:
        type: int
        description:
          - The size (in GiB) to use if creating new storage.
      sparse:
        type: bool
        description:
          - Whether to skip fully allocating newly created storage.
      format:
        type: str
        description:
          - Disk image format. For file volumes, this can be V(raw), V(qcow2), V(vmdk), etc.
      backing_store:
        type: str
        description:
          - Path to a disk to use as the backing store for the newly created image.
      backing_format:
        type: str
        description:
          - Disk image format of I(backing_store).
      bus:
        type: str
        description:
          - Disk bus type. (e.g. V(ide), V(sata), V(scsi), V(usb), V(virtio), V(xen))
      readonly:
        type: bool
        description:
          - Set drive as readonly
      shareable:
        type: bool
        description:
          - Set drive as shareable
      cache:
        type: str
        choices: [ none, writethrough, directsync, unsafe, writeback ]
        description:
          - The cache mode to be used.
      serial:
        type: str
        description:
          - Serial number of the emulated disk device.
      snapshot:
        type: str
        choices: [ "internal", "external", "no" ]
        description:
          - Indicates the default behavior of the disk during disk snapshots.
      rawio:
        type: bool
        description:
          - Specify whether the disk needs rawio capability.
      sgio:
        type: str
        choices: [ filtered, unfiltered ]
        description:
          - Specify whether unprivileged SG_IO commands are filtered for the disk.
          - Only available when the device is 'lun'.
      transient:
        type: bool
        description:
          - If V(true), this indicates that changes to the device contents should be reverted automatically when the guest exits.
      transient_opts:
        type: dict
        description:
          - Additional options for transient disk configuration.
        suboptions:
          share_backing:
            type: bool
            description:
              - If V(true), the transient disk is supposed to be shared between multiple concurrently running VMs.
      driver:
        type: dict
        description:
          - Specify the details of the hypervisor disk driver.
          - The dictionary contains key/value pairs that define individual properties.
      source:
        type: dict
        description:
          - Specify the details of the disk source.
          - The dictionary contains key/value pairs that define individual properties.
      target:
        type: dict
        description:
          - Specify the details of the target disk device.
          - The dictionary contains key/value pairs that define individual properties.
      address:
        type: dict
        description:
          - Specify the controller properties where the disk should be attached.
          - The dictionary contains key/value pairs that define individual properties.
      boot:
        type: dict
        description:
          - Specify the boot order for the disk device.
          - The dictionary contains key/value pairs that define individual properties.
          - The per-device boot elements cannot be used together with general boot elements in the OS bootloader section.
      iotune:
        type: dict
        description:
          - Specify additional per-device I/O tuning.
          - The dictionary contains key/value pairs that define individual properties.
      blockio:
        type: dict
        description:
          - Override the default block device properties for the disk.
          - The dictionary contains key/value pairs that define individual properties.
      geometry:
        type: dict
        description:
          - Override geometry settings for the disk.
          - The dictionary contains key/value pairs that define individual properties.
  filesystems:
    type: list
    elements: dict
    description:
      - Specifies directories on the host to export to the guest.
    suboptions:
      type:
        type: str
        choices: [ mount, template, file, block, ram, bind ]
        description:
          - Specify the source type of the filesystem.
      accessmode:
        type: str
        choices: [ passthrough, mapped, squash ]
        description:
          - Specify the security mode for accessing the source.
      source:
        type: dict
        description:
          - The source directory configuration on the host.
          - The dictionary contains key/value pairs that define individual properties.
      target:
        type: dict
        description:
          - The mount target configuration in the guest.
          - The dictionary contains key/value pairs that define individual properties.
      fmode:
        type: str
        description:
          - The creation mode for files when used with the V(mapped) value for I(accessmode).
      dmode:
        type: str
        description:
          - The creation mode for directories when used with the V(mapped) value for I(accessmode).
      multidevs:
        type: str
        choices: [ default, remap, forbid, warn ]
        description:
          - Specify how to deal with a filesystem export containing more than one device.
      readonly:
        type: bool
        description:
          - Enable exporting filesystem as a readonly mount for guest.
      space_hard_limit:
        type: int
        description:
          - Maximum space available to this guest's filesystem
      space_soft_limit:
        type: int
        description:
          - Maximum space available to this guest's filesystem.
      driver:
        type: dict
        description:
          - Specify the details of the hypervisor driver.
          - The dictionary contains key/value pairs that define individual properties.
      address:
        type: dict
        description:
          - Specify the controller properties where the filesystem should be attached.
          - The dictionary contains key/value pairs that define individual properties.
      binary:
        type: dict
        description:
          - Tune the options for virtiofsd.
          - The dictionary contains key/value pairs that define individual properties.
  # Network options
  networks:
    type: list
    elements: dict
    description:
      - Connect the guest to the host network.
      - Empty list V([]) means no default network interface.
    suboptions:
      type:
        type: str
        choices: [ direct ]
        description:
          - The type of network interface.
          - V(direct) provides direct attachment to host network interface using macvtap.
          - If omitted, the type of network interface is determined by other options.
      network:
        type: str
        description:
          - Name of the libvirt virtual network to connect to.
      bridge:
        type: str
        description:
          - Name of the host bridge device to connect to.
      hostdev:
        type: str
        description:
          - Name of the host device to connect to for type=hostdev.
          - This uses PCI passthrough to directly assign a network device.
      mac:
        type: dict
        description:
          - MAC address configuration for the network interface.
        suboptions:
          address:
            type: str
            description:
              - Fixed MAC address for the guest interface.
              - If not specified, a suitable address will be randomly generated.
      mtu:
        type: dict
        description:
          - Configure MTU settings for the virtual network link.
           - The dictionary contains key/value pairs that define individual properties.
      state:
        type: dict
        description:
          - Set state of the virtual network link
          - The dictionary contains key/value pairs that define individual properties.
      model:
        type: dict
        description:
          - Network device model configuration.
        suboptions:
          type:
            type: str
            description:
              - Network device model as seen by the guest.
              - Examples include V(virtio), V(e1000), V(rtl8139).
      driver:
        type: dict
        description:
          - Specify the details of the hypervisor driver.
          - The dictionary contains key/value pairs that define individual properties.
      boot:
        type: dict
        description:
          - Specify the boot order for the network interface.
          - The dictionary contains key/value pairs that define individual properties.
          - The per-device boot elements cannot be used together with general boot elements in the OS bootloader section.
      filterref:
        type: dict
        description:
          - Configure network traffic filter rules for the guest.
          - The dictionary contains key/value pairs that define individual properties.
      rom:
        type: dict
        description:
          - Specify the interface ROM BIOS configuration
          - The dictionary contains key/value pairs that define individual properties.
      source:
        type: dict
        description:
          - Specify the details of the source network interface.
          - The dictionary contains key/value pairs that define individual properties.
      target:
        type: dict
        description:
          - Specify the details of the target network device.
          - The dictionary contains key/value pairs that define individual properties.
      address:
        type: dict
        description:
          - Specify the controller properties where the filesystem should be attached.
          - The dictionary contains key/value pairs that define individual properties.
      virtualport:
        type: dict
        description:
          - Configure virtual port settings for the network interface.
          - The dictionary contains key/value pairs that define individual properties.
          - Common properties include I(type) (e.g. V(802.1Qbg), V(802.1Qbh), V(openvswitch), V(midonet)) and C(parameters) containing type-specific settings.
      trust_guest_rx_filters:
        type: bool
        description:
          - When set to V(true), enables the host to trust and accept MAC address changes and receive filter modifications reported by the guest VM.
  # Graphics Options
  graphics:
    type: dict
    description:
      - Configure the graphical display for the guest virtual machine.
      - The dictionary contains key/value pairs that define individual properties.
      - Common properties include I(type) (e.g. V(vnc), V(spice)) and I(listen).
  graphics_devices:
    type: list
    elements: dict
    description:
      - Configure multiple graphics devices for the guest.
  # Virtualization Options
  virt_type:
    type: str
    description:
      - The hypervisor used to create the VM guest. Example choices are V(kvm), V(qemu), or V(xen).
  hvm:
    type: bool
    description:
      - Request the use of full virtualization.
  paravirt:
    type: bool
    description:
      - This guest should be a paravirtualized guest.
  container:
    type: bool
    description:
      - This guest should be a container type guest.
  # Device Options
  controller:
    type: dict
    description:
      - Attach a controller device to the guest.
      - The dictionary contains key/value pairs that define individual controller properties.
      - Examples include I(type=usb,model=none) to disable USB, or I(type=scsi,model=virtio-scsi) for VirtIO SCSI.
  controller_devices:
    type: list
    elements: dict
    description:
      - Configure multiple controller devices for the guest.
  input:
    type: dict
    description:
      - Attach an input device to the guest.
      - Input device types include mouse, tablet, or keyboard.
      - The dictionary contains key/value pairs that define individual input device properties.
  input_devices:
    type: list
    elements: dict
    description:
      - Configure multiple input devices for the guest.
  hostdev:
    type: dict
    description:
      - Attach a physical host device to the guest.
      - The dictionary contains key/value pairs that define individual host device properties.
  host_devices:
    type: list
    elements: dict
    description:
      - Configure multiple host devices for the guest.
  sound:
    type: dict
    description:
      - Attach a virtual audio device to the guest.
      - The dictionary contains key/value pairs that define individual sound device properties.
      - Common properties include I(model) (e.g. V(ich6), V(ich9), V(ac97)).
  sound_devices:
    type: list
    elements: dict
    description:
      - Configure multiple sound devices for the guest.
  audio:
    type: dict
    description:
      - Configure host audio output for the guest's sound hardware.
      - The dictionary contains key/value pairs that define individual audio backend properties.
  audio_devices:
    type: list
    elements: dict
    description:
      - Configure multiple audio backends for the guest.
  watchdog:
    type: dict
    description:
      - Attach a virtual hardware watchdog device to the guest.
      - The dictionary contains key/value pairs that define individual watchdog properties.
  watchdog_devices:
    type: list
    elements: dict
    description:
      - Configure multiple watchdog devices for the guest.
  serial:
    type: dict
    description:
      - Attach a serial device to the guest with various redirection options.
      - The dictionary contains key/value pairs that define individual serial device properties.
  serial_devices:
    type: list
    elements: dict
    description:
      - Configure multiple serial devices for the guest.
  parallel:
    type: dict
    description:
      - Attach a parallel device to the guest.
      - The dictionary contains key/value pairs that define individual parallel device properties.
  parallel_devices:
    type: list
    elements: dict
    description:
      - Configure multiple parallel devices for the guest.
  channel:
    type: dict
    description:
      - Attach a communication channel device to connect the guest and host machine.
      - The dictionary contains key/value pairs that define individual channel properties.
  channel_devices:
    type: list
    elements: dict
    description:
      - Configure multiple channel devices for the guest.
  console:
    type: dict
    description:
      - Connect a text console between the guest and host.
      - The dictionary contains key/value pairs that define individual console properties.
      - Common properties include I(type) and I(target) for different console types.
  console_devices:
    type: list
    elements: dict
    description:
      - Configure multiple console devices for the guest.
  video:
    type: dict
    description:
      - Specify what video device model will be attached to the guest.
      - The dictionary contains key/value pairs that define individual video device properties.
  video_devices:
    type: list
    elements: dict
    description:
      - Configure multiple video devices for the guest.
  smartcard:
    type: dict
    description:
      - Configure a virtual smartcard device.
      - The dictionary contains key/value pairs that define individual smartcard properties.
  smartcard_devices:
    type: list
    elements: dict
    description:
      - Configure multiple smartcard devices for the guest.
  redirdev:
    type: dict
    description:
      - Add a redirected device for USB or other device redirection.
      - The dictionary contains key/value pairs that define individual redirection properties.
      - Common properties include I(bus=usb), I(type=tcp) or I(type=spicevmc).
  redirected_devices:
    type: list
    elements: dict
    description:
      - Configure multiple redirected devices for the guest.
  memballoon:
    type: dict
    description:
      - Attach a virtual memory balloon device to the guest.
      - The dictionary contains key/value pairs that define individual memory balloon properties.
      - Common properties include I(model) (e.g. V(virtio), V(xen)).
  memballoon_devices:
    type: list
    elements: dict
    description:
      - Configure multiple memory balloon devices for the guest.
  tpm:
    type: dict
    description:
      - Configure a virtual TPM (Trusted Platform Module) device.
      - The dictionary contains key/value pairs that define individual TPM properties.
  tpm_devices:
    type: list
    elements: dict
    description:
      - Configure multiple TPM devices for the guest.
  rng:
    type: dict
    description:
      - Configure a virtual random number generator (RNG) device.
      - The dictionary contains key/value pairs that define individual RNG properties.
  rng_devices:
    type: list
    elements: dict
    description:
      - Configure multiple RNG devices for the guest.
  panic:
    type: dict
    description:
      - Attach a panic notifier device to the guest.
      - The dictionary contains key/value pairs that define individual panic device properties.
  panic_devices:
    type: list
    elements: dict
    description:
      - Configure multiple panic devices for the guest.
  shmem:
    type: dict
    description:
      - Attach a shared memory device to the guest.
      - The dictionary contains key/value pairs that define individual shared memory properties.
  shmem_devices:
    type: list
    elements: dict
    description:
      - Configure multiple shared memory devices for the guest.
  vsock:
    type: dict
    description:
      - Configure a vsock host/guest interface.
      - The dictionary contains key/value pairs that define individual vsock properties.
  vsock_devices:
    type: list
    elements: dict
    description:
      - Configure multiple vsock devices for the guest.
  iommu:
    type: dict
    description:
      - Add an IOMMU device to the guest.
      - The dictionary contains key/value pairs that define individual IOMMU properties.
  iommu_devices:
    type: list
    elements: dict
    description:
      - Configure multiple IOMMU devices for the guest.
  # Miscellaneous Options
  autostart:
    type: bool
    description:
      - Set the autostart flag for a domain.
  transient:
    type: bool
    description:
      - If set to V(true), libvirt forgets the XML configuration of the VM after shutdown or host restart.
  destroy_on_exit:
    type: bool
    description:
      - If set to V(true), the VM will be destroyed when the console window is exited.
  noreboot:
    type: bool
    description:
      - If set to V(true), the VM will not automatically reboot after the install has completed.
extends_documentation_fragment:
    - community.libvirt.virt.options_uri
    - community.libvirt.requirements
attributes:
    check_mode:
        description: Supports check_mode.
        support: full
requirements:
    - "virt-install"
notes:
    - The C(virt-install) command is provided by different packages on different distributions.
    - On Debian/Ubuntu, install the C(virtinst) package.
    - On RHEL/CentOS/Fedora and openSUSE, install the C(virt-install) package.
seealso:
  - name: virt-install Man Page
    description: Ubuntu manpage of virt-install tool.
    link: https://manpages.ubuntu.com/manpages/focal/man1/virt-install.1.html
"""

EXAMPLES = """
# Basic VM creation with Fedora installation
- name: Create a basic Fedora VM
  community.libvirt.virt_install:
    name: my-fedora-vm
    memory: 2048
    vcpus: 2
    disks:
      - size: 20
    osinfo:
      name: fedora39
    location: https://download.fedoraproject.org/pub/fedora/linux/releases/39/Server/x86_64/
    graphics:
      type: spice
    networks:
      - network: default

# Windows 10 VM with CDROM installation
- name: Create Windows 10 VM
  community.libvirt.virt_install:
    name: my-win10-vm
    memory: 4096
    vcpus: 4
    disks:
      - size: 40
        format: qcow2
    osinfo:
      name: win10
    cdrom: /path/to/my/win10.iso
    graphics:
      type: vnc
      password: mypassword
    networks:
      - network: default
        model:
          type: e1000

# Import existing disk image
- name: Import existing Debian VM
  community.libvirt.virt_install:
    name: my-debian-vm
    memory: 1024
    vcpus: 2
    disks:
      - path: /home/user/VMs/my-debian9.img
    osinfo:
      name: debian9
    import: true
    networks:
      - bridge: br0

# CentOS installation with custom storage and network configuration
- name: Create CentOS VM with custom configuration
  community.libvirt.virt_install:
    name: centos-server
    memory: 8192
    vcpus: 8
    disks:
      - pool: default
        size: 50
        format: qcow2
        cache: writeback
      - pool: default
        size: 100
        format: qcow2
        bus: virtio
    osinfo:
      name: centos7.0
    location: http://mirror.centos.org/centos-7/7/os/x86_64/
    extra_args: "ks=http://myserver/centos7.ks"
    graphics:
      type: vnc
      listen: 0.0.0.0
      port: 5901
    networks:
      - bridge: br0
        model:
          type: virtio
      - network: isolated-net

# Ubuntu server with unattended installation
- name: Create Ubuntu server with unattended install
  community.libvirt.virt_install:
    name: ubuntu-server
    memory: 2048
    vcpus: 2
    disks:
      - size: 25
    osinfo:
      name: ubuntu20.04
    location: http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/
    unattended:
      profile: jeos
      admin_password_file: /tmp/root_password
      user_login: ansible
      user_password_file: /tmp/user_password
    networks:
      - network: default

# ARM VM with custom kernel
- name: Create ARM VM with custom kernel
  community.libvirt.virt_install:
    name: arm-test-vm
    memory: 1024
    vcpus: 2
    arch: armv7l
    machine: vexpress-a9
    disks:
      - path: /home/user/VMs/myarmdisk.img
    boot:
      kernel: /tmp/my-arm-kernel
      initrd: /tmp/my-arm-initrd
      dtb: /tmp/my-arm-dtb
      kernel_args: "console=ttyAMA0 rw root=/dev/mmcblk0p3"
    graphics:
      type: none
    networks:
      - network: default

# VM with SEV launch security (AMD)
- name: Create SEV-enabled VM
  community.libvirt.virt_install:
    name: sev-vm
    memory: 4096
    memtune:
      hard_limit: 4563402
    vcpus: 4
    machine: q35
    boot: uefi
    disks:
      - size: 15
        bus: scsi
    controller_devices:
      - type: scsi
        model: virtio-scsi
        driver:
          iommu: "on"
      - type: virtio-serial
        driver:
          iommu: "on"
    networks:
      - network: default
        model:
          type: virtio
        driver:
          iommu: "on"
    rng:
      backend:
        type: random
        source: /dev/random
      driver:
        iommu: "on"
    memballoon:
      model: virtio
      driver:
        iommu: "on"
    launch_security:
      type: sev
      policy: "0x01"
    osinfo:
      name: fedora39
    import: true


# Recreate existing VM
- name: Recreate existing VM with new configuration
  community.libvirt.virt_install:
    name: existing-vm
    state: present
    recreate: true
    memory: 4096
    vcpus: 4
    disks:
      - size: 40
    osinfo:
      name: fedora39
    cdrom: /path/to/fedora39.iso
    networks:
      - network: default

# Remove VM
- name: Remove VM
  community.libvirt.virt_install:
    name: unwanted-vm
    state: absent
"""

RETURN = r""" # """

from ansible_collections.community.libvirt.plugins.module_utils.virt_install import (
    LibvirtWrapper
)
from ansible_collections.community.libvirt.plugins.module_utils.libvirt import (
    HAS_VIRT, HAS_XML, VMNotFound
)
from ansible.module_utils.basic import AnsibleModule

VIRT_FAILED = 1
VIRT_SUCCESS = 0
VIRT_UNAVAILABLE = 2

OPTION_BOOL_ONOFF = 1


def _get_option_mapping(key, mapping):
    if mapping is None:
        return (key, None)

    if key in mapping:
        name, valmap = mapping[key]
        if name is None:
            name = key
        return (name, valmap)
    else:
        return (key, None)


def _dict2options(obj, mapping, prefix=""):

    if obj is None:
        return ""

    if not isinstance(obj, dict):
        return str(obj)

    parts = []
    for k, v in obj.items():
        if v is None:
            continue

        name, valmap = _get_option_mapping(k, mapping)

        if isinstance(v, dict):
            sub_prefix = "{}{}.".format(prefix, name)
            parts.append(_dict2options(v, valmap, prefix=sub_prefix))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                item_name = "{}{}{}".format(prefix, name, i)
                if isinstance(item, dict):
                    sub_prefix = "{}.".format(item_name)
                    parts.append(
                        _dict2options(
                            item,
                            valmap,
                            prefix=sub_prefix))
                elif isinstance(item, bool):
                    if valmap == OPTION_BOOL_ONOFF:
                        parts.append(
                            "{}={}".format(
                                item_name,
                                'on' if item else 'off'))
                    else:
                        parts.append(
                            "{}={}".format(
                                item_name,
                                'yes' if item else 'no'))
                else:
                    parts.append("{}={}".format(item_name, str(item)))
        elif isinstance(v, bool):
            if valmap == OPTION_BOOL_ONOFF:
                parts.append(
                    "{}{}={}".format(
                        prefix,
                        name,
                        'on' if v else 'off'))
            else:
                parts.append(
                    "{}{}={}".format(
                        prefix,
                        name,
                        'yes' if v else 'no'))
        else:
            parts.append("{}{}={}".format(prefix, name, str(v)))

    if parts:
        return ",".join(parts)
    else:
        return ""


class VirtInstallTool(object):

    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.warnings = []
        self.command_argv = ['virt-install']

        self._vm_name = self.params.get('name')

    def _add_parameter(
            self,
            flag,
            primary_value=None,
            dict_value=None,
            dict_mapping=None):
        """Add a command line option to virt-install command"""
        if primary_value:
            if dict_value:
                self.command_argv.append("{}".format(flag))
                self.command_argv.append(
                    "{},{}".format(
                        str(primary_value),
                        _dict2options(
                            dict_value,
                            dict_mapping)))
                return
            else:
                self.command_argv.append("{}".format(flag))
                self.command_argv.append("{}".format(str(primary_value)))
                return
        else:
            if dict_value:
                self.command_argv.append("{}".format(flag))
                self.command_argv.append("{}".format(
                    _dict2options(dict_value, dict_mapping)))
                return
            else:
                self.command_argv.append("{}".format(flag))
                return

    def _add_flag_parameter(self, flag, value):
        """Add a flag command line option to virt-install command"""
        if value:
            self.command_argv.append("{}".format(flag))
            return

    def _get_param_combined_items(self, singular_key, plural_key):
        combined_items = []
        if self.params.get(singular_key) is not None:
            combined_items.append(self.params[singular_key])
        if self.params.get(plural_key) is not None:
            combined_items.extend(self.params[plural_key])

        return combined_items

    def _build_basic_options(self):
        """Build basic VM configuration options"""
        # Required options
        if self.params.get('uri') is not None:
            self._add_parameter('--connect', self.params['uri'])

        if self.params.get('name') is not None:
            self._add_parameter('--name', self.params['name'])

        if self.params.get('memory') is not None:
            memory_mapping = {
                'current_memory': ('currentMemory', None),
                'max_memory': ('maxMemory', None),
                'max_memory_opts': ('maxMemory', None),
            }
            self._add_parameter('--memory', self.params['memory'],
                                dict_value=self.params.get('memory_opts'),
                                dict_mapping=memory_mapping)

        if self.params.get('memorybacking') is not None:
            memorybacking_mapping = {
                'hugepage_specs': ('hugepages.page', {
                    'page_size': ('size', None),
                }),
            }
            self._add_parameter('--memorybacking',
                                dict_value=self.params['memorybacking'],
                                dict_mapping=memorybacking_mapping)

        if self.params.get('arch') is not None:
            self._add_parameter('--arch', self.params['arch'])

        if self.params.get('machine') is not None:
            self._add_parameter('--machine', self.params['machine'])

        if self.params.get('metadata') is not None:
            self._add_parameter('--metadata', self.params['metadata'])

        if self.params.get('events') is not None:
            self._add_parameter('--events', self.params['events'])

        if self.params.get('resource') is not None:
            self._add_parameter('--resource', self.params['resource'])

        if self.params.get('sysinfo') is not None:
            self._add_parameter('--sysinfo', self.params['sysinfo'])

        if self.params.get('qemu_commandline') is not None:
            self._add_parameter(
                '--qemu-commandline',
                self.params['qemu_commandline'])

        if self.params.get('vcpus') is not None:
            vcpus_mapping = {
                'current': ('vcpu.current', None),
                'placement': ('vcpu.placement', None),
                'vcpu_specs': ('vcpus.vcpu', None),
            }
            self._add_parameter('--vcpus', self.params['vcpus'],
                                dict_value=self.params.get('vcpus_opts'),
                                dict_mapping=vcpus_mapping)

        if self.params.get('numatune') is not None:
            numatune_mapping = {
                'memnode_specs': ('memnode', None)
            }
            self._add_parameter('--numatune',
                                dict_value=self.params['numatune'],
                                dict_mapping=numatune_mapping)

        if self.params.get('memtune') is not None:
            self._add_parameter('--memtune', dict_value=self.params['memtune'])

        if self.params.get('blkiotune') is not None:
            blkiotune_mapping = {
                'devices': ('device', None)
            }
            self._add_parameter('--blkiotune',
                                dict_value=self.params['blkiotune'],
                                dict_mapping=blkiotune_mapping)

        if self.params.get('cpu') is not None:
            cpu_mapping = {
                'model_opts': ('model', None),
                'numa': (None, {
                    'cell_specs': ('cell', {
                        'mem_access': ('memAccess', None),
                        'distances': (None, {
                            'sibling_specs': ('sibling', None)
                        }),
                        'cache_specs': ('cache', None)
                    }),
                    'interconnects': (None, {
                        'bandwidth_specs': ('bandwidth', None),
                        'latency_specs': ('latency', None)
                    })
                })
            }
            cpu_dict_value = self.params['cpu']
            cpu_primary_argv = []
            if 'model' in cpu_dict_value:
                cpu_model = cpu_dict_value.pop('model')
                if cpu_model:
                    cpu_primary_argv.append(cpu_model)
            if 'features' in cpu_dict_value:
                cpu_feature_param = cpu_dict_value.pop('features')
                if cpu_feature_param:
                    for k, v in cpu_feature_param.items():
                        if v in [
                            'force',
                            'require',
                            'optional',
                            'disable',
                                'forbid']:
                            cpu_primary_argv.append("{}={}".format(v, k))
            if cpu_primary_argv:
                cpu_primary_value = ','.join(cpu_primary_argv)
                self._add_parameter('--cpu', cpu_primary_value,
                                    dict_value=cpu_dict_value,
                                    dict_mapping=cpu_mapping)
            else:
                self._add_parameter('--cpu',
                                    dict_value=cpu_dict_value,
                                    dict_mapping=cpu_mapping)

        if self.params.get('cputune') is not None:
            cputune_mapping = {
                'vcpupin_specs': ('vcpupin', None),
                'iothreadpin_specs': ('iothreadpin', None),
                'vcpusched_specs': ('vcpusched', None),
                'iothreadsched_specs': ('iothreadsched', None),
            }
            self._add_parameter('--cputune',
                                dict_value=self.params['cputune'],
                                dict_mapping=cputune_mapping)

        if self.params.get('security') is not None:
            self._add_parameter(
                '--seclabel',
                dict_value=self.params['security'])

        if self.params.get('keywrap') is not None:
            keywrap_mapping = {
                'ciphers': ('cipher', None)
            }
            self._add_parameter('--keywrap',
                                dict_value=self.params['keywrap'],
                                dict_mapping=keywrap_mapping)

        if self.params.get('iothreads') is not None:
            iothreads_mapping = {
                'iothread_specs': ('iothreadids.iothread', None),
            }
            self._add_parameter('--iothreads', self.params['iothreads'],
                                dict_value=self.params.get('iothreads_opts'),
                                dict_mapping=iothreads_mapping)

        if self.params.get('features') is not None:
            self._add_parameter(
                '--features',
                dict_value=self.params['features'])

        if self.params.get('clock') is not None:
            clock_mapping = {
                'timers': ('timer', None)
            }
            self._add_parameter('--clock',
                                dict_value=self.params['clock'],
                                dict_mapping=clock_mapping)

        if self.params.get('pm') is not None:
            self._add_parameter('--pm',
                                dict_value=self.params['pm'])

        if self.params.get('launch_security') is not None:
            launch_security_mapping = {
                'dh_cert': ('dhCert', None),
                'reduced_phys_bits': ('reducedPhysBits', None)
            }
            self._add_parameter('--launchSecurity',
                                dict_value=self.params['launch_security'],
                                dict_mapping=launch_security_mapping)

    def _build_installation_options(self):        # Installation media options
        if self.params.get('cdrom') is not None:
            self._add_parameter('--cdrom', self.params['cdrom'])

        if self.params.get('location') is not None:
            self._add_parameter('--location', self.params['location'],
                                dict_value=self.params.get('location_opts'))

        if self.params.get('pxe') is not None:
            self._add_flag_parameter('--pxe', self.params['pxe'])

        if self.params.get('import'):
            self._add_flag_parameter('--import', self.params['import'])

        if self.params.get('extra_args') is not None:
            self._add_parameter('--extra-args', self.params['extra_args'])

        if self.params.get('initrd_inject') is not None:
            self._add_parameter(
                '--initrd-inject',
                self.params['initrd_inject'])

        if self.params.get('install') is not None:
            self._add_parameter('--install',
                                dict_value=self.params['install'])

        if self.params.get('unattended') is not None:
            unattended_mapping = {
                'admin_password_file': ('admin-password-file', None),
                'user_login': ('user-login', None),
                'user_password_file': ('user-password-file', None),
                'product_key': ('product-key', None),
            }
            self._add_parameter('--unattended',
                                dict_value=self.params['unattended'],
                                dict_mapping=unattended_mapping)

        if self.params.get('cloud_init') is not None:
            cloud_init_mapping = {
                'root_password_generate': (
                    'root-password-generate',
                    OPTION_BOOL_ONOFF),
                'disable': (
                    'disable',
                    OPTION_BOOL_ONOFF),
                'root_password_file': (
                    'root-password-file',
                    None),
                'root_ssh_key': (
                    'root-ssh-key',
                    None),
                'clouduser_ssh_key': (
                    'clouduser-ssh-key',
                    None),
                'network_config': (
                    'network-config',
                    None),
                'meta_data': (
                    'meta-data',
                    None),
                'user_data': (
                    'user-data',
                    None),
            }
            self._add_parameter('--cloud-init',
                                dict_value=self.params['cloud_init'],
                                dict_mapping=cloud_init_mapping)

        if self.params.get('boot') is not None:
            self._add_parameter('--boot', self.params['boot'],
                                dict_value=self.params.get('boot_opts'))

        if self.params.get('idmap') is not None:
            self._add_parameter('--idmap',
                                dict_value=self.params['idmap'])

    def _build_guest_os_options(self):
        if self.params.get('osinfo') is not None:
            osinfo_mapping = {
                'detect': ('detect', OPTION_BOOL_ONOFF),
                'require': ('require', OPTION_BOOL_ONOFF),
            }
            self._add_parameter('--osinfo',
                                dict_value=self.params['osinfo'],
                                dict_mapping=osinfo_mapping)

    def _build_storage_options(self):
        if self.params.get('disks') is not None:
            disk_mapping = {
                'backing_store': ('backing_store', None),
                'backing_format': ('backing_format', None),
                'transient_opts': ('transient', {
                    'share_backing': ('shareBacking', None)
                })
            }
            for disk in self.params['disks']:
                self._add_parameter('--disk',
                                    dict_value=disk,
                                    dict_mapping=disk_mapping)

        if self.params.get('filesystems') is not None:
            for filesystem in self.params['filesystems']:
                self._add_parameter('--filesystem',
                                    dict_value=filesystem)

    def _build_network_options(self):
        if self.params.get('networks') is not None:
            network_param = self.params['networks']
            if len(network_param) == 0:
                self._add_parameter('--network', 'none')
                return

            network_mapping = {
                'trust_guest_rx_filters': ('trustGuestRxFilters', None),
                'state': ('link.state', None),
            }
            for network in network_param:
                self._add_parameter('--network',
                                    dict_value=network,
                                    dict_mapping=network_mapping)

    def _build_graphics_options(self):
        graphics_params = self._get_param_combined_items(
            'graphics', 'graphics_devices')

        if len(graphics_params) == 0:
            self._add_parameter('--graphics', 'none')
            return

        for item in graphics_params:
            graphics_primary_value = None
            if 'type' in item:
                graphics_primary_value = item.pop('type')
                self._add_parameter('--graphics', graphics_primary_value,
                                    dict_value=item)
            else:
                self._add_parameter('--graphics',
                                    dict_value=item)

    def _build_virt_options(self):
        if self.params.get('virt_type') is not None:
            self._add_parameter('--virt-type', self.params['virt_type'])

        if self.params.get('hvm') is not None:
            self._add_flag_parameter('--hvm', self.params['hvm'])

        if self.params.get('paravirt') is not None:
            self._add_flag_parameter('--paravirt', self.params['paravirt'])

        if self.params.get('container') is not None:
            self._add_flag_parameter('--container', self.params['container'])

    def _build_device_options(self):
        # Controller devices
        controller_params = self._get_param_combined_items(
            'controller', 'controller_devices')
        for item in controller_params:
            self._add_parameter('--controller',
                                dict_value=item)

        # Input devices
        input_params = self._get_param_combined_items('input', 'input_devices')
        for item in input_params:
            self._add_parameter('--input',
                                dict_value=item)

        # Host devices
        hostdev_params = self._get_param_combined_items(
            'hostdev', 'host_devices')
        for item in hostdev_params:
            self._add_parameter('--hostdev',
                                dict_value=item)

        # Sound devices
        sound_params = self._get_param_combined_items('sound', 'sound_devices')
        for item in sound_params:
            self._add_parameter('--sound',
                                dict_value=item)

        # Audio devices
        audio_params = self._get_param_combined_items('audio', 'audio_devices')
        for item in audio_params:
            self._add_parameter('--audio',
                                dict_value=item)

        # Watchdog devices
        watchdog_params = self._get_param_combined_items(
            'watchdog', 'watchdog_devices')
        for item in watchdog_params:
            self._add_parameter('--watchdog',
                                dict_value=item)

        # Serial devices
        serial_params = self._get_param_combined_items(
            'serial', 'serial_devices')
        for item in serial_params:
            self._add_parameter('--serial',
                                dict_value=item)

        # Parallel devices
        parallel_params = self._get_param_combined_items(
            'parallel', 'parallel_devices')
        for item in parallel_params:
            self._add_parameter('--parallel',
                                dict_value=item)

        # Channel devices
        channel_params = self._get_param_combined_items(
            'channel', 'channel_devices')
        for item in channel_params:
            self._add_parameter('--channel',
                                dict_value=item)

        # Console devices
        console_params = self._get_param_combined_items(
            'console', 'console_devices')
        for item in console_params:
            self._add_parameter('--console',
                                dict_value=item)

        # Video devices
        video_params = self._get_param_combined_items('video', 'video_devices')
        for item in video_params:
            self._add_parameter('--video',
                                dict_value=item)

        # Smartcard devices
        smartcard_params = self._get_param_combined_items(
            'smartcard', 'smartcard_devices')
        for item in smartcard_params:
            self._add_parameter('--smartcard',
                                dict_value=item)

        # Redirection devices
        redirdev_params = self._get_param_combined_items(
            'redirdev', 'redirected_devices')
        for item in redirdev_params:
            self._add_parameter('--redirdev',
                                dict_value=item)

        # Memory balloon devices
        memballoon_params = self._get_param_combined_items(
            'memballoon', 'memballoon_devices')
        memballoon_mapping = {
            'freePageReporting': ('freePageReporting', OPTION_BOOL_ONOFF),
            'autodeflate': ('autodeflate', OPTION_BOOL_ONOFF),
        }
        for item in memballoon_params:
            self._add_parameter('--memballoon',
                                dict_value=item,
                                dict_mapping=memballoon_mapping)

        # TPM devices
        tpm_params = self._get_param_combined_items('tpm', 'tpm_devices')
        tpm_mapping = {
            'active_pcr_banks': ('active_pcr_banks', {
                'sha1': ('sha1', OPTION_BOOL_ONOFF),
                'sha256': ('sha256', OPTION_BOOL_ONOFF),
                'sha384': ('sha384', OPTION_BOOL_ONOFF),
                'sha512': ('sha512', OPTION_BOOL_ONOFF),
            }),
            'backend': ('backend', {
                'persistent_state': ('persistent_state', OPTION_BOOL_ONOFF),
            }),
        }
        for item in tpm_params:
            self._add_parameter('--tpm',
                                dict_value=item,
                                dict_mapping=tpm_mapping)

        # RNG devices
        rng_params = self._get_param_combined_items('rng', 'rng_devices')
        for item in rng_params:
            self._add_parameter('--rng',
                                dict_value=item)

        # Panic devices
        panic_params = self._get_param_combined_items('panic', 'panic_devices')
        for item in panic_params:
            self._add_parameter('--panic',
                                dict_value=item)

        # Shared memory devices
        shmem_params = self._get_param_combined_items('shmem', 'shmem_devices')
        shmem_mapping = {
            'msi': ('msi', {
                'ioeventfd': ('ioeventfd', OPTION_BOOL_ONOFF),
            }),
        }
        for item in shmem_params:
            self._add_parameter('--shmem',
                                dict_value=item,
                                dict_mapping=shmem_mapping)

        # Vsock devices
        vsock_params = self._get_param_combined_items('vsock', 'vsock_devices')
        vsock_mapping = {
            'cid': ('cid', {
                'auto': ('auto', OPTION_BOOL_ONOFF),
            }),
        }
        for item in vsock_params:
            self._add_parameter('--vsock',
                                dict_value=item,
                                dict_mapping=vsock_mapping)

        # IOMMU devices
        iommu_params = self._get_param_combined_items('iommu', 'iommu_devices')
        iommu_mapping = {
            'driver': ('driver', {
                'caching_mode': ('caching_mode', OPTION_BOOL_ONOFF),
                'eim': ('eim', OPTION_BOOL_ONOFF),
                'intremap': ('intremap', OPTION_BOOL_ONOFF),
                'iotlb': ('iotlb', OPTION_BOOL_ONOFF),
            }),
        }
        for item in iommu_params:
            self._add_parameter('--iommu',
                                dict_value=item,
                                dict_mapping=iommu_mapping)

    def _build_misc_options(self):
        if self.params.get('autostart') is not None:
            self._add_flag_parameter('--autostart', self.params['autostart'])

        if self.params.get('transient') is not None:
            self._add_flag_parameter('--transient', self.params['transient'])

        if self.params.get('destroy_on_exit') is not None:
            self._add_flag_parameter(
                '--destroy-on-exit',
                self.params['destroy_on_exit'])

        if self.params.get('noreboot') is not None:
            self._add_flag_parameter('--noreboot', self.params['noreboot'])

    def _validate_params(self):
        """Validate parameter combinations and dependencies according to virt-install requirements"""

        extra_key_pairs = [
            ('memory', 'memory_opts'),
            ('vcpus', 'vcpus_opts'),
            ('location', 'location_opts'),
            ('boot', 'boot_opts'),
            ('iothreads', 'iothreads_opts'),
        ]

        for param_key, extra_key in extra_key_pairs:
            if (extra_key in self.params) and (param_key not in self.params):
                self.module.fail_json(
                    msg="{} requires {} to be specified".format(
                        extra_key, param_key))

    def _build_command(self):
        """Build the complete virt-install command"""
        self._validate_params()

        # Build command sections
        self._build_basic_options()
        self._build_installation_options()
        self._build_guest_os_options()
        self._build_storage_options()
        self._build_network_options()
        self._build_graphics_options()
        self._build_virt_options()
        self._build_device_options()
        self._build_misc_options()

        # Always add --noautoconsole for non-interactive execution
        self.command_argv.append('--noautoconsole')

    def execute(self, dryrun=False):
        changed = False
        result = dict()

        self._build_command()

        if dryrun:
            self.command_argv.append('--dry-run')

        # Execute the command
        rc, stdout, stderr = self.module.run_command(
            self.command_argv, check_rc=False)

        if rc == 0:
            changed = True
            result["msg"] = "virtual machine '{}' created successfully".format(
                self._vm_name
            )
            return changed, VIRT_SUCCESS, result

        error_msg = "failed to create virtual machine '{}': {}".format(
            self._vm_name, stderr.strip() if stderr else stdout.strip()
        )
        result["msg"] = error_msg
        return changed, rc, result


def core(module):
    state = module.params.get('state')
    name = module.params.get('name')
    uri = module.params.get('uri')
    recreate = module.params.get('recreate', False)

    result = dict(
        changed=False,
        orignal_message="",
        message="",
    )

    virtConn = LibvirtWrapper(module)
    virtInstall = VirtInstallTool(module)

    if not name:
        module.fail_json(msg="virtual machine name is missing")

    vm_exists = False
    try:
        vm = virtConn.find_vm(name)
        vm_exists = True
    except VMNotFound:
        vm_exists = False

    if state == 'present':
        if vm_exists and not recreate:
            result['message'] = "virtual machine '%s' already exists" % name
            return VIRT_SUCCESS, result
        elif vm_exists and recreate:
            if vm.isActive():
                virtConn.destroy(name)
            virtConn.undefine(name)

        # run virt-install to create new vm
        changed, rc, extra_res = virtInstall.execute(dryrun=module.check_mode)
        result['changed'] = changed
        result.update(extra_res)

        return rc, result
    elif state == 'absent':
        if not vm_exists:
            result['message'] = "virtual machine '%s' is already absent" % name
            return VIRT_SUCCESS, result

        if vm.isActive():
            virtConn.destroy(name)
        virtConn.undefine(name)

        result["changed"] = True
        return VIRT_SUCCESS, result

    module.fail_json(msg="unsupported state '%s'" % state)


def main():
    """Main module entry point"""

    # Define argument specification
    argument_spec = dict(
        # Connection options
        uri=dict(type='str', default="qemu:///system"),
        # Basic VM options
        name=dict(type='str', required=True),
        state=dict(
            type='str',
            choices=[
                'present',
                'absent'],
            default='present'),
        recreate=dict(type='bool', default=False),
        # Hardware configuration
        memory=dict(type='int'),
        memory_opts=dict(
            type='dict',
            options=dict(
                current_memory=dict(type='int'),
                max_memory=dict(type='int'),
                max_memory_opts=dict(
                    type='dict', options=dict(
                        slots=dict(
                            type='int'))),
            ),
        ),
        memorybacking=dict(
            type='dict',
            options=dict(
                hugepages=dict(type='bool'),
                hugepage_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        page_size=dict(
                            type='int'), nodeset=dict(
                            type='str')),
                ),
                nosharepages=dict(type='bool'),
                locked=dict(type='bool'),
                access=dict(
                    type='dict',
                    options=dict(
                        mode=dict(
                            type='str',
                            choices=[
                                'shared',
                                'private'])),
                ),
                allocation=dict(
                    type='dict',
                    options=dict(
                        mode=dict(
                            type='str', choices=[
                                'immediate', 'ondemand']),
                        threads=dict(type='int'),
                    ),
                ),
                discard=dict(type='bool'),
            ),
        ),
        arch=dict(type='str'),
        machine=dict(type='str'),
        metadata=dict(type='dict'),
        events=dict(
            type='dict',
            options=dict(
                on_poweroff=dict(
                    type='str',
                    choices=[
                        'destroy',
                        'restart',
                        'preserve',
                        'rename-restart'],
                ),
                on_reboot=dict(
                    type='str',
                    choices=[
                        'destroy',
                        'restart',
                        'preserve',
                        'rename-restart'],
                ),
                on_crash=dict(
                    type='str',
                    choices=[
                        'destroy',
                        'restart',
                        'preserve',
                        'rename-restart',
                        'coredump-destroy',
                        'coredump-restart',
                    ],
                ),
                on_lockfailure=dict(
                    type='str', choices=['poweroff', 'restart', 'pause', 'ignore']
                ),
            ),
        ),
        resource=dict(type='dict'),
        sysinfo=dict(type='dict'),
        qemu_commandline=dict(type='str'),
        # CPU configuration
        vcpus=dict(type='int'),
        vcpus_opts=dict(
            type='dict',
            options=dict(
                maxvcpus=dict(type='int'),
                sockets=dict(type='int'),
                dies=dict(type='int'),
                clusters=dict(type='int'),
                cores=dict(type='int'),
                threads=dict(type='int'),
                current=dict(type='int'),
                cpuset=dict(type='str'),
                placement=dict(type='str', choices=['static', 'auto']),
                vcpu_specs=dict(type='list', elements="dict"),
            ),
        ),
        numatune=dict(
            type='dict',
            options=dict(
                memory=dict(
                    type='dict',
                    options=dict(
                        mode=dict(
                            type='str', choices=['interleave', 'preferred', 'strict']
                        ),
                        nodeset=dict(type='str'),
                        placement=dict(type='str', choices=['static', 'auto']),
                    ),
                ),
                memnode_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        cellid=dict(type='int'),
                        mode=dict(
                            type='str', choices=['interleave', 'preferred', 'strict']
                        ),
                        nodeset=dict(type='str'),
                    ),
                ),
            ),
        ),
        memtune=dict(type='dict'),
        blkiotune=dict(
            type='dict',
            options=dict(
                weight=dict(type='int'), devices=dict(type='list', elements="dict")
            ),
        ),
        cpu=dict(
            type='dict',
            options=dict(
                model=dict(type='str'),
                model_opts=dict(
                    type='dict',
                    options=dict(
                        fallback=dict(type='str', choices=['forbid', 'allow']),
                        vendor_id=dict(type='str'),
                    ),
                ),
                match=dict(type='str', choices=['exact', 'minimum', 'strict']),
                migratable=dict(type='bool'),
                vendor=dict(type='str'),
                features=dict(type='dict'),
                cache=dict(
                    type='dict',
                    options=dict(
                        mode=dict(
                            type='str', choices=['emulate', 'passthrough', 'disable']
                        ),
                        level=dict(type='int'),
                    ),
                ),
                numa=dict(
                    type='dict',
                    options=dict(
                        cell_specs=dict(
                            type='list',
                            elements="dict",
                            options=dict(
                                id=dict(type='int'),
                                cpus=dict(type='str'),
                                memory=dict(type='int'),
                                mem_access=dict(
                                    type='str', choices=[
                                        'shared', 'private']),
                                discard=dict(type='bool'),
                                distances=dict(
                                    type='dict',
                                    options=dict(
                                        sibling_specs=dict(
                                            type='list', elements="dict"),
                                    ),
                                ),
                                cache_specs=dict(type='list', elements="dict"),
                            ),
                        ),
                        interconnects=dict(
                            type='list',
                            elements="dict",
                            options=dict(
                                bandwidth_specs=dict(
                                    type='list', elements="dict"),
                                latency_specs=dict(
                                    type='list', elements="dict"),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        cputune=dict(
            type='dict',
            options=dict(
                vcpupin_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        vcpu=dict(type='int'),
                        cpuset=dict(type='str'),
                    ),
                ),
                emulatorpin=dict(
                    type='dict',
                    options=dict(
                        cpuset=dict(type='str'),
                    )
                ),
                iothreadpin_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        iothread=dict(type='int'),
                        cpuset=dict(type='str'),
                    ),
                ),
                vcpusched_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        vcpus=dict(type='str'),
                        scheduler=dict(
                            type='str', choices=[
                                'batch', 'idle', 'fifo', 'rr']),
                        priority=dict(type='int'),
                    ),
                ),
                iothreadsched_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        iothreads=dict(type='str'),
                        scheduler=dict(
                            type='str', choices=[
                                'batch', 'idle', 'fifo', 'rr']),
                        priority=dict(type='int'),
                    ),
                ),
                emulatorsched=dict(
                    type='dict',
                    options=dict(
                        scheduler=dict(
                            type='str', choices=[
                                'batch', 'idle', 'fifo', 'rr']),
                        priority=dict(type='int'),
                    ),
                ),
                shares=dict(type='int'),
                period=dict(type='int'),
                quota=dict(type='int'),
                global_period=dict(type='int'),
                global_quota=dict(type='int'),
                emulator_period=dict(type='int'),
                emulator_quota=dict(type='int'),
                iothread_period=dict(type='int'),
                iothread_quota=dict(type='int'),
            ),
        ),
        security=dict(type='dict'),
        keywrap=dict(
            type='dict', options=dict(ciphers=dict(type='list', elements="dict")), no_log=True
        ),
        iothreads=dict(type='int'),
        iothreads_opts=dict(
            type='dict',
            options=dict(
                iothread_specs=dict(
                    type='list',
                    elements="dict",
                    options=dict(
                        id=dict(type='int'),
                        thread_pool_min=dict(type='int'),
                        thread_pool_max=dict(type='int'),
                    ),
                ),
                defaultiothread=dict(
                    type='dict',
                    options=dict(
                        thread_pool_min=dict(type='int'),
                        thread_pool_max=dict(type='int'),
                    ),
                ),
            ),
        ),
        features=dict(type='dict'),
        clock=dict(
            type='dict',
            options=dict(
                offset=dict(type='str'), timers=dict(type='list', elements="dict")
            ),
        ),
        pm=dict(
            type='dict',
            options=dict(
                suspend_to_mem=dict(
                    type='dict', options=dict(enabled=dict(type='bool'))
                ),
                suspend_to_disk=dict(
                    type='dict', options=dict(enabled=dict(type='bool'))
                ),
            ),
        ),
        launch_security=dict(
            type='dict',
            options=dict(
                type=dict(type='str', required=True),
                policy=dict(type='str'),
                cbitpos=dict(type='int'),
                reduced_phys_bits=dict(type='int'),
                dh_cert=dict(type='str'),
                session=dict(type='str'),
            ),
        ),
        # Installation options
        cdrom=dict(type='str'),
        location=dict(type='str'),
        location_opts=dict(
            type='dict', options=dict(kernel=dict(type='str'), initrd=dict(type='str'))
        ),
        pxe=dict(type='bool'),
        extra_args=dict(type='str'),
        initrd_inject=dict(type='str'),
        install=dict(
            type='dict',
            options=dict(
                os=dict(type='str', required=True),
                kernel=dict(type='str'),
                initrd=dict(type='str'),
                kernel_args=dict(type='str'),
                kernel_args_overwrite=dict(type='bool'),
                bootdev=dict(type='str'),
                no_install=dict(type='bool'),
            ),
        ),
        unattended=dict(
            type='dict',
            options=dict(
                profile=dict(type='str'),
                admin_password_file=dict(type='str'),
                user_login=dict(type='str'),
                user_password_file=dict(type='str'),
                product_key=dict(type='str', no_log=True),
            ),
        ),
        cloud_init=dict(
            type='dict',
            options=dict(
                root_password_generate=dict(type='bool'),
                disable=dict(type='bool'),
                root_password_file=dict(type='str'),
                root_ssh_key=dict(type='str', no_log=True),
                clouduser_ssh_key=dict(type='str', no_log=True),
                network_config=dict(type='str'),
                meta_data=dict(type='dict'),
                user_data=dict(type='dict'),
            ),
        ),
        boot=dict(type='str'),
        boot_opts=dict(type='dict'),
        idmap=dict(
            type='dict',
            options=dict(
                uid=dict(
                    type='dict',
                    options=dict(
                        start=dict(type='int'),
                        target=dict(type='int'),
                        count=dict(type='int'),
                    ),
                ),
                gid=dict(
                    type='dict',
                    options=dict(
                        start=dict(type='int'),
                        target=dict(type='int'),
                        count=dict(type='int'),
                    ),
                ),
            ),
        ),
        # Guest OS options
        osinfo=dict(
            type='dict',
            options=dict(
                name=dict(type='str', aliases=['short_id']),
                id=dict(type='str'),
                detect=dict(type='bool'),
                require=dict(type='bool'),
            ),
        ),
        # Storage options
        disks=dict(
            type='list',
            elements="dict",
            options=dict(
                path=dict(type='str'),
                pool=dict(type='str'),
                vol=dict(type='str'),
                size=dict(type='int'),
                sparse=dict(type='bool'),
                format=dict(type='str'),
                backing_store=dict(type='str'),
                backing_format=dict(type='str'),
                bus=dict(type='str'),
                readonly=dict(type='bool'),
                shareable=dict(type='bool'),
                cache=dict(
                    type='str',
                    choices=[
                        "none",
                        "writethrough",
                        "directsync",
                        "unsafe",
                        "writeback",
                    ],
                ),
                serial=dict(type='str'),
                snapshot=dict(
                    type='str', choices=[
                        'internal', 'external', 'no']),
                rawio=dict(type='bool'),
                sgio=dict(type='str', choices=['filtered', 'unfiltered']),
                transient=dict(type='bool'),
                transient_opts=dict(
                    type='dict', options=dict(share_backing=dict(type='bool'))
                ),
                driver=dict(type='dict'),
                source=dict(type='dict'),
                target=dict(type='dict'),
                address=dict(type='dict'),
                boot=dict(type='dict'),
                iotune=dict(type='dict'),
                blockio=dict(type='dict'),
                geometry=dict(type='dict'),
            ),
        ),
        filesystems=dict(
            type='list',
            elements="dict",
            options=dict(
                type=dict(
                    type='str',
                    choices=[
                        'mount',
                        'template',
                        'file',
                        'block',
                        'ram',
                        'bind'],
                ),
                accessmode=dict(
                    type='str', choices=['passthrough', 'mapped', 'squash']
                ),
                source=dict(type='dict'),
                target=dict(type='dict'),
                fmode=dict(type='str'),
                dmode=dict(type='str'),
                multidevs=dict(
                    type='str', choices=['default', 'remap', 'forbid', 'warn']
                ),
                readonly=dict(type='bool'),
                space_hard_limit=dict(type='int'),
                space_soft_limit=dict(type='int'),
                driver=dict(type='dict'),
                address=dict(type='dict'),
                binary=dict(type='dict'),
            ),
        ),
        # Network options
        networks=dict(
            type='list',
            elements="dict",
            options=dict(
                type=dict(type='str', choices=['direct']),
                network=dict(type='str'),
                bridge=dict(type='str'),
                hostdev=dict(type='str'),
                source=dict(type='dict'),
                mac=dict(type='dict', options=dict(address=dict(type='str'))),
                mtu=dict(type='dict'),
                state=dict(type='dict'),
                model=dict(type='dict', options=dict(type=dict(type='str'))),
                driver=dict(type='dict'),
                boot=dict(type='dict'),
                filterref=dict(type='dict'),
                rom=dict(type='dict'),
                target=dict(type='dict'),
                address=dict(type='dict'),
                virtualport=dict(type='dict'),
                trust_guest_rx_filters=dict(type='bool'),
            ),
        ),
        # Graphics options
        graphics=dict(type='dict'),
        graphics_devices=dict(type='list', elements="dict"),
        # Virtualization options
        virt_type=dict(type='str'),
        hvm=dict(type='bool'),
        paravirt=dict(type='bool'),
        container=dict(type='bool'),
        # Device options
        controller=dict(type='dict'),
        controller_devices=dict(type='list', elements="dict"),
        input=dict(type='dict'),
        input_devices=dict(type='list', elements="dict"),
        hostdev=dict(type='dict'),
        host_devices=dict(type='list', elements="dict"),
        sound=dict(type='dict'),
        sound_devices=dict(type='list', elements="dict"),
        audio=dict(type='dict'),
        audio_devices=dict(type='list', elements="dict"),
        watchdog=dict(type='dict'),
        watchdog_devices=dict(type='list', elements="dict"),
        serial=dict(type='dict'),
        serial_devices=dict(type='list', elements="dict"),
        parallel=dict(type='dict'),
        parallel_devices=dict(type='list', elements="dict"),
        channel=dict(type='dict'),
        channel_devices=dict(type='list', elements="dict"),
        console=dict(type='dict'),
        console_devices=dict(type='list', elements="dict"),
        video=dict(type='dict'),
        video_devices=dict(type='list', elements="dict"),
        smartcard=dict(type='dict'),
        smartcard_devices=dict(type='list', elements="dict"),
        redirdev=dict(type='dict'),
        redirected_devices=dict(type='list', elements="dict"),
        memballoon=dict(type='dict'),
        memballoon_devices=dict(type='list', elements="dict"),
        tpm=dict(type='dict'),
        tpm_devices=dict(type='list', elements="dict"),
        rng=dict(type='dict'),
        rng_devices=dict(type='list', elements="dict"),
        panic=dict(type='dict'),
        panic_devices=dict(type='list', elements="dict"),
        shmem=dict(type='dict'),
        shmem_devices=dict(type='list', elements="dict"),
        vsock=dict(type='dict'),
        vsock_devices=dict(type='list', elements="dict"),
        iommu=dict(type='dict'),
        iommu_devices=dict(type='list', elements="dict"),
        # Miscellaneous options
        autostart=dict(type='bool'),
        transient=dict(type='bool'),
        destroy_on_exit=dict(type='bool'),
        noreboot=dict(type='bool'),
    )
    # Add the 'import' option (Python keyword)
    argument_spec['import'] = dict(type='bool')

    # Create module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True)

    if not HAS_VIRT:
        module.fail_json(
            msg="The `libvirt` module is not importable. Check the requirements.")

    if not HAS_XML:
        module.fail_json(
            msg='The `lxml` module is not importable. Check the requirements.'
        )

    rc = VIRT_SUCCESS
    try:
        rc, result = core(module)
    except Exception as e:
        module.fail_json(msg=str(e))

    if rc != 0:  # something went wrong emit the msg
        module.fail_json(rc=rc, msg=result)
    else:
        module.exit_json(**result)


if __name__ == "__main__":
    main()
