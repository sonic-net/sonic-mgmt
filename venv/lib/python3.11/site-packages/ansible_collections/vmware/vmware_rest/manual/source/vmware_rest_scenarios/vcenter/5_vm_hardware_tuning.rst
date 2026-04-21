.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_vm_hardware_tuning:

*******************************
How to modify a virtual machine
*******************************

.. contents::
  :local:


Introduction
============

This section shows you how to use Ansible to modify an existing virtual machine.

Scenario requirements
=====================

You've already followed :ref:`vmware_rest_create_vm` and created a VM.

How to add a CDROM drive to a virtual machine
=============================================

In this example, we use the ``vcenter_vm_hardware_*`` modules to add a new CDROM to an existing VM.

Add a new SATA adapter
______________________

First we create a new SATA adapter. We specify the ``pci_slot_number``. This way if we run the task again it won't do anything if there is already an adapter there.

.. ansible-task::

  - name: Create a SATA adapter at PCI slot 34
    vmware.vmware_rest.vcenter_vm_hardware_adapter_sata:
      vm: '{{ test_vm1_info.id }}'
      pci_slot_number: 34
    register: _sata_adapter_result_1

Add a CDROM drive
_________________

Now we can create the CDROM drive:

.. ansible-task::

  - name: Attach an ISO image to a guest VM
    vmware.vmware_rest.vcenter_vm_hardware_cdrom:
      vm: '{{ test_vm1_info.id }}'
      type: SATA
      sata:
        bus: 0
        unit: 2
      start_connected: true
      backing:
        iso_file: '[ro_datastore] fedora.iso'
        type: ISO_FILE
    register: _result


.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_attach_a_network:

How to attach a VM to a network
===============================

Attach a new NIC
________________

Here we attach the VM to the network (through the portgroup). We specify a ``pci_slot_number`` for the same reason.

The second task adjusts the NIC configuration.



.. ansible-tasks::

  - name: Identify the portgroup called my-portgroup
    vmware.vmware_rest.vcenter_network_info:
      filter_types: DISTRIBUTED_PORTGROUP
      filter_names: "my portrgoup"
    register: my_portgroup

  - name: Attach a VM to a dvswitch
    vmware.vmware_rest.vcenter_vm_hardware_ethernet:
      vm: '{{ test_vm1_info.id }}'
      pci_slot_number: 4
      backing:
        type: DISTRIBUTED_PORTGROUP
        network: "{{ my_portgroup.value[0].network }}"
      start_connected: false
    register: vm_hardware_ethernet_1


Adjust the configuration of the NIC
___________________________________

.. ansible-task::

  - name: Turn the NIC's start_connected flag on
    vmware.vmware_rest.vcenter_vm_hardware_ethernet:
      nic: '{{ vm_hardware_ethernet_1.id }}'
      start_connected: true
      vm: '{{ test_vm1_info.id }}'

Increase the memory of the VM
=============================

We can also adjust the amount of memory that we dedicate to our VM.

.. ansible-task::

  - name: Increase the memory of a VM
    vmware.vmware_rest.vcenter_vm_hardware_memory:
      vm: '{{ test_vm1_info.id }}'
      size_MiB: 1080
    register: _result

Upgrade the hardware version of the VM
======================================

Here we use the ``vcenter_vm_hardware`` module to upgrade the version of the hardware: 

.. ansible-task::

  - name: Upgrade the VM hardware version
    vmware.vmware_rest.vcenter_vm_hardware:
      upgrade_policy: AFTER_CLEAN_SHUTDOWN
      upgrade_version: VMX_13
      vm: '{{ test_vm1_info.id }}'
    register: _result


Adjust the number of CPUs of the VM
===================================

You can use ``vcenter_vm_hardware_cpu`` for that:

.. ansible-task::

  - name: Dedicate one core to the VM
    vmware.vmware_rest.vcenter_vm_hardware_cpu:
      vm: '{{ test_vm1_info.id }}'
      count: 1
    register: _result

Remove a SATA controller
========================

In this example, we remove the SATA controller of the PCI slot 34.

.. ansible-task::

  - name: Dedicate one core to the VM
    vmware.vmware_rest.vcenter_vm_hardware_cpu:
      vm: '{{ test_vm1_info.id }}'
      count: 1
    register: _result

Attach a floppy drive
=====================

Here we attach a floppy drive to a VM.

.. ansible-task::

  - name: Add a floppy disk drive
    vmware.vmware_rest.vcenter_vm_hardware_floppy:
      vm: '{{ test_vm1_info.id }}'
      allow_guest_control: true
    register: my_floppy_drive

Attach a new disk
=================

Here we attach a tiny disk to the VM. The ``capacity`` is in bytes.

.. ansible-task::

  - name: Create a new disk
    vmware.vmware_rest.vcenter_vm_hardware_disk:
      vm: '{{ test_vm1_info.id }}'
      type: SATA
      new_vmdk:
        capacity: 320000
    register: my_new_disk
