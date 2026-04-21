.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_vm_info:

***************************************
Retrieve information from a specific VM
***************************************

.. contents::
  :local:


Introduction
============

This section shows you how to use Ansible to retrieve information about a specific virtual machine.

Scenario requirements
=====================

You've already followed :ref:`vmware_rest_create_vm` and you've got create a new VM called ``test_vm1``.

How to collect virtual machine information
==========================================

List the VM
___________

In this example, we use the ``vcenter_vm_info`` module to collect information about our new VM.

In this example, we start by asking for a list of VMs. We use a filter to limit the results to just the VM called ``test_vm1``. So we are in a list context, with one single entry in the ``value`` key.

.. ansible-task::

  - name: Look up the VM called test_vm1 in the inventory
    vmware.vmware_rest.vcenter_vm_info:
      filter_names:
        - test_vm1
    register: search_result

As expected, we get a list. And thanks to our filter, we just get one entry.


Collect the details about a specific VM
_______________________________________

For the next steps, we pass the ID of the VM through the ``vm`` parameter. This allow us to collect more details about this specific VM.

.. ansible-task::

  - name: Collect information about a specific VM
    vmware.vmware_rest.vcenter_vm_info:
      vm: '{{ search_result.value[0].vm }}'
    register: test_vm1_info


The result is a structure with all the details about our VM. You will note this is actually the same information that we get when we created the VM.

Get the hardware version of a specific VM
_________________________________________

We can also use all the ``vcenter_vm_*_info`` modules to retrieve a smaller amount
of information. Here we use ``vcenter_vm_hardware_info`` to know the hardware version of
the VM.

.. ansible-task::

  - name: Collect the hardware information
    vmware.vmware_rest.vcenter_vm_hardware_info:
      vm: '{{ search_result.value[0].vm }}'
    register: my_vm1_hardware_info

List the SCSI adapter(s) of a specific VM
_________________________________________

Here for instance, we list the SCSI adapter(s) of the VM:

.. ansible-task::

  - name: List the SCSI adapter of a given VM
    vmware.vmware_rest.vcenter_vm_hardware_adapter_scsi_info:
      vm: '{{ test_vm1_info.id }}'
    register: _result

You can do the same for the SATA controllers with ``vcenter_vm_adapter_sata_info``.

List the CDROM drive(s) of a specific VM
________________________________________

And we list its CDROM drives.

.. ansible-task::

  - name: List the cdrom devices on the guest
    vmware.vmware_rest.vcenter_vm_hardware_cdrom_info:
      vm: '{{ test_vm1_info.id }}'
    register: _result

Get the memory information of the VM
____________________________________

Here we collect the memory information of the VM:

.. ansible-task::

  - name: Retrieve the memory information from the VM
    vmware.vmware_rest.vcenter_vm_hardware_memory_info:
      vm: '{{ test_vm1_info.id }}'
    register: _result


Get the storage policy of the VM
--------------------------------

We use the ``vcenter_vm_storage_policy_info`` module for that:

.. ansible-task::

  - name: Get VM storage policy
    vmware.vmware_rest.vcenter_vm_storage_policy_info:
      vm: '{{ test_vm1_info.id }}'
    register: _result


Get the disk information of the VM
----------------------------------

We use the ``vcenter_vm_hardware_disk_info`` for this operation:

.. ansible-task::

  - name: Retrieve the disk information from the VM
    vmware.vmware_rest.vcenter_vm_hardware_disk_info:
      vm: '{{ test_vm1_info.id }}'
    register: _result
