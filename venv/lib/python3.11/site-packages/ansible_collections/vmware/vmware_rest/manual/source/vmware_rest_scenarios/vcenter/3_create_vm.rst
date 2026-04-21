.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_create_vm:

*******************************
How to create a Virtual Machine
*******************************

.. contents::
  :local:


Introduction
============

This section shows you how to use Ansible to create a virtual machine.

Scenario requirements
=====================

You've already followed :ref:`vmware_rest_collect_info` and you've got the following variables defined:

- ``my_cluster_info``
- ``my_datastore``
- ``my_virtual_machine_folder``
- ``my_cluster_info``

How to create a virtual machine
===============================

In this example, we will use the ``vcenter_vm`` module to create a new guest.

.. ansible-task::

  - name: Create a VM
    vmware.vmware_rest.vcenter_vm:
      placement:
        cluster: "{{ my_cluster_info.id }}"
        datastore: "{{ my_datastore.datastore }}"
        folder: "{{ my_virtual_machine_folder.folder }}"
        resource_pool: "{{ my_cluster_info.value.resource_pool }}"
      name: test_vm1
      guest_OS: DEBIAN_8_64
      hardware_version: VMX_11
      memory:
        hot_add_enabled: true
        size_MiB: 1024
    register: _result


.. note::
    ``vcenter_vm`` accepts more parameters, however you may prefer to start with a simple VM and use the ``vcenter_vm_hardware`` modules to tune it up afterwards. It's easier this way to identify a potential problematical step.
