.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_run_a_vm:

****************************
How to run a virtual machine
****************************

.. contents::
  :local:


Introduction
============

This section covers the power management of your virtual machine.

Power information
=================

Use ``vcenter_vm_power_info`` to know the power state of the VM.

.. ansible-task::

  - name: Get guest power information
    vmware.vmware_rest.vcenter_vm_power_info:
      vm: '{{ test_vm1_info.id }}'
    register: _result


How to start a virtual machine
==============================

Use the ``vcenter_vm_power`` module to start your VM:

.. ansible-task::

  - name: Turn the power of the VM on
    vmware.vmware_rest.vcenter_vm_power:
      state: start
      vm: '{{ test_vm1_info.id }}'

How to wait until my virtual machine is ready
=============================================

If your virtual machine runs VMware Tools, you can build a loop
around the ``center_vm_tools_info`` module:

.. ansible-task::

  - name: Wait until my VM is ready
    vmware.vmware_rest.vcenter_vm_tools_info:
      vm: '{{ test_vm1_info.id }}'
    register: vm_tools_info
    until:
    - vm_tools_info is not failed
    - vm_tools_info.value.run_state == "RUNNING"
    retries: 60
    delay: 5
