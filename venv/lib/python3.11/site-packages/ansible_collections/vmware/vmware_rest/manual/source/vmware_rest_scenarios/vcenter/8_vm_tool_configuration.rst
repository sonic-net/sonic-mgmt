.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_vm_tool_configuration:

**************************************************************
How to configure the VMware tools of a running virtual machine 
**************************************************************

.. contents::
  :local:


Introduction
============

This section show you how to collection information from a running virtual machine.

Scenario requirements
=====================

You've already followed :ref:`vmware_rest_run_a_vm` and your virtual machine runs VMware Tools.

How to change the upgrade policy
================================

Change the upgrade policy to MANUAL
---------------------------------------------------

You can adjust the VMware Tools upgrade policy with the ``vcenter_vm_tools`` module.

.. ansible-task::

  - name: Change vm-tools upgrade policy to MANUAL
    vmware.vmware_rest.vcenter_vm_tools:
      vm: '{{ test_vm1_info.id }}'
      upgrade_policy: MANUAL
    register: _result


Change the upgrade policy to UPGRADE_AT_POWER_CYCLE 
------------------------------------------------------------------------------------------

.. ansible-task::

  - name: Change vm-tools upgrade policy to UPGRADE_AT_POWER_CYCLE
    vmware.vmware_rest.vcenter_vm_tools:
      vm: '{{ test_vm1_info.id }}'
      upgrade_policy: UPGRADE_AT_POWER_CYCLE
    register: _result
