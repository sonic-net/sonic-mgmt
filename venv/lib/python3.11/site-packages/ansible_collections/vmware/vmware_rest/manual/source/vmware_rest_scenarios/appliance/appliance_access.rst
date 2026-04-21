.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_appliance_access:

************************************
Configure the console and SSH access
************************************

Introduction
============

This section show you how to manage the console and SSH access of the vCenter Server Appliance (VCSA).

Scenario requirements
=====================

You've got an up and running vCenter Server Appliance.

Manage the shell access
-----------------------

Detect if the Shell is enabled.

.. ansible-task::

  - name: Check if the Shell is enabled
    vmware.vmware_rest.appliance_access_shell_info:

Or turn on the Shell access with a timeout:

.. ansible-task::

  - name: Disable the Shell
    vmware.vmware_rest.appliance_access_shell:
      enabled: False
      timeout: 600

Manage the Direct Console User Interface (DCUI)
-----------------------------------------------

You can use :ref:`vmware.vmware_rest.appliance_access_dcui_info_module` to get the current state of the configuration:

.. ansible-task::

  - name: Check if the Direct Console User Interface is enabled
    vmware.vmware_rest.appliance_access_dcui_info:

You can enable or disable the interface with appliance_access_dcui:

.. ansible-task::

   - name: Disable the Direct Console User Interface
     vmware.vmware_rest.appliance_access_dcui:
       enabled: False

Manage the SSH interface
------------------------

You can also get the status of the SSH interface with appliance_access_ssh_info:

.. ansible-task::

  - name: Check is the SSH access is enabled
    vmware.vmware_rest.appliance_access_ssh_info:

And to enable the SSH interface:

.. ansible-task::

  - name: Ensure the SSH access ie enabled
    vmware.vmware_rest.appliance_access_ssh:
      enabled: true
