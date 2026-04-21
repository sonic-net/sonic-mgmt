.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_appliance_shutdown:

****************
System managment
****************

How to reboot or shutdown the VCSA
==================================

You can use Ansible to trigger or cancel a shutdown. The appliance_shutdown_info module is useful to know if a shutdown is already scheduled.

.. ansible-task::

    - name: Check if there is a shutdown scheduled
      vmware.vmware_rest.appliance_shutdown_info:

When you trigger a shutdown, you can also specify a ``reason``. The information will be exposed to the other users:

.. ansible-task::

    - name: Shutdown the appliance
      vmware.vmware_rest.appliance_shutdown:
        state: poweroff
        reason: this is an example
        delay: 600

To cancel a shutdown, you must set the ``state`` to ``cancel``:

.. ansible-task::

    - name: Abort the shutdown of the appliance
      vmware.vmware_rest.appliance_shutdown:
        state: cancel


*********
FIPS mode
*********

Federal Information Processing Standards (FIPS)
===============================================

The appliance_system_globalfips_info module will tell you if FIPS is enabled.

.. ansible-task::

    - name: "Get the status of the Federal Information Processing Standard mode"
      vmware.vmware_rest.appliance_system_globalfips_info:

You can turn the option on or off with appliance_system_globalfips:

.. warning::

   The VCSA will silently reboot itself if you change the FIPS configuration.

.. ansible-task::

    - name: Turn off the FIPS mode and reboot
      vmware.vmware_rest.appliance_system_globalfips:
        enabled: false

*******************************
Time and Timezone configuration
*******************************

Timezone
========

The appliance_system_time_timezone and ppliance_system_time_timezone_info modules handle the Timezone configuration. You can get the current configuration with:

.. ansible-task::

    - name: Get the timezone configuration
      vmware.vmware_rest.appliance_system_time_timezone_info:

And to adjust the system's timezone, just do:

.. ansible-task::

    - name: Use the UTC timezone
      vmware.vmware_rest.appliance_system_time_timezone:
        name: UTC

In this example we set the ``UTC`` timezone, you can also pass a timezone in the ``Europe/Paris`` format.

Current time
============

If you want to get the current time, use appliance_system_time_info:

.. ansible-task::

    - name: Get the current time
      vmware.vmware_rest.appliance_system_time_info:

Time Service (NTP)
==================

The VCSA can get the time from a NTP server:

.. ansible-task::

  - name: Get the NTP configuration
    vmware.vmware_rest.appliance_ntp_info:

You can use the appliance_ntp module to adjust the system NTP servers. The module accepts one or more NTP servers:

.. ansible-task::

  - name: Adjust the NTP configuration
    vmware.vmware_rest.appliance_ntp:
      servers:
        - time.google.com

If you set ``state=test``, the module will validate the servers are rechable.

.. ansible-task::

  - name: Test the NTP configuration
    vmware.vmware_rest.appliance_ntp:
      state: test
      servers:
        - time.google.com

You can check the clock synchronization with appliance_timesync_info:

.. ansible-task::

    - name: Get information regarding the clock synchronization
      vmware.vmware_rest.appliance_timesync_info:

Or also validate the system use NTP with:

.. ansible-task::

    - name: Ensure we use NTP
      vmware.vmware_rest.appliance_timesync:
        mode: NTP

**************
Storage system
**************

The collection also provides modules to manage the storage system. appliance_system_storage_info will list the storage partitions:


.. ansible-task::

    - name: Get the appliance storage information
      vmware.vmware_rest.appliance_system_storage_info:

You can use the ``state=resize_ex`` option to extend an existing partition:

.. ansible-task::

    - name: Resize the first partition and return the state of the partition before and after the operation
      vmware.vmware_rest.appliance_system_storage:
        state: resize_ex

.. note::
   ``state=resize`` also works, but you won't get as much information as with ``resize_ex``.
