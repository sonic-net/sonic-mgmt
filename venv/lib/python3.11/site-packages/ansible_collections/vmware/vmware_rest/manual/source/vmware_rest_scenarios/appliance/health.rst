.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_appliance_health:

*******************************************
Get the health state of the VCSA components
*******************************************

Introduction
============

The collection provides several modules that you can use to know the state of the different components of the VCSA.

Scenario requirements
=====================

You've got an up and running vCenter Server Appliance.


Health state per component
--------------------------

The database storage:

.. ansible-task::

  - name: Get the database storage heath status
    vmware.vmware_rest.appliance_health_databasestorage_info:

The system load:

.. ansible-task::

  - name: Get the system load status
    vmware.vmware_rest.appliance_health_load_info:

The memory usage:

.. ansible-task::

  - name: Get the system mem status
    vmware.vmware_rest.appliance_health_mem_info:


The system status:

.. ansible-task::

  - name: Get the system health status
    vmware.vmware_rest.appliance_health_system_info:

The package manager:

.. ansible-task::

  - name: Get the health of the software package manager
    vmware.vmware_rest.appliance_health_softwarepackages_info:

The storage system:

.. ansible-task::

  - name: Get the health of the storage system
    vmware.vmware_rest.appliance_health_storage_info:

The swap usage:

.. ansible-task::

  - name: Get the health of the swap
    vmware.vmware_rest.appliance_health_swap_info:


Monitoring
----------

You can also retrieve information from the VCSA monitoring backend. First you need the name of the item. To get a full list of these items, run:

.. ansible-task::

  - name: Get the list of the monitored items
    vmware.vmware_rest.appliance_monitoring_info:
    register: result


With this information, you can access the information for a given time frame:

.. ansible-task::

  - name: Query the monitoring backend
    vmware.vmware_rest.appliance_monitoring_query:
      end_time: 2021-04-14T09:34:56.000Z
      start_time: 2021-04-14T08:34:56.000Z
      names:
        - mem.total
      interval: MINUTES5
      function: AVG
    register: result
