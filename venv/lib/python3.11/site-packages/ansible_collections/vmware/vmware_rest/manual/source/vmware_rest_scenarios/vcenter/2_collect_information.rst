.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_collect_info:

*************************************************
How to collect information about your environment
*************************************************

.. ansible-tasks::
  :hide:

  - import_role:
      name: prepare_lab

Introduction
============

This section shows you how to utilize Ansible to collect information about your environment.
This information is useful for the other tutorials.

Scenario requirements
=====================

In this scenario we've got a vCenter with an ESXi host.

Our environment is pre-initialized with the following elements:

- A datacenter called ``my_dc``
- A cluster called ``my_cluser``
- A cluster called ``my_cluser``
- An ESXi host called ``esxi1`` is in the cluster
- Two datastores on the ESXi: ``rw_datastore`` and ``ro_datastore``
- A dvswitch based guest network

Finally, we use the environment variables to authenticate ourselves as explained in :ref:`vmware_rest_authentication`.

How to collect information
==========================

In these examples, we use the ``vcenter_*_info`` module to collect information about the associated resources.

All these modules return a ``value`` key. Depending on the context, this ``value`` key will be either a list or a dictionary.

Datacenter
----------

Here we use the ``vcenter_datacenter_info`` module to list all the datacenters. As expected, the ``value`` key of the output is a list.

.. ansible-task::

  - name: collect a list of the datacenters
    vmware.vmware_rest.vcenter_datacenter_info:
    register: my_datacenters

Cluster
-------

Here we do the same with ``vcenter_cluster_info`` module:

.. ansible-task::

  - name: Build a list of all the clusters
    vmware.vmware_rest.vcenter_cluster_info:
    register: all_the_clusters

And we can also fetch the details about a specific cluster, with the ``cluster`` parameter:

.. ansible-task::

  - name: Retrieve details about the first cluster
    vmware.vmware_rest.vcenter_cluster_info:
      cluster: "{{ all_the_clusters.value[0].cluster }}"
    register: my_cluster_info


And the ``value`` key of the output is this time a dictionary.

Datastore
---------

Here we use ``vcenter_datastore_info`` to get a list of all the datastore called ``rw_datastore``:


.. ansible-task::

  - name: Retrieve a list of all the datastores
    vmware.vmware_rest.vcenter_datastore_info:
      filter_names:
      - rw_datastore
    register: my_datastores

We save the first datastore in `my_datastore` fact for later use.

.. ansible-task::

 - name: Set my_datastore
   set_fact:
      my_datastore: '{{ my_datastores.value|first }}'


Folder
------

And here again, you use the ``vcenter_folder_info`` module to retrieve a list of all the folders.

.. ansible-task::

  - name: Build a list of all the folders
    vmware.vmware_rest.vcenter_folder_info:
    register: my_folders

Most of the time, you will just want one type of folder. In this case we can use filters to reduce the amount to collect. Most of the ``_info`` modules come with similar filters.

.. ansible-task::

  - name: Build a list of all the folders with the type VIRTUAL_MACHINE and called vm
    vmware.vmware_rest.vcenter_folder_info:
      filter_type: VIRTUAL_MACHINE
      filter_names:
        - vm
    register: my_folders


We register the first folder for later use with ``set_fact``.

.. ansible-task::

  - name: Set my_virtual_machine_folder
    set_fact:
      my_virtual_machine_folder: '{{ my_folders.value|first }}'
