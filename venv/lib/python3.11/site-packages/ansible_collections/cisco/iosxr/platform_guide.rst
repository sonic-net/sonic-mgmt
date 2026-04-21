.. _iosxr_platform_options:

***************************************
IOS-XR Platform Options
***************************************

The `Cisco IOS-XR collection <https://galaxy.ansible.com/ui/repo/published/cisco/iosxr>`_ supports multiple connections. This page offers details on how each connection works in Ansible and how to use it.

.. contents::
  :local:

Connections available
================================================================================

.. table::
    :class: documentation-table

    ====================  ==========================================  ============================================================================================================
    ..                    CLI                                         NETCONF
                                                                      only for modules ``iosxr_banner``, ``iosxr_interface``, ``iosxr_logging``, ``iosxr_system``, ``iosxr_user``
    ====================  ==========================================  ============================================================================================================
    Protocol              SSH                                         XML over SSH

    Credentials           uses SSH keys / SSH-agent if present        uses SSH keys / SSH-agent if present
                          accepts ``-u myuser -k`` if using password  accepts ``-u myuser -k`` if using password

    Indirect Access       by a bastion (jump host)                    by a bastion (jump host)

    Connection Settings   ``ansible_connection:``                     ``ansible_connection:``
                            ``ansible.netcommon.network_cli``             ``ansible.netcommon.netconf``

    Enable Mode            not supported                              not supported
    (Privilege Escalation)

    Returned Data Format  Refer to individual module documentation    Refer to individual module documentation
    ====================  ==========================================  ============================================================================================================


The ``ansible_connection: local`` has been deprecated. Please use ``ansible_connection: ansible.netcommon.network_cli`` or ``ansible_connection: ansible.netcommon.netconf`` instead.

Using CLI in Ansible
====================

Example CLI inventory ``[iosxr:vars]``
----------------------------------------

.. code-block:: yaml

   [iosxr:vars]
   ansible_connection=ansible.netcommon.network_cli
   ansible_network_os=cisco.iosxr.iosxr
   ansible_user=myuser
   ansible_password=!vault...
   ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -q bastion01"'

- If you are using SSH keys (including an ssh-agent) you can remove the ``ansible_password`` configuration.
- If you are accessing your host directly (not through a bastion/jump host) you can remove the ``ansible_ssh_common_args`` configuration.
- If you are accessing your host through a bastion/jump host, you cannot include your SSH password in the ``ProxyCommand`` directive. To prevent secrets from leaking out (for example in ``ps`` output), SSH does not support providing passwords through environment variables.

Example CLI task
----------------

.. code-block:: yaml

   - name: Retrieve IOS-XR version
     cisco.iosxr.iosxr_command:
       commands: show version
     when: ansible_network_os == 'cisco.iosxr.iosxr'

Using NETCONF in Ansible
==========================

Enabling NETCONF
---------------

Before you can use NETCONF to connect to a switch, you must:

 - install the ``ncclient`` python package on your control node(s) with ``pip install ncclient``
 - enable NETCONF on the Cisco IOS-XR device(s)

To enable NETCONF on a new switch with Ansible, use the ``cisco.iosxr.iosxr_netconf`` module through the CLI connection. Set up your platform-level variables just like in the CLI example above, then run a playbook task like this:

.. code-block:: yaml

   - name: Enable NETCONF
     connection: ansible.netcommon.network_cli
     cisco.iosxr.iosxr_netconf:
     when: ansible_network_os == 'cisco.iosxr.iosxr'

Once NETCONF is enabled, change your variables to use the NETCONF connection.

Example NETCONF inventory ``[iosxr:vars]``
------------------------------------------

.. code-block:: yaml

   [iosxr:vars]
   ansible_connection=ansible.netcommon.netconf
   ansible_network_os=cisco.iosxr.iosxr
   ansible_user=myuser
   ansible_password=!vault |
   ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -q bastion01"'


Example NETCONF task
-----------------------

.. code-block:: yaml

   - name: Configure hostname and domain-name
     cisco.iosxr.iosxr_system:
       hostname: iosxr01
       domain_name: test.example.com
       domain_search:
         - ansible.com
         - redhat.com
         - cisco.com


Warning
--------
Never store passwords in plain text. We recommend using SSH keys to authenticate SSH connections. Ansible supports ssh-agent to manage your SSH keys. If you must use passwords to authenticate SSH connections, we recommend encrypting them with Ansible Vault.

Cisco IOS-XR platform support matrix
===================================

The following platforms and software versions have been certified by Cisco to work with this version of Ansible.

.. table:: Platform / Software Minimum Requirements
     :align: center

     ===================  ======================
     Supported Platforms  Minimum IOS-XR Version
     ===================  ======================
     Cisco IOS-XR         7.0.2 and later
     ===================  ======================


Notes
-----

`Setting Timeout Option <https://docs.ansible.com/ansible/latest/network/getting_started/network_connection_options.html#timeout-options>`_
