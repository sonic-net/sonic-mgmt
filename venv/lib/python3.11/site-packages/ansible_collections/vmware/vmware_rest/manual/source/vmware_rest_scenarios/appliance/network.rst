.. _ansible_collections.vmware.vmware_rest.docsite.vmware_rest_appliance_network:

*****************
Network managment
*****************

IP configuration
================

You can also use Ansible to get and configure the network stack of the VCSA.

Global network information
--------------------------

The appliance_networking_info exposes the state of the global network configuration:

.. ansible-task::

  - name: Get network information
    vmware.vmware_rest.appliance_networking_info:

And you can adjust the parameters with the appliance_networking module.

.. ansible-task::

  - name: Set network information
    vmware.vmware_rest.appliance_networking:
      ipv6_enabled: False

Network Interface configuration
-------------------------------

The appliance_networking_interfaces_info returns a list of the Network Interface of the system:

.. ansible-task::

  - name: Get a list of the network interfaces
    vmware.vmware_rest.appliance_networking_interfaces_info:

You can also use the ``interface_name`` parameter to just focus on one single entry:

.. ansible-task::

  - name: Get details about one network interfaces
    vmware.vmware_rest.appliance_networking_interfaces_info:
      interface_name: nic0


DNS configuration
=================

The hostname configuration
--------------------------

The appliance_networking_dns_hostname_info module can be use to retrieve the hostname of the VCSA:

.. ansible-task::

  - name: Get the hostname configuration
    vmware.vmware_rest.appliance_networking_dns_hostname_info:


The DNS servers
---------------

Use the appliance_networking_dns_servers_info to get DNS servers currently in use:

.. ansible-task::

  - name: Get the DNS servers
    vmware.vmware_rest.appliance_networking_dns_servers_info:
    ignore_errors: True  # May be failing because of the CI set-up

The appliance_networking_dns_servers can be used to set a different name server.

.. ansible-task::

  - name: Set the DNS servers
    vmware.vmware_rest.appliance_networking_dns_servers:
      servers:
        - 192.168.123.1
      mode: is_static

You can test a list of servers if you set ``state=test``:

.. ansible-task::

  - name: Test the DNS servers
    vmware.vmware_rest.appliance_networking_dns_servers:
      state: test
      servers:
        - var

The search domain configuration
-------------------------------


The search domain configuration can be done with appliance_networking_dns_domains and appliance_networking_dns_domains_info. The second module returns a list of domains:

.. ansible-task::

  - name: Get DNS domains configuration
    vmware.vmware_rest.appliance_networking_dns_domains_info:

There is two way to set the search domain. By default the value you pass in ``domains`` will overwrite the existing domain:

.. ansible-task::

  - name: Update the domain configuration
    vmware.vmware_rest.appliance_networking_dns_domains:
      domains:
        - foobar

If you instead use the ``state=add`` parameter, the ``domain`` value will complet the existing list of domains.

.. ansible-task::

  - name: Add another domain configuration
    vmware.vmware_rest.appliance_networking_dns_domains:
      domain: barfoo
      state: add

Firewall settings
=================

You can also configure the VCSA firewall. You can add new ruleset with the appliance_networking_firewall_inbound module. In this example, we reject all the traffic coming from the ``1.2.3.0/24`` subnet:

.. ansible-task::

  - name: Set a firewall rule
    vmware.vmware_rest.appliance_networking_firewall_inbound:
      rules:
        - address: 1.2.3.0
          prefix: 24
          policy: REJECT

The appliance_networking_firewall_inbound_info module returns a list of the inbound ruleset:

.. ansible-task::

  - name: Get the firewall inbound configuration
    vmware.vmware_rest.appliance_networking_firewall_inbound_info:

HTTP proxy
==========

You can also configurre the VCSA to go through a HTTP proxy. The collection provides a set of modules to configure the proxy server and manage the noproxy filter.


In this example, we will set up a proxy and configure the ``noproxy`` for ``redhat.com`` and ``ansible.com``:

.. ansible-tasks::

  - name: Set the HTTP proxy configuration
    vmware.vmware_rest.appliance_networking_proxy:
      enabled: true
      server: https://datastore.test
      port: 3128
      protocol: https
  - name: Set HTTP noproxy configuration
    vmware.vmware_rest.appliance_networking_noproxy:
      servers:
        - redhat.com
        - ansible.com

We can validate the configuration with the associated _info modules:

.. ansible-tasks::

  - name: Get the HTTP proxy configuration
    vmware.vmware_rest.appliance_networking_proxy_info:
  - name: Get HTTP noproxy configuration
    vmware.vmware_rest.appliance_networking_noproxy_info:

And we finally reverse the configuration:

.. ansible-tasks::

  - name: Delete the HTTP proxy configuration
    vmware.vmware_rest.appliance_networking_proxy:
      config: {}
      protocol: http
      state: absent
  - name: Remove the noproxy entries
    vmware.vmware_rest.appliance_networking_noproxy:
      servers: []
