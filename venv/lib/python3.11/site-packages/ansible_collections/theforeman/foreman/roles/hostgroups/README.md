theforeman.foreman.hostgroups
=============================

This role creates and manages Hostgroups.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

- `foreman_hostgroups`: List of hostgroups to manage that are each represented as a dictionary. See module documentation for a list of available options for each hostgroup.
  Hostgroups may have any set of fields defined on them and may optionally define a `parent` for nested hostgroups.
  A variety of examples are demonstrated in the data structure below:

```yaml
foreman_hostgroups:
  - name: "Basic example"
    architecture: "x86_64"
    operatingsystem: "CentOS"
    medium: "media_name"
    ptable: "partition_table_name"
  - name: "Proxies hostgroup"
    environment: production
    puppet_proxy: puppet-proxy.example.com
    puppet_ca_proxy: puppet-proxy.example.com
    openscap_proxy: openscap-proxy.example.com
  - name: "CentOS 7"
    organization: "Default Organization"
    lifecycle_environment: "Production"
    content_view: "CentOS 7"
    activation_keys: centos-7
  - name: "Webserver"
    parent: "CentOS 7"
    environment: production
    puppet_proxy: puppet-proxy.example.com
    puppet_ca_proxy: puppet-proxy.example.com
    openscap_proxy: openscap-proxy.example.com
```

Example Playbooks
-----------------

This example creates several hostgroups with some nested examples.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.hostgroups
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_hostgroups:
          - name: "Basic example"
            architecture: "x86_64"
            operatingsystem: "CentOS"
            medium: "media_name"
            ptable: "partition_table_name"
          - name: "Proxies hostgroup"
            environment: production
            puppet_proxy: puppet-proxy.example.com
            puppet_ca_proxy: puppet-proxy.example.com
            openscap_proxy: openscap-proxy.example.com
          - name: "CentOS 7"
            organization: "Default Organization"
            lifecycle_environment: "Production"
            content_view: "CentOS 7"
            activation_keys: centos-7
          - name: "Webserver"
            parent: "CentOS 7"
            environment: production
            puppet_proxy: puppet-proxy.example.com
            puppet_ca_proxy: puppet-proxy.example.com
            openscap_proxy: openscap-proxy.example.com
```
