theforeman.foreman.subnets
==========================

This role creates and manages Subnets.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_subnets`. Each `subnet` requires the following fields:

- `name`: The name of the subnet.
- `network`: Subnet IP address.

For all other fields see the `subnet` module.

Example Playbook
----------------

Create subnet `192.168.0.0/26`:

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.subnets
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_subnets:
          - name: "My subnet"
            description: "My description"
            network: "192.168.0.0"
            mask: "255.255.255.192"
            gateway: "192.168.0.1"
            from_ip: "192.168.0.2"
            to_ip: "192.168.0.42"
            boot_mode: "Static"
            dhcp_proxy: "smart-proxy1.foo.example.com"
            tftp_proxy: "smart-proxy1.foo.example.com"
            dns_proxy: "smart-proxy2.foo.example.com"
            template_proxy: "smart-proxy2.foo.example.com"
            vlanid: 452
            mtu: 9000
            domains:
            - "foo.example.com"
            - "bar.example.com"
            organizations:
            - "Example Org"
            locations:
            - "Uppsala"
```
