oVirt Networks
==============

The `networks` role sets up oVirt networks.

Role Variables
--------------

The `data_center_name` variable specifes the data center name of the network.

The `logical_networks` list can contain following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| name          | UNDEF          | Name of the network.                   |
| state         | present        | Specifies whether the network state is `present` or `absent`. |
| vlan_tag      | UNDEF          | Specify VLAN tag.                |
| vm_network    | True           | If True network will be marked as network for VM.             |
| mtu           | UNDEF          | Maximum transmission unit (MTU) of the network.    |
| description   | UNDEF          | Description of the network.  |
| clusters      | UNDEF          | List of dictionaries describing how the network is managed in specific cluster. |
| label         | UNDEF          | Name of the label to assign to the network. |

More information about the parameters can be found in the [ovirt_network](http://docs.ansible.com/ansible/ovirt_network_module.html) module documentation.

The `host_networks` list can contain following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| name          | UNDEF          | Name of the host.                      |
| state         | UNDEF          | Specifies whether the network state is `present` or `absent`.            |
| check         | UNDEF          | If true, verifies the connection between the host and engine. |
| save          | UNDEF          | If true, the network configuration will be persistent, by default it is temporary. |
| bond          | UNDEF          | Dictionary describing the network bond. |
| networks      | UNDEF          | Dictionary describing the networks to be attached to the interface or bond. |
| labels        | UNDEF          | List of names of the network label to be assigned to the bond or interface. |
| interface     | UNDEF          | Name of the network interface where the logical network should be attached. |

More information about the parameters can be found in the [ovirt_host_network](http://docs.ansible.com/ansible/ovirt_host_network_module.html) module documentation.

Example Playbook
----------------

```yaml
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
   logical_networks:
     - name: mynetwork
       clusters:
         - name: development
           assigned: yes
           required: no
           display: no
           migration: yes
           gluster: no

   host_networks:
     - name: myhost1
       check: true
       save: true
       bond:
         name: bond0
         mode: 2
         interfaces:
           - eth2
           - eth3
       networks:
         - name: mynetwork
           boot_protocol: dhcp

  roles:
    - ovirt.ovirt.infra.roles.networks
```
