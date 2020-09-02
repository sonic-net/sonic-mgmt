# Testbed internals

## Topology definition

 - List of currently defined topologies in veos inventory file
```
[servers:vars]
topologies=[‘t1', ‘t1-lag', 't0', 'ptf32', 'ptf64']
```
 - Topologies stored inside of vars/topo_*.yml, where * is a topology name
 - Configuration templates for the topologies saved in roles/eos/templates/*.yml

## Topology file

 - Topology file is a regular ansible yaml file with variables:
   - topology – defines physical topology
   - configuration – defines variables for VMs configuration templates
   - configuration_properties – defines group variables for VMs configuration templates

 - topology dictionary is required
 - configuration and configuration_properties are optional and used only for topologies with VMs

## Topology file. topology dictionary

 - Two dictionaries:
   - host_interface – defines a list of port offsets which would be inserted into the PTF container
   - VMs – defines a list and a physical configuration of VMs used in topology

```
topology:
  host_interfaces:
    - 0
    - 1
  VMs:
    ARISTA01T1:
      vlans:
        - 2
        - 3
      vm_offset: 0
    ARISTA02T1:
      vlans:
        - 4
      vm_offset: 1

```
 - ARISTA01T1 – hostname for a VM
 - vlans - list of vlan offsets used in VM
 - vm_offset – offset of VM with base configured as vm_base in testbed.csv

 - In this example:
   - Let’s consider: vm_base == VM0100, vlan_base == ‘100’
   - First VM:
     - hostname ARISTA01T1
     - Uses VM with physical name VM0100
     - Ethernet1 is connected to vlan 102
     - Ethernet2 is connected to vlan 103
     - Ethernet9 is connected to backplane network (implicitly configured)
   - Second VM:
     - hostname ARISTA02T1
     - Uses VM with physical name VM0101 (vm_offset: 1 + vm_base: VM0100)
     - Ethernet1 is connected to vlan 104
     - Ethernet9 is connected to backplane network (implicitly configured)
   - PTF container:
     - 5 ethernet interfaces:
     - eth0 is directly connected to DUT. vlan 100
     - eth1 is directly connected to DUT. vlan 101
     - eth2 is injected interface for Ethernet1 of VM ARISTA01T1
     - eth3 is injected interface for Ethernet2 of VM ARISTA01T1
     - eth4 is injected interface for Ethernet1 of VM ARISTA02T1

## Topology file. configuration_properties
```
configuration_properties:
  common:
    nhipv4: 10.10.246.100
    nhipv6: FC0A::C9
  spine:
    swrole: spine
    podset_number: 200
    tor_number: 16
    tor_subnet_number: 2
    leaf_asn_start: 62001
    tor_asn_start: 65501
    failure_rate: 0
  tor:
    swrole: tor
    tor_subnet_number: 5

```
 - Configuration properties contains any number of dictionary entries
 - You could have as many as you want
 - Lately you can refer to these entries in your configuration dictionary. See entry “properties”
 - You could use them as {{ props.property_name }} inside of jinja2 template. Example: {% for tor in range(0, props.tor_number) %}

## Topology file. configuration
```
configuration:
  ARISTA01T2:
    properties:
    - common
    - spine
    bgp:
      asn: 65200
      peers:
        65100:
        - 10.0.0.0
        - FC00::1
    interfaces:
      Loopback0:
        ipv4: 100.1.0.1/32
        ipv6: 2064:100::1/128
      Ethernet1:
        ipv4: 10.0.0.1/31
        ipv6: fc00::2/126
      Ethernet9:
        ipv4: 10.10.246.1/24
        ipv6: fc0a::2/64

```
 - Configurations contains any number of dictionary entries
 - You could have as many as you want
 - You have to have entry properties when you want to bring some common property into the configuration
 - You could use configuration as {{configuration[hostname].property }} inside of jinja2 template.

   Example:
```
{% set host = configuration[hostname] %}
{% for name, iface in host['interfaces'].items() %}
```
