## Overview
The purpose is to test VLAN functions on the SONiC switch.  

### Scope
The tests will include:

1. Functionalities of VLAN ports.
2. VLAN interfaces routing.
3. IP2me traffic on VLAN interfaces.

The test will trying to cover all functionalities of VLAN ports including Ethernet ports and LAGs. And will make sure the IP traffic and IP2me traffic is working well.

### Functionalities of VLAN ports

A VLAN port will include three attributes:

* PVID: Ingress untagged packets will be tagged with PVID, and PVID will always in Permit VLAN IDs.

* Permit VLAN IDs: Which VLAN ID of ingress and egress packets is allowed in the port.

* tagged VLAN IDs: Determine which VLAN IDs egress packets will be tagged.  

  For the VLAN trunk feature,  the tagged VLAN IDs are limited to Permit VLAN IDs besides PVID, e.g., if PVID is 100, Permit VLAN IDs are 100,200,300, tagged VLAN IDs are 200,300, in other words, untagged VLAN ID is 100.

The detail actions of VLAN ports:


| Packet Tagged or Untagged | Direction | Action                                   |
| :------------------------ | :-------- | :--------------------------------------- |
| Untagged                  | Ingress   | Tags the packet with the PVID tag.       |
|                           | Egress    | If VLAN ID of the packet is equal with untagged VLAN ID, untag and send out the packet. Besides, if VLAN ID is in Permit VLAN IDs, send out the packet with tag. |
| Tagged                    | Ingress   | If VLAN ID of the packet is not in Permit VLAN IDs, drop the packet. |
|                           | Egress    | If VLAN ID of the packet is equal with untagged VLAN ID, untag and send out the packet. Besides, if VLAN ID is in Permit VLAN IDs, send out the packet with tag. |

## TEST structure

1. The tests assume fanout switch support QinQ (stacked VLAN), so that stacked VLAN packets can passthrough fanout switch and can be tested on DUT with inner VLAN.

   ```
   | testbed server | <------------------> | Fanout switch | <------------------> | DUT |
                        stacked vlan pkt                        single vlan pkt
                        outer vlan: 1681                        vlan: 100
                        inner vlan: 100
   ```

2. Tests will be based on *t0* testbed type. The IP address of every LAGs on the DUT will be flushed to make all LAGs act as L2 ports. New test IP addresses will be configured on VLAN interfaces.

3. VMs are only used to do LACP negotiation for LAGs; PTF is used to send packet and verify VLAN functionalities.

4. The test contains three files:

   vlan_info.j2: Define VLAN ports info and VLAN interface info for vlan.yml and vlan_test.py

   vlan.yml: Configure DUT for the test according to vlan_info.j2

   vlan_test.py: Do the PTF test according to vlan_info.j2

5. vlan_info.j2 will choose several Ethernet ports and LAG ports from minigraph of current topology and generate VLAN port info and VLAN interface info for PTF python script to do test. 

   ```jinja2
   {% set vlan_id_list = [ 100, 200 ] %}
   vlan_ports_list:
   {% for lag_number in range(2) %}
     - dev: '{{ minigraph_portchannels.keys()[lag_number|int] }}'
       port_index: '{{ minigraph_port_indices[minigraph_portchannels[minigraph_portchannels.keys()[lag_number|int]].members[0]] }}'
       pvid: '{{ vlan_id_list[(lag_number|int)%2] }}'
       permit_vlanid:
   {% for vlan in vlan_id_list %}
         '{{ vlan }}':
           peer_ip: '192.168.{{ vlan }}.{{ minigraph_port_indices[minigraph_portchannels[minigraph_portchannels.keys()[lag_number|int]].members[0]] }}'
           remote_ip: '{{vlan}}.1.1.{{ minigraph_port_indices[minigraph_portchannels[minigraph_portchannels.keys()[lag_number|int]].members[0]] }}'
   {% endfor %}
   {% endfor %}
   {% for port_number in range(2) %}
     - dev: '{{ minigraph_ports.keys()[port_number|int]}}'
       port_index: '{{ minigraph_port_indices[minigraph_ports.keys()[port_number|int]]}}'
       pvid: '{{ ((port_number|int)%2+1)*100}}'
       permit_vlanid:
   {% for vlan in vlan_id_list %}
         '{{ vlan }}':
           peer_ip: '192.168.{{ vlan }}.{{ minigraph_port_indices[minigraph_ports.keys()[port_number|int]] }}'
           remote_ip: '{{vlan}}.1.1.{{ minigraph_port_indices[minigraph_ports.keys()[port_number|int]] }}'
   {% endfor %}
   {% endfor %}

   vlan_intf_list:
   {% for vlan in vlan_id_list %}
     - vlan_id: '{{ (vlan|int) }}'
       ip: '192.168.{{ vlan }}.1/24'
   {% endfor %}
   ```

   and generate vlan.yml. Below is for an example:

   ```yaml
   vlan_ports_list:
     - dev: 'PortChannel03'
       port_index: '30'
       pvid: '100'
       permit_vlanid:
         '100':
           peer_ip: '192.168.100.30'
           remote_ip: '100.1.1.30'
         '200':
           peer_ip: '192.168.200.30'
           remote_ip: '200.1.1.30'
     - dev: 'PortChannel02'
       port_index: '29'
       pvid: '200'
       permit_vlanid:
         '100':
           peer_ip: '192.168.100.29'
           remote_ip: '100.1.1.29'
         '200':
           peer_ip: '192.168.200.29'
           remote_ip: '200.1.1.29'
     - dev: 'Ethernet8'
       port_index: '8'
       pvid: '100'
       permit_vlanid:
         '100':
           peer_ip: '192.168.100.8'
           remote_ip: '100.1.1.8'
         '200':
           peer_ip: '192.168.200.8'
           remote_ip: '200.1.1.8'
     - dev: 'Ethernet9'
       port_index: '9'
       pvid: '200'
       permit_vlanid:
         '100':
           peer_ip: '192.168.100.9'
           remote_ip: '100.1.1.9'
         '200':
           peer_ip: '192.168.200.9'
           remote_ip: '200.1.1.9'

   vlan_intf_list:
     - vlan_id: '100'
       ip: '192.168.100.1/24'
     - vlan_id: '200'
       ip: '192.168.200.1/24'
   ```


## TEST case

All the test cases will try to send packets from all the VLAN ports defined in vlan.yml, and try to verify packets from all expected VLAN ports.

### Test case #1

#### Test objective

To verify untagged packets received and be sent out with tag or without tag determined by egress port PVID. 

#### Test description

```
Test example:
                                            |(untag:100/permit:100,200)->pkt(untagged)
pkt(untagged)->(pvid:100/permit:100,200)|DUT|
                                            |(untag:200/permit:100,200)->pkt(tagged:100)
```

1. PTF send untagged packets(destination MAC unknown).
2. Verify packets can be received from other ports which permit PVID on ingress port. And packets will egress untagged if PVID on ingress port is same with egress ports , or packets will egress tagged with ingress port PVID.

### Test case #2

#### Test objective

To verify if tagged packets received in Permit VLAN IDs and be sent out with tag or without tag determined by egress port PVID. 

#### Test description

```
Test example:
                                              |(untag:100/permit:100,200)->pkt(untagged)
pkt(tagged:100)->(pvid:100/permit:100,200)|DUT|
                                              |(untag:200/permit:100,200)->pkt(tagged:100)
                                                 
                                              |(untag:100/permit:100,200)->pkt(tagged:200)
pkt(tagged:200)->(pvid:100/permit:100,200)|DUT|
                                              |(untag:200/permit:100,200)->pkt(untagged)
```

1. PTF send tagged packets(destination MAC unknown), which VLAN ID is in Permit VLAN IDs of ingress port.
2. Verify packets can be received from other ports which permit PVID on ingress port. And packets will egress untagged if PVID on ingress port is same with egress ports , or packets will egress tagged with ingress port PVID.

### Test case #3

#### Test objective

To verify if tagged packets received not in Permit VLAN IDs, the packets will be dropped

#### Test description

```
Test example:
                                               |(untag:100/permit:100,200)->no pkt egress
pkt(tagged:4095)->(pvid:100/permit:100,200)|DUT|
                                               |(untag:200/permit:100,200)->no pkt egress
```

1. PTF send tagged packets(destination MAC unknown), which VLAN ID is not in Permit VLAN IDs of ingress port.
2. Verify no packets received from other ports. 

### Test case #4
#### Test objective

To verify the  VLAN interface routing is working.

#### Test description

```
Test example:
Vlan100: 192.168.100.1/24
Vlan200: 192.168.200.1/24

192.168.100.30->192.168.200.30 (for directly-connected routing)
pkt(tagged:100)->(pvid:200/permit:100,200)|DUT|(untag:100/permit:100,200)->pkt(tagged:200)
pkt(untagged)->(pvid:100/permit:100,200)|DUT|(untag:100/permit:100,200)->pkt(tagged:200)
pkt(untagged)->(pvid:100/permit:100,200)|DUT|(untag:200/permit:100,200)->pkt(untagged)

1.1.1.30->2.1.1.30 (for indirectly-connected routing)
pkt(tagged:100)->(pvid:200/permit:100,200)|DUT|(untag:100/permit:100,200)->pkt(tagged:200)
pkt(untagged)->(pvid:100/permit:100,200)|DUT|(untag:100/permit:100,200)->pkt(tagged:200)
pkt(untagged)->(pvid:100/permit:100,200)|DUT|(untag:200/permit:100,200)->pkt(untagged)
```

1. PTF send IP packets over VLAN interfaces.
2. Verify packets can be receive on the egress port.

### Test case #5
#### Test objective

To verify the IP traffic to VLAN interface self is working.

#### Test description

```
Test example:
Vlan100: 192.168.100.1/24
Vlan200: 192.168.200.1/24

192.168.100.30->192.168.100.1
pkt(untagged)->
                (pvid:100/untag:100/permit:100,200)|DUT|
pkt(untagged)<-

192.168.100.30->192.168.100.1
pkt(tagged:100)->
                 (pvid:200/untag:200/permit:100,200)|DUT|
pkt(tagged:100)<-
```

1. PTF send ICMP request packet to VLAN interfaces.
2. Verify ICMP reply packets can be received from ingress port.


