# Testbed Routing Design

This document discusses the BGP routing design in the Testbed.

```
              +------+
              +  VM  +---------+
              +------+         |
                               |
              +------+         |
              +  VM  +---------+
              +------+         |
+-------+                  +---+---+     
|  PTF  +------------------+  DUT  |
+-------+                  +---+---+
              +------+         |
              +  VM  +---------+
              +------+         |
                               |
              +------+         |
              +  VM  +---------+
              +------+
```
              
In this topology, VMs (vEOS) act as the BGP neighbors of the DUT. VMs generate and advertise BGP routes to the DUT.
This approach has several issues:
- Difficult to generate arbitary routes from the vEOS, e.g., write complex route-map and filter to generate the needed routes.
- Consume lots of memory in the vEOS
- Rules are specific the NOS. If we plan to switch VM to SONiC, we need to rewrite all the route-maps.


```
              +------+
    +---------+  VM  +---------+
    |         +------+         |
    |                          |
    |         +------+         |
    +---------+  VM  +---------+
    |         +------+         |
+---+---+                  +---+---+     
|  PTF  |                  |  DUT  |
+---+---+                  +---+---+
    |         +------+         |
    +---------+  VM  +---------+
    |         +------+         |
    |                          |
    |         +------+         |
    +---------+  VM  +---------+
              +------+
```

The new approach is use VM as a pass-through device. We run exabgp instances on PTF docker, 
and exabgp advertise the routes to the VM, and VM then re-advertise the routes to DUT. 
This approach has several advantages
- VM template becomes much more simplified. Only basic interface, lag, BGP configuration.
- VM memory consumption is smaller.
- Exabgp can generate complex routes.
- Easy to support different NOS as neigbhor devices, for example SONiC VM.

## Implementation details:
- backplane bridge to physically connect ptf docker and vm. bridge ```the br-b-{{ testbed name }}``` is created 
on the host to connect the eos and ptf via backplane network.
 
```
br-b-vms6-1             8000.72bb0a6ad08c       no      VM0100-back
                                                        VM0101-back
                                                        VM0102-back
                                                        VM0103-back
                                                        ptf-vms6-1-b
```

- eos vm backplane interface. ```Et5``` is created in eos as the backplane interface.

```
ARISTA01T1#show int status
Port       Name      Status       Vlan     Duplex Speed  Type            Flags Encapsulation
Et1                  connected    in Po1   full   unconf EbraTestPhyPort                    
Et2                  connected    1        full   unconf EbraTestPhyPort                    
Et3                  connected    1        full   unconf EbraTestPhyPort                    
Et4                  connected    1        full   unconf EbraTestPhyPort                    
Et5        backplane connected    routed   full   unconf EbraTestPhyPort                    
Ma0                  connected    routed   full   10G    10/100/1000                        
Po1                  connected    routed   full   unconf N/A                    
```

- ptf backplane interface. ```backplane``` interface is created in ptf docker.

```
root@6884a0fcd031:~# ip addr show backplane
1359: backplane@if1360: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 96:1f:0e:1f:fc:09 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.10.246.254/24 scope global backplane
       valid_lft forever preferred_lft forever
    inet6 fc0a::ff/64 scope global 
       valid_lft forever preferred_lft forever
```

- eos bgp connection to exabgp. ```exabgp_v4``` and ```exabgp_v6``` (not shown below) is created in eos to connect with exabgp. 
The bgp connection is iBGP connection.

```
ARISTA01T1#show ip bgp sum
BGP summary information for VRF default
Router identifier 100.1.0.29, local AS number 64600
Neighbor Status Codes: m - Under maintenance
  Description              Neighbor         V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
  65100                    10.0.0.56        4  65100           5081      5080    0    0    1d07h Estab   2      2
  exabgp_v4                10.10.246.254    4  64600           8277      1880    0    0    1d07h Estab   6399   6399
```

- exabgp ansible module to control exabgp service in PTF docker. You can use ```supervisorctl``` to check the exabgp service status. 
  - create, remove, restart exabgp service using supervisord. 
  - each exabgp instance listen to a http port for route announce/withdraw
  
```
root@6884a0fcd031:~# supervisorctl status
exabgp-ARISTA01T1                RUNNING   pid 118, uptime 2 days, 8:16:45
exabgp-ARISTA01T1-v6             RUNNING   pid 131, uptime 2 days, 8:16:42
exabgp-ARISTA02T1                RUNNING   pid 92, uptime 2 days, 8:16:53
exabgp-ARISTA02T1-v6             RUNNING   pid 105, uptime 2 days, 8:16:49
exabgp-ARISTA03T1                RUNNING   pid 66, uptime 2 days, 8:17:00
exabgp-ARISTA03T1-v6             RUNNING   pid 79, uptime 2 days, 8:16:57
exabgp-ARISTA04T1                RUNNING   pid 40, uptime 2 days, 8:17:07
exabgp-ARISTA04T1-v6             RUNNING   pid 53, uptime 2 days, 8:17:04
ptf_nn_agent                     RUNNING   pid 14, uptime 2 days, 10:35:21
sshd                             RUNNING   pid 13, uptime 2 days, 10:35:21
```

- pytest fib fixture to generate routes to exabgp
  - currently support t0, t1, t1-lag, extending to other topology is straighforward
  - fib module generate http request to exabgp instance
  
## Future applications:
- multi-path relax test. pytest will instruct multiple exabgp instances to advertise 
same VIP to different T0 VM.
- add/remove routes test. pytest will control exabgp to advertise/withdraw routes

## How to use exabgp module

start an exabgp instance
```python
        ptfhost.exabgp(name=k,
                       state="started", \
                       router_id = 10.0.0.1, \
                       local_ip  = 10.0.0.1, \
                       peer_ip   = 10.0.0.2, \
                       local_asn = 65100, \
                       peer_asn  = 65100, \
                       port = 6000)
```

use a fib fixture. The fixture will detect your testbed type and then generate routes based your testbed type.

```python
import pytest

def test_announce_routes(fib):
    """Simple test case that utilize fib to announce route in order to a newly setup test bed receive
       BGP routes from remote devices
    """
    assert True
```

## Q&A
Q: Why not use exabgp to advertise routes directly to the DUT?
A: Yes, we can. But, we could not simulate the BGP over LAG as there is no LAG protocol 
running inside the PTF docker.
