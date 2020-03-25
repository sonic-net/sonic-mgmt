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

Implementation details:
- exabgp ansible module to control exabgp service in PTF docker
  - create, remove, restart exabgp service
  - each exabgp instance listen to a http port for route announce/withdraw
- pytest fib fixture to generate routes to exabgp
  - currently support t0, t1-lag, extending to other topology is straighforward
  - fib module generate http request to exabgp instance
- exabgp and VM have iBGP connection to exchange routes (v4 and v6 are separated)

Future applications:
- multi-path relax test. pytest will instruct multiple exabgp instances to advertise 
same VIP to different T0 VM.
- add/remove routes test. pytest will control exabgp to advertise/withdraw routes

Q: Why not use exabgp to advertise routes directly to the DUT?
A: Yes, we can. But, we could not simulate the BGP over LAG as there is no LAG protocol 
running inside the PTF docker.
