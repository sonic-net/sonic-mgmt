# BGP Scale Test Plan

- [Overview](#Overview)
  - [Scope](#Scope)
  - [Testbed](#Testbed)
  - [Scale Description](#Scale-Description)
- [Setup Configuration](#Setup-Configuration)
- [Test Methodology](#Test-Methodology)
- [Test Cases](#Test-Cases)
  - [BGP Sessions Flapping Test](#BGP-Sessions-Flapping-Test)
  - [Unisolation Test](#Unisolation-Test)
  - [Nexthop Group Member Scale Test](#Nexthop-Group-Member-Scale-Test)


# Overview

This test plan is to test if control/data plane can handle the initialization/flapping of numerous BGP session holding a lot routes, and estimate the impact on it.


## Scope

This test plan runs on any device running SONIC system with fully functioning configuration with numerouse BGP peers with count 256/512.

This test plan is dedicated to IPv6.

This test plan shows if there is any service crush, if hardware resource run out, if device has acceptable performance and data/control plane availability.


## Testbed

This test run on testbeds with topologies:
- t0: topo_t0-isolated-d2u254s1, topo_t0-isolated-d2u254s2, topo_t0-isolated-d2u510
- t1: topo_t1-isolated-d254u2s1, topo_t1-isolated-d254u2s2 and topo_t1-isolated-d510u2.

*Fig.1 topo_t0-isolated-d2u254s1/s2*
![](Img/t0-isolated-d2u254s.png)

*Fig.2 topo_t0-isolated-d2u510*
![](Img/t0-isolated-d2u510.png)

*Fig.3 topo_t1-isolated-d254u2s1/s2*
![](Img/t1-isolated-d254u2s.png)

*Fig.4 topo_t1-isolated-d510u2*
![](Img/t1-isolated-d510u2.png)


## Scale Description
In this scale test, the maximum bgp peers number reach crazy count 510!

We haven't even tried 200 before, so this is a giant leap for us.

With great number of bgp peers, come with the great number of ceos containers that are used to establish bgp sessions with full NOS functionality for all possible testing.

One ceos will comsume around 1.3GB memory, 510 means we need a server with 663GB. To deploy this topology with 510 even more bgp peers, we initial a design to achieve [deploy testbed with multiple servers](https://github.com/sonic-net/sonic-mgmt/pull/15395), with this design, we can leverage multiple servers' CPU, memory and network capacity, to break the single server resource limitation.

# Setup Configuration
The count of routes from BGP peers is vital, we will leverage exabpg to advertise routes to all BGP peers, and those routes be be advertised to device under test finally.

When DUT is T0, via exabgp, firstly, we will advertise 511 routes with prefix length 120 to all peer T1 devices for simulating downstream routes (VLAN IPv6 addresses of T0s), secondly, we will dvertise 15 routes with prefix length 64 to all peer T1 devices for simulating upstream routes (Aggregated IPv6 addresses of T0s' VLAN on T2s), finally, the DUT T0 will receive those routes from BGP peers.

When DUT is T1, we won't mock any routes.


# Test Methodology
For simulating the initialization of system, we shutdown all ports before test.

For simulating BGP session flapping on DUT, we will shutdown port a little while and unshut the port.

For simulating BGP routes flapping on DUT, we will withdrawn routes on BGP peers via exabgp for a littele while and advertise routes again.

For checking if all expected routes are programed into ASIC, fristly, we will check routes count, secondly, we will keep sending packets for all routes, and check if all expected nexthop in same group receving packets for all routes.

For estimating data plane downtime, we will keep sending packets with fix interval, and observer packet drop count.


# Test Cases


## BGP Sessions Flapping Test
### Objective
When BGP sessions are flapping, make sure control plane is functional and data plane has no downtime or acceptable downtime.
### Steps
1. Pick N random ports to shut down.
1. Start to sending packets with all routes in fix time interval to the rest ports via ptf.
1. Shutdown the N ports and count packets received on ports. 1. Wait for the N BGP sessions are down and routes are stable.
1. Stop sending packets
1. Estamite data plane down time


## Unisolation Test
### Objective
In the worst senario, verify control/data plane have acceptable conergence time.
### Steps
1. Shut down all ports on device.
1. Start to sending packets with all routes in fix time interval to all portes via ptf.
1. Unshut all ports and count packets received on ports.
1. Wait for routes are stable.
1. Stop sending packets.
1. Estamite control/data plane convergence time.


## Nexthop Group Member Scale Test
### Objective
When routes on BGP peers are flapping, make sure DUT's control plane is functional and data plane has no downtime or acceptable downtime.
### Steps
1. Pick N random BGP peers to manipulate routes.
1. Pick random half of common routes as RHoCRs.
#### Test Withdrawn
1. Start to sending packets with RHoCRs with in fix time interval to all portes via ptf.
1. Withdrawn RHoCRs
1. Wait for routes are stable.
1. Stop sending packets.
1. Estamite data plane down time.
#### Test Advertising
1. Start to sending packets with RHoCRs with in fix time interval to all portes via ptf.
1. Advertise RHoCRs
1. Wait for routes are stable.
1. Stop sending packets.
1. Estamite control/data plane convergence time.
