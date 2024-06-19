- [T2-Chassis: BGP Suppress FIB Pending Test Plan](#t2-chassis--bgp-suppress-fib-pending-test-plan)
  * [Related documents](#related-documents)
  * [Overview](#overview)
    + [Scope](#scope)
    + [Scale / Performance](#scale---performance)
    + [Related **DUT** CLI commands](#related---dut---cli-commands)
    + [Supported Topology](#supported-topology)
  * [Test cases](#test-cases)
    + [Test case # 1 - BGPv4 route suppress test](#test-case---1---bgpv4-route-suppress-test)
    + [Test case # 2 - Test BGP route without suppress](#test-case---2---test-bgp-route-without-suppress)
    + [Test case # 3 - Test BGP route suppress under negative operation](#test-case---3---test-bgp-route-suppress-under-negative-operation)
    + [Test case # 4 - Test BGP route suppress in credit loops scenario](#test-case---4---test-bgp-route-suppress-in-credit-loops-scenario)
    + [Test case # 5 - Test BGP route suppress under stress](#test-case---5---test-bgp-route-suppress-under-stress)
    + [Test case # 6 - Test BGP route suppress performance](#test-case---6---test-bgp-route-suppress-performance)
	
	
# T2-Chassis: BGP Suppress FIB Pending Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| BGP Suppress FIB Pending HLD | [https://github.com/stepanblyschak/SONiC/blob/bgp-suppress-fib-pending/doc/BGP/BGP-supress-fib-pending.md]|
| T1 - BGP Suppress FIB Pending| [https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Suppress-FIB-Pending-test-plan.md]|

## Overview

This test plan is an extension of the __BGP Suppress FIB Pending Test Plan__ added for T1 DUT at [https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Suppress-FIB-Pending-test-plan.md]. 

As of today, SONiC BGP advertises learnt prefixes regardless of whether these prefixes were successfully programmed into ASIC.
While route programming failure is followed by orchagent crash and all services restart, even for successfully created routes there is a short period of time when the peer will be black holing traffic.

### Scope

The test is to verify the mechanism that allows BGP not to advertise routes that haven't been installed into ASIC yet.


### Scale / Performance

No scale/performance test involved in this test plan

### Related **DUT** CLI commands
Command to enable the feature:
```
admin@sonic:~$ sudo config suppress-fib-pending enabled
```
Command to disable the feature:
```
admin@sonic:~$ sudo config suppress-fib-pending disabled
```

### Supported Topology
The tests will be supported on t1 as well as on t2 topo.


## Test cases

As part of test changes for T2, to be consistent with existing T1 test cases, we will choose DUT which is connected to downstream T1 neighbors. This is because, on the other line card connected to upstream neighbors, it is not possible to verify traffic not being sent to the neighbor advertising the prefix since there is already a default route pointing to it.

### Test case # 1 - BGPv4 route suppress test
1. Enable BGP suppress-fib-pending function at DUT.
2. Save configuration and do config reload on DUT.
3. Suspend orchagent process on both asics to simulate a delay.
```
kill -SIGSTOP $(pidof orchagent)
```
4. Announce BGP ipv4 prefixes to DUT from one of T1 peer using exabgp.
5. Make sure announced BGP routes are in __queued__ state in the DUT routing table
6. Verify the routes are not announced via __IBGP__ or __EBGP__ to any of the peers. * (IBGP verification and on both upstream T3, downstream T1 neighbors)
7. Send traffic matching the prefixes from one of T3 peer .
8. Verify packets are not forwarded to any T1 peers of downstream line cards. And also make sure packets are forwarded to other T3 peers because of default route.
9. Restore orchagent process on both asics by,
```
kill -SIGSTOP $(pidof orchagent)
```
10. Make sure announced BGP routes are __not__ in __queued__ state in the DUT routing table.
11. Make sure the routes are programmed in FIB by checking offloaded flag value in the DUT routing table.
12. Verify the routes are announced to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
13. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 2 - Test BGP route without suppress

1. Disable BGP suppress-fib-pending function at DUT.
2. Suspend orchagent process on both asics to simulate a delay.
```
kill -SIGSTOP $(pidof orchagent)
```
3. Announce BGP ipv4 prefixes to DUT from one of T1 peer using exabgp.
4. Make sure announced BGP routes are __not__ in __queued__ state in the DUT routing table.
5. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
6.  Restore orchagent process on both asics by,
```
kill -SIGSTOP $(pidof orchagent)
```
7. Make sure the routes are programmed in FIB by checking offloaded flag in the DUT routing table.
8. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 3 - Test BGP route suppress under negative operation

1. Enable BGP suppress-fib-pending function at DUT.
2. Save configuration and do config reload on DUT.
3. Suspend orchagent process on both asics to simulate a delay.
```
kill -SIGSTOP $(pidof orchagent)
```
4. Announce BGP prefixes to DUT from one of T1 peer using exabgp.
5. Execute BGP session restart by restarting all BGP sessions on the DUT.
6. Verify BGP neighborships are reestablished.
7. Make sure announced BGP routes are in __queued__ state in the DUT routing table
8. Verify the routes are not announced via __IBGP__ or __EBGP__ to any of the peers. 
9. Configure static routes then redistribute to BGP.
10. Verify the redistributed routes are in the DUT routing table.
11. Verify the static routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
12. Send traffic matching the prefixes from one of T3 peer .
13. Verify packets are not forwarded to any T1 peers of downstream line cards. And also make sure packets are forwarded to other T3 peers because of default route.
14. Restore orchagent process on both asics by,
```
kill -SIGSTOP $(pidof orchagent)
```
14. Make sure announced BGP routes are __not__ in __queued__ state in the DUT routing table.
15. Make sure the routes are programmed in FIB by checking offloaded flag in the DUT routing table.
16. Verify the routes are announced to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
17. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 4 - Test BGP route suppress in credit loops scenario

1. Disable BGP suppress-fib-pending function at DUT.
2. Suspend orchagent process on both asics to simulate a delay.
```
kill -SIGSTOP $(pidof orchagent)
```
3. Announce a default route to DUT from one of T3 peer.
4. Announce BGP prefixes to DUT from one of T1 peer using exabgp.
5. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
6. Send traffic matching the prefixes from the T3 peer and verify packets are forwarded back to the same T3 peer.
7. Enable BGP suppress-fib-pending function on the same DUT
8. Save configuration and do config reload on DUT.
9. Restore orchagent process on both asics by,
```
kill -SIGSTOP $(pidof orchagent)
```
10. Make sure the routes are programmed in FIB by checking offloaded flag in the DUT routing table.
11. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 5 - Test BGP route suppress under stress

1. Do BGP route flap 5 times - Announce/Withdraw BGP prefixes from one of T1 peer using exabgp.
2. Disable BGP suppress-fib-pending function on DUT
3. Send traffic matching the prefixes in the BGP route flap from one of T3 peer and verify packets are forwarded back to the same T3 peer.
4. Suspend orchagent process to simulate a delay on both asics.
```
kill -SIGSTOP $(pidof orchagent)
```
5. Announce 1K BGP prefixes to DUT from T1 peer by exabgp
6. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
7. Send traffic matching the prefixes in the BGP route flap from one of T3 VM and verify packets are forwarded back to the same T3 VM.
8. Enable BGP suppress-fib-pending function at DUT
9. Restore orchagent process on both asics by,
```
kill -SIGSTOP $(pidof orchagent)
```
10. Verify the routes are programmed in FIB by checking offloaded flag in the DUT routing table
11. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.


### Test case # 6 - Test BGP route suppress performance

1. Enable BGP suppress-fib-pending function at DUT.
2. Save configuration and do config reload on DUT.
3. Start tcpdump capture at the ingress and egress port at DUT
4. Announce 1K BGP prefixes to DUT from T1 VM by exabgp
5. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard as well as to all other T1 peers on the downstream linecards including DUT.
6. Withdraw 1K BGP prefixes to DUT from the same T1 VM using exabgp
7. Verify the BGP routes are withdrawn from all T3/T1 VM peer neighbors across linecards.
8. Stop tcpdump capture on the DUT ingress and egress ports.
9. Verify the average as well as middle route process time is under threshold.
