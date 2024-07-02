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
Note: Issue raised for the above command not working on multi-asic environment globally, https://github.com/sonic-net/sonic-buildimage/issues/19022 . Currently it works only as specific asic commands.

### Supported Topology
The tests will be supported on t1 as well as on t2 topo.


## Test cases

As part of test changes for T2, to be consistent with existing T1 test cases, we will choose DUT which is connected to downstream T1 neighbors. This is because, on the other line card connected to upstream neighbors, it is not possible to verify traffic not being sent to the neighbor advertising the prefix since there is already a default route pointing to it.

### Test case # 1 - BGPv4 route suppress test
1. Enable BGP suppress-fib-pending function on all DUTs in multi-dut scenario.
2. Save configuration and do config reload on DUTs.
3. Suspend orchagent process on both asics to simulate a delay on downstream DUT.
```
kill -SIGSTOP $(pidof orchagent)
```
4. Announce BGP ipv4 prefixes to downstream DUT from one of T1 peer using exabgp.
5. Make sure announced BGP routes are in __queued__ state in the downstream DUT routing table for the specific asic.
6. Verify the routes are not announced via __IBGP__ or __EBGP__ to any of the peers.
7. Send traffic matching the prefixes from one of T3 peer.
8. Verify packets are not forwarded to any T1 peers of downstream line cards. And also make sure packets are forwarded to other T3 peers because of default route.
9. Suspend orchagent process on both asics to simulate a delay on upstream DUT.
```
kill -SIGCONT $(pidof orchagent)
```
10. Restore orchagent process on both asics of the downstream dut,
```
kill -SIGCONT $(pidof orchagent)
```
11. Make sure announced BGP routes are __not__ in __queued__ state in the downstream DUT routing table.
12. Make sure the routes are programmed in FIB by checking offloaded flag value in the downstream DUT routing table.
13. Make sure announced BGP routes are in __queued__ state in the upstream DUT routing table for the specific asic.
14. Verify the routes are not announced via __IBGP__ or __EBGP__ to any of the T3 peers.
15. Restore orchagent process on both asics of the upstream dut,
```
kill -SIGCONT $(pidof orchagent)
```
16. Make sure announced BGP routes are __not__ in __queued__ state in the upstream DUT routing table.
17. Make sure the routes are programmed in FIB by checking offloaded flag value in the upstream DUT routing table.
18. Verify the routes are announced to all T3 peer neighbors on the upstream linecard.
19. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 2 - Test BGP route without suppress

1. Disable BGP suppress-fib-pending function at both upstream and downstream DUT(Default configuration).
2. Suspend orchagent process on both asics to simulate a delay on both upstream and downstream DUTs.
```
kill -SIGSTOP $(pidof orchagent)
```
3. Announce BGP ipv4 prefixes to DUT from one of T1 peer using exabgp.
4. Make sure announced BGP routes are __not__ in __queued__ state on both DUT's routing table.
5. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard.
6.  Restore orchagent process on both asics for both DUTs,
```
kill -SIGCONT $(pidof orchagent)
```
7. Make sure the routes are programmed in FIB by checking offloaded flag in the upstream and downstream DUT routing table.
8. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 3 - Test BGP route suppress under negative operation

1. Enable BGP suppress-fib-pending function on all DUTs in multi-dut scenario.
2. Save configuration and do config reload on DUTs.
3. Suspend orchagent process on both asics to simulate a delay on downstream DUT.
```
kill -SIGSTOP $(pidof orchagent)
```
4. Announce BGP ipv4 prefixes to downstream DUT from one of T1 peer using exabgp.
5. Execute BGP session restart by restarting all BGP sessions on the downstream DUT.
6. Verify BGP neighborships are re-established.
7. Make sure announced BGP routes are in __queued__ state in the downstream DUT routing table
8. Verify the routes are not announced via __IBGP__ or __EBGP__ to any of the peers. 
9. Configure static routes then redistribute to BGP.
10. Verify the redistributed routes are in the DUT routing table.
11. Verify the static routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard.
12. Send traffic matching the prefixes from one of T3 peer .
13. Verify packets are not forwarded to any T1 peers of downstream line cards. And also make sure packets are forwarded to other T3 peers because of default route.
14. Suspend orchagent process on both asics to simulate a delay on upstream DUT.
```
kill -SIGCONT $(pidof orchagent)
```
15. Restore orchagent process on both asics of the downstream dut,
```
kill -SIGCONT $(pidof orchagent)
```
16. Make sure announced BGP routes are __not__ in __queued__ state in the downstream DUT routing table.
17. Make sure the routes are programmed in FIB by checking offloaded flag value in the downstream DUT routing table.
18. Make sure announced BGP routes are in __queued__ state in the upstream DUT routing table for the specific asic.
19. Verify the routes are not announced via __IBGP__ or __EBGP__ to any of the T3 peers.
20. Restore orchagent process on both asics of the upstream dut,
```
kill -SIGCONT $(pidof orchagent)
```
21. Make sure announced BGP routes are __not__ in __queued__ state in the upstream DUT routing table.
22. Make sure the routes are programmed in FIB by checking offloaded flag value in the upstream DUT routing table.
23. Verify the routes are announced to all T3 peer neighbors on the upstream linecard.
24. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 4 - Test BGP route suppress in credit loops scenario

1. Disable BGP suppress-fib-pending function at both upstream and downstream DUT(Default configuration).
2. Suspend orchagent process on both asics to simulate a delay on the upstream DUT.
```
kill -SIGSTOP $(pidof orchagent)
```
3. Announce BGP prefixes to downstream DUT from one of T1 peer using exabgp.
4. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard.
5. Send traffic matching the prefixes from the T3 peer and verify packets are forwarded back to the same T3 peer.
6. Enable BGP suppress-fib-pending function on the downstream DUT.
7. Restore orchagent process on both asics on the upstream DUT now,
```
kill -SIGCONT $(pidof orchagent)
```
8. Make sure the routes are programmed in FIB by checking offloaded flag in the downstream DUT routing table.
9. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.

### Test case # 5 - Test BGP route suppress under stress

1. Do BGP route flap 5 times - Announce/Withdraw BGP prefixes from one of T1 peer using exabgp.
2. Disable BGP suppress-fib-pending function on both upstream and downstream DUT
3. Send traffic matching the prefixes in the BGP route flap from one of T3 peer and verify packets are forwarded back to the same T3 peer.
4. Suspend orchagent process to simulate a delay on both asics of the upstream DUT.
```
kill -SIGSTOP $(pidof orchagent)
```
5. Announce 1K BGP prefixes to DUT from T1 peer by exabgp
6. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard.
7. Send traffic matching the prefixes in the BGP route flap from one of T3 VM and verify packets are forwarded back to the same T3 VM.
8. Enable BGP suppress-fib-pending function at downstream DUT.
9. Restore orchagent process on both asics on the upstream DUT now,
```
kill -SIGCONT $(pidof orchagent)
```
10. Verify the routes are programmed in FIB by checking offloaded flag in the downstream DUT routing table
11. Send traffic matching the prefixes from one of T3 peer and verify packets are forwarded to expected T1 peer only.


### Test case # 6 - Test BGP route suppress performance

1. Enable BGP suppress-fib-pending function at the downstream DUT.
2. Start tcpdump capture at the ingress and egress port at DUTs
3. Announce 1K BGP prefixes to DUT from T1 VM by exabgp
4. Verify the routes are announced via __IBGP__ and __EBGP__ to all T3 peer neighbors on the upstream linecard.
5. Withdraw 1K BGP prefixes to DUT from the same T1 VM using exabgp
6. Verify the BGP routes are withdrawn from all T3 VM peer neighbors.
7. Stop tcpdump capture on the DUTs' ingress and egress ports.
8. Verify the average as well as middle route process time is under threshold.
