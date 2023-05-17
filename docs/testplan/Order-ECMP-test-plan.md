- [Overview](#overview)
    - [Testbed](#testbed)
- [Test cases](#test-cases)
- [TODO](#todo)

## Overview
The purpose is to test order ecmp feature and assumes all necessary configuration is already pre-configured
on the SONIC switch before test runs.

### Testbed
The test will run on the following testbeds:
- t1
- t1-lag

## Test cases

### Test case \#1
Verify Order ECMP is working as expected (across 2 different T1’s)
| Step | Goal | Expected results |
|-|-|-|
| 1. Add neighbor's (8 of them) randomly binded to one of Active IP Interface (using `arp -s`). | This step simulates neighbors being resolved different time on T1 devices | ARP entry creation |
| 2. Add Static Route binded to these 8 Neighbors/Nexthop(using `ip route add via xx via xx`) | Nexthop are passed in random order to simulate FRR by giving Nexthop to OA in random order to form Nexthop Group Creation | IP Route Creation |
| 3. Send IPv4 TCP Routable Packet with Dest IP as Static Route Prefix and all the other Hash Tuple being fixed other than TCP Ports. We are increasing Source and Destination Port to send 50 different flows. | To verify routing and enough entropy using 50 flow to distribute across all 8 Nexthops | Packets are routed correctly. Update map of  M0 : Flow to Neighbor Mac |
| Repeat Step 1 to 3 | This step simulates another device going to the same transition. | Packets are routed correctly. Update map of M1 : Flow to Neighbor Mac Compare map M0 and M1 and they should be same. |

#### Test steps

- Randomly choose VM for the test.
- Reboot VM.
- Verify BGP timeout (at least 115 seconds routes should stay in fib).
- Verify all routes are preserved (no reinstallation after BGP open message from the neighbor).
- Verify that BGP session with the VM established.

### Test case \#2 - BGP GR helper mode routes change.

#### Test objective

Verify that traffic run without changes during neighbor graceful restart.

#### Test steps

- Randomly choose VM for the test.
- Change VM startup config (advertised routes should be different).
- Reboot VM.
- Verify that preserved routes are removed when VM back.
- Verify that new routes are installed when VM back.
- Restore VM startup config.

## TODO

## Open Questions
- Should tests run for neighbors behind physical interfaces only or behind LAGs as well?
- On which topologies test should run?
