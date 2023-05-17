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
| 3. Send IPv4 TCP Routable Packet with Dest IP as Static Route Prefix and all the other Hash Tuple being fixed other than TCP Ports. We are increasing Source and Destination Port to send 50 different flows. | To verify routing and enough entropy using 50 flow to distribute across all 8 Nexthops | Packets are routed correctly. Update map M0 as : Flow to Neighbor Mac |
| 4. Repeat Step 1 to 3 | This step simulates another device going to the same transition. | Packets are routed correctly. Update map M1 as : Flow to Neighbor Mac and Compare map M0 and M1 and they should be same. |

### Test case \#2
Verify order ECMP is working as expected after link flap event.
| Step | Goal | Expected results |
|-|-|-|
| 1. Add neighbor's (8 of them) randomly binded to one of Active IP Interface (using `arp -s`). | This step simulates neighbors being resolved different time on T1 devices | ARP entry creation |
| 2. Add Static Route binded to these 8 Neighbors/Nexthop(using `ip route add via xx via xx`) | Nexthop are passed in random order to simulate FRR by giving Nexthop to OA in random order to form Nexthop Group Creation | IP Route Creation |
| 3. Send IPv4 TCP Routable Packet with Dest IP as Static Route Prefix and all the other Hash Tuple being fixed other than TCP Ports. We are increasing Source and Destination Port to send 50 different flows. | To verify routing and enough entropy using 50 flow to distribute across all 8 Nexthops | Packets are routed correctly. Update map M0 as : Flow to Neighbor Mac |
| 4. Shutdown the BGP docker so that we don’t get any FRR Route update event | This is to make sure we can verify ECMP Acceleration path of Orchagent. | BGP docker stops running. |
| 5. Log on to the peer fanout switch and shut down the interface corresponding active ip interface | This will trigger ECMP Member removal operation for all the nexthops. ECMP Group it self will not be deleted but only member removal from it. | SAI_ECMP_MEMBER_REMOVAL should invoke |
| 6. Startup the interface again on the peer switch | This will trigger ECMP Member add operation for all the next hops in ordered sequence  to the existing ECMP Group. | SAI_ECMP_MEMBER_ADD should invoke |
| 7. Repeat Step 3 | Packets should get routed |  Update map M1 as : Flow to Neighbor Mac and Compare map M0 and M1 and they should be same. |

### Test case \#3
To make sure Hash Function remain same across SAI releases.
| Step | Goal | Expected results |
|-|-|-|
| 1. Add neighbor's (8 of them) randomly binded to one of Active IP Interface (using `arp -s`). | This step simulates neighbors being resolved different time on T1 devices | ARP entry creation |
| 2. Add Static Route binded to these 8 Neighbors/Nexthop(using `ip route add via xx via xx`) | Nexthop are passed in random order to simulate FRR by giving Nexthop to OA in random order to form Nexthop Group Creation | IP Route Creation |
| 3. Send IPv4 TCP Routable Packet with Dest IP as Static Route Prefix and all the other Hash Tuple being fixed other than TCP Ports. We are increasing Source and Destination Port to send 50 different flows. | To verify routing and enough entropy using 50 flow to distribute across all 8 Nexthops | Packets are routed correctly. Update map M0 as : Flow to Neighbor Mac |
| 4. Save the map M0 to given ASICx type | To verify hash function, remain same over SAI release | None |
| 5. Repeat Step 3 | Packets should get routed |  Update map M1 as : Flow to Neighbor Mac and Compare map M0 and M1 and they should be same for given ASICx. |

### Test case \#4
To Verify Order ECMP for VNET Tunnel route with health monitoring.
Modification need to be done as part of Test plan define here:https://raw.githubusercontent.com/sonic-net/SONiC/master/doc/vxlan/Overlay%20ECMP%20with%20BFD.md
| Step | Goal | Expected results |
|-|-|-|
| 1. Create tunnel route 1 to endpoint group of four endpoints A = {a1, a2, a3, a4}. Send packets to addresses in route 1’s prefix | Verify tunnel route create function for ECMP | Packets are received at either a1,a2, a3, a4. Save the map of Flow to Tunnel End-point as M0 for given ASICx |
| 2. Re-Create tunnel route 1 to endpoint group of four endpoints A = {a2,a1,a4,a3}. Send packets to addresses in route 1’s prefix | Randomize the order in APP_DB VNET Route table for end point | Packets are received with same tunnel nexthop as present in map M0 for given ASICx |
| 3. Make BFD state as disable for some of the endpoint | SAI_ECMP_MEMBER_REMOVAL operation | None |
| 4. Re-enable BFD state for all the endpoints | SAI_ECMP_MEMBER_ADD operation | None |
| 5. Send packets to addresses in route 1’s prefix | To verify after BFD State transition tunnel nexthop endpoint order remians same | Packets are received with same tunnel nexthop as present in map M0 for given ASICx |

##TODO
- Need to enahnce for Ipv6 tcp flow.
