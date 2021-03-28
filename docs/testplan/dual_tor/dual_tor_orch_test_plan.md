# Dual ToR Orchagent Test Plan

### Scope

The scope of this test plan is to verify correct tunnel, ecmp, acl behavior. This is a continuation to dual_tor_test_hld.md and please refer this document for more details on topology etc. 

Standby ToR refers to a ToR scenario in which the packet is destined to/from server where the Mux is in Standby Mode.
Active ToR refers to a ToR scenario in which the packet is destined to/from server where the Mux is in Active Mode.

### Testbed Setup

The test can be executed on a single Tor testbed with proposed configurations that simulates the active/standby mux behavior

### Config command:

Example mux cable config in Config DB
```
{       
    "MUX_CABLE":{
        "Ethernet4":{
            "server_ipv4":"192.168.0.100/32",
            "server_ipv6":"fc02:1000::100/80"
	  }
}
```

The following command can be used to set a mux port to standby/active via swssconfig

```
muxstandby.json 
[
    {
        "MUX_CABLE_TABLE:Ethernet4" : {
            "state":"standby"
        },
        "OP": "SET"
    } 
]

docker exec swss sh -c \"swssconfig /muxstandby.json\"
```

Neigbhor add:

```
ip -4 neigh add 192.168.0.2 lladdr 00:00:11:22:33:44 dev Vlan1000
```

Neighbor flush:

```
ip -4 neigh del 192.168.0.2 dev Vlan1000
```

Loopback (Peer Switch) route add

```
ip route add 1.1.1.1 nexthop via 10.0.0.57 nexthop via 10.0.0.59 nexthop via 10.0.0.61
```

## Test Cases

1. T1 -> Standby ToR

    Send traffic of varying tuple destined to server under standby mux. The following are the various steps and those which have to be executed in a sequence is grouped together. 
    
    | Step | Goal | Expected results |
    |-|-|-|
    | All ports to T1s are up; Loopback route configured | ECMP hashing | Verify tunnel traffic to Active ToR is distributed equally across nexthops; Verify no traffic is forwarded to downlink in case of standby mux |
    | Shutdown one uplink to T1 | ECMP hashing/CRM | Verify traffic is shifted to the active links and no traffic drop observed; Verify CRM that no new nexthop created|
    | Bring back the uplink to T1; Note: For static route to peer, this would require reprogramming route | ECMP hashing/CRM | Verify traffic is now equally distributed; Verify CRM that no new nexthop created |
    ||||
    | Shutdown one BGP session to T1 | ECMP hashing/CRM | Verify traffic is shifted to the active links and no traffic drop observed; Verify CRM that no new nexthop created|
    | Bring back BGP session to T1 | ECMP hashing/CRM | Verify traffic is now equally distributed; Verify CRM that no new entries created |
    ||||
    | Server Neighbor entry flushed | Standby Dropping | Verify traffic is dropped; No tunnel traffic and no traffic fwded to neighbor directly; Verify CRM for neighbor |
    | Server Neighbor entry relearnt | Standby Forwarding | Verify traffic is restored to tunnel and no traffic fwded to neighbor directly; Verify CRM for neighbor |
    ||||
    | Remove Loopback route; Note: This requires extra SAI setting (sai_tunnel_underlay_route_mode=1) | ECMP hashing | Verify traffic is  equally distributed via default route |
    | Re-add Loopback route | ECMP hashing | Verify traffic is  equally distributed via loopback route|
    ||||
    | Add route to a nexthop which is a standby Neighbor | Standby Forwarding | Verify traffic to this route dst is forwarded to Active ToR and equally distributed|
    | Simulate Mux state change to active | Active Forwarding | Verify traffic to this route dst is forwarded directly to server |
    | Simulate Mux state change to standby | Standby Forwarding | Verify traffic to this route dst is now redirected back to Active ToR and equally distributed|

2. Server -> Standby ToR

    For the CRM tests, it is expected to read the values before and after test and compare the resource count for usage/leaks.
    
    | Step | Goal | Expected results |
    |-|-|-|
    | Mux state in Standby | ACL | Verify traffic is dropped by ACL rule and drop counters incremented |
    | Simulate Mux state change to active | ACL/CRM | Verify traffic is not dropped by ACL and fwd-ed to uplinks; Verify CRM show and no nexthop objects are stale |
    | Simulate Mux state change to standby | ACL/CRM | Verify traffic is dropped by ACL; Verify CRM show and no nexthop objects are stale |
    
3. T1 -> Active ToR

    Send traffic to server under active mux.
    
    | Step | Goal | Expected results |
    |-|-|-|
    | Neighbor learnt | Forwarding | Verify no tunnel traffic for Active mux. All traffic to server should be directly forwarded; Verify CRM for neighbor |
    | Neighbor flushed | Drop | Verify no tunnel traffic but packets are dropped; Verify CRM for neighbor |
    | Neighbor re-learnt | Forwarding | Verify no tunnel traffic and packets are fwded |
    ||||
    | Neighbor within subnet learnt on an active mux port; Note: This new neighbor must not be one configured for Server IPs in MUX_CABLE | Active Forwarding | Verify no tunnel traffic. All traffic to server should be directly forwarded; Verify CRM for neighbor |
    | Simulate MAC move by sending same ARP req/reply from another port which is standby | Standby Forwarding | Verify that traffic to this neighbor is now forwarded to Active ToR via tunnel nexthop |
    | Simulate FDB ageout/flush on this mac | Standby Forwarding | Verify that tunnel traffic is not impacted by fdb del event |
    | Simulate MAC move by sending same ARP req/reply from another port which is active | Active Forwarding | Verify that traffic to this neighbor is now forwarded directly and no tunnel traffic |
    | Simulate FDB ageout/flush on this mac | Active Dropping | Verify that traffic to this neighbor is now dropped |
    
4. T1 -> Tor (IPinIP packet)

    Send IPinIP encapsulated packet. Configure some ports in Active, some ports in Standby mode
    
    | Step | Goal | Expected results |
    |-|-|-|
    | Outer srcIP as peer IP, dstIP as loopback0, Inner Dst IP as Active Server IP; Ensure ARP/MAC is learnt for this Server IP | Decap | Verify traffic is decapsulated and fwded to Server port |
    ||||
    | Outer srcIP as peer IP, dstIP as loopback0, Inner Dst IP as Standby Server IP; Ensure ARP/MAC is learnt for this Server IP | Decap | Verify traffic is not fwded to Server port or re-encapsulated to T1s |

5. Stress test

    Continous mux state change based on configurable parameter 'N'
    
    | Step | Goal | Expected results |
    |-|-|-|
    | Change mux state from Active->Standby->Active 'N' times | CRM  | Verify CRM values for routes/nexthop and check for leaks |
    ||||
    | Flush and re-learn Neighbor entry 'N' times in Standby state | CRM  | Verify CRM values for routes/neighbor/nexthop and check for leaks |
    ||||
    | Flush and re-learn Neighbor entry 'N' times in Active state | CRM  | Verify CRM values for routes/neighbor/nexthop and check for leaks |

5. ECMP Route test

    Send packets to route destinations with ECMP nexthops.

    | Step | Goal | Expected results |
    |-|-|-|
    | Add route with four nexthops, where four muxes are active| ECMP  | Verify traffic to this route destination is distributed to four server ports |
    | Simulate nexthop1 mux state change to Standby| ECMP  | Verify traffic to this route destination is distributed to three server ports and one tunnel nexthop |
    | Simulate nexthop2 mux state change to Standby| ECMP  | Verify traffic to this route destination is distributed to two server ports and two tunnel nexthop |
    | Simulate nexthop3 mux state change to Standby| ECMP  | Verify traffic to this route destination is distributed to one server port and three tunnel nexthop |
    | Simulate nexthop4 mux state change to Standby| ECMP  | Verify traffic to this route destination is distributed to four tunnel nexthops |
    | Simulate nexthop4 mux state change to Active | ECMP  | Verify traffic to this route destination is distributed to one server port and three tunnel nexthop |
    | Simulate nexthop3 mux state change to Active | ECMP  | Verify traffic to this route destination is distributed to two server ports and two tunnel nexthop |
    ||||


5. SLB test

    This test requires a dual-tor setup as outlined in dual_tor_test_hld.md. Testing requires enhancement to BGP speaker test to simulate SLB creating peering session, one to Active ToR and another to Standby ToR.

    | Step | Goal | Expected results |
    |-|-|-|
    | Create peering session from the SLB to Active ToR | SLB  | Verify session is established |
    | Create peering session from the SLB to Standby ToR | SLB  | Verify session is established |
    ||||
    | Announce routes from SLB to Active ToR | SLB  | Verify routes in Active ToR |
    | Announce routes from SLB to Standby ToR | SLB  | Verify routes in Standby ToR |
    ||||
    | Run PTF tests on Active ToR | SLB  | Verify packets forwarded directly to active SLB port |
    | Run PTF tests on Standby ToR | SLB  | Verify packets forwarded via tunnel to Active ToR |
    ||||
    | Withdraw routes from SLB to Active ToR | SLB  | Verify routes removed in Active ToR |
    | Withdraw routes from SLB to Standby ToR | SLB  | Verify routes removed in Standby ToR |
    ||||
    | Repeat PTF tests as above | SLB  | Verify no packets forwarded |
    ||||
    | Simulate a mux state change for the SLB port | SLB  | Verify both sessions stays established and not disrupted |
    ||||
    | Announce routes from SLB to new Active ToR | SLB  | Verify routes in Active ToR |
    | Announce routes from SLB to new Standby ToR | SLB  | Verify routes in Standby ToR |
    ||||
    | Repeat PTF tests as above | SLB  | Verify packet forwarding based on mux state|
    ||||
    | Verify teardown by shutting peering session one by one | SLB  | After one session is down, verify other peering session is active and routes present|
