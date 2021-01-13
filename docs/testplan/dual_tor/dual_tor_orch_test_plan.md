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
    | Bring back the uplink to T1 | ECMP hashing/CRM | Verify traffic is now equally distributed; Verify CRM that no new nexthop created |
    ||||
    | Shutdown one BGP session to T1 | ECMP hashing/CRM | Verify traffic is shifted to the active links and no traffic drop observed; Verify CRM that no new nexthop created|
    | Bring back BGP session to T1 | ECMP hashing/CRM | Verify traffic is now equally distributed; Verify CRM that no new entries created |
    ||||
    | Server Neighbor entry flushed/relearnt | Standby Forwarding | Verify no impact to tunnel traffic and no traffic fwded to neighbor directly; Verify CRM for neighbor |
    ||||
    | Remove Loopback route | ECMP hashing | Verify traffic is  equally distributed via default route|
    | Re-add Loopback route | ECMP hashing | Verify traffic is  equally distributed via loopback route|


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
    
4. T1 -> Tor (IPinIP packet)

    Send IPinIP encapsulated packet. Configure some ports in Active, some ports in Standby mode
    
    | Step | Goal | Expected results |
    |-|-|-|
    | Outer IP as loopback, Inner Dst IP as Active Server IP | Decap | Verify traffic is decapsulated and fwded to Server port |
    ||||
    | Outer IP as loopback, Inner Dst IP as Standby Server IP | Decap | Verify traffic is not fwded to Server port or re-encapsulated to T1s |

5. Stress test

    Continous mux state change based on configurable parameter 'N'
    
    | Step | Goal | Expected results |
    |-|-|-|
    | Change mux state from Active->Standby->Active 'N' times | CRM  | Verify CRM values for routes/nexthop and check for leaks |
    ||||
    | Flush and re-learn Neighbor entry 'N' times in Standby state | CRM  | Verify CRM values for routes/neighbor/nexthop and check for leaks |
    ||||
    | Flush and re-learn Neighbor entry 'N' times in Active state | CRM  | Verify CRM values for routes/neighbor/nexthop and check for leaks |

