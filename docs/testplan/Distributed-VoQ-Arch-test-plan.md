# **Distributed VoQ Architecture Test Plan**

 - [Introduction](#intro)
 - [References](#reference)
 - [Debuggability](#debug)
 - [Test Setup](#test-setup)
 - [Test Cases](#test-cases)
     - [System Initialization](#sys_init)
     - [Neighbors](#arp)
     - [Router Interfaces](#ri)
     - [Host IP Connectivity](#ipfwd)
     - [Inband VLAN](#inbandvlan)

     
# Introduction <a name="intro"></a>

This is the test plan for SONIC Distributed VOQ support, as described in the [Distributed VOQ HLD](https://github.com/Azure/SONiC/blob/master/doc/voq/voq_hld.md). 

The associated PRs covered in this test plan are:

1. [Distributed VOQ PR 380](https://github.com/Azure/sonic-swss-common/pull/380)
2. [Distributed VOQ PR 657](https://github.com/Azure/sonic-sairedis/pull/657)
3. [Distributed VOQ PR 1431](https://github.com/Azure/sonic-swss/pull/1431)

Redis CLI commands will be used for some validation until SONIC CLI commands are available for system port information.

## Scope

The functionalty covered in this test plan is:
* system ports, 
* router interfaces, when configured on multiple cards, and
* neighbors, when learned on local and remote ports. 

Other HLDs in the [Chassis Subgroup feature list](https://github.com/Azure/SONiC/wiki/SONiC-Chassis-Subgroup) will be covered in other test plans.

## Debuggability  <a name="debug"></a>
The following are useful commands for validating the testcases that follow.

1. Keys from redis in container when no redis-dump exists:

`docker exec database1 redis-cli -h <ip> -n 6 KEYS "*"`

2. Values from redis in container when no redis-dump exists:

`docker exec database1 redis-cli -h <ip> -n 6 hgetall "SYSTEM_NEIGH_TABLE|Inband4|3.3.3.5"`

3. Chassis App Database on Supervisor card:

`redis-dump -h <ip> -p 6380 -d 12 -y -k "*SYSTEM_INT*"`


# Test Setup <a name="test-setup"></a>

These test cases will be run in the proposed [T2 topology](https://github.com/Azure/sonic-mgmt/pull/2638/). It is assumed that such a configuration is deployed on the chassis.

# Test Cases <a name="test-cases"></a>

## System Initialization  <a name="sys_init"></a>

#### Test Case 1. System Bringup

##### Test Objective
Verify VoQ system initializes correctly on startup.

##### Test Steps
* Configure a VoQ system with valid configuration files and verify the system comes up.
* Verify supervisor card is up, and all required containers and processes are running.
* Verify redis on supervisor is running and Chassis AppDB is reachable.
* Verify line cards are up and reachable from supervisor.
    
#### Test Case 2. Switch Creation
##### Test Objective
Verify ASIC Switch object is correct on all line cards.

##### Test Steps
* Verify ASIC_DB gets switch object created on all asics and linecards (redis-dump -h <ip> -d 1 on each linecard)
* Verify switch ID, cores, port list in ASIC DB have the same values as the config_db.json file.
* Verify switch type is voq.

##### Sample output
```
  "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:oid:0x21000000000000": {
    "expireat": 1550863898.649604,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "NULL": "NULL",
      "SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED": "0",
      "SAI_SWITCH_ATTR_FDB_AGING_TIME": "600",
      "SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY": "0x55df0bc54540",
      "SAI_SWITCH_ATTR_INIT_SWITCH": "true",
      "SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED": "0",
      "SAI_SWITCH_ATTR_MAX_SYSTEM_CORES": "48",
      "SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY": "0x55df0bc54550",
      "SAI_SWITCH_ATTR_SRC_MAC_ADDRESS": "14:7B:AC:3A:C9:7F",
      "SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO": "8:48,52,58,48,48,46,48,0",
      "SAI_SWITCH_ATTR_SWITCH_ID": "36",
      "SAI_SWITCH_ATTR_SWITCH_SHUTDOWN_REQUEST_NOTIFY": "0x55df0bc54560",
      "SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST":  "{\"count\":304,\"list\":[{\"attached_core_index\":\"0\", etc
```

#### Test Case 3. System port creation.
##### Test Objective
Verify system ports are created on all line cards.

##### Test Steps
* Verify ASIC_DB get all system ports referenced in config_db.json created on all hosts and ASICs.
* Verify object creation and values of port attributes.

##### Sample output
```
  "ASIC_STATE:SAI_OBJECT_TYPE_SYSTEM_PORT:oid:0x5d0000000000e4": {
    "expireat": 1550863898.617927,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "NULL": "NULL",
      "SAI_SYSTEM_PORT_ATTR_CONFIG_INFO": "{\"attached_core_index\":\"0\",\"attached_core_port_index\":\"20\",\"attached_switch_id\":\"18\",\"num_voq\":\"8\",\"port_id\":\"596\",\"speed\":\"400000\"}"
    }
  },
```


#### Test Case 4. Local Ports
##### Test Objective
Verify local ports are created on all line cards.

##### Test Steps
* Verify ASIC_DB has host interface information for all local ports on all cards and ASICs.
* Verify host interfaces exist on host CLI (ifconfig).
* Verify interfaces exist in show interfaces on the linecard.

##### Sample output
```
  "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF:oid:0xd00000000126b": {
    "expireat": 1550863898.591804,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "SAI_HOSTIF_ATTR_NAME": "Ethernet0",
      "SAI_HOSTIF_ATTR_OBJ_ID": "oid:0x1000000000002",
      "SAI_HOSTIF_ATTR_OPER_STATUS": "false",
      "SAI_HOSTIF_ATTR_TYPE": "SAI_HOSTIF_TYPE_NETDEV"
    }
  },
```
```
admin@dut1-imm2:~$ sudo ifconfig Ethernet0
Ethernet0: flags=4098<BROADCAST,MULTICAST>  mtu 9100
        ether 14:7b:ac:3a:c9:7f  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

#### Test Case 5.  Router Interface Creation
##### Test Objective
Verify router interfaces are created on all line cards and present in Chassis App Db.

##### Test Steps
* Verify router interface creation on local ports in ASIC DB.
* PORT_ID should match system port table and traced back to config_db.json, mac and MTU should match as well.
* Verify SYSTEM_INTERFACE table in Chassis AppDb (redis-dump -h <ip> -p 6380 -d 12 on supervisor).
* Verify creation interfaces with different MTUs in config_db.json.
* Verify creation of different subnet masks in config_db.json.
* Repeat with IPv4, IPv6, dual-stack.

##### Sample output 
ASIC:
```
  "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:oid:0x60000000012b3": {
    "expireat": 1550863898.6557322,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "SAI_ROUTER_INTERFACE_ATTR_MTU": "9100",
      "SAI_ROUTER_INTERFACE_ATTR_PORT_ID": "oid:0x5d00000000015a",
      "SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS": "14:7B:AC:3A:C9:7F",
      "SAI_ROUTER_INTERFACE_ATTR_TYPE": "SAI_ROUTER_INTERFACE_TYPE_PORT",
      "SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID": "oid:0x3000000000027"
    }
  },
```

Chassis AppDB:

```
  "SYSTEM_INTERFACE|Slot7|Asic0|Ethernet24": {
    "expireat": 1605628181.7629092,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "rif_id": "oid:0x19000600001499"
    }
  },
```

#### Test Case 6.  Inband Configuration Type

##### Test Objective
Verify inband ports, neighbors, and routes are setup as in device configuration.

##### Test Steps

* Configure system in inband port mode.
```
"VOQ_INBAND_INTERFACE": {
    "Inband3": {
        "inband_type": "port"
    },
    "Inband3|133.133.133.4/32": {}
},
```
* On each linecard, verify inband ports are present in ASICDB.
* On each linecard, verify inband router interfaces are present in ASICDB
* On supervisor card, verify inband router interfaces are present in Chassis App DB
* On each linecard, verify permanent neighbors for all inband ports.
* On each linecard, verify kernel routes for all inband ports.
* Repeat with IPv4, IPv6, dual-stack.


#### Test Case 7. Local Neighbors

##### Test Objective
Verify neighbor entries are created on linecards for locally adjacent VMS. 

##### Test Steps
* ARP/NDP should be resolved when BGP to adjacent VMs is established.
* On local linecard, verify ASIC DB entries.
    * MAC address matches MAC of neighbor VM.
    * Router interface OID matches back to the correct interface and port the neighbor was learned on.        
* On local linecard, verify show arp/ndp, ip neigh commands.
    * MAC address matches MAC of neighbor VM.
* On local linecard. verify neighbor table in appDB.
    * MAC address matches MAC of neighbor VM.
* On supervisor card, verify SYSTEM_NEIGH table in Chassis AppDB (redis-dump -h <ip> -p 6380 -d 12 on supervisor).
    * Verify encap index and MAC address match between ASICDB the Chassis AppDB
* Repeat with IPv4, IPv6, dual-stack.

##### Sample output     
* Asic:
```
  "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{\"ip\":\"102.0.0.1\",\"rif\":\"oid:0x6000000001290\",\"switch_id\":\"oid:0x21000000000000\"}": {
    "expireat": 1550863898.638045,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "6E:3A:88:CF:C6:2A",
      "SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX": "1074790407"
    }
  },

  "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:oid:0x40000000012c2": {
    "expireat": 1550863898.637784,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "SAI_NEXT_HOP_ATTR_IP": "102.0.0.1",
      "SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID": "oid:0x6000000001290",
      "SAI_NEXT_HOP_ATTR_TYPE": "SAI_NEXT_HOP_TYPE_IP"
    }
  },
```
* AppDb:
```
  "NEIGH_TABLE:Ethernet8:102.0.0.1": {
    "expireat": 1550863889.965874,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "family": "IPv4",
      "neigh": "6e:3a:88:cf:c6:2a"
    }
  },
```
* Chassis AppDb:
```
  "SYSTEM_NEIGH|Slot7|Asic0|Ethernet8:102.0.0.1": {
    "expireat": 1605628181.762964,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "encap_index": "1074790407",
      "neigh": "6e:3a:88:cf:c6:2a"
    }
  },
```

#### Test Case 8. Remote Neighbors

##### Test Objective
Verify when local neighbors are established on a linecard, other linecards in the VoQ system will be programmed with neighbor entries.

##### Test Steps
* When local neighbors are established as in the Local Neighbor testcase, corresponding entries will be established on all other line cards.  On each remote card, verify:
* Verify ASIC DB entries on remote linecards.
    * Verify impose index=True in ASIC DB. 
    * Verify MAC address in ASIC DB is the remote neighbor mac.
    * Verify encap index for ASIC DB entry matches Chassis App DB.
    * Verify router interface OID matches the interface the neighbor was learned on.
* Verify on linecard CLI, show arp/ndp, ip neigh commands.
    * For inband port, MAC should be inband port mac in kernel table and LC appDb.
    * For inband vlan mode, MAC will be remote ASIC mac in kernel table and LC appdb.
* Verify neighbor table in linecard appdb.
* Verify static route is installed in kernel routing table with /32 (or /128 for IPv6) for neighbor entry.
* Repeat with IPv4, IPv6, dual-stack.

##### Sample Output
* Asic DB
```
  "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{\"ip\":\"101.0.0.1\",\"rif\":\"oid:0x60000000012b3\",\"switch_id\":\"oid:0x21000000000000\"}": {
    "expireat": 1550863898.651915,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "4E:49:E4:62:ED:88",
      "SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_IMPOSE_INDEX": "true",
      "SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX": "1074790407",
      "SAI_NEIGHBOR_ENTRY_ATTR_IS_LOCAL": "false"
    }
  },

  "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:oid:0x40000000012c0": {
    "expireat": 1550863898.6276,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "SAI_NEXT_HOP_ATTR_IP": "101.0.0.1",
      "SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID": "oid:0x60000000012b3",
      "SAI_NEXT_HOP_ATTR_TYPE": "SAI_NEXT_HOP_TYPE_IP"
    }
  },
```
* App DB
```
  "NEIGH_TABLE:Inband18:101.0.0.1": {
    "expireat": 1550863889.96545,
    "ttl": -0.001,
    "type": "hash",
    "value": {
      "family": "IPv4",
      "neigh": "14:7b:ac:3a:c9:7f"
    }
  },
```
* Chassis App DB
```
"SYSTEM_NEIGH|Slot8|Asic0|Ethernet23:101.0.0.1": {
"expireat": 1605628181.7629762,
"ttl": -0.001,
"type": "hash",
"value": {
  "encap_index": "1074790407",
  "neigh": "4e:49:e4:62:ed:88"
}
},
```

* Host
```
show ip route
K>* 101.0.0.1/32 [0/0] is directly connected, Inband18, 20:55:26

netstat -rn
101.0.0.1       0.0.0.0         255.255.255.255 UH        0 0          0 Inband18
```



## Neighbor Lifecycle <a name="arp"></a>

### Preconditions

In order to verify neighbor behaviors, BGP sessions on the DUT and attached VMs will be temporarily shutdown.  This 
will allow the tests to validate the various table deletes before the entries are recreated.


### Test cases

#### Test Case 1. Clear ARP, single address.
##### Test Objective
Verify tables, databases, and kernel routes are correctly deleted when a single neighbor adjacency is cleared.
##### Test Steps
* On local linecard:
    * Clear single address with command:  `ip neigh flush to "addr"`.
    * Verify ARP/NDP entry removed from CLI.
    * Verify table entries in ASIC, AppDb are removed for only the cleared address.
* On Supervisor card:
    * Verify Chassis App DB entry are removed for only the cleared address.
* On remote linecards:
    * Verify table entries in ASICDB, APPDB, and host ARP table are removed.
    * Verify kernel route for cleared address is deleted.
* Restart traffic, verify relearn.
* Repeat with IPv4, IPv6, dual-stack.


#### Test Case 2. Clear ARP table via sonic command.
##### Test Objective
Verify tables, databases, and kernel routes are correctly deleted when the entire neighbor table is cleared.
##### Test Steps
* On local linecard:
    * Issue `sonic-clear arp` command. and verify all addresses are removed and kernel routes are deleted on all hosts and ASICs.
    * Verify ARP/NDP entries are removed from CLI.
    * Verify table entries in ASIC, AppDb are removed for all cleared addresses.
* On Supervisor card:
    * Verify Chassis App DB entry are removed for only the cleared address.  Entries for addresses on other line cards
    should still be present.
* On remote linecards:
    * Verify table entries in ASICDB, APPDB, and host ARP table are removed for cleared addresses.
    * Verify kernel routes for cleared address are deleted.
* Send full mesh traffic and verify relearn and DB.
* Repeat with IPv4, IPv6, dual-stack.


#### Test Case 3. Front panel port link flap
##### Test Objective
Verify tables, databases, and kernel routes are unaffected when the front panel port flaps and restores.
##### Test Steps
* Admin down interface on fanout to cause LOS on DUT.
* On local linecard:
    * Verify local interface is down, verify ARP is still present in local database.
* On Supervisor card:
    * Verify Chassis App DB entry are still present.
* On remote linecards:
    * Verify table entries in ASICDB, APPDB, and host ARP table are present for affected addresses.
    * Verify kernel routes are present for affected addresses.
* Admin interface up, verify recreation after restarting traffic.
* Verify ARP entries on linecards and supervisors are still correct.
* Repeat with IPv4, IPv6, dual-stack.


#### Test Case 4. Gratuitous ARP - Known IP - Mac change
##### Test Objective
Verify tables, databases, and kernel routes are correctly updated when a unsolicited ARP packet changes the MAC address of learned neighbor.
##### Test Steps
* Send unsolicited ARP packet into DUT for an IP known by DUT with a different MAC address for the neighbor.
* Change the MAC address of the neighbor VM.
* On local linecard:
    * Verify table entries in local ASIC, APP, and host ARP table are updated with new MAC.
* On supervisor card:
    * Verify Chassis App DB entry is correct for with the updated MAC address. 
* On remote linecards:
    * Verify table entries in remote hosts/ASICs in APPDB, and host ARP table are still present with inband MAC address
    * Verify ASIC DB is updated with new MAC.
    * Verify kernel route in remote hosts are still present to inband port.
* Verify that packets can be sent from local and remote linecards to learned address.
* Repeat with IPv4, IPv6, dual-stack.

#### Test Case 5. ARP Request/Reply - Mac change
##### Test Objective
Verify tables, databases, and kernel routes are correctly updated when the MAC address of a neighbor changes and is updated via request/reply exchange.
##### Test Steps
* Change the MAC address on a remote host that is already present in the ARP table.
* Without clearing the entry in the DUT, allow the existing entry to time out and the new reply to have the new MAC address.
* On local linecard:
    * Verify table entries in local ASIC, APP, and host ARP table are updated with new MAC.
* On supervisor card:
    * Verify Chassis App DB entry is correct for with the updated MAC address. 
* On remote linecards:
    * Verify table entries in remote hosts/ASICs in APPDB, and host ARP table are still present with inband MAC address
    * Verify ASIC DB is updated with new MAC.
    * Verify kernel route in remote hosts are still present to inband port.
* Verify that packets can be sent from local and remote linecards to the learned address.
* Repeat with IPv4, IPv6, dual-stack.

#### Test Case 6. Disruptive Events
##### Test Objective
Verify port, router interface, and neighbor recovery after disruptive events.
##### Test Steps
* After the following events:
    * chassis power cycle,
    * supervisor reboot,
* Verify, as in the previous test cases:
    * Local neighbor learning,
    * remote neighbor learning and route creation
    * timeout and clear of neighbors
     

## Router Interface Lifecycle <a name = "ri"></a>

#### Test Case 1.  IP Interface Creation
##### Test Objective
Verify Chassis App DB is updated with new interface entry when a new IP Interface is added.
##### Test Steps
* Add IP to a previously unconfigured port by adding minigraph configuration to that linecard.
* Reload the new minigraph and line card.
* On the line card:
    * Verify address state in CLI.
    * Verify interface in ASIC DB
* On the supervisor card:
    * Verify the interface is present in the SYSTEM_INTERFACE table of the Chassis App DB.
    * Verify the OID is unique, and matches the router interface ID in the ASIC DB.
    * Verify the slot and port are correct.
* Verify bidirectional traffic to an attached host on the newly created port from local and remote linecards.
* Repeat with IPv4, IPv6, dual-stack.

#### Test Case 2. Interface Deletion
##### Test Objective
Verify Chassis App DB is updated with new interface entry when an IP interface is removed from a port.
##### Test Steps
* Remove IP configuration from a previously configured port by removing the minigraph configuration for that port 
on the linecard minigraph.
* Reload the new minigraph and line card.
* On the line card:
    * Verify address is removed from CLI.
    * Verify interface is removed from ASIC DB.
* On the supervisor card:
    * Verify the interface is removed from the SYSTEM_INTERFACE table of the Chassis App DB.
* Verify bidirectional traffic to attached host on the port from local and remote ASICs is dropped.
* Repeat with IPv4, IPv6, dual-stack.
        

## Host IP Forwarding <a name="ipfwd">


### Configuration

Please reference the [T2 topology](https://github.com/Azure/sonic-mgmt/pull/2638/) files topo_t2.yml and testbed-t2.png for network topology and sample IP addresses.  The addresses and VMS below are taken from that example topology.

VMs attached to line card 1 and line card 2 will be used for this test.
DUT Port A&B are on line card 1, D is on line card 2.

The HIDE_INTERNAL route policy will prevent inband and interface address from being advertised to EBGP peers. Looback addresses will be used to test traffic flows across cards and VMs.

```
                      ---------- DUT ----------    
                      |--- LC1 ---|--- LC2 ---|
VM01T3   -------------|A          |           |
                      |         F0|F1        D|------------- VM01T1
VM02T3   -------------|B     LB1  |   LB2     |
```

_VM01T3_
* Loopbacks:
    * ipv4: `100.1.0.1/32`
    * ipv6: `2064:100::1/128`
* Ethernet:
    * ipv4: `10.0.0.1/31`
    * ipv6: `FC00:2/126`


_VM02T3_
* Loopbacks:
    * ipv4: `100.1.0.2/32`
    * ipv6: `2064:100::2/128`
* Ethernet:
    * ipv4: `10.0.0.3/31`
    * ipv6: `FC00:6/126`

_VM01T1_
* Loopbacks:
    * ipv4: `100.1.0.33/32`
    * ipv6: `2064:100::21/128`
* Ethernet:
    * ipv4: `10.0.0.65/31`
    * ipv6: `FC00:82/126`

_DUT_

* Linecard 1
    * Port A (to VM01T3)
        * `10.0.0.0/31`
        * `FC00:1/126`
    * Port B (to VM02T3)
        * `10.0.0.2/31`
        * `FC00:5/126`
    * Inband IP ( Port F0)
        * `133.133.133.1`
        * `2064:133::1`
    * Loopback LB1
        * `11.1.0.1/32`
        * `2064:111::1/128`
* Linecard 2
    * Port D (to VM01T1)
        * `10.0.0.64/31`
        * `FC00:81/126`
    * Inband IP (Port F1)
        * `133.133.133.5`
        * `2064:133::5`
    * Loopback LB2 
        * `11.1.0.2/32`
        * `2064:111::2/128`

#### Test Case 1. Table Verification
##### Test Objective
Verify the kernel route table is correct based on the topology.
##### Test Steps
* Verify routes for local addresses on both line cards are directly connected.
* Verify routes for local inband interfaces are directly connected.
* Verify BGP established between line cards.
* Verify routes of remote linecard inband interfaces are connected via local linecard inband interface.
* Verify all learned prefixes from neighbors have their neighbors as next hop.
* Repeat for IPv4 only, IPv6 only, dual-stack.

#### Test Case 2. Router Interface to Router Interface
##### Test Objective  
Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to local line card interfaces.
##### Test Steps
* On linecard 1, send ping from:
    * DUT IP interface A to DUT IP Interface B. (10.0.0.0 to 10.0.0.2) 
* Repeat for TTL 0,1,2,255
* Repeat for 64, 1500, 9100B packets
* Repeat for IPv6

#### Test Case 3. Router Interface to neighbor addresses
##### Test Objective  
Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to neighbor addresses.
##### Test Steps
* On linecard 1, send ping from:
    * DUT IP Interface on port A to directly connected neighbor address. (10.0.0.0 to 10.0.0.1)
* On Router 01T3, send ping from:
    * Router IP interface to DUT address on port A. (10.0.0.1 to 10.0.0.0)
* Repeat for TTL 0,1,2,255
* Repeat for 64, 1500, 9100B packets
* Repeat for IPv6

#### Test Case 4. Router Interface to routed addresses. 
##### Test Objective 
Verify Host IP forwarding for IPv4 and IPv6 for various packet sizes and ttls to learned route addresses.
##### Test Steps
* On linecard 1, send ping from:
    * DUT IP Interface A to routed loopback address from router 01T3. (10.0.0.0 to 100.1.0.1)
* On Router 01T3, send ping from:
    * Router loopback interface to DUT address on port A. (100.1.0.1 to 10.0.0.0)
* Repeat for TTL 0,1,2,255
* Repeat for 64, 1500, 9100B packets
* Repeat for IPv6

#### Test Case 5. Inband Router Interface connectivity
##### Test Objective 
Verify IP connectivity over inband interfaces.
##### Test Steps
* On linecard 1 send ping from:
    * Inband interface F0 to inband interface F1 (133.133.133.1 to 133.133.133.5)
    * Inband interface F0 to neighbor on port A (133.133.133.1 to 10.0.0.1)
* Repeat for TTL 0,1,2,255
* Repeat for 64, 1500, 9100B packets
* Repeat for IPv6

#### Test Case 6. Line card loopback interface connectivity
##### Test Objective
Verify IP Connectivity to DUT loopback addresses. 
##### Test Steps
* On linecard 1 send ping from:
    * Loopback to IP interface of port D (11.1.0.1 to 10.0.0.64)
    * Loopback to neighbor on port D (11.1.0.1 to 10.0.0.65)
    * Loopback to routed loopback address (11.1.0.1 to 100.1.0.1)
    * Loopback to routed loopback address (11.1.0.1 to 100.1.0.33)
* On Router 01T3, send ping from:
    * Router loopback interface to DUT loopback address on linecard 1. (100.1.0.1 to 11.1.0.1)
    * Router loopback interface to DUT loopback address on linecard 2. (100.1.0.1 to 11.1.0.2)
* Repeat for TTL 0,1,2,255
* Repeat for 64, 1500, 9100B packets
* Repeat for IPv6

#### Test Case 7. End to End traffic. 
##### Test Objective            
Verify end to end routing IPv4/v6, packet sizes, ttl(0,1,2,255)
##### Test Steps
* On Router 1, send ping from:
    * End to end port A to B, ports on same linecard.  (100.1.0.1 to 100.1.0.2)
    * End to end port A to D, ports across multiple linecards. (100.1.0.1 to 100.1.0.33)
* Repeat for TTL 0,1,2,255
* Repeat for 64, 1500, 9100B packets
* Repeat for IPv6          

#### Test Case 8. Front Panel port link flap
##### Test Objective            
Traffic to Sonic host interfaces recovers after the front panel port flaps.
##### Test Steps
* Admin down interface on fanout connected to DUT port A to cause LOS on DUT.
* On linecard 1 verify ping is successful from: 
    * DUT IP Interface B to DUT Interface D
    * DUT Neighbor IP B to DUT Neighbor IP D
* On Router 02T3, verify ping is successful from Router Interface to DUT IP Interface B and D.
* On linecard 1, verify ping fails from:
    * DUT IP Interface A to DUT IP interface B and D.
    * DUT IP Interface A to attached neighbor.
* On Router 01T3, verify ping fails to all DUT addresses.
* On fanout switch, admin up the downed interface.
* Validate all traffic flows are correct as in test cases 2-7.
* Retry traffic with TTL 0,1,2,255
* Retry traffic with 64, 1500, 9100B packets
* Retry traffic with IPv6  

## VLAN Inband Mode <a name="inbandvlan"></a>

#### Test Case 1. Inband VLAN mode configuration.
##### Test Objective  
Verify system initialization in Inband VLAN mode.
##### Test Steps
* Verify vlan inband interface is used when in this mode.
* Verify correct VLAN ID is used on all nodes.
* On each linecard, verify inband VLAN router interfaces are present in ASICDB
* On supervisor card, verify inband VLAN router interfaces are present in Chassis App DB

#### Test Case 2. Inband VLAN neighbors
##### Test Objective 
Verify neighbor adjacency as in [arp](#arp). Inband port will be replaced with VLAN interface as neighbor interface.
##### Test Steps
* Repeat tests for:
    * Local neighbor learning,
    * remote neighbor learning and route creation
    * timeout and clearing of neighbors

#### Test Case 3. Inband VLAN host connectivity
##### Test Objective 
Verify host reachability as in [Host IP Connectivity](#ipfwd).  VLAN interface will replace inband port as next hop.
##### Test Steps
* Repeat traffic tests for:
    * router interface to remote ports,
    * router interface to local and remote neighbors,
    * router interface to learned routes.
    * inband interface to all addresses.
    * DUT loopback interface to all addresses.

#### Test Case 4. Mode Switch.
##### Test Objective 
Verify VoQ system can be switched between modes when configuration is replaced.
##### Test Steps
* Regenerate configuration of VoQ system, switching device from inband port to inband VLAN.
* Reboot the chassis.
* Verify system is stable in new mode.
* Restore to inband port mode.
