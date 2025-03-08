# Build A 2-Tier Network

- [Build A 2-Tier Network](#build-a-2-tier-network)
  - [Overview](#overview)
  - [Goals](#goals)
  - [Connecting Traffic Generators and T0 SONiC Switches](#connecting-traffic-generators-and-t0-sonic-switches)
    - [Connections](#connections)
    - [Configuration and Settings](#configuration-and-settings)
  - [Establish BGP Sessions](#establish-bgp-sessions)
    - [Topology](#topology)
    - [Configuration](#configuration)
      - [Enable BGP Feature](#enable-bgp-feature)
      - [Define Device Metadata](#define-device-metadata)
      - [Configure Ports and Interfaces](#configure-ports-and-interfaces)
      - [Specify BGP Neighbor Attributes](#specify-bgp-neighbor-attributes)
    - [Verifying  BGP Establishment](#verifying--bgp-establishment)
  - [Establish Scaling Number of Routes](#establish-scaling-number-of-routes)
    - [Configuration Steps for Route Advertisement from T0 Switches](#configuration-steps-for-route-advertisement-from-t0-switches)
      - [Define VLANs](#define-vlans)
      - [Add Ports Connected to Traffic Generators to VLANs](#add-ports-connected-to-traffic-generators-to-vlans)
      - [Assign IP Addresses to VLANs](#assign-ip-addresses-to-vlans)
    - [Verifying Route Advertisement](#verifying-route-advertisement)
  - [Conclusion](#conclusion)

## Overview

This document provides a comprehensive guide for building a 2-tier network architecture to support multiple BGP (Border Gateway Protocol) sessions and facilitate scalable route management. The 2-tier network consists of T0 (Top-of-Rack) switches and T1 (Leaf) switches, forming a hierarchical structure that ensures efficient traffic routing and network scalability.

The document outlines the necessary settings and configurations for establishing BGP sessions between T0 and T1 switches, ensuring ECMP (Equal-Cost Multi-Path). Additionally, it details the process for handling a large number of routing entries to accommodate network growth while maintaining performance and reliability.

![overview](./2Tier_Network.png)

## Goals

The routing configuration of the BT0 switches should ensure that all data traffic go through one of the T1 switches.
The primary objective of this network design is to ensure that all data traffic is routed efficiently through one of the T1 switches, optimizing network performance and reliability. The key goals of this implementation include:

- Efficient Traffic Routing – Configuring the T0 switches to ensure that all outbound and inbound data flows through a T1 switch, preventing unnecessary network congestion.
- Scalability – Establishing a structured approach for managing a large number of BGP sessions and routing entries, allowing the network to grow without performance degradation.
- Redundancy and Failover – Ensuring high availability by enabling multiple BGP sessions between T0 and T1 switches, so traffic can dynamically reroute in case of link or node failures.
- Optimized Resource Utilization – Balancing traffic distribution across available paths to maximize network efficiency and prevent bottlenecks.
- Standardized Configuration Approach – Defining a consistent method for setting up BGP, VLANs, and routing policies across all network devices for easier deployment and maintenance.

This document provides step-by-step instructions for achieving these goals, ensuring a resilient and high-performance network infrastructure.

## Connecting Traffic Generators and T0 SONiC Switches

To ensure proper traffic flow and routing validation, traffic generators are connected to the T0 SONiC switches. This section details the physical connectivity, logical topology, and configuration requirements for integrating traffic generators into the network.

### Connections

Each T0 switch is connected to a traffic generator via multiple optical cables to facilitate high-bandwidth data transmission. There are no direct connections between any two traffic generators to ensure that all traffic is routed through the T0 switches, aligning with the network's hierarchical design. The number of optical cables and ports utilized depends on network capacity and performance requirements, ensuring sufficient bandwidth for traffic generation and testing.

### Configuration and Settings

To enable proper communication between the traffic generators and T0 switches, the following configurations must be performed:

- Topology Setup: In the traffic generator management application, create a dedicated topology for each traffic generator. Ensure that each topology accurately represents the physical connections between the traffic generator and the corresponding T0 switch.
- Port Configuration: Add the ports in the traffic generator that are physically connected to the T0 switch. Verify that the ports are active and properly linked.
- Protocol Configuration: Define and enable the required network protocols, such as IP and VLAN, to ensure end-to-end communication. Assign VLAN IDs to differentiate traffic types and facilitate proper routing through the network. Configure IP addresses for each interface, ensuring they are correctly assigned within the network's subnet structure.
- Protocol Activation: Start the configured protocols in the traffic generator management application. Verify that the traffic generator can send and receive packets through the T0 switch. Conduct initial tests to confirm the proper establishment of connections and protocol functionality.

By following these steps, the traffic generators will be correctly integrated into the network, allowing for accurate traffic simulation, route validation, and performance testing.

## Establish BGP Sessions

### Topology

In this 2-tier network architecture, T0 (Top-of-Rack) switches establish BGP peering with T1 (Leaf) switches to facilitate efficient and scalable routing.

- Many-to-Many Connectivity: Each T0 switch connects to multiple T1 switches via multiple physical links, ensuring load balancing and redundancy.
- No Direct Connectivity Between Same-Tier Devices: T0 switches do not have direct connections to other T0 switches, and T1 switches do not directly connect to other T1 switches. This enforces a strict hierarchical routing model where all traffic between T0 switches must traverse a T1 switch.
- BGP Session Distribution: Assume each T1 switch has X logical ports available for BGP peering. Suppose there are Y T0 switches in the network. In this case, each T0 switch establishes X/Y BGP sessions with T1 switches to evenly distribute the session load and optimize routing efficiency.

This topology ensures that traffic is always routed through a T1 switch, providing a structured, predictable, and scalable routing environment.

### Configuration

For example, assume T0-A's Ethernet256 is connected to T1-A's Ethernet0. To establish a BGP session between a T0 switch (T0-A) and a T1 switch (T1-A), the following configurations must be applied.

#### Enable BGP Feature

First, BGP must be enabled on both T0 and T1 switches to allow them to participate in BGP-based route exchange.

T0-A Configuration:

```json
"FEATURE": {
    "bgp": {
        "auto_restart": "enabled",
        "check_up_status": "false",
        "delayed": "False",
        "has_global_scope": "False",
        "has_per_asic_scope": "True",
        "high_mem_alert": "disabled",
        "set_owner": "local",
        "state": "enabled",
        "support_syslog_rate_limit": "true"
    }
}
```

T1-A Configuration:

```json
"FEATURE": {
    "bgp": {
        "auto_restart": "enabled",
        "check_up_status": "false",
        "delayed": "False",
        "has_global_scope": "False",
        "has_per_asic_scope": "True",
        "high_mem_alert": "disabled",
        "set_owner": "local",
        "state": "enabled",
        "support_syslog_rate_limit": "true"
    }
}
```

#### Define Device Metadata

Define the metadata of the two devices. Each switch must be correctly identified with its BGP Autonomous System Number (ASN) and router ID. T0 switches function as top-of-rack routers, while T1 switches serve as leaf routers.

T0-A Configuration:

```json
"DEVICE_METADATA": {
    "localhost": {
        "bgp_asn": "64001",
        "buffer_model": "traditional",
        "cloudtype": "Public",
        "default_bgp_status": "up",
        "default_pfcwd_status": "enable",
        "deployment_id": "1",
        "docker_routing_config_mode": "separated",
        "hostname": "switch-T0-A",
        "hwsku": "ABCDEFG",
        "region": "None",
        "synchronous_mode": "enable",
        "timezone": "UTC",
        "type": "ToRRouter",
        "yang_config_validation": "disable",
        "bgp_router_id": "10.100.0.81"
    }
}
```

T1-A Configuration:

```json
"DEVICE_METADATA": {
    "localhost": {
        "bgp_asn": "65001",
        "buffer_model": "traditional",
        "cloudtype": "Public",
        "default_bgp_status": "up",
        "default_pfcwd_status": "enable",
        "deployment_id": "1",
        "docker_routing_config_mode": "separated",
        "hostname": "switch-T1-A",
        "hwsku": "ABCDEFG",
        "region": "None",
        "synchronous_mode": "enable",
        "timezone": "UTC",
        "type": "LeafRouter",
        "yang_config_validation": "disable",
        "bgp_router_id": "10.100.0.88"
    }
}
```

#### Configure Ports and Interfaces

Each BGP session requires a pair of interfaces. Configure the two interfaces, ensuring they are in the same subnet.

T0-A Configuration:

```json
"PORT": {
    "Ethernet0": {
        "admin_status": "up",
        "alias": "Ethernet1/1",
        "description": "Ethernet1/1",
        "fec": "rs",
        "index": "1",
        "lanes": "17",
        "mtu": "9100",
        "pfc_asym": "off",
        "speed": "100000",
        "subport": "1",
        "tpid": "0x8100"
    }
},
"INTERFACE": {
    "Ethernet0": {},
    "Ethernet0|2001:db9::1:0:10/120": {}
}
```

T1-A Configuration:

```json
"PORT": {
    "Ethernet256": {
        "admin_status": "up",
        "alias": "Ethernet33/1",
        "description": "Ethernet33/1",
        "fec": "rs",
        "index": "33",
        "lanes": "273",
        "mtu": "9100",
        "pfc_asym": "off",
        "speed": "100000",
        "subport": "1",
        "tpid": "0x8100"
    }
},
"INTERFACE": {
    "Ethernet256": {},
    "Ethernet256|2001:db9::1:0:1/120": {}
}
```

#### Specify BGP Neighbor Attributes

Each switch must recognize the other as a BGP neighbor and establish a peer session for route exchange.

T0-A Configuration:

```json
"BGP_NEIGHBOR": {
    "2001:db9::1:0:10": {
        "admin_status": "up",
        "asn": 65001,
        "holdtime": "10",
        "keeplive": "3",
        "local_addr": "2001:db9::1:0:1",
        "name": "T1-A-0",
        "nhopself": "0",
        "rrclient": "0"
    }
},
"DEVICE_NEIGHBOR": {
    "Ethernet256": {
        "name": "T1-A-0",
        "port": "Ethernet256"
    }
},
"DEVICE_NEIGHBOR_METADATA": {
    "T1-A-0": {
        "cluster": "StressTest",
        "deployment_id": "1",
        "lo_addr": "10.100.0.88/32",
        "lo_addr_v6": "fc00:1::88/128",
        "mgmt_addr": "10.64.246.88/23",
        "mgmt_addr_v6": "fc00:2::88/64",
        "hwsku": "ABCDEFG",
        "type": "LeafRouter"
    }
}
```

T1-A Configuration:

```json
"BGP_NEIGHBOR": {
    "2001:db9::1:0:1": {
        "admin_status": "up",
        "asn": 64001,
        "holdtime": "10",
        "keeplive": "3",
        "local_addr": "2001:db9::1:0:10",
        "name": "T0-A-0",
        "nhopself": "0",
        "rrclient": "0"
    }
},
"DEVICE_NEIGHBOR": {
    "Ethernet0": {
        "name": "T0-A-0",
        "port": "Ethernet0"
    }
},
"DEVICE_NEIGHBOR_METADATA": {
    "T0-A-0": {
        "cluster": "StressTest",
        "deployment_id": "1",
        "lo_addr": "10.100.0.81/32",
        "lo_addr_v6": "fc00:1::81/128",
        "mgmt_addr": "10.64.246.81/23",
        "mgmt_addr_v6": "fc00:2::81/64",
        "hwsku": "ABCDEFG",
        "type": "ToRRouter"
    }
}
```

### Verifying  BGP Establishment

Once the configurations are applied, the BGP session will be established, and the switches will begin exchanging routing information. Proper verification using `show bgp summary` and `show bgp neighbors` commands can be conducted to confirm session establishment and route propagation.

## Establish Scaling Number of Routes

To facilitate efficient routing and ensure network scalability, a large number of routes need to be advertised dynamically across the network. This can be achieved using two primary approaches:

- Traffic Generator-Based Route Advertisement:
Traffic generators can be configured to simulate a large number of network prefixes and advertise them to the T0 switches. This approach is useful for testing the network’s ability to handle large-scale route propagation.

- T0 Switch-Based Route Advertisement:
T0 switches can be configured to generate and advertise routes directly to T1 switches. This method is preferred for persistent and scalable network configurations.

For the T0 switch-based approach, the following steps outline the process of establishing a scaling number of routes:

### Configuration Steps for Route Advertisement from T0 Switches

#### Define VLANs

To enable route advertisement, VLANs can be created on the T0 switches. These VLANs will act as logical interfaces to handle traffic and route announcements. Each VLAN should be assigned a unique VLAN ID, which will be used for segmentation and route identification.

Configuration Example:

```json
"VLAN": {
    "Vlan1000": {
        "vlanid": "1000"
    },
    "Vlan1001": {
        "vlanid": "1001"
    }
}
```

#### Add Ports Connected to Traffic Generators to VLANs

Once VLANs are defined, the interfaces that are connected to traffic generators must be assigned to the appropriate VLANs.

Configuration Example:

```json
"VLAN_MEMBER": {
    "Vlan1000|Ethernet0": {
        "tagging_mode": "untagged"
    },
    "Vlan1000|Ethernet4": {
        "tagging_mode": "untagged"
    },
    "Vlan1001|Ethernet8": {
        "tagging_mode": "untagged"
    },
    "Vlan1001|Ethernet12": {
        "tagging_mode": "untagged"
    }
}
```

In this example, Ethernet0 and Ethernet4 are part of VLAN1000. Ethernet8 and Ethernet12 are part of VLAN1001. This ensures that traffic received from the traffic generators is properly categorized and routed through the VLANs.

#### Assign IP Addresses to VLANs

To scale the number of advertised routes, X/Y × 10 IP addresses should be assigned to VLANs.

- X = Number of logical ports per T1 switch.
- Y = Number of T0 switches in the network.
- X/Y × 10 = Number of IP addresses to be assigned to VLANs.

Configuration Example:

```json
"INTERFACE": {
    "Vlan1000|10.1.1.1/24": {},
    "Vlan1000|10.1.2.1/24": {},
    "Vlan1001|10.2.1.1/24": {},
    "Vlan1001|10.2.2.1/24": {}
}
```

This assigns multiple IP addresses to each VLAN, simulating a large number of advertised routes.

### Verifying Route Advertisement

Once VLANs and IPs are configured, T0 switches can advertise these routes via BGP to T1 switches. To verify that routes are being correctly advertised, run `show ip bgp summary` on the T0 switch. To confirm that routes are received on the T1 switch, use `show ip route bgp`. This will display the learned routes and their respective nexthop IP addresses.

## Conclusion

The successful implementation of a 2-Tier Network enables efficient traffic management, high scalability, and robust routing capabilities. This 2-Tier Network design provides a solid foundation for scalability, redundancy, and performance optimization, making it ideal for large-scale data centers and high-performance networking environments. Future enhancements could include automation, traffic engineering, and real-time monitoring to further improve network resilience and efficiency.
