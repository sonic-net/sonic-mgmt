# Build A Multi-Tier Network

- [Build A Multi-Tier Network](#build-a-multi-tier-network)
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
    - [Verifying BGP Establishment](#verifying-bgp-establishment)
  - [Establish Routes](#establish-routes)
    - [Configure T0 switches](#configure-t0-switches)
    - [Configure Traffic Generators](#configure-traffic-generators)
  - [Verifying Route Advertisement](#verifying-route-advertisement)
  - [Conclusion](#conclusion)

## Overview

This document provides a comprehensive guide for building a multi-tier network architecture to support multiple BGP (Border Gateway Protocol) sessions and facilitate scalable route management. The multi-tier network consists of T0 (Top-of-Rack) switches and T1 (Leaf) switches, forming a hierarchical structure that ensures efficient traffic routing and network scalability.

The document outlines the necessary settings and configurations for establishing BGP sessions between switches of different tiers, ensuring ECMP (Equal-Cost Multi-Path). Additionally, it details the process for handling a large number of routing entries to accommodate network growth while maintaining performance and reliability.

![overview](./2Tier_Network.png)

## Goals

The routing configuration of the BT0 switches should ensure that all data traffic go through one of the T1 switches.
The primary objective of this network design is to ensure that all data traffic is routed efficiently through one of the T1 switches, optimizing network performance and reliability. The key goals of this implementation include:

- Efficient Traffic Routing – Configuring the T0 switches to ensure that all outbound and inbound data flows through a T1 switch, preventing unnecessary network congestion.
- Scalability – Establishing a structured approach for managing a large number of BGP sessions and routing entries, allowing the network to grow without performance degradation.
- Redundancy and Failover – Ensuring high availability by enabling multiple BGP sessions between T0 and T1 switches, so traffic can dynamically reroute in case of link or node failures.
- Optimized Resource Utilization – Balancing traffic distribution across available paths to maximize network efficiency and prevent bottlenecks.
- Standardized Configuration Approach – Defining a consistent method for setting up BGP, and routes across all network devices for easier deployment and maintenance.

This document provides step-by-step instructions for achieving these goals, ensuring a resilient and high-performance network infrastructure.

## Connecting Traffic Generators and T0 SONiC Switches

To ensure proper traffic flow and routing validation, traffic generators are connected to the T0 SONiC switches. This section details the physical connectivity, logical topology, and configuration requirements for integrating traffic generators into the network.

### Connections

Each T0 switch is connected to a traffic generator via multiple optical cables to facilitate high-bandwidth data transmission. There are no direct connections between any two traffic generators to ensure that all traffic is routed through the T0 switches, aligning with the network's hierarchical design. The number of optical cables and ports utilized depends on network capacity and performance requirements, ensuring sufficient bandwidth for traffic generation and testing.

### Configuration and Settings

To enable proper communication between the traffic generators and T0 switches, the following configurations must be performed:

- Topology Setup: In the traffic generator management application, create a dedicated topology for each traffic generator. Ensure that each topology accurately represents the physical connections between the traffic generator and the corresponding T0 switch.
- Port Configuration: Add the ports in the traffic generator that are physically connected to the T0 switch. Verify that the ports are active and properly linked.
- Protocol Configuration: Define and enable the required network protocols, such as IP and VLAN, to establish end-to-end communication and facilitate proper routing through the network. Configure IP addresses for each interface, ensuring they are correctly assigned within the network's subnet structure.
- Protocol Activation: Start the configured protocols in the traffic generator management application. Verify that the traffic generator can send and receive packets through the T0 switch. Conduct initial tests to confirm the proper establishment of connections and protocol functionality.

By following these steps, the traffic generators will be correctly integrated into the network, allowing for accurate traffic simulation, route validation, and performance testing.

## Establish BGP Sessions

![Establish BGP Sessions](./BGP_peering.png)

### Topology

In this multi-tier network architecture, BGP sessions are established between T0 (Top-of-Rack) switches and T1 (Leaf) switches to enable efficient and scalable routing across the network.

- Many-to-Many Connectivity: Each T0 switch connects to multiple T1 switches via multiple physical links, ensuring load balancing and redundancy.
- No Direct Connectivity Between Same-Tier Devices: T0 switches do not have direct connections to other T0 switches, and T1 switches do not directly connect to other T1 switches. This enforces a strict hierarchical routing model where all traffic between T0 switches must traverse a T1 switch.
- BGP Session Distribution: Assume a T1 switch has X logical ports connected to a T0 switch. We establish X BGP sessions—one per port—between the two switches to evenly distribute the session load and enhance routing efficiency.

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

T1-A Configuration:

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

### Verifying BGP Establishment

Once the configurations are applied, the BGP session will be established, and the switches will begin exchanging routing information. Proper verification using `show bgp summary` and `show bgp neighbors` commands can be conducted to confirm session establishment and route propagation.

## Establish Routes

To simulate realistic network conditions and validate routing behavior, BGP sessions are established between the switches and traffic generators. Traffic generators can be configured to emulate a large number of network prefixes and advertise them to the T0 switches. This setup is instrumental in testing the network’s scalability and its ability to handle extensive route propagation.

The key to setting up BGP is configuring proper peering relationships — whether the sessions are between two switches or between a switch and a traffic generator. The steps below outline the process for establishing BGP sessions and advertising routes:

### Configure T0 switches

1. Set up the ports on the DUT that are connected to the traffic generators. For example:

    ```json
    "PORT": {
        "Ethernet0": {
            "admin_status": "up",
            "alias": "Ethernet1/1",
            "description": "Servers0:eth0",
            "fec": "rs",
            "index": "1",
            "lanes": "17",
            "mtu": "9100",
            "pfc_asym": "off",
            "speed": "100000",
            "subport": "1",
            "tpid": "0x8100"
        }
    }
    ```

2. Assign the IPv6 interface for BGP peering:

    ```json
    "INTERFACE": {
        "Ethernet0": {},
        "Ethernet0|2001:db8::1:0:10/120": {}
    }
    ```

3. Configure the traffic generator as a BGP neighbor on the switch:

    ```json
    "BGP_NEIGHBOR": {
        "2001:db8::1:0:1": {
            "admin_status": "up",
            "asn": 63001,
            "holdtime": "10",
            "keeplive": "3",
            "local_addr": "2001:db8::1:0:10",
            "name": "IXIA1-0",
            "nhopself": "0",
            "rrclient": "0"
        }
    }
    "DEVICE_NEIGHBOR": {
        "Ethernet0": {
            "name": "IXIA1-0",
            "port": "Ethernet0"
        }
    },
    "DEVICE_NEIGHBOR_METADATA": {
        "IXIA1-0": {
            "cluster": "StressTest",
            "deployment_id": "1",
            "hwsku": "ABCDEFG",
            "lo_addr": "10.3.145.9/32",
            "mgmt_addr": "10.3.145.9/32",
            "type": "TG"
        }
    }
    ```

### Configure Traffic Generators

The traffic generator (e.g., IXIA, Keysight, Spirent) must be configured to match the switch’s BGP settings. This can be done via GUI or via automation APIs like snappi, IxNetwork, or PyATS.

1. Assign IPs to Test Ports Connected to Switches
   - Set the local IPv6 address of each test port (e.g., 2001:db8::1:0:1/120).
   - Configure the default gateway as the switch-side IP (2001:db8::1:0:10)

2. Enable BGP Protocol Stack
   - Assign the local AS number.
   - Set the remote AS (ASN of the switch).
   - Configure BGP timers: hold time, keepalive.
   - Assign the peer IP address.

3. Advertise Routes
   - Define a set of IPv6 routes to be advertised.
   - Configure route attributes: prefix length, next-hop address, and route counts.

## Verifying Route Advertisement

Once the ports and IPs are configured, T0 switches can advertise these routes via BGP to T1 switches. To verify that routes are being correctly advertised, run `show ip bgp summary` on the T0 switch. To confirm that routes are received on the T1 switch, use `show ip route bgp`. This will display the learned routes and their respective nexthop IP addresses.

## Conclusion

The successful implementation of a multi-tier Network enables efficient traffic management, high scalability, and robust routing capabilities. This multi-tier Network design provides a solid foundation for scalability, redundancy, and performance optimization, making it ideal for large-scale data centers and high-performance networking environments. Future enhancements could include automation, traffic engineering, and real-time monitoring to further improve network resilience and efficiency.
