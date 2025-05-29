# Testbed Setup with Network Under Test (NUT)

1. [1. Overview](#1-overview)
2. [2. Testbed CLI: `deploy-cfg`](#2-testbed-cli-deploy-cfg)
3. [3. Testbed definition](#3-testbed-definition)
   1. [3.1. Device and link definition](#31-device-and-link-definition)
   2. [3.2. Testbed YAML definition](#32-testbed-yaml-definition)
4. [4. NUT config deployment: `deploy-cfg`](#4-nut-config-deployment-deploy-cfg)
   1. [4.1. Generate device metadata](#41-generate-device-metadata)
   2. [4.2. Generate port config](#42-generate-port-config)
   3. [4.3. Establish BGP Sessions](#43-establish-bgp-sessions)
      1. [4.3.1. Enable BGP Feature](#431-enable-bgp-feature)
      2. [4.3.2. Interface IP assignment](#432-interface-ip-assignment)
      3. [4.3.3. Generate BGP Neighbor configuration](#433-generate-bgp-neighbor-configuration)
   4. [4.4. Verifying BGP Establishment](#44-verifying-bgp-establishment)
5. [5. Traffic generator setup](#5-traffic-generator-setup)
   1. [5.1. Port configuration](#51-port-configuration)
   2. [5.2. Routes advertisement](#52-routes-advertisement)
6. [6. Verifying Route Advertisement](#6-verifying-route-advertisement)

## 1. Overview

This document provides a comprehensive guide for building a SONiC testbed that supports using multiple devices in multi-tier topology as the test target (Network Under Test, NUT), without any neighbors such as cEOS. This testbed is particularly helpful to support test cases that doesn't require any virtual neighbors to be created to help with traffic routing and use hardware traffic generators to generate traffic.

Just like what the datacenter network is designed today, this tested leverages BGP (Border Gateway Protocol) to facilitate scalable route management. In this multi-tier network:

1. All devices will have BGP enabled and sessions to be created on each logical port pairs as long as it is defined in the links csv.
2. The topology only creates the BGP sessions to facilitate traffic routing, but no routes will be created during the `deploy-mg` and `add-topo` steps.
3. Each test needs to inject the routes into the network from the ports that directly connected to traffic generator in its pretest setup fixture. Then the routes will be advertised all the way from lower tiers to higher tiers, tier by tier.

```mermaid
graph LR
    subgraph "Tier-2 Switches"
        T20[T2 Switch 0]
    end

    subgraph "Tier-1 Switches"
        T10[T1 Switch 0]
        T11[T1 Switch 1]
    end

    subgraph "Tier-0 Switches"
        T00[T0 Switch 0]
        T01[T0 Switch 1]
        T02[T0 Switch 2]
    end

    subgraph "Traffic Generator"
        TG[Traffic Generator]
    end

    T10 -->|BGP Session| T20
    T11 -->|BGP Session| T20

    T00 -->|BGP Session| T10
    T01 -->|BGP Session| T10
    T02 -->|BGP Session| T11

    TG -->|BGP Session| T00
    TG -->|BGP Session| T01
    TG -->|BGP Session| T02
    TG -->|BGP Session| T11
```

## 2. Testbed CLI: `deploy-cfg`

Because our current testbed-cli and topology management (`deploy-mg` and `add-topo`) is designed to support SONiC testbed with virtual neighbors, and hard to make it compatible with this type of testbed, we will create a new testbed-cli command `deploy-cfg` to deploy the NUT configuration.

This command will skip the minigraph generator and directly generates the required configuration in the format of config DB JSON. This simplifies the deployment process and allows for a more straightforward and flexiable configuration of the NUT.

## 3. Testbed definition

### 3.1. Device and link definition

Just like how regular SONiC testbed is defined, The devices and links between all devices in the NUT need to be defined in the `sonic_*_devices.csv` and `sonic_*_links.csv` file.

The following example represents a definition of a T0 switch:

```csv
Hostname,ManagementIp,HwSku,Type,Protocol
tg-1,10.0.0.200/24,IXIA-tester,DevIxiaChassis,
switch-t0-1,10.0.0.123/24,HWSKU-TO-TEST,DevSonic,
```

The following example represent a 100G link from the traffic generator port 1 to the first port of a T0 switch:

```csv
StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode,AutoNeg
switch-t0-1,Ethernet0,tg-1,Port1.1,100000,,Access,
```

### 3.2. Testbed YAML definition

The current testbed yaml definition is not designed to support NUT, so we will create a new testbed YAML definition `testbed.nut.yml` that is compatible with the NUT. The following example shows how to define a testbed for NUT with multiple tiers:

```yaml
- conf-name: testbed-nut-1
  dut:
    - switch-t0-1
    - switch-t0-2
    - switch-t0-3
    - switch-t1-1
    - switch-t1-2
    - switch-t2-1
  dut_template:
    - { name: ".*-t0-.*", config_template: "t0", loopback_v4: "100.1.0.0/24", loopback_v6: "2064:100:0:0::/64", start_asn: 64001, p2p_v4: "10.0.0.0/16", p2p_v6: "fc0a::/64" }
    - { name: ".*-t1-.*", config_template: "t1", loopback_v4: "100.1.1.0/24", loopback_v6: "2064:100:0:1::/64", start_asn: 65001, p2p_v4: "10.0.0.0/16", p2p_v6: "fc0a::/64" }
    - { name: ".*-t2-.*", config_template: "t2", loopback_v4: "100.1.2.0/24", loopback_v6: "2064:100:0:2::/64", start_asn: 63001, p2p_v4: "10.0.0.0/16", p2p_v6: "fc0a::/64" }
  tg:
    - tg-1
  inv_name: lab
  auto_recover: 'True'
  comment: "Testbed for NUT with multi-tier topology"
```

## 4. NUT config deployment: `deploy-cfg`

### 4.1. Generate device metadata

First, the device metadata must be generated using the device information defined in the `sonic_*_devices.csv` file. And here is an example of the device metadata for a T0 switch:

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
        "hostname": "switch-t0-0",
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

Certain information is not defined specifically in the `sonic_*_devices.csv` file, such as the BGP Autonomous System Number (ASN), router ID and role. These info will be automatically generated by the `deploy-cfg` tool based on the testbed-wise global information defined in the testbed YAML file.

- `bgp_asn`: The BGP ASN is generated based on the device type and its index in the testbed. For example, T0 switches will have an ASN of 64001, while T1 switches will have an ASN of 65001.

### 4.2. Generate port config

With the link definition, the port configuration will be created on the T0 switch during `deploy-cfg`, which setup port speed, FEC, auto negotiation, and other port attributes.

An example of the port configuration generated for the T0 switch is as follows:

```json
"PORT": {
    "Ethernet256": {
        "admin_status": "up",
        "alias": "etp33a",
        "description": "etp33a",
        "fec": "rs",
        "index": "33",
        "lanes": "273",
        "mtu": "9100",
        "pfc_asym": "off",
        "speed": "100000",
        "subport": "1",
        "tpid": "0x8100"
    }
}
```

Each interface will also have IP address assigned, which will be explained as part of the BGP session establishment in the next section.

### 4.3. Establish BGP Sessions

To establish BGP sessions between the switches and the traffic generators, the following steps are required:

#### 4.3.1. Enable BGP Feature

First, BGP must be enabled to allow them to participate in BGP-based route exchange.

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

#### 4.3.2. Interface IP assignment

`deploy-cfg` will automatically assign IP addresses to the interfaces based on the testbed-wide defined IP pools:

```yaml
dut_template:
  - { name: ".*-t0-.*", loopback_v4: "100.1.0.0/24", loopback_v6: "2064:100:0:0::/64", start_asn: 64001, router_id: "172.16.0.0/16", p2p_v4: "10.0.0.0/16", p2p_v6: "2001:db9::/64" }
  - { name: ".*-t1-.*", loopback_v4: "100.1.1.0/24", loopback_v6: "2064:100:0:1::/64", start_asn: 65001, router_id: "172.16.0.0/16", p2p_v4: "10.0.0.0/16", p2p_v6: "2001:db9::/64" }
  - { name: ".*-t2-.*", loopback_v4: "100.1.2.0/24", loopback_v6: "2064:100:0:2::/64", start_asn: 63001, router_id: "172.16.0.0/16", p2p_v4: "10.0.0.0/16", p2p_v6: "2001:db9::/64" }
```

The detailed step follows the following algorithm:

1. Read all IP pools defined in the testbed YAML file and unify the IP pools across all devices. (Different devices can share the same IP pool.)
2. Set devices in the TG (Traffic generator) list in the testbed as the start devices.
3. Walk through the links defined in the `sonic_*_links.csv` file in BFS order.
4. For each link (port pair),
   1. Curve out a loopback v4 IP from the unified IP pool (1 IP).
   2. Curve out a loopback v6 IP from the unified IP pool (1 IP).
   3. If loopback V4 IP pool is not assigned, curve out a router ID v4 IP from the unified IP pool (1 IP).
   4. Curve out a 2-bit subnet from the unified IP pool (4 IPs), where the second IP will be used on the downlink port, while the third IP will be used on the uplink port.
5. Generate the interface configuration for each port for each devices as config shows below.

```json
"INTERFACE": {
    "Ethernet256": {},
    "Ethernet256|2001:db9::1:0:1/126": {}
}
```

In the end, the devices will have the following interface IPs assigned:

```mermaid
graph LR
    subgraph T0-1
        T0P1[Port1: 2001:db9::1:0:1/126]
    end

    subgraph T1-1
        T1P1[Port1: 2001:db9::1:0:2/126]
    end

    T0P1 <--> T1P1
```

#### 4.3.3. Generate BGP Neighbor configuration

To enable BGP sessions, the BGP neighbor configuration must be generated for each switch. This configuration includes the ASN, hold time, keepalive time, local address, and other necessary parameters.

<table>
<tr>
<td>T0-0 Configuration:</td>
<td>T1-0 Configuration:</td>
</tr>
<td>

```json
"BGP_NEIGHBOR": {
    "2001:db9::1:0:2": {
        "admin_status": "up",
        "asn": 65001,
        "holdtime": "10",
        "keeplive": "3",
        "local_addr": "2001:db9::1:0:1",
        "name": "switch-t1-0",
        "nhopself": "0",
        "rrclient": "0"
    }
},
"DEVICE_NEIGHBOR": {
    "Ethernet256": {
        "name": "switch-t1-0",
        "port": "Ethernet256"
    }
},
"DEVICE_NEIGHBOR_METADATA": {
    "switch-t1-0": {
        "cluster": "StressTest",
        "deployment_id": "1",
        "lo_addr": "100.1.1.1/32",
        "lo_addr_v6": "2064:100:0:1::1/128",
        "mgmt_addr": "10.250.1.1/24",
        "mgmt_addr_v6": "fec0::1:1/64",
        "hwsku": "ABCDEFG",
        "type": "LeafRouter"
    }
}
```

</td>
<td>

```json
"BGP_NEIGHBOR": {
    "2001:db9::1:0:1": {
        "admin_status": "up",
        "asn": 64001,
        "holdtime": "10",
        "keeplive": "3",
        "local_addr": "2001:db9::1:0:2",
        "name": "switch-t0-0",
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
    "switch-t0-0": {
        "cluster": "StressTest",
        "deployment_id": "1",
        "lo_addr": "100.1.0.1/32",
        "lo_addr_v6": "2064:100:0:0::1/128",
        "mgmt_addr": "10.250.0.1/24",
        "mgmt_addr_v6": "fec0::0:1/64",
        "hwsku": "ABCDEFG",
        "type": "ToRRouter"
    }
}
```

</td>
</tr>
</table>

### 4.4. Verifying BGP Establishment

Once the configurations are applied, the BGP session will be established, and the switches will begin exchanging routing information. Proper verification using `show bgp summary` and `show bgp neighbors` commands can be conducted to confirm session establishment and route propagation.

## 5. Traffic generator setup

Although certain traffic generator configurations can be generated in the `deploy-cfg` step, it is deferred to the pretest fixture of each test case. This allows the traffic generators to be shared by all the tests in the most flexiable way - they are only configured whenever they are actually needed.

### 5.1. Port configuration

During the pretest fixture, the test will read the configurations from the device, for example, port configurations, IP address, and VLAN settings. Then generate the traffic generator configuration accordingly and apply it for later usage, which includes:

- Port breakout, speed and FEC settings.
- IP address assignment for each port.
  - This can be deducted from the port IP subnet. Use the second IP in the subnet.
  - For example, if the switch port is assigned with `2001:db9::1:0:2/126`, the traffic generator port will be assigned with `2001:db9::1:0:1/126`.
- Estabilishing BGP sessions from each traffic generator logical port.
  - To get thing started, the ASN range of the traffic generater is set to 60000-61000.

### 5.2. Routes advertisement

If more routes is required for testing, the test case will need to inject routes into the NUT. This is done by configuring the traffic generator to advertise specific routes via BGP sessions established in the pretext fixture.

## 6. Verifying Route Advertisement

To verify that routes are being correctly advertised, we can run `show ip route bgp` or `show ipv6 route bgp` on the T0 switch and confirm all routes advertised by the traffic generator are visible in the routing table. This ensures that the routes injected by the traffic generator are propagated through the multi-tier network.
