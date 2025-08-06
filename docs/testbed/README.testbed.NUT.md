# Testbed Setup with Network Under Test (NUT)

1. [1. Overview](#1-overview)
2. [2. Testbed CLI: `deploy-cfg`](#2-testbed-cli-deploy-cfg)
3. [3. Testbed definition](#3-testbed-definition)
   1. [3.1. Device definition](#31-device-definition)
   2. [3.2. Link definition](#32-link-definition)
   3. [3.3. Testbed YAML definition](#33-testbed-yaml-definition)
   4. [3.4. Topology definition](#34-topology-definition)
4. [4. NUT config deployment: `deploy-cfg`](#4-nut-config-deployment-deploy-cfg)
   1. [4.1. Initial config generation](#41-initial-config-generation)
   2. [4.2. Generate device metadata](#42-generate-device-metadata)
   3. [4.3. Generate port config](#43-generate-port-config)
   4. [4.4. Establish BGP Sessions](#44-establish-bgp-sessions)
      1. [4.4.1. Enable BGP Feature](#441-enable-bgp-feature)
      2. [4.4.2. Interface IP assignment](#442-interface-ip-assignment)
      3. [4.4.3. Generate BGP Neighbor configuration](#443-generate-bgp-neighbor-configuration)
   5. [4.5. Apply config](#45-apply-config)
5. [5. Traffic generator setup](#5-traffic-generator-setup)
   1. [5.1. Port configuration](#51-port-configuration)
   2. [5.2. Routes advertisement](#52-routes-advertisement)
   3. [5.3. Verifying Route Advertisement](#53-verifying-route-advertisement)
6. [6. Command references](#6-command-references)
   1. [6.1. Generate config: `gen-cfg`](#61-generate-config-gen-cfg)
   2. [6.2. Deploy config: `deploy-cfg`](#62-deploy-config-deploy-cfg)
   3. [6.3. Run tests](#63-run-tests)

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

### 3.1. Device definition

Just like how regular SONiC testbed is defined, The devices and links between all devices in the NUT need to be defined in the `sonic_*_devices.csv` and `sonic_*_links.csv` file.

The following example represents a definition of a T0 switch:

```csv
Hostname,ManagementIp,HwSku,Type,Protocol
tg-1,10.0.0.200/24,IXIA-tester,DevIxiaChassis,
switch-t0-1,10.0.0.123/24,HWSKU-TO-TEST,DevSonic,
```

If you have multiple traffic generator, you might need to define one of them as primary, which looks like below:

```csv
Hostname,ManagementIp,HwSku,Type,Protocol
tg-1,10.0.0.200/24,IXIA-tester,DevIxiaChassis_Primary,
tg-2,10.0.0.201/24,IXIA-tester,DevIxiaChassis,
```

### 3.2. Link definition

The following example represent a 100G link from the traffic generator port 1 to the first port of a T0 switch:

```csv
StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode,AutoNeg
switch-t0-1,Ethernet0,tg-1,Port1.1,100000,,Access,
switch-t1-1,Ethernet0,switch-t0-1,Ethernet256,100000,,Access,
```

### 3.3. Testbed YAML definition

The current testbed yaml definition is not designed to support NUT, so we will create a new testbed YAML definition `testbed.nut.yml` that is compatible with the NUT. The following example shows how to define a testbed for NUT with multiple tiers:

```yaml
- name: testbed-nut-1
  comment: "Testbed for NUT with multi-tier topology"
  inv_name: lab
  topo: nut-2tiers
  duts:
    - switch-t0-1
    - switch-t0-2
    - switch-t0-3
    - switch-t1-1
    - switch-t1-2
  tgs:
    - tg-1
  tg_api_server: 10.2.0.1:443
  auto_recover: 'True'
```

### 3.4. Topology definition

The testbed has a reference to the topology using `topo` field. The topology definitions for NUT testbeds are defined under the `ansible/vars/nut_topos` directory. The file name is the topology name and *MUST* start with "nut-". In the testbed above, the topo name is `nut-2tiers`, which refers to `ansible/vars/nut_topos/nut-2tiers.yml`.

The following example shows how a 2-tier topology looks like:

- The `dut_templates` section defines the common parameters for T0 and T1 switches, including the IP pools for allocating loopback IPs, BGP ASN ranges, and P2P IPs.
- The `tg_template` section defines the common parameters for the traffic generator, such as the ASN range and P2P IPs.

```yaml
dut_templates:
  - name: ".*-t0-.*"
    type: "ToRRouter"
    loopback_v4: "10.1.0.0/24"
    loopback_v6: "2064:100:0:0::/64"
    asn_base: 64001
    asn_step: 1
    p2p_v4: "10.0.0.0/16"
    p2p_v6: "fc0a::/64"
  - name: ".*-t1-.*"
    type: "LeafRouter"
    loopback_v4: "10.1.1.0/24"
    loopback_v6: "2064:100:0:1::/64"
    asn_base: 65001
    asn_step: 0
    p2p_v4: "10.0.0.0/16"
    p2p_v6: "fc0a::/64"
tg_template:
  type: "ToRRouter"
  asn_base: 60001
  p2p_v4: "10.0.0.0/16"
  p2p_v6: "fc0a::/64"
```

## 4. NUT config deployment: `deploy-cfg`

### 4.1. Initial config generation

First of all, an initial configuration needs to be generated for applying our testbed setup, such as port, IP and BGP configs. At this step, the `deploy-cfg` command will:

1. First, use jq to backup some tables from the existing `config_db.json`. This allows us to preserve some settings, that might comes from manual fixes, such as DEVICE_METADATA, FEATURE, NTP and etc.
2. Second, use `sonic-cfggen` to load the backup `config_db.json` and generate a clean initial configuration based on the HWSKU and save it to disk, as below:

  ```bash
  sonic-cfggen -H -k <hwsku-name> --json /tmp/config_db_keep.json --print-data > /tmp/config_db_clean.json
  ```

After this, all other changes will be made to the config DB via json patches.

### 4.2. Generate device metadata

There are a few things that needs to be updated in the device metadata, such as BGP ASN, router ID, and other device-specific information. The `deploy-cfg` command will generate the patch for each device.

```json
[
  { "op": "replace", "path": "/DEVICE_METADATA/localhost/hostname", "value": "switch-t0-1" },
  { "op": "replace", "path": "/DEVICE_METADATA/localhost/type", "value": "ToRRouter" },
  { "op": "replace", "path": "/DEVICE_METADATA/localhost/bgp_asn", "value": "64001" },
  { "op": "replace", "path": "/DEVICE_METADATA/localhost/bgp_router_id", "value": "10.100.0.81" },
  ...
]
```

Here is an example of the device metadata for a T0 switch after the `deploy-cfg` command is executed:

```json
"DEVICE_METADATA": {
    "localhost": {
        "hwsku": "ABCDEFG",
        "bgp_asn": "64001",
        "bgp_router_id": "10.1.0.1",
        "buffer_model": "traditional",
        "create_only_config_db_buffers": "true",
        "default_bgp_status": "down",
        "default_pfcwd_status": "enable",
        "deployment_id": "1",
        "hostname": "switch-t0-0",
        "mac": "50:00:e6:e5:56:1c",
        "platform": "some-platform",
        "timezone": "UTC",
        "type": "BackEndToRRouter"
    }
}
```

Certain information is not defined specifically in the `sonic_*_devices.csv` file, such as the BGP Autonomous System Number (ASN), router ID and role. These info will be automatically generated by the `deploy-cfg` tool based on the testbed-wise global information defined in the testbed YAML file.

The detailed step follows the following algorithm:

1. Read all loopback IP pools defined in the testbed YAML file and create allocators based on the usage. Multiple devices can share the same pool.
2. Walk through the devices defined in the testbed from first to last. For each device,
   1. Curve out a loopback v4 IP from the unified IP pool (1 IP), based on the device index.
   2. Curve out a loopback v6 IP from the unified IP pool (1 IP), based on the device index.
   3. If loopback V4 IP pool is not assigned, curve out a router ID v4 IP from the unified IP pool (1 IP), based on the device index.
   4. Curve out BGP ASN from the testbed-wide defined ASN range, based on the device index.

### 4.3. Generate port config

`deploy-cfg` will also load the connection graph defined in `sonic_*_devices.csv` file, and use it to generate all the port configurations, which setup port speed, FEC, auto negotiation, and other port attributes.

```json
[
  { "op": "replace", "path": "/PORT/Ethernet256/admin_status", "value": "up" },
  { "op": "replace", "path": "/PORT/Ethernet256/fec", "value": "rs" },
  { "op": "replace", "path": "/PORT/Ethernet256/speed", "value": "100000" },
  { "op": "replace", "path": "/PORT/Ethernet256/description", "value": "Link to switch-t1-0 Ethernet0" },
  ...
]
```

An example of the port configuration generated for the T0 switch is as follows:

```json
"PORT": {
    "Ethernet256": {
        "admin_status": "up",
        "alias": "etp33a",
        "description": "Link to switch-t1-0 Ethernet0",
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

### 4.4. Establish BGP Sessions

To establish BGP sessions between the switches and the traffic generators, the following steps are required:

#### 4.4.1. Enable BGP Feature

First, BGP must be enabled to allow them to participate in BGP-based route exchange.

```json
[
  { "op": "replace", "path": "/FEATURE/bgp/auto_restart", "value": "enabled" },
  { "op": "replace", "path": "/FEATURE/bgp/state", "value": "enabled" }
]
```

This will enable the BGP feature on the device. In the end, the configuration will look like this:

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

#### 4.4.2. Interface IP assignment

`deploy-cfg` will automatically assign IP addresses to the interfaces based on the testbed-wide defined IP pools:

```yaml
dut_template:
  - { name: ".*-t0-.*", p2p_v4: "10.0.0.0/16", p2p_v6: "2001:db9::/64", ... }
  - { name: ".*-t1-.*", p2p_v4: "10.0.0.0/16", p2p_v6: "2001:db9::/64", ... }
  - { name: ".*-t2-.*", p2p_v4: "10.0.0.0/16", p2p_v6: "2001:db9::/64", ... }
```

The detailed step follows the following algorithm:

1. Read P2P IP pools defined in the testbed YAML file and create IP allocators based on usage.
2. Set devices in the TG (Traffic generator) list in the testbed as the start devices.
3. Walk through the links defined in the `sonic_*_links.csv` file in BFS order.
4. For each link (port pair), curve out a 2-bit subnet from the unified IP pool (4 IPs), where the second IP will be used on the downlink port, while the third IP will be used on the uplink port.
5. Generate the interface configuration for each port for each devices as config shows below.

```json
[
  { "op": "add", "path": "/INTERFACE", "value": {} },
  { "op": "add", "path": "/INTERFACE/Ethernet256", "value": {} },
  { "op": "add", "path": "/INTERFACE/Ethernet256|2001:db9::1:0:1/126", "value": {} },
  ...
]
```

And here is the example of the interface configuration generated for the T0 switch:

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

#### 4.4.3. Generate BGP Neighbor configuration

To enable BGP sessions, the BGP neighbor configuration must be generated for each switch. This configuration includes the ASN, hold time, keepalive time, local address, and other necessary parameters.

<table>
<tr>
<td>T0-0 Configuration:</td>
<td>T1-0 Configuration:</td>
</tr>
<td>

```json
[
  {
    "op": "add",
    "path": "/BGP_NEIGHBOR/2001:db9::1:0:2",
    "value": {
        "admin_status": "up",
        "asn": 65001,
        "holdtime": "10",
        "keeplive": "3",
        "local_addr": "2001:db9::1:0:1",
        "name": "switch-t1-0",
        "nhopself": "0",
        "rrclient": "0"
    },
  },
  {
    "op": "add",
    "path": "/DEVICE_NEIGHBOR/Ethernet256",
    "value": {
        "name": "switch-t1-0",
        "port": "Ethernet256"
    }
  },
  {
    "op": "add",
    "path": "/DEVICE_NEIGHBOR_METADATA/switch-t1-0",
    "value": {
        "cluster": "StressTest",
        "deployment_id": "1",
        "lo_addr": "100.1.1.1",
        "lo_addr_v6": "2064:100:0:1::1",
        "mgmt_addr": "10.250.1.1",
        "mgmt_addr_v6": "fec0::1:1",
        "hwsku": "ABCDEFG",
        "type": "LeafRouter"
    }
  }
]
```

</td>
<td>

```json
[
  {
    "op": "add",
    "path": "/BGP_NEIGHBOR/2001:db9::1:0:1",
    "value": {
        "admin_status": "up",
        "asn": 64001,
        "holdtime": "10",
        "keeplive": "3",
        "local_addr": "2001:db9::1:0:2",
        "name": "switch-t0-0",
        "nhopself": "0",
        "rrclient": "0"
    },
  },
  {
    "op": "add",
    "path": "/DEVICE_NEIGHBOR/Ethernet0",
    "value": {
        "name": "T0-A-0",
        "port": "Ethernet0"
    }
  },
  {
    "op": "add",
    "path": "/DEVICE_NEIGHBOR_METADATA/switch-t0-0",
    "value": {
        "cluster": "StressTest",
        "deployment_id": "1",
        "lo_addr": "100.1.0.1",
        "lo_addr_v6": "2064:100:0:0::1",
        "mgmt_addr": "10.250.0.1",
        "mgmt_addr_v6": "fec0::0:1",
        "hwsku": "ABCDEFG",
        "type": "ToRRouter"
    }
  }
]
```

</td>
</tr>
</table>

### 4.5. Apply config

After all the configuration patches are generated, the `deploy-cfg` command will

1. Apply all patches to the clean initial configuration generated in the first step, using `jsonpatch` command.
2. Backup and replace the original `config_db.json` with the newly generated one.
3. Run `config reload` to apply the new configuration.
4. Run `config qos reload` to apply the new QoS configuration, if any.
5. Finish some common post-configuration tasks, such as deploy certificates, enable core analyzer and etc.
6. Run a final config save and config reload to ensure all changes are applied.

Once the configurations are applied, the BGP session will be established, and the switches will begin exchanging routing information.

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

### 5.3. Verifying Route Advertisement

To verify that routes are being correctly advertised, we can run `show ip route bgp` or `show ipv6 route bgp` on the T0 switch and confirm all routes advertised by the traffic generator are visible in the routing table. This ensures that the routes injected by the traffic generator are propagated through the multi-tier network.

## 6. Command references

### 6.1. Generate config: `gen-cfg`

`gen-cfg` will generate the configuration for the testbed without applying it to the devices. This is useful for testing and debugging purposes, allowing you to see what configuration will be applied without actually changing the device configuration.

```bash
# ./testbed-cli.sh -t <testbed-yaml-file-path> gen-cfg <testbed-name> <inventory-name> <password-file>
./testbed-cli.sh -t testbed.nut.yaml gen-cfg nut-testbed-1 ixia ../../password.txt
```

The configuration will be generated into a few places:

- `/tmp/config_patch.json` (on each DUT): This is the patch that will be applied to the newly generated config DB.
- `/tmp/config_db_new.json` (on each DUT): This is the new config DB that will be applied to the device.

### 6.2. Deploy config: `deploy-cfg`

`deploy-cfg` will do everything that `gen-cfg` does, but also apply the configuration to the devices in the testbed. This will generate the configuration and apply it to the devices in the testbed.

```bash
# ./testbed-cli.sh -t <testbed-yaml-file-path> deploy-cfg <testbed-name> <inventory-name> <password-file>
./testbed-cli.sh -t testbed.nut.yaml deploy-cfg nut-testbed-1 ixia ../../password.txt
```

### 6.3. Run tests

We can directly use the `pytest` module to run the tests against the NUT testbed:

```bash
# Under tests directory, run:
./run_tests.sh -f ../ansible/testbed.nut.yaml -i <inventory-file> -n nut-testbed-1 -d all -m individual -a False -u -l debug -e "--skip_sanity --disable_loganalyzer" -c <test case>

# Or directly use pytest
python3 -m pytest --inventory <inventory-file> --host-pattern all --testbed nut-testbed-1 --testbed_file ../ansible/testbed.nut.yaml --show-capture=stdout --log-cli-level info <test_file>
```
