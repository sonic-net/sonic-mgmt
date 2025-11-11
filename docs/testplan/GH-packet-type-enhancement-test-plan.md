# Generic Hash packet type enhancement Test Plan

## Related documents

| Document Name      | Link                                                                                              |
|--------------------|--------------------------------------------------------------------------------------------------|
| SONiC Generic Hash | [hash-design.md](https://github.com/sonic-net/SONiC/blob/master/doc/hash/hash-design.md)          |


## 1. Overview

This enhancement extends generic hash features to support 
* Native hash fields for RoCE traffic
  - `SAI_NATIVE_HASH_FIELD_RDMA_BTH_OPCODE`
  - `SAI_NATIVE_HASH_FIELD_RDMA_BTH_DEST_QP`

* Per packet type ECMP/LAG hash configuration, leveraging SAI switch attributes including:
  - `SAI_SWITCH_ATTR_ECMP_HASH_IPV4`
  - `SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4`
  - `SAI_SWITCH_ATTR_ECMP_HASH_IPV6`
  - `SAI_SWITCH_ATTR_LAG_HASH_IPV4`
  - `SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4`
  - `SAI_SWITCH_ATTR_LAG_HASH_IPV6`
  - `SAI_SWITCH_ATTR_ECMP_HASH_IPV4_RDMA`
  - `SAI_SWITCH_ATTR_ECMP_HASH_IPV6_RDMA`
  - `SAI_SWITCH_ATTR_LAG_HASH_IPV4_RDMA`
  - `SAI_SWITCH_ATTR_LAG_HASH_IPV6_RDMA`

## 2. Requirements

### 2.1 The enhanced feature supports:

1. Per packet type ECMP and LAG hash configuration (IPv4, IPv6, IPv4-in-IPv4, RDMA, etc.).
2. The packet type hash takes precedence when configured; otherwise, the global switch hash is applied.
3. Reboot/reload with state persistence for all packet type configs.

### 2.2 Supported commands:

1. `config` commands to set per packet type hash for ECMP/LAG.
2. `show` commands display per packet type and global hash configuration/capability.

### 2.3 Error handling:

#### 2.3.1 Frontend

- Invalid or unsupported packet type provided to CLI or DB.

#### 2.3.2 Backend

- Invalid removal or update of per packet type hash configs.

## 3. Scope

Verify per packet type hash config can be independently managed and affects ECMP/LAG distribution only for matching traffic.

### 3.1 Scale / Performance

No additional scale requirements compared to generic hash.

### 3.2 CLI Commands

#### 3.2.1 Config
The following command can be used to configure generic hash with packet-type support:
```
config
|--- switch-hash
     |--- global
          |--- ecmp-hash [packet-type <pkt-type> <add|del>] ARGS
          |--- lag-hash [packet-type <pkt-type> <add|del>] ARGS
          |--- ecmp-hash-algorithm ARG
          |--- lag-hash-algorithm ARG 
```


#### 3.2.2 Show
The following command shows switch hash global configuration:
```
show
|--- switch-hash
     |--- global [packet-type <pkt-type>]
     |--- capabilities
```

#### 3.2.3 Supported packet types
| **Packet Type** | **Description** |
|------------------|-----------------|
| ipv4 | IPv4 packets |
| ipv6 | IPv6 packets |
| ipnip | IPv4-in-IPv4 encapsulated packets |
| ipv4-rdma | RDMA over IPv4 packets |
| ipv6-rdma | RDMA over IPv6 packets |
| all | Show all packet type configurations (for show command only) |


**Note:-**
- _In config command:_
  - _`packet-type <pkt-type> <add|del>`: Optional parameter, if omitted updates default hash_
    - _`add`: Creates packet-type hash if one doesn't exist, else updates (overwrites) the existing hash fields_
    - _`del`: Deletes Packet type hash_
- _In show command:_
  - _`packet-type <pkt-type>` is optional; `all` packet-type is valid only for show_
  - _If pkt-type omitted: Shows default hash configuration/capabilities_
  - _If pkt-type is all: Shows all packet type hash configuration/capabilities_


### 3.3 CLI usage examples
1. config switch-hash global ecmp-hash 'SRC_MAC' 'ETHERTYPE'
1. config switch-hash global ecmp-hash packet-type ipv4 add 'SRC_IP' 'DST_IP'
1. config switch-hash global lag-hash packet-type ipv6-rdma add 'RDMA_BTH_OPCODE' 'RDMA_BTH_DEST_QP'
1. config switch-hash global ecmp-hash packet-type ipv4 del
1. show switch-hash global packet-type ipv4
1. show switch-hash global packet-type all

### 3.4 Supported topology
The test should support t0 and t1 topologies.

## 4 Test Cases for per packet type hash enhancement

### 4.1 Test case list

| No. | Test Name                                    | Purpose                                                               |
|-----|----------------------------------------------|-----------------------------------------------------------------------|
| 1   | test_hash_field_distribution_rdma            | Verify RDMA hash field impact on traffic distribution                 |
| 2   | test_pkt_type_hash_priority_and_override     | Priority/override between default and per-pkt-type hash               |
| 3   | test_pkt_type_hash_config_persistence_reload | Persistence of pkt_type_hash config after reboot/reload for ECMP/LAG  |
| 4   | test_pkt_type_lag_hash_warm_boot             | Validate warm boot with packet type hash for ECMP/LAG                 |
| 5   | test_pkt_type_ecmp_hash_fast_boot            | Validate fast boot with packet type hash for ECMP/LAG                 |

### 4.2 Test case descriptions

#### 1. test_hash_field_distribution_rdma
---
**Purpose:**  Configure RDMA fields (`RDMA_BTH_OPCODE`, `RDMA_BTH_DEST_QP`) for RDMA packet types; send test traffic and verify egress distribution changes per field.

**Steps:**  
1. Configure RDMA fields:   
   - `config switch-hash global ecmp-hash packet-type ipv6-rdma add 'DST_MAC' 'RDMA_BTH_OPCODE' 'RDMA_BTH_DEST_QP'`
   - `config switch-hash global lag-hash packet-type ipv6-rdma add 'DST_MAC' 'RDMA_BTH_OPCODE' 'RDMA_BTH_DEST_QP'`
1. Generate RDMA-over-IPv6 packets varying BTH Opcode and Dest_QP.
1. Observe load-balancing across ECMP/LAG paths.

**Expected Result:**  Egress ports vary based on RDMA fields and distribution observed across members.

#### 2. test_pkt_type_hash_priority_and_override
---
**Purpose:**  Configure default hash and per packet-type hash; generate matching/non-matching traffic and verify per packet-type config is prioritized for that traffic, default used otherwise.

**Steps:**  
1. Configure default ECMP hash:  `config switch-hash global ecmp-hash 'SRC_MAC' 'ETHERTYPE'`
1. Select two supported packet types (e.g., packet-type 1: IPv4, packet-type 2: IPv6) and configure unique hashes for each:
1. The hash fields for packet-type can be selected randomly.
1. For packet-type 1 (e.g., IPv4):
   - config switch-hash global ecmp-hash packet-type ipv4 add <IPV4_HASH_FIELD_1> <IPV4_HASH_FIELD_2>
   - Example: config switch-hash global ecmp-hash packet-type ipv4 add 'SRC_IP' 'DST_IP'
1. Generate traffic corresponding to the selected packet-types.
   - Example: Send both IPv4 and IPv6 packets
1. Observe hash result.

**Expected Result:**  Packet-type 1 traffic follows per packet-type hash and packet-type 2 traffic continues to use the default global hash.

#### 3. test_hash_config_persistence_reload
---
**Purpose:**  Configure various packet-type hashes, reload/reboot the switch and ensure configuration and data plane behavior persist.

**Steps:**  
1. Configure ECMP and LAG hashes for multiple pkt-types.
1. Send relevant traffic continuously.
1. Save config and reboot.
1. Post reboot, run: `show switch-hash global packet-type all`
1. Verify data-plane behavior remains consistent after reboot.

**Expected Result:**  All per packet-type configs are preserved after reboot.

#### 4. test_pkt_type_warm_boot
---
**Purpose:**  Ensure that both ECMP and LAG packet-type hash configurations persist across a warm boot.
**Steps:** 
1. Configure ECMP/LAG with global and packet-type-specific hashes (example `ecmp_hash`, `ecmp_hash_ipv4`).
1. Send relevant traffic continuously.
1. Trigger a warm boot, after boot, verify:
    - Packet-type hash behavior for ECMP/LAG is preserved.
    - There should be no traffic loss.

**Expected Result:**   Packet-type hash behavior for ECMP/LAG is preserved with no traffic loss.

#### 5. test_pkt_type_fast_boot
---
**Purpose:**  Ensure that both ECMP and LAG packet-type hash configurations persist across fast boot

**Steps:** 
1. Configure ECMP/LAG with global and packet-type hashes.
1. Send relevant traffic continuously
1. Trigger a fast boot, after boot, verify:
    - Packet-type hash behavior for ECMP/LAG is preserved.
    - Traffic drop should not be for more than 30 sec

**Expected Result:**   Packet-type hash behavior for ECMP/LAG is preserved with traffic loss less than 30 sec


### General Verification Points
- Packet-type hash configuration should persist across both warm and fast boot.
- State DB and config DB values must restore correctly.
- Hash functionality should match pre-boot state.
- No unexpected errors in logs.









