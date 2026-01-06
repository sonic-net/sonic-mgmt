# DHCPv4 Relay Test Plan

<!-- TOC -->
- [DHCPv4 Relay Test Plan](#dhcpv4-relay-test-plan)
  - [Document Information](#document-information)
  - [References](#references)
  - [Overview](#overview)
  - [Test Environment](#test-environment)
    - [Topology Requirements](#topology-requirements)
  - [Test Matrix](#test-matrix)
    - [Relay Agent Types](#relay-agent-types)
    - [Test Categories](#test-categories)
  - [Test Cases](#test-cases)
    - [1. Basic Functionality Tests](#1-basic-functionality-tests)
      - [1.1 Interface Binding Test (`test_interface_binding`)](#11-interface-binding-test-test_interface_binding)
      - [1.2 DHCPv4 Feature Flag Validation Test (`test_dhcpv4_feature_flag_validation`)](#12-dhcpv4-feature-flag-validation-test-test_dhcpv4_feature_flag_validation)
      - [1.3 DHCPv4 Relay Disabled Validation Test (`test_dhcpv4_relay_disabled_validation`)](#13-dhcpv4-relay-disabled-validation-test-test_dhcpv4_relay_disabled_validation)
      - [1.4 Default DHCPv4 relay Test (`test_dhcp_relay_default`)](#14-default-dhcpv4-relay-test-test_dhcp_relay_default)
      - [1.5 Source Port IP in Relay Test (`test_dhcp_relay_with_source_port_ip_in_relay_enabled`)](#15-source-port-ip-in-relay-test-test_dhcp_relay_with_source_port_ip_in_relay_enabled)
    - [2. Network Resilience Tests](#2-network-resilience-tests)
      - [2.1 Link Flap Test (`test_dhcp_relay_after_link_flap`)](#21-link-flap-test-test_dhcp_relay_after_link_flap)
      - [2.2 Uplinks Down at Start Test (`test_dhcp_relay_start_with_uplinks_down`)](#22-uplinks-down-at-start-test-test_dhcp_relay_start_with_uplinks_down)
    - [3. Advanced Features Tests](#3-advanced-features-tests)
      - [3.1 Unicast MAC Test (`test_dhcp_relay_unicast_mac`)](#31-unicast-mac-test-test_dhcp_relay_unicast_mac)
      - [3.2 Random Source Port Test (`test_dhcp_relay_random_sport`)](#32-random-source-port-test-test_dhcp_relay_random_sport)
      - [3.3 Counter Validation Test (`test_dhcp_relay_counter`)](#33-counter-validation-test-test_dhcp_relay_counter)
      - [3.4 max-hop-count Test (`test_dhcp_max_hop_count`)](#34-max-hop-count-test-test_dhcp_max_hop_count)
    - [4. Option 82 and Agent Mode Tests](#4-option-82-and-agent-mode-tests)
      - [4.1 Option 82 Sub-options Test (`test_dhcp_relay_option82_suboptions`)](#41-option-82-sub-options-test-test_dhcp_relay_option82_suboptions)
      - [4.2 Agent Mode Test (`test_dhcp_relay_agent_mode`)](#42-agent-mode-test-test_dhcp_relay_agent_mode)
    - [5. VRF Support Tests](#5-vrf-support-tests)
      - [5.1 Non-Default VRF Test (`test_dhcp_relay_with_non_default_vrf`)](#51-non-default-vrf-test-test_dhcp_relay_with_non_default_vrf)
      - [5.2 Different VRF Test (`test_dhcp_relay_with_different_non_default_vrf`)](#52-different-vrf-test-test_dhcp_relay_with_different_non_default_vrf)
  - [Test Utilities and Fixtures](#test-utilities-and-fixtures)
    - [Key Helper Functions](#key-helper-functions)
    - [Fixtures](#fixtures)
  - [Validation Criteria](#validation-criteria)
    - [DHCP Message Flow](#dhcp-message-flow)
    - [Counter Validation](#counter-validation)
    - [Log Analysis](#log-analysis)
    - [Performance Requirements](#performance-requirements)
  - [Known Limitations](#known-limitations)
    - [Version Restrictions](#version-restrictions)
    - [Feature Restrictions](#feature-restrictions)
  - [Troubleshooting Guide](#troubleshooting-guide)
    - [Common Issues](#common-issues)
    - [Debug Commands](#debug-commands)

## Document Information
- **Test Suite**: SONiC DHCPv4 relay Testing
- **Files**: `tests/dhcp_relay/test_dhcp_relay.py`, `tests/dhcp_relay/test_dhcpv4_relay.py`
- **Date**: June 25, 2025
- **Version**: 1.0

## References

| **Document Name** | **Link** |
|-------------------|----------|
| SONIC DHCPv4 Relay | [DHCPv4_relay/DHCPv4-relay-agent-High-Level-Design.md](https://github.com/sonic-net/SONiC/blob/master/doc/dhcp_server/port_based_dhcp_server_high_level_design.md)|

## Overview

This test plan covers comprehensive testing of DHCPv4 relay functionality in SONiC switches. The test suite validates both ISC DHCPv4 relay agent and SONiC DHCPv4 relay agent implementations across various network topologies and configurations.

## Test Environment

### Topology Requirements

  Supported Topologies: T0, dual-tor, M0
  Unsupported Topologies/setups: Tests for EVPN, MC-LAG, SAG and Unnumbered Interfaces are pending due to lack of existing infrastructure. They will be added in future updates.

## Test Matrix

### Relay Agent Types
- **ISC Relay Agent**: Existing DHCPv4 relay implementation that has been EOL'ed by ISC
- **SONiC Relay Agent**: Native SONiC DHCPv4 relay implementation designed to replace ISC relay agent.

### Test Categories

| Category | Test Count | Description |
|----------|------------|-------------|
| Basic Functionality | 5 | Core DHCPv4 relay operations and feature flags |
| Network Resilience | 2 | Link failure and recovery scenarios |
| Advanced Features | 4 | MAC handling, counters, and special modes |
| Option 82 Testing | 2 | DHCP Option 82 sub-options and modes |
| VRF Support | 2 | Virtual Routing and Forwarding scenarios |

## Test Cases

### 1. Basic Functionality Tests

#### 1.1 Interface Binding Test (`test_interface_binding`)
- **Objective**: Verify DHCPv4 relay agent binds to correct interfaces
- **Relay Agents**: Both ISC and SONiC
- **Test Steps**:
  1. Check if DHCPv4 relay service is listening on port 67
  2. Verify binding to downlink VLAN interface
  3. Verify binding to all uplink interfaces
  4. Reload configuration if binding fails
- **Expected Results**: All interfaces show `:67` binding in socket status

#### 1.2 DHCPv4 Feature Flag Validation Test (`test_dhcpv4_feature_flag_validation`)
- **Objective**: Verify DHCPv4 feature flag enable/disable behavior
- **Relay Agents**: SONiC only
- **Test Steps**:
  1. Apply valid relay config and enable feature flag
  2. Verify sonic-dhcpv4 sockets are active
  3. Cleanup config and disable feature flag
- **Expected Results**: Feature flag controls sonic-dhcpv4 process startup correctly

#### 1.3 DHCPv4 Relay Disabled Validation Test (`test_dhcpv4_relay_disabled_validation`)
- **Objective**: Verify that DHCP relay doesn't work when feature flag is disabled
- **Relay Agents**: SONiC only
- **Test Steps**:
  1. Configure DHCP relay but keep feature flag disabled
  2. Execute PTF test to verify no DHCP response
  3. Verify sonic-dhcpv4 process/socket is not running
- **Expected Results**: DHCP Discover packet receives no response when feature disabled

#### 1.4 Default DHCPv4 relay Test (`test_dhcp_relay_default`)
- **Objective**: Validate basic DHCPv4 relay functionality
- **Relay Agents**: Both ISC and SONiC
- **Test Steps**:
  1. Initialize DHCP monitor counters
  2. Execute PTF DHCP test with standard parameters
  3. Validate DHCP message flow (Discover→Offer→Request→ACK)
  4. Verify counter values match expected patterns
  5. Check dual-tor standby behavior if applicable
- **Expected Results**: Complete DHCP transaction with correct counter values and client is assigned a valid IP address

#### 1.5 Source Port IP in Relay Test (`test_dhcp_relay_with_source_port_ip_in_relay_enabled`)
- **Objective**: Test DHCPv4 relay with source IP set to client interface IP for request packets. This functionality is exercised for deployment_id of 8.
- **Relay Agents**: Both ISC and SONiC
- **Test Steps**:
  1. Enable source port IP feature (deployment_id = "8"). For SONiC relay agent, redis-cli is used to set the deployment-id before running the test. For ISC, a json patch is applied to config-db and dhcp service is restarted after that.
  2. Execute PTF test with source port IP enabled
  3. Validate relay behavior
- **Expected Results**: Source IP of the any request packets from client -> Server has the client relay interface IP

### 2. Network Resilience Tests

#### 2.1 Link Flap Test (`test_dhcp_relay_after_link_flap`)
- **Objective**: Verify DHCPv4 relay recovery after uplink failures
- **Relay Agents**: Both ISC and SONiC
- **Test Steps**:
  1. Bring down all uplink interfaces
  2. Wait for link status confirmation
  3. Bring up all uplink interfaces
  4. Wait for route recovery
  5. Execute DHCPv4 relay test
- **Expected Results**: DHCPv4 relay functions normally after link recovery

#### 2.2 Uplinks Down at Start Test (`test_dhcp_relay_start_with_uplinks_down`)
- **Objective**: Test relay agent startup with uplinks initially down
- **Relay Agents**: Both ISC and SONiC
- **Test Steps**:
  1. Bring down uplink interfaces
  2. Restart DHCPv4 relay service
  3. Wait for service startup
  4. Bring up uplink interfaces
  5. Execute DHCPv4 relay test
- **Expected Results**: DHCPv4 relay adapts to link state changes

### 3. Advanced Features Tests

#### 3.1 Unicast MAC Test (`test_dhcp_relay_unicast_mac`)
- **Objective**: Validate DHCPv4 relay with unicast destination MAC
- **Relay Agents**: Both ISC and SONiC
- **Limitations**: Single VLAN configurations only
- **Test Steps**:
  1. Use DUT router MAC instead of broadcast MAC
  2. Execute PTF test with unicast MAC
- **Expected Results**: DHCPv4 relay works with unicast addressing

#### 3.2 Random Source Port Test (`test_dhcp_relay_random_sport`)
- **Objective**: Test DHCPv4 relay with non-standard client ports
- **Relay Agents**: Both ISC and SONiC
- **Test Steps**:
  1. Generate random source port (1000-65535)
  2. Execute PTF test with random port
- **Expected Results**: DHCPv4 relay handles SNAT'd clients

#### 3.3 Counter Validation Test (`test_dhcp_relay_counter`)
- **Objective**: Verify DHCP message counters in STATE_DB
- **Relay Agents**: Both ISC and SONiC
- **Version Requirements**: Excludes 201811, 201911, 202012
- **Test Steps**:
  1. Initialize counters to zero
  2. Execute PTF DHCP test
  3. Validate counter values for each message type
  4. Check RX/TX counters on all interfaces
- **Expected Results**: Accurate counter reporting for all DHCP messages

#### 3.4 max-hop-count Test (`test_dhcp_max_hop_count`)
- **Objective**: Validate max-hop-count functionality in DHCPv4 relay
- **Relay Agents**: SONiC only
- **Test Steps**:
  1. Configure max-hop-count in DHCPv4 relay settings
  2. Execute PTF test with varying hop counts
  3. Verify that packets are dropped or forwarded based on hop count
- **Expected Results**: Incoming packets with hop count exceeding configured limit are dropped, while valid packets are processed correctly.

### 4. Option 82 and Agent Mode Tests

#### 4.1 Option 82 Sub-options Test (`test_dhcp_relay_option82_suboptions`)
- **Objective**: Test DHCP Option 82 sub-option handling for link selection and server ID override options. Also validate the source interface CLI option to ensure correct giaddr insertion.
- **Relay Agents**: SONiC only
- **Test Modes**:
  - `source_intf`: Source interface and link selection
  - `server_id_override`: Server ID override functionality
- **Test Steps**:
  1. Configure relay with test-specific options
  2. Execute PTF test with Option 82 validation
  3. Verify correct sub-option insertion
- **Expected Results**: Proper Option 82 sub-option handling

#### 4.2 Agent Mode Test (`test_dhcp_relay_agent_mode`)
- **Objective**: Validate different relay agent modes for Option 82
- **Relay Agents**: SONiC only
- **Agent Modes**:
  - `discard`: Drop packets with Option 82
  - `replace`: Replace existing Option 82
  - `append`: Append to existing Option 82
- **Test Steps**:
  1. Configure relay with specific agent mode
  2. Execute PTF test with Option 82 packets
  3. Validate mode-specific behavior
- **Expected Results**: Correct Option 82 handling per mode

### 5. VRF Support Tests

#### 5.1 Non-Default VRF Test (`test_dhcp_relay_with_non_default_vrf`)
- **Objective**: Test DHCPv4 relay in non-default VRF contexts
- **Relay Agents**: SONiC only
- **Test Cases**:
  - `vrf_selection`: Basic VRF selection
  - `source_intf`: VRF with source interface
  - `server_id_override`: VRF with server ID override
- **Test Steps**:
  1. Remove existing IP configurations on uplink interfaces
  2. Create and configure a non-default VRF ("Vrf01")
  3. Bind both uplink and downlink interfaces to the new VRF
  4. Restore existing IP configurations from the default VRF to Vrf01
  5. Add Vrf01-specific routes for forwarding client requests to the DHCP server
  6. Execute PTF test with VRF parameters
  7. Clean up Vrf01 configuration and restore default VRF settings
- **Expected Results**: DHCPv4 relay functions correctly in VRF context

#### 5.2 Different VRF Test (`test_dhcp_relay_with_different_non_default_vrf`)
- **Objective**: Test relay with client and server in different non-default VRFs
- **Relay Agents**: SONiC only
- **VRF Configuration**:
  - Client VRF: "Vrf01"
  - Server VRF: "Vrf03"
- **Test Steps**:
  1. Create separate VRFs for client and server sides
  2. Bind VLAN interface to client VRF
  3. Bind PortChannels to server VRF
  4. Configure cross-VRF routing
  5. Execute PTF test with multi-VRF setup
  6. Clean up VRF configurations and restore default VRF settings
- **Expected Results**: DHCPv4 relay correcly forwards all relay packets across different VRFs successfully

## Test Utilities and Fixtures

### Key Helper Functions
- `check_interface_status()`: Verify relay agent socket binding
- `query_dhcpmon_counter_result()`: Retrieve DHCP counters from dhcpmon
- `validate_dhcpmon_counters()`: Validate counter accuracy from dhcpmon
- `restart_dhcpmon_in_debug()`: Enable dhcpmon debug mode
- `init_dhcpmon_counters()`: Reset counter values from dhcpmon

### Fixtures
- `ignore_expected_loganalyzer_exceptions`: Filter expected errors
- `enable_source_port_ip_in_relay`: Configure source IP feature
- `config_dhcp_relay_agent`: Setup relay agent configuration
- `verify_acl_drop_on_standby_tor`: Validate dual-tor ACL behavior

## Validation Criteria

### DHCP Message Flow
- Discover: Client → Relay → Server
- Offer: Server → Relay → Client
- Request: Client → Relay → Server
- ACK: Server → Relay → Client

### Counter Validation
- RX counters: Messages received on interfaces
- TX counters: Messages transmitted from interfaces
- Per-interface accuracy
- Per-message-type accuracy

### Log Analysis
- Syslog pattern matching for dhcpmon
- Error pattern filtering
- Counter reporting validation

### Performance Requirements
- Service restart within 120 seconds


## Known Limitations

### Version Restrictions
- DHCP monitor features unavailable in 201811, 201911, 202111
- Counter validation excluded from 201811, 201911, 202012
- Dual-tor support requires 202106+
- sonic-dhcp-relay requires 202511+

### Feature Restrictions
- Unicast MAC testing limited to single VLAN setups
- non-default VRF testing SONiC-only
- Option 82 features like server override are SONiC-only


## Troubleshooting Guide

### Common Issues
1. **Interface Binding Failures**: Check service status and reload config
2. **Counter Mismatches**: Verify counter initialization and reset
3. **Link Recovery Issues**: Validate routing table and interface status
4. **VRF Configuration Problems**: Ensure proper VRF binding and routing

### Debug Commands
```bash
# Check DHCPv4 relay status
# ISC relay agent:
docker exec -t dhcp_relay ss -nlp | grep dhcrelay

# SONiC relay agent:
docker exec -t dhcp_relay ss -nlp | grep dhcp4relay

# View DHCP counters
sonic-db-cli COUNTERS_DB hgetall "DHCPV4_COUNTER_TABLE:Vlan1000"

# Monitor DHCPv4 relay logs
tail -f /var/log/syslog | grep dhcpv4_relay
```
