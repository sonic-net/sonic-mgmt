# RADIUS Authentication Test Plan

## Table of Contents
- [RADIUS Authentication Test Plan](#radius-authentication-test-plan)
  - [Table of Contents](#table-of-contents)
  - [1 Overview](#1-overview)
  - [2 Scope](#2-scope)
  - [3 Test Setup](#3-test-setup)
    - [3.1 Test Environment](#31-test-environment)
    - [3.2 RADIUS Server Configuration](#32-radius-server-configuration)
  - [4 Test Cases](#4-test-cases)
    - [4.1 User Authentication Tests](#41-user-authentication-tests)
    - [4.2 Command Authorization](#42-command-authorization)
    - [4.3 Authentication Fallback](#43-authentication-fallback)
    - [4.4 Error Handling](#44-error-handling)
    - [4.5 Source IP Configuration](#45-source-ip-configuration)
    - [4.6 Management VRF](#46-management-vrf)
    - [4.7 IPv6 RADIUS Server Support](#47-ipv6-radius-server-support)
  - [5 Implementation Details](#5-implementation-details)
    - [5.1 Test Framework](#51-test-framework)
    - [5.2 Key Utilities](#52-key-utilities)
    - [5.3 Test Configuration](#53-test-configuration)
  - [6 Expected Results](#6-expected-results)

## 1 Overview

This document outlines the test plan for validating RADIUS (Remote Authentication Dial-In User Service) authentication functionality in SONiC. The tests verify the proper configuration, operation, and integration of RADIUS authentication services with SONiC devices.

## 2 Scope

The test plan covers the following aspects of RADIUS authentication:
- RADIUS server configuration and management
- User authentication and authorization
- Error handling and fallback mechanisms
- Integration with SONiC authentication system

Key components tested:
- FreeRADIUS server setup and configuration
- RADIUS client configuration on SONiC
- User credentials management
- Network connectivity between RADIUS client and server

## 3 Test Setup

### 3.1 Test Environment

The test environment consists of:
- SONiC Device Under Test (DUT)
- PTF (Packet Test Framework) host running FreeRADIUS server
- Test credentials defined in `radius_creds.yaml`
- Network connectivity between DUT and RADIUS server

Required packages and services:
- FreeRADIUS server package
- Configuration templates:
  * `clients.conf.j2` - RADIUS client configuration
  * `users.j2` - User authentication database

### 3.2 RADIUS Server Configuration

The RADIUS server is configured with:
- Server IP address and authentication port (default: 1812)
- Shared secret for client authentication
- User database with test credentials
- Client configuration for DUT access

Configuration files:
```
/etc/freeradius/3.0/
├── clients.conf          # Client configuration
└── mods-config/
    └── files/
        └── authorize     # User database
```

## 4 Test Cases

### 4.1 User Authentication Tests

**Test Case 1: Read-Write User Authentication (`test_radius_rw_user`)**
- Verify authentication of read-write user
- Test user group membership using `cat /etc/group`
- Verify RADIUS statistics:
  * Access-Accept counter increments
  * Access-Reject counter remains unchanged

**Test Case 2: Read-Only User Authentication (`test_radius_ro_user`)**
- Verify authentication of read-only user
- Test user group membership using `cat /etc/passwd`
- Verify RADIUS statistics:
  * Access-Accept counter increments
  * Access-Reject counter remains unchanged

### 4.2 Command Authorization

**Test Case 3: Command Authorization (`test_radius_command_auth`)**
- Test read-only user access to allowed commands:
  * show version
  * show interface status
  * show lldp table
  * show ip bgp summary
  * show ip route
  * sudo cat /var/log/syslog
- Test read-only user access to restricted commands:
  * sudo config -h
  * sudo cat /var/log/auth.log
- Verify proper authorization enforcement

### 4.3 Authentication Fallback

**Test Case 4: Local Authentication Fallback (`test_radius_fallback`)**
- Setup local user with password
- Test authentication with local credentials
- Verify RADIUS statistics:
  * Access-Reject counter increments
- Confirm fallback to local authentication works

### 4.4 Error Handling

**Test Case 5: Failed Authentication (`test_radius_failed_auth`)**
- Test authentication with invalid credentials
- Verify authentication failure
- Verify RADIUS statistics:
  * Access-Reject counter increments

### 4.5 Source IP Configuration

**Test Case 6: Source IP Feature (`test_radius_source_ip`)**
- Configure RADIUS source interface
- Capture RADIUS packets using tcpdump
- Verify RADIUS packets use correct source IP
- Skip test if no routed interfaces are available

### 4.6 Management VRF

**Test Case 7: RADIUS with Management VRF (`test_radius_mgmt_vrf`)**
- Enable management VRF on DUT
- Verify RADIUS server reachability through mgmt VRF
- Test read-write user authentication:
  * Verify successful authentication
  * Check user group membership
  * Verify RADIUS statistics:
    - Access-Accept counter increments
    - Access-Reject counter remains unchanged
- Test read-only user authentication:
  * Verify successful authentication
  * Check user group membership
  * Verify RADIUS statistics:
    - Access-Accept counter increments
    - Access-Reject counter remains unchanged
- Clean up:
  * Remove management VRF
  * Verify SSH accessibility after VRF removal

### 4.7 IPv6 RADIUS Server Support

**Test Case 8: IPv6-only RADIUS Authentication (`test_radius_ipv6_only`)**
- Configure RADIUS server with IPv6 address only
- Verify RADIUS server configuration:
  * Check IPv6 address is properly configured
  * Verify connectivity to RADIUS server over IPv6
- Test read-write user authentication:
  * Verify successful authentication
  * Check user group membership
  * Verify RADIUS statistics:
    - Access-Accept counter increments
    - Access-Reject counter remains unchanged
- Test read-only user authentication:
  * Verify successful authentication
  * Check user group membership
  * Verify RADIUS statistics:
    - Access-Accept counter increments
    - Access-Reject counter remains unchanged
- Test command authorization for both user types
- Test authentication failure with invalid credentials
- Verify RADIUS packets use correct IPv6 source and destination addresses
- Clean up:
  * Remove IPv6 RADIUS server configuration
  * Restore IPv4 RADIUS server configuration

**Test Case 9: Dual-Stack RADIUS Server Failover (`test_radius_ipv6_failover`)**
- Configure RADIUS server with both IPv4 and IPv6 addresses
- Set priority to prefer IPv6 server
- Verify primary (IPv6) server authentication works
- Disable IPv6 connectivity to RADIUS server
- Verify failover to IPv4 RADIUS server:
  * Confirm authentication still succeeds
  * Verify RADIUS statistics show IPv4 server is being used
- Re-enable IPv6 connectivity
- Verify system fails back to IPv6 RADIUS server
- Clean up:
  * Restore original RADIUS server configuration

## 5 Implementation Details

### 5.1 Test Framework
- Python pytest framework
- Test fixtures for setup and teardown:
  * `radius_creds`: Loads test credentials
  * `setup_radius_server`: Configures FreeRADIUS
  * `setup_radius_client`: Configures DUT

### 5.2 Key Utilities
- `ssh_remote_run`: Execute commands via SSH
- `check_radius_stats`: Monitor RADIUS counters
- `verify_radius_capture`: Analyze packet captures
- `check_group_output`: Verify user group membership

### 5.3 Test Configuration
- Credentials stored in `radius_creds.yaml`
- Server configuration via Jinja2 templates
- DUT configuration using SONiC CLI

## 6 Expected Results

All test cases should:
- Complete successfully without errors
- Verify proper authentication behavior
- Handle error conditions gracefully
- Clean up configurations after completion

Test failures should provide:
- Clear error messages
- Relevant log information
- RADIUS statistics for debugging
