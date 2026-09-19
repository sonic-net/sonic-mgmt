# Test Plan: Extended VXLAN Interface Name Length
Feature: Removal of 15-character limit on Interface Names
Date: June 17, 2025

## 1. Introduction
This document outlines the test plan for verifying a software change that removes the 15-character (IFNAMSIZ - 1) length limitation for VXLAN tunnel interface names. The purpose of this test plan is to ensure that the system can correctly create, manage, and delete VXLAN tunnels with names exceeding the previous 15-character restriction, aligning with new system capabilities.

The original limitation was primarily due to the YANG model and the IFNAMSIZ constant, which restricted interface names to 15 characters. The change allows for longer names, enhancing flexibility in naming conventions for VXLAN tunnels. See PR: https://github.com/sonic-net/sonic-buildimage/pull/20108

This plan focuses specifically on the VXLAN Tunnel interface type to confirm that the system correctly handles extended-length names.

## 2. Test Objectives
Verify that a VXLAN tunnel can be successfully created with a name longer than 15 characters (e.g., 16, 32, and 63 characters).

Ensure that the change does not negatively impact the creation, operation, or deletion of any VXLAN tunnels.

Confirm that the acceptance of longer names works by using loading configuration from a config_db.json file.

## 3. Test Scope
### 3.1 In Scope
Testing VXLAN interface creation with names of various lengths, specifically focusing on those greater than 15 characters.

Testing via config load of a config_db.json file.

Verifying interface state using show commands.

### 3.2 Out of Scope
Determining the new maximum possible length; this plan will test up to a reasonably high number (e.g., 63) to prove the old limit is gone.

Performance or scale testing with a large number of long-named interfaces.

Testing other interface types (VLAN, PortChannel, etc.).

## 4. Test Environment and Setup
SONiC Version: A build containing the new PR that removes the name length validation.

Hardware/Platform: A SONiC-supported device or a virtual test environment (e.g., sonic-vs).

Pre-requisites: The device is running a base SONiC configuration and is accessible via SSH/console.

## 5. Test Cases

### Test Case 1:

Description:
Create VXLAN with Extended Name via config load

Test Steps:
1. Create a file add_long_vxlan.json with the content:
json{"VXLAN_TUNNEL": {"ThisNameIsAlsoVeryLongAndValid": {"src_ip": "1.1.1.1"}}}
2. Copy the file to the device.
3. Run config load ./add_long_vxlan.json -y

Expected Results:
1. The command completes successfully.
2. The interface ThisNameIsAlsoVeryLongAndValid is created.
3. show vxlan tunnel lists the new tunnel.

### Test Case 2:

Description:
Delete a Long-Named VXLAN Tunnel

1. Using the tunnel from Test Case 1(ThisNameIsAlsoVeryLongAndValid).
2. Run the command on the device:
```
admin@router:~$ sudo redis-cli -n 4 del "VXLAN_TUNNEL|ThisNameIsAlsoVeryLongAndValid"
```
3. Verify the tunnel is removed:
```
admin@router:~$ show vxlan tunnel
```

Expected Results:
1. The commands are accepted without error.
2. The interface ThisNameIsAlsoVeryLongAndValid is successfully removed.
3. show vxlan tunnel no longer lists the tunnel.

## 6. Success Criteria
The test plan is considered successful if:

All test cases, including those with names longer than 15 characters, pass without error.

The system remains stable and responsive after the creation and deletion of long-named interfaces.
