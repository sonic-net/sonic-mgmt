- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The goal of the test to check that the IOS XR migration script functions to migrate a chassis from Sonic to IOS XR and back to Sonic.

### Scope
The test is targeting a running SONIC system on a Cisco chassis. The purpose of the test is to test IOS XR migration.

### Testbed
The test could run on Cisco testbed in physcial switch environment.

## Setup configuration
The migration and rollback files must be staged on a location the DUT can secure copy from.

## Test
The test migrates the chassis from Sonic to IOS XR and back to Sonic.

## Test cases
### Test case # 1 - Migrate from Sonic to IOS XR and back to Sonic
1.  Copy files from rollback file location to DUT hard disk.
2.  Run the migration script to migrate to XR Rollback Image.
3.  Perform FPD rollback.
4.  Verify IOS XR rollback succeeded.
5.  Configure the management interface in IOS XR to ensure reachability for scp.
6.  Copy files from migration file location to DUT hard disk.
7.  Perform IOS XR migration upgrade check.
8.  Upgrade to IOS XR interum image.
9.  Install Authenticated Variable and Migrate to Sonic.
10. Perform postcheck from migration script.
