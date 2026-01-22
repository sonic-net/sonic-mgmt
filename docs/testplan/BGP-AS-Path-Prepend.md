- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The goal of the test to check that as-path prepend feature works correctly. The as-path prepend feature manipulates the path from the DUT and check if the path has been correctly changed. The feature is implemented through vtysh commands.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test as-path prepend commands.

### Testbed
The test could run on t1 testbed in virtual switch environment.

## Setup configuration
This test requires to change default bgp configuration.

## Test
The test configures "as-path" feature with predefined rules. After that the test announces routes to check what path is passed from the DUT to T1.

## Test cases
### Test case # 1 
- Pre-check command
1. Run show commands to collect baseline BGP Routes on DUT
2. Check if the command returns without error

- As-path config
1. Configure route-map for as-path prepend
2. Apply route-map to BGP peer-group
3. Check the correct output from the command

- Post-check command
1. Run show commands to collect baseline BGP Routes on DUT
2. Check for exitense of as-path added

- Remove as-path
1. Remove route-map for as-path prepend
2. Remove route-map to BGP peer-group
3. Check all removed without error

- Restore check 
1. Run show commands to collect baseline BGP Routes on DUT
2. Check for exitense of as-path was removed