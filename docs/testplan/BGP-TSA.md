- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The purpose is to test TSA functionality. The TSA feature allows stop any BGP announcements from the DUT, restore them, and also check the current status of it.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test TSA commands.

### Testbed
The test could run on t1 testbed.

## Setup configuration
The exabgp instance runs on ptf to work as BGPMON. The BGPMON session is configured to make sure that BGPMON will receive all routes.

## Test
The test will run TSA, TSB, and TSC commands and check what routes are being announced to the DUT peers and to the BGPMON session.

## Test cases
### Test case # 1 - TSA command
1. Configure BGPMON on DUT
2. Run TSA command on DUT host
3. Check the correct output from the command
4. Check that DUT neighbors only receives the route to DUT loopback address with the predefined community value
5. Check that BGPMON recevies all routes.
6. Run TSB command to restore DUT

### Test case # 2 - TSB command
1. Configure BGPMON on DUT
2. Run TSB command on DUT host
3. Check the correct output from the command
4. Check that DUT neighbors receives all routes.
5. Check that BGPMON recevies all routes.
