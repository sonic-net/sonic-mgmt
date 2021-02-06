- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The goal of the test to check that [Allow List](https://github.com/Azure/sonic-buildimage/pull/5309) feature works correctly. The feature is implemented on bgpcfgd. The bgpcfgd dynamicaly changes BGP configuration, which adjust BGP routing policy.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test BBR feature, which includes bgpcfgd implementation and BGP.

### Testbed
The test could run on t1 testbed in virtual switch environment.

## Setup configuration
This test requires to change default EOS bgp configuration. We need to enable sending community to the peers.

## Test
The test configures "Allow List" feature with predefined rules. After that the test announce routes to check what routes will be passed from the T0 to T2, and which routes are being dropped.

## Test cases
### Test case # 1 - No "Allow List" configuration is applied. The default action rule is "permit" in constants.yml
1. Set "Allow list" default action to "permit" in constants.yml
2. Don't apply any "Allow List" configuration
3. Announce predefined ipv4 and ipv6 routes from one of the T0s to DUT.
4. Check that all routes has been marked with the drop_community and announced to T2 peer
5. Restore "Allow list" default action in constants.yml

### Test case # 2 - No "Allow List" configuration is applied. The default action rule is "deny" in constants.yml
1. Set "Allow list" default action to "deny" in constants.yml
2. Don't apply any "Allow List" configuration
3. Announce predefined ipv4 and ipv6 routes from one of the T0s to DUT.
4. Check that all routes has been dropped on DUT, so no routes were announced to T2
5. Restore "Allow list" default action in constants.yml

### Test case # 3 - "Allow List" configuration is applied. The default action rule is "permit" in constants.yml
1. Set "Allow list" default action to "permtt" in constants.yml
2. Apply some predefined "Allow List" configuration
3. Announce predefined ipv4 and ipv6 routes from one of the T0s to DUT.
4. Check that all routes has been announced to T2, but the routes which weren't defined in the "Allow List" marked with the drop_community
5. Restore "Allow list" default action in constants.yml

### Test case # 4 - "Allow List" configuration is applied. The default action rule is "deny" in constants.yml
1. Set "Allow list" default action to "deny" in constants.yml
2. Apply some predefined "Allow List" configuration
3. Announce predefined ipv4 and ipv6 routes from one of the T0s to DUT.
4. Check that only routes which were defined in the "Allow List" has been announced to T2.
5. Restore "Allow list" default action in constants.yml

### Test case # 5 - "Allow List" configuration is applied with default_action field equal to "permit". The default action rule is "deny" in constants.yml
1. Set "Allow list" default action to "deny" in constants.yml
2. Apply some predefined "Allow List" configuration. Set "default_action" field to "permit"
3. Announce predefined ipv4 and ipv6 routes from one of the T0s to DUT.
4. Check that all routes has been announced to T2, but the routes which weren't defined in the "Allow List" marked with the drop_community
5. Restore "Allow list" default action in constants.yml

### Test case # 6 - "Allow List" configuration is applied with default_action field equal to "deny". The default action rule is "permit" in constants.yml
1. Set "Allow list" default action to "permtt" in constants.yml
2. Apply some predefined "Allow List" configuration.  Set "default_action" field to "deny"
3. Announce predefined ipv4 and ipv6 routes from one of the T0s to DUT.
4. Check that only routes which were defined in the "Allow List" has been announced to T2.
5. Restore "Allow list" default action in constants.yml
