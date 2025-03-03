- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)

## Overview
The goal of the test to check that BBR feature works correctly. The feature is implemented on bgpcfgd. The bgpcfgd dynamicaly changes BGP configuration, which either enable or disabled BBR functionality. The BBR functionality is enablement to see DUT ASN in the routes aspath not more than once.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test BBR feature and configuration, which includes bgpcfgd implementation and BGP.

### Testbed
The test could run on t1 testbed in virtual switch environment.

## Setup configuration
This test doesn't require any configuration.

## Test
The test announces ipv4 and ipv6 routes from one of the T0s, and checks when DUT accepts them with different BBR state.

## Test cases
### Test case # 1 - BBR enabled, aspath contains one DUT ASN
1. Ensure that BBR is enabled on the DUT
2. Announce ipv4 and ipv6 routes fron one of the T0s to DUT. Each route must have patched aspath which contains DUT ASN once.
3. Check that DUT BGP accepted both routes to the routing table
4. Restore the BBR state how it was been before the test


### Test case # 2 - BBR enabled, aspath contains two DUT ASN
1. Ensure that BBR is enabled on the DUT
2. Announce ipv4 and ipv6 routes fron one of the T0s to DUT. Each route must have patched aspath which contains DUT ASN two times.
3. Check that DUT BGP rejected both routes to the routing table
4. Restore the BBR state how it was been before the test

### Test case # 3 - BBR disabled, aspath contains one DUT ASN
1. Ensure that BBR is disabled on the DUT
2. Announce ipv4 and ipv6 routes fron one of the T0s to DUT. Each route must have patched aspath which contains DUT ASN once.
3. Check that DUT BGP rejected both routes to the routing table
4. Restore the BBR state how it was been before the test

### Test case # 4 - BBR status remains consistent after config reload
1. Set the BBR status in the config_db to the value specified by the `bbr_status` parameters using the redis-cli command.
2. Save the configuration using the `sudo config save -y` command.
3. Reload the configuration using the `config_reload` function.
4. Retrieve the BBR status and verified it matches the expected `bbr_status` value.
5. Restore the BBR status how it was been before the test.
