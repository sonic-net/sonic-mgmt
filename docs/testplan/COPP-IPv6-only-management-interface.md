# COPP IPv6 only Management Interface Test Plan

- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)


## Overview

This test plan validates that Control Plane Policing (CoPP) functions correctly when the device is configured with an IPv6-only management interface

It ensures:

* Control-plane traffic over IPv6 is permitted as expected
* CoPP policies are enforced correctly for IPv6 traffic

### Scope

* IPv6-only management interface (`eth0`)
* CoPP behavior for:

  * Allowed control-plane traffic
  * Rate-limited / dropped traffic
* Protocols:

  * SSH (TCP/22)
  * ICMPv6
  * BGP (optional if mgmt used)

### Testbed

* DUT with management interface configured IPv6-only
* PTF or test host capable of generating IPv6 traffic toward mgmt interface
* CoPP configured with default or custom policy

## Setup Configuration

1. Configure management interface with IPv6 only:

   ```
   config interface ip remove eth0 <IPv4_addr>
   config interface ip add eth0 <IPv6_addr>/<prefix>
   ```

2. Verify:

   ```
   show ip interfaces
   show ipv6 interfaces
   ```

3. Ensure CoPP is enabled:

   ```
   show copp configuration
   ```

## Test Cases

### Test Case #1 – IPv6 Management Reachability Under CoPP

#### Test objective

Verify that permitted control-plane IPv6 traffic is allowed when management interface is IPv6-only.

Steps:

1. Configure DUT with IPv6-only mgmt interface
2. From test host, send:

   * ICMPv6 echo (ping)
   * SSH connection attempt to DUT IPv6 address

Verification:

1. Ping response
2. SSH login prompt reachable

Expected Result:

1. ICMPv6 and SSH traffic are permitted
2. No unexpected drops in CoPP
3. Counters reflect accepted traffic


### Test Case #2 – CoPP Policing for IPv6 Traffic

#### Test objective

Verify CoPP rate-limiting and drop behavior for IPv6 control-plane traffic on mgmt interface.

Steps:

1. Ensure IPv6-only mgmt configuration
2. Generate high-rate IPv6 traffic toward DUT:

   * ICMPv6 flood OR TCP SYN flood (toward SSH port)
3. Sustain traffic above CoPP threshold

Expected Result:

1. Excess IPv6 traffic is rate-limited or dropped
2. CoPP counters increment for drops
3. DUT remains responsive to legitimate traffic (e.g., SSH still accessible)
4. No control-plane crash or instability
