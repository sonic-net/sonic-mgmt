# Overview

This document describes the test plan for exercising 68 gNMI platform-related paths with the headings:



*   `mgmt` (23 paths to test, 5 unused paths)
*   `chassis` (14 paths to test, 1 unused path)
*   `primary-network-stack` (7 paths)
*   `alternate-network-stack` (7 paths)
*   `primary-os` (6 paths)
*   `alternate-os` (6 paths)
*   `bootloader` (4 paths)

State paths are read-only paths.  They are used to reflect the state of the system.  For end to end tests, state paths cannot be directly modified by a gNMI set operation.  They may be modified via gNMI set operations on the corresponding config path.   The state paths may be altered by a system command (e.g. an installation operation), or by system state changes (e.g. packet counter events).  

Config paths can be read or written.  Writing a config path indicates a desired system change.  There is a corresponding state path that is updated once the change takes effect.  Most of the gNMI config path tests verify both the gNMI get (read) path is operating as expected and that the gNMI set (write) path updates the system state as expected.


## Test types

The tests that cover the management, chassis, network stack, OS, and bootloader gNMI paths described in this document fall into three basic test categories. 


### Get (G)

A _get_ test performs a gNMI get (read) operation for a particular gNMI path.  Generally, a get-only test will exercise gNMI _state_ paths.  These paths are read-only and cannot be modified directly by a gNMI operation.  A _state_ path can, however, be modified indirectly by a gNMI write operation to a corresponding gNMI _config_ path or by a system command (e.g. a new network stack installation operation).  


### Set / Get (SG)

A _set-get_ test performs a sequence of gNMI get, set (write), and get operations.  Generally, a _set-get_ test exercises that a write to a gNMI _config_ path is accepted and updates the corresponding gNMI _state_ path.  These tests will perform gNMI set operations on the gNMI _config_ path and gNMI get operations on both the _state_ and _config_ paths.


### Set Invalid / Get (Negative) (SI)

A set-invalid test is a negative test whose intent is to verify that invalid configuration information results in a gNMI set error or, at the very least, that the invalid configuration does not result in an update to the corresponding gNMI _state_ path and that no unexpected exceptions or crashes result.


## Test Summary


<table>
  <tr>
   <td><strong>Area</strong>
   </td>
   <td><strong>Get Tests</strong>
   </td>
   <td><strong>Set/Get Tests</strong>
   </td>
   <td><strong>Set Invalid Tests</strong>
   </td>
   <td><strong>Total</strong>
   </td>
  </tr>
  <tr>
   <td>Management
   </td>
   <td>5
   </td>
   <td>3
   </td>
   <td>6
   </td>
   <td><strong>13</strong>
   </td>
  </tr>
  <tr>
   <td>Chassis
   </td>
   <td>3
   </td>
   <td>2
   </td>
   <td>1
   </td>
   <td><strong>6</strong>
   </td>
  </tr>
  <tr>
   <td>Network Stack
   </td>
   <td>2
   </td>
   <td>0
   </td>
   <td>0
   </td>
   <td><strong>2</strong>
   </td>
  </tr>
  <tr>
   <td>OS
   </td>
   <td>2
   </td>
   <td>0
   </td>
   <td>0
   </td>
   <td><strong>2</strong>
   </td>
  </tr>
  <tr>
   <td>Bootloader
   </td>
   <td>1
   </td>
   <td>0
   </td>
   <td>0
   </td>
   <td><strong>1</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Totals</strong>
   </td>
   <td><strong>13</strong>
   </td>
   <td><strong>5</strong>
   </td>
   <td><strong>6</strong>
   </td>
   <td><strong>24</strong>
   </td>
  </tr>
</table>


Table 1: Summary of test cases.


# Management Paths

There are a total of 23 management paths being considered, of which 6 config paths and 17 are state paths.  The following sections describe tests that will cover the behaviors of these paths.


## Test Summary

There are a total of 14 unique tests described in this document for the gNMI management paths. The test coverage for the 23 paths are summarized in Table 2.


<table>
  <tr>
   <td><strong>gNMI path</strong>
   </td>
   <td><strong>Tests that use path</strong>
   </td>
   <td><strong>Test Type(s)</strong>
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/config/name
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/config/type
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/ethernet/state/mac-address
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/interface-role
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/name
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/oper-status
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/type
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/in-discards
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/in-errors
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/in-octets
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/in-pkts
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/out-discards
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/out-errors
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/out-octets
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/state/counters/out-pkts
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/config/ip
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/config/prefix-length
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/state/ip
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/state/prefix-length
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/config/ip
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/config/prefix-length
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/state/ip
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/state/prefix-length
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
</table>


Table 2: Summary of management interface tests.


## Generic management interface tests

The tests in this section cover the following gNMI paths.



*   /interfaces/interface[name=&lt;mgmt>]/config/name
*   /interfaces/interface[name=&lt;mgmt>]/config/type
*   /interfaces/interface[name=&lt;mgmt>]/ethernet/state/mac-address
*   /interfaces/interface[name=&lt;mgmt>]/state/name
*   /interfaces/interface[name=&lt;mgmt>]/state/oper-status
*   /interfaces/interface[name=&lt;mgmt>]/state/type


### Test 1: Get default interface values

1. Use gNMI get operations to fetch the state values for `mac-address`, `interface-role`, `name`, `oper-status`, and `type`.
2. Expect the following results:
    1. `mac-address` matches a pattern of the form `00:00:00:00:00:00`.
        1. If installation provides a specific MAC address, expect that value.
    2. `name` is the name of the interface.  Allowed values, depending on the path, include `bond0`, `eth0`, and `eth1`.  Only one of these values is allowed for a given path.
    3. `oper-status` is `up`.  Allowed values are `up`, `down`, `testing`, `unknown`, `dormant`, `not_present`, and `lower_layer_down`. 
    4. `type` is `ethernetCsmacd`.

### Test 2: Set name


1. Use a gNMI get operation to fetch the state value for `name`.
2. Use a gNMI set replace operation to add a new interface.
    1. We will give it a `name` that is “bond7”.  Allowed values must match the pattern here.`(eth|bond)([1-3][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])`.
3. Use a gNMI get operation to fetch the state value for `name`.
4. Expect the read state value for `name` to be “bond7,” indicating the write operation has taken effect.


### Test 3: Set invalid types 

1. Use gNMI get operation to fetch the state value for `type`.
2. Use gNMI set operation to modify the config path for `type`.
    1. Set type to be invalid value, e.g. “test\_mgmt”.
3. Expect gNMI set operation to fail, since this is not a valid value from the enum.
4. Use gNMI get operation to fetch the state value for `type`.
5. Expect `state` value to remain as `ethernetCsmacd`, indicating that no state change has occurred.
6. Repeat the above steps, but using a valid enum value, such as “loopback”.  An error is still expected.


### Test 4: Set invalid name 

1. Use gNMI get operation to fetch the state value for `name`.
2. Use gNMI set operation to modify the config path for `name`.
    1. Set type to be invalid value, e.g. “mybond0”.
3. Expect gNMI set operation to fail, since this name does not match the allowed pattern.
4. Use gNMI get operation to fetch the state value for `name`.
5. Expect state value to be the original name, indicating that no state change has occurred.


## In Counters

The tests in this section cover the following state counter gNMI paths.



*   /interfaces/interface[name=&lt;mgmt>]/state/counters/in-discards
*   /interfaces/interface[name=&lt;mgmt>]/state/counters/in-errors
*   /interfaces/interface[name=&lt;mgmt>]/state/counters/in-octets
*   /interfaces/interface[name=&lt;mgmt>]/state/counters/in-pkts

The gNMI frontend retrieves the values for these paths by reading <code>[/proc/net/dev]</code>, which contains interface packet counters.  On the appropriate output line, the counter values are found at the index indicated in Table 3.


<table>
  <tr>
   <td><strong>Line Index</strong>
   </td>
   <td><strong>Path</strong>
   </td>
  </tr>
  <tr>
   <td>1
   </td>
   <td>state/counters/in-octets
   </td>
  </tr>
  <tr>
   <td>2
   </td>
   <td>state/counters/in-pkts
   </td>
  </tr>
  <tr>
   <td>3
   </td>
   <td>state/counters/in-errors
   </td>
  </tr>
  <tr>
   <td>4
   </td>
   <td>state/counters/in-discards
   </td>
  </tr>
  <tr>
   <td>8
   </td>
   <td>state/counters/in-multicast-pkts
   </td>
  </tr>
</table>


Table 3: In counter index from `/proc/net/dev` output.


### Test 5: Fetch management interface in counters

1. Use gNMI get operations to fetch the initial state values for `in-discards`, `in-errors`, `in-octets`, and `in-pkts`.
2. Inject well-formed packets of known structures and types from this test case that are destined to the management interface of the switch being tested.  
3. Use gNMI get operations to fetch the same state paths again.
4. Expect the following differences between the first and second read:
    1. `in-discards` should have no difference (ideally both values are 0).
    2. `in-errors` should have no difference (ideally both values are 0).
    3. `in-octets` should have increased by at least the count of packet bytes injected.  (It’s a bit tricky to guarantee that there is no other traffic on this management interface.)
    4. `in-pkts` should have increased by at least the number of packets injected.
5. Inject invalid packets (e.g. packets with incorrect checksums).
6. Use gNMI get operations to fetch the same state paths once more.
7. Expect the following differences between the first and second read:
    5. `in-discards` should have no difference (ideally both values are 0).
    6. `in-errors` should have increased by at least the count of error packets injected.
    7. `in-octets` should have increased by at least the count of packet bytes injected.
    8. `in-pkts` should have increased by at least the number of error packets injected.

Note that the management interface is live, and it is the path by which the gNMI client is connected to the gNMI server, so there is expected to be traffic on it.  This might require adjusting the expectations for the number of packet bytes sent and the number of packets received.


## Out Counters

The tests in this section cover the following state counter gNMI paths.



*   /interfaces/interface[name=&lt;mgmt>]/state/counters/out-discards
*   /interfaces/interface[name=&lt;mgmt>]/state/counters/out-errors
*   /interfaces/interface[name=&lt;mgmt>]/state/counters/out-octets
*   /interfaces/interface[name=&lt;mgmt>]/state/counters/out-pkts

The gNMI frontend retrieves the values for these paths by reading <code>[/proc/net/dev]</code>, which contains interface packet counters.  On the appropriate output line, the counter values are found at the index indicated in Table 4.


<table>
  <tr>
   <td><strong>Line Index</strong>
   </td>
   <td><strong>Path</strong>
   </td>
  </tr>
  <tr>
   <td>9
   </td>
   <td>state/counters/out-octets
   </td>
  </tr>
  <tr>
   <td>10
   </td>
   <td>state/counters/out-pkts
   </td>
  </tr>
  <tr>
   <td>11
   </td>
   <td>state/counters/out-errors
   </td>
  </tr>
  <tr>
   <td>12
   </td>
   <td>state/counters/out-discards
   </td>
  </tr>
</table>


Table 4: Out counter index from `/proc/net/dev` output.


### Test 6: Fetch management interface out counters

1. Use gNMI get operations to fetch the initial state values for `out-discards`, `out-errors`, `out-octets`, and `out-pkts`.
2. Use gNMI get operations to fetch the same state paths again.
3. Expect the following differences between the first and second read:
    1. `out-discards` should have no difference (ideally both values are 0)
    2. `out-errors` should have no difference (ideally both values are 0)
    3. `out-octets` should have increased.
    4. `out-pkts` should have increased.

Note that the management interface is live, and it is the path by which the gNMI client is connected to the gNMI server, so there is expected to be traffic on it.


## IPv4 Addresses

The tests in this section cover the following gNMI paths.



*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/config/ip
*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/config/prefix-length
*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/state/ip
*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv4/addresses/address[ip=&lt;address>]/state/prefix-length


### Test 7: Set IPv4 address and prefix-length

1. Use gNMI get operations to fetch the state values for `ip` and `prefix-length`.
2. Use gNMI set operations to modify the config paths to different values.
3. Use gNMI get operations to fetch the state values for `ip` and `prefix-length`.
4. Expect the values written, indicating the write operation has taken effect.
5. Use gNMI set operations to write the original `ip` and `prefix-length` values to the config path. 
6. Use gNMI get operations to confirm the state paths have been updated as expected.
7. Repeat the above steps for other _expected_ values.  


### Test 8: Set invalid prefix-length with valid IPv4 address


1. Use gNMI get operations to fetch the state value for `ip` and `prefix-length`.
2. Use gNMI set operations to modify the config paths to an invalid value for `prefix-length`, e.g. 4, and a valid value for `ip`.  These paths are required to be written in the same operation.
3. Expect a gNMI set error, since the `prefix-length` is invalid.
4. Use gNMI get operations to fetch the state value for `ip` and `prefix-length`.
5. Expect the original values, indicating the write operations did not take effect.


### Test 9: Set invalid IPv4 address with valid prefix-length


1. Use gNMI get operations to fetch the state values for `ip` and `prefix-length`.
2. Use gNMI set operations to write an invalid IPv4 address, e.g. `255.0.0.0`, and a valid `prefix-length`, e.g. 32.
3. Expect a gNMI set error, since the IPv4 address is invalid.
4. Use gNMI get operations to fetch the state value for `ip` and `prefix-length`.
5. Expect the original values, indicating the write operation did not take effect.


## IPv6 Addresses

The tests in this section cover the following gNMI paths.



*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/config/ip
*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/config/prefix-length
*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/state/ip
*   /interfaces/interface[name=&lt;mgmt>]/subinterfaces/subinterface[index=&lt;index>]/ipv6/addresses/address[ip=&lt;address>]/state/prefix-length

Note that changing the IP address for the management interface is expected to result in a loss of connection, including the connection between the gNMI client to the gNMI server in [Figure 1].  Tests that will change the IP address and prefix length will require a testbed that supports IPv4 and IPv6 simultaneously.


### Test 10: Fetch IPv6 default address parameters


1. Use gNMI get operations to fetch the initial state values for `ip`, and `prefix-length`. 
2. Expect the following results:
    1. `ip` matches a pattern of the form `fe80::f25c:77ff:fe7f:69be`.
    2. `prefix-length` may only be 64 or 128.


### Test 11: Set IPv6 address and prefix-length


1. Use gNMI get operations to fetch the state values for `ip` and `prefix-length`.
2. Use gNMI set operations to modify the config paths to different values.  Use one or more `prefix-length`s that are expected to be used.
3. Use gNMI get operations to fetch the state values for `ip` and `prefix-length`.
4. Expect the values written, indicating the write operation has taken effect.
5. Use gNMI set operations to write the original `ip` and `prefix-length` values to the config path. 
6. Use gNMI get operations to confirm the state paths have been updated as expected.
7. Repeat the above steps for other _expected_ values.  


### Test 12: Set invalid prefix-length with valid IPv6 address


1. Use gNMI get operations to fetch the state values for `ip` and `prefix-length`.
2. Use gNMI set operations to modify the config paths to an invalid value, e.g. 129, for `prefix-length` and a valid value `ip`.  Note: there are no restrictions for prefix-length for IPv6 addresses at the moment, other than being in the range [0:128].  (Loopback interfaces are limited to be <code>/64 and /128</code>.)
3. Use gNMI get operations to fetch the config values for <code>ip</code> and <code>prefix-length</code>.
4. Expect the values just written.
5. Use gNMI get operation to fetch the state values for <code>ip</code> and <code>prefix-length</code>.
6. Expect the original values, indicating the write operation did not take effect.


### Test 13: Set invalid IPv6 address with valid prefix-length


1. Use gNMI get operations to fetch the state value for `ip` and `prefix-length`.
2. Use gNMI set operations to write an invalid IPv6 address, e.g. `ffff:ffff:ffff:ffff:ffff:f25c:77ff:fe7f:69be`, and a valid `prefix-length`, e.g. 64.
3. Expect a gNMI set error.
4. Use gNMI get operations to fetch the state value for `ip` and `prefix-length`.
5. Expect the original values, indicating the write operation did not take effect.


# Chassis Paths

There are a total of 14 chassis paths being considered, of which 2 are config paths and 12 are state paths.  The following sections describe tests that will cover the behaviors of these paths.


## Test Summary

There are a total of 5 unique tests described in this document for the gNMI chassis paths. The test coverage for the 15 paths are summarized in [Table 5].


<table>
  <tr>
   <td><strong>gNMI path</strong>
   </td>
   <td><strong>Tests that use path</strong>
   </td>
   <td><strong>Test Type(s)</strong>
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/chassis/state/base-mac-address
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/chassis/state/mac-address-pool-size
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/chassis/state/platform
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/config/fully-qualified-name
   </td>
   <td>3
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/config/name
   </td>
   <td>2
   </td>
   <td>SG, SI
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/firmware-version
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/fully-qualified-name
   </td>
   <td>4
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/hardware-version
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/model-name
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/mfg-date
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/name
   </td>
   <td>3
   </td>
   <td>G, SG, SI
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/part-no
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/serial-no
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;chassis>]/state/type
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
</table>


Table 5: Summary of chassis tests.


## MAC Addresses

The tests in this section cover the following gNMI paths.



*   /components/component[name=&lt;chassis>]/chassis/state/base-mac-address
*   /components/component[name=&lt;chassis>]/chassis/state/mac-address-pool-size


### Test 1: Get default MAC address values


1. Use gNMI get operations to fetch the state values for `base-mac-address` and `mac-address-pool-size`.
2. Expect the following results:
    1. `base-mac-address` matches a pattern of the form `00:00:00:00:00:00`.  Note that if the installation specifies a specific MAC address, this test should expect that value.
    2. `mac-address-pool-size` is a number greater than or equal to 1.


## Chassis Info

The tests in this section cover the following gNMI paths.



*   /components/component[name=&lt;chassis>]/chassis/state/platform
*   /components/component[name=&lt;chassis>]/config/fully-qualified-name
*   /components/component[name=&lt;chassis>]/config/name
*   /components/component[name=&lt;chassis>]/state/firmware-version
*   /components/component[name=&lt;chassis>]/state/fully-qualified-name
*   /components/component[name=&lt;chassis>]/state/hardware-version
*   /components/component[name=&lt;chassis>]/state/model-name
*   /components/component[name=&lt;chassis>]/state/mfg-date
*   /components/component[name=&lt;chassis>]/state/name
*   /components/component[name=&lt;chassis>]/state/part-no
*   /components/component[name=&lt;chassis>]/state/serial-no
*   /components/component[name=&lt;chassis>]/state/type

Typically, chassis information is held in an EEPROM that is populated during
manufacturing.  One example mapping for state path variable from an EEPROM
file name is as shown in [Table 6].


<table>
  <tr>
   <td><strong>gNMI Path Variable</strong>
   </td>
   <td><strong>EEPROM File Name</strong>
   </td>
   <td><strong>Example Value</strong>
   </td>
  </tr>
  <tr>
   <td>hardware-version
   </td>
   <td>hardware_revision
   </td>
   <td>5
   </td>
  </tr>
  <tr>
   <td>mfg-date
   </td>
   <td>manufacture_date
   </td>
   <td>4894
   </td>
  </tr>
  <tr>
   <td>part-no
   </td>
   <td>assembly_part_number
   </td>
   <td>`some value`
   </td>
  </tr>
  <tr>
   <td>serial-no
   </td>
   <td>assembly_serial_number
   </td>
   <td>`some value`
   </td>
  </tr>
</table>


Table 6: gNMI path variable to EEPROM file name mapping.


### Test 1: Fetch default chassis info

1. Use gNMI get operations to fetch the state values for `firmware-version`, `fully-qualified-name`, `hardware-version`, `model-name`, `mfg-date`, `name`, `part-no`, `platform`, `serial-no`, and `type`.
2. Expect the following values:
    1. `firmware-version` matches against a build label that identifies an image version.
    2. `fully-qualified-name` matches against a machine name, e.g. something ending in `.com`.
    3. `hardware-version` is a single byte, so the value should be in the range 0 to 255.
    4. `model-name` is a string.
    5. `mfg-date` is a string that matches the format `%m/%d/%Y %H:%M:%S`.
    6. `name` is a `chassis`.
    7. `part-no` is a string.
    8. `platform` is the a string for the platform name.
    9. `serial-no` is a string.
    10. `type` is `CHASSIS`.  Allowed values based on the enumeration are `chassis`, `backplane`, `fabric`, `power_supply`, `fan`, `sensor`, `fru`, `linecard`, `controller_card`, `port`, `transceiver`, `cpu`, `storage`, `intergrated_circuit`, `operating_system`, `operating_system_update`, `boot_loader`, and `software_module`.


### Test 2: Set names

1. Use gNMI get operations to fetch the state values for `name` and `fully-qualified-name`.
2. Use gNMI set operations to write the config paths for `name` and `fully-qualified-name` to values other than what was read on the state paths in step 1.
3. Use gNMI get operation to fetch the config paths for `name` and `fully-qualified-name`.
4. Expect the values just written.
5. Use gNMI get operations to fetch the state values for `name` and `fully-qualified-name`.
6. Expect the values written, indicating the write operations have taken effect.


### Test 3: Set invalid name

1. Use a gNMI set operation to write the valid expected value of `name` to “chassis”.  
2. Use a gNMI get operation to read the state path for `name`.
3. Expect the read value to be “chassis.”
4. Use a gNMI set operation to write an invalid value for `name`, e.g. “mychassis.”
5. Expect a gNMI set error.
6. Use a gNMI get operation to read the state path for `name`.
7. Expect the read value to remain as “chassis.”


### Test 4: Changes persist after reboot

1. Use gNMI get operations to fetch the state values for `firmware-version`, `fully-qualified-name`, `hardware-version`, `model-name`, `mfg-date`, `name`, `part-no`, `platform`, `serial-no`, and `type`.
2. Use a gNMI set operation to write the config value for `fully-qualified-name`.
3. Use a gNMI get operation to confirm the state value for `fully-qualified-name` has been updated.
4. Reboot the system and reestablish the gNMI connection.
5. Use a gNMI get operation to confirm the state value for `fully-qualified-name` remains as the updated value.


# Network Stack Paths

There are a total of 14 network stack paths being considered, all of which are state paths.  The following sections describe tests that will cover the behaviors of these paths.


## Test Summary

There are two tests described in this document for the gNMI network stack paths.  All paths are _state_ paths. The test coverage for the 14 paths are summarized in [Table 7](#bookmark=id.ah0dedaeucal).


<table>
  <tr>
   <td><strong>gNMI path</strong>
   </td>
   <td><strong>Tests that use path</strong>
   </td>
   <td><strong>Test Type(s)</strong>
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/software-module/state/module-type
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/state/name
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/state/oper-status
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/state/parent
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/state/software-version
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/state/storage-side
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-network-stack>]/state/type
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/software-module/state/module-type
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/state/name
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/state/oper-status
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/state/parent
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/state/software-version
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/state/storage-side
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-network-stack>]/state/type
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
</table>


Table 7: Summary of network stack tests.


## Test 1: Fetch default network stack info

1. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, `type`, and `module-type`.
2. Expect the following values:
    1. `name` is a string that is `network_stack0` or `network_stack1`.
    2. `oper-status` matches `active` for the primary path and inactive for alternate path. Allowed values are `active`, `inactive`, and `disabled`.
    3. `parent` is `chassis`.
    4. `software-version` against a build label that identifies an image version.
    5. `storage-side` is either `a` or `b` for systems that support a primary and alternate stack to be loaded.  If the primary path returns `a`, then the alternate path must return `b`.  If the primary path returns `b`, then the alternate path must return `a`.
    6. `type` is `SOFTWARE_MODULE`.  Allowed values based on the enumeration are `chassis`, `backplane`, `fabric`, `power_supply`, `fan`, `sensor`, `fru`, `linecard`, `controller_card`, `port`, `transceiver`, `cpu`, `storage`, `intergrated_circuit`, `operating_system`, `operating_system_update`, `boot_loader`, and `software_module`.
    7. `module-type` is `USERSPACE_PACKAGE_BUNDLE`.  Allowed values based on the enumeration are `userspace_package_bundle` and `userspace_package`. 


## Test 2: Install new stack

1. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, `type`, and `module-type`.
2. Push a new image, staging it for install.  Do not reboot.
3. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, `type`, and `module-type` for the `alternate-network-stack` paths.  
4. Confirm that the `alternate-network-stack` paths have been updated as expected.  Only `software-version` should change.
5. Perform reboot operation.
6. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, `type`, and `module-type`.
7. Confirm that the `primary-network-stack` paths reflect the values for the image just installed and that the `alternate-network-stack` paths reflect the previously installed (previous primary) values.

 


# OS Paths

There are a total of 12 operating system paths being considered, all of which are state paths.  The following sections describe tests that will cover the behaviors of these paths.


## Test Summary

There are two tests described in this document for the gNMI operating system (OS) paths.  All paths are _state_ paths. The test coverage for the 12 paths are summarized in Table 8.


<table>
  <tr>
   <td><strong>gNMI path</strong>
   </td>
   <td><strong>Tests that use path</strong>
   </td>
   <td><strong>Test Type(s)</strong>
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-os>]/state/name
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-os>]/state/oper-status
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-os>]/state/parent
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-os>]/state/software-version
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-os>]/state/storage-side
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;primary-os>]/state/type
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-os>]/state/name
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-os>]/state/oper-status
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-os>]/state/parent
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-os>]/state/software-version
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;alternate-os>]/state/storage-side
   <td>2
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>components/component[name=&lt;alternate-os>]/state/type
   </td>
   <td>2
   </td>
   <td>G
   </td>
  </tr>
</table>


Table 8: Summary of OS tests.


## Test 1: Fetch default operating system info

1. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, and `type`.
2. Expect the following values:
    1. `name` is a string that is `os0` or `os1`.
    2. `oper-status` matches `active` for the primary path and inactive for alternate path. Allowed values are `active`, `inactive`, and `disabled`.
    3. `parent` is `chassis`.
    4. `software-version` is the Linux kernel version.  For example, a pattern that looks like `6.1.10` should match.
    5. `storage-side` is either `a` or `b`.  If the primary path returns `a`, then the alternate path must return `b`.  If the primary path returns `b`, then the alternate path must return `a`.
    6. `type` is `OPERATING_SYSTEM`.  Allowed values based on the enumeration are `chassis`, `backplane`, `fabric`, `power_supply`, `fan`, `sensor`, `fru`, `linecard`, `controller_card`, `port`, `transceiver`, `cpu`, `storage`, `intergrated_circuit`, `operating_system`, `operating_system_update`, `boot_loader`, and `software_module`.


## Test 2: Install new stack

1. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, and `type`.
2. Push a new image, staging it for install.  Do not reboot.
3. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, and `type` for the `alternate-os` paths.  
4. Confirm that the `alternate-os` paths have been updated as expected.  Only `software-version` is expected to change.
5. Perform reboot operation.
6. Use gNMI get operations to fetch the state values for `name`, `oper-status`, `parent`, `software-version`, `storage-side`, and `type`.
7. Confirm that the `primary-os` paths reflect the values for the image just installed and that the `alternate-os` paths reflect the previously installed (previous primary) values.


# Bootloader Paths

There are a total of 4 bootloader paths being considered, all of which are state paths.  The following sections describe tests that will cover the behaviors of these paths.


## Test Summary

There is a single unique test described in this document for the gNMI bootloader paths, since all paths are _state_ paths. The test coverage for the 4 paths are summarized Table 9.


<table>
  <tr>
   <td><strong>gNMI path</strong>
   </td>
   <td><strong>Tests that use path</strong>
   </td>
   <td><strong>Test Type(s)</strong>
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;bootloader>]/state/name
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;bootloader>]/state/parent
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;bootloader>]/state/software-version
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
  <tr>
   <td>/components/component[name=&lt;bootloader>]/state/type
   </td>
   <td>1
   </td>
   <td>G
   </td>
  </tr>
</table>


Table 9: Summary of bootloader tests.


## Test 1: Fetch default bootloader info

1. Use gNMI get operations to fetch the state values for `name`, `parent`, `software-version`, and `type`.
2. Expect the following values:
    1. `name` is a string that is `boot_loader`.
    2. `parent` is `chassis`.
    3. `software-version` is a string that represents a bundled boot loader image.
    4. `type` is `BOOT_LOADER`.  Allowed values based on the enumeration are `chassis`, `backplane`, `fabric`, `power_supply`, `fan`, `sensor`, `fru`, `linecard`, `controller_card`, `port`, `transceiver`, `cpu`, `storage`, `intergrated_circuit`, `operating_system`, `operating_system_update`, `boot_loader`, and `software_module`.


# Container Monitor

The container monitor is a Google-specific monitoring daemon that periodically polls that containers and top-level processes are running as expected.  If a container or top-level process has exited unexpectedly, the container monitor may restart the container or top-level process, depending on configuration settings.  The containers and processes to monitor the actions to take based on events are defined by a configuration protobuf.
 


## Test 1: Force stop a container that can be restarted

For this test, we want to verify that the container monitor can successfully restart a faulty container.  We select a container tha is configured to allow restarts to perform this verification.  This test will perform the following steps:

1. Check that the container monitor and selected container are running as expected.
2. Force stop the selected container.  Wait for up to two minutes to detect that the selected container returns an error when the status is checked.
3. Wait for the container monitor to restart the selected container.  Wait for up to three minutes to detect the selected container reports an operational status.

## Test 2: Force-stop a container that cannot be restarted

For this test, we want to verify that the container monitor reports the system is in a critical state when the container is not running as expected.  We select a container that is not allowed to be restarted (e.g. `syncd`) to perform this verification.  This test will perform the following steps:

1. Check that the container monitor and selected container are running as expected.
2. Force stop the selected container.  Wait for up to two minutes to detect that the selected container returns a `CRITICAL` state error when the status is checked.
3. Reboot the switch and validate if the selected container process gets restored.
