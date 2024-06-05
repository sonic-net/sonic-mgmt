# Overview

This document describes the test plan for exercising 42 gNMI port management related paths.

# Test Types

### Get (G)

A *get* test performs a gNMI get (read) operation for a particular gNMI path.  Generally, a get-only test will exercise gNMI *state* paths.  These paths are read-only and cannot be modified directly by a gNMI operation.  A *state* path can, however, be modified indirectly by a gNMI write operation to a corresponding gNMI *config* path or by a system command (e.g. a new network stack installation operation).

### Set / Get (SG)

A *set-get* test performs a sequence of gNMI get, set (write), and get operations.  Generally, a *set-get* test exercises that a write to a gNMI *config* path is accepted and updates the corresponding gNMI *state* path.  These tests will perform gNMI set operations on the gNMI *config* path and gNMI get operations on both the *state* and *config* paths.

### Set Invalid / Get (Negative) (SI)

A *set-invalid* test is a negative test whose intent is to verify that invalid configuration information results in a gNMI set error or, at the very least, that the invalid configuration does not result in an update to the corresponding gNMI *state* path and that no unexpected exceptions or crashes result.

### Traffic Validation (TV)

A *traffic validation* test injects packets from either the control switch or SUT and observes the appropriate counters on the peer switch. Additionally, these tests might involve injecting packets using traffic generators, verifying counters on the SUT and verifying traffic generator statistics. These tests might require flow configuration on the SUT or control switch.

# Front panel port paths

## Test Summary

<table>
  <thead>
    <tr>
      <th><strong>gNMI path</strong></th>
      <th><strong>Test Type(s)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/enabled</td>
      <td>SG, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/enabled</td>
      <td>SG, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/oper-status</td>
      <td>SG, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/admin-status</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/last-change</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/config/port-speed</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/state/port-speed</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/mtu</td>
      <td>SG, SI, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/mtu</td>
      <td>SG, SI, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/loopback-mode</td>
      <td>SG, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/loopback-mode</td>
      <td>SG, TV</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/id</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/id</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/name</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/name</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/description</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/description</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/fully-qualified-interface-name</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/fully-qualified-interface-name</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/type</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/type</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/management</td>
      <td>G</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/cpu</td>
      <td>G</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/hardware-port</td>
      <td>G</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/state/mac-address</td>
      <td>G</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/config/health-indicator</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/health-indicator</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/config/link-training</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/state/link-training</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/hold-time/config/up</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/hold-time/config/down</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/hold-time/state/up</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/hold-time/state/down</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/counters/carrier-transitions</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/components/component[name=<physical_port>]/subcomponents/subcomponent[name=    <transceiver-id>]/config/name</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/components/component[name=<physical_port>]/subcomponents/subcomponent[name=transceiver-id]/state/name</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/state/transceiver</td>
      <td>SG</td>
    </tr>
    <tr>
      <td>/components/component[name=<physical_port>]/config/name</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/components/component[name=<physical_port>]/state/name</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/components/component[[name=<physical_port>]/state/parent</td>
      <td>G</td>
    </tr>
    <tr>
      <td>/components/component[name=<physical_port>]/port/config/port-id</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/components/component[name=<physical_port>]/port/state/port-id</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/config/fec-mode</td>
      <td>SG, SI</td>
    </tr>
    <tr>
      <td>/interfaces/interface[name=<port>]/ethernet/state/fec-mode</td>
      <td>SG, SI</td>
    </tr>
  </tbody>
</table>

## Port admin status tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/config/enabled
-   /interfaces/interface[name=<port>]/state/enabled
-   /interfaces/interface[name=<port>]/state/oper-status
-   /interfaces/interface[name=<port>]/state/admin-status
-   /interfaces/interface[name=<port>]/state/last-change
-   /interfaces/interface[name=<port>]/state/counters/carrier-transitions

### Test 1: Disable/Enable port

The following steps will be performed:

1.  Use gNMI get operations to fetch the state values for `last-change` and `carrier-transitions` on SUT.
2.  Use gNMI set operation to disable the port on SUT.
    1.  `enabled` is `false` on SUT.
3.  Use gNMI get operations to fetch the state values for `enabled, oper-status, admin-status, last-change` and `carrier-transitions` on SUT.
4.  Expect the following state values, indicating write operations have taken effect on SUT.
    1.  `enabled` is `false`
    2.  `oper-status` is "`DOWN`"
    3.  `admin-status` is "`DOWN`"
    4.  `last-change` is greater than `last-change` timestamp in step 1.
    5.  `carrier-transitions` is `1 `more than` carrier-transitions `in step 1.
5.  Use gNMI get operations to fetch the state values for `oper-status` on control switch.
6.  Expect that `oper-status` is "`DOWN`" on the control switch.
7.  Perform traffic validation test with control switch being the source and SUT being the destination using the interface under test.
    1.  Ensure that no container is sending control traffic between SUT and control switch.
        1.  If required, stop LLDP, Teamd and BGP containers.
    2.  Using gNMI get operations, fetch the state value of `out-pkts` on the control switch and `in-pkts` on SUT.
    3.  Using P4RT packet I/O, send `N` IP packets from the control switch to the SUT via the port under test.
    4.  Using gNMI get operations, fetch the state value of `out-pkts` on the control switch and `in-pkts` on SUT.
    5.  Expect that `out-pkts` on the control switch and `in-pkts` on SUT are the same as the previous value in step 7(b). This indicates that packets have not egressed the control switch due to the port being operationally down.
8.  Use gNMI set operation to enable the port on SUT.
    1.  `enabled` is `true` on SUT.
9.  Use gNMI get operations to fetch the state values for `enabled, oper-status, admin-status, last-change `and` carrier-transitions` on SUT.
10.  Expect the following state values, indicating write operations have taken effect on SUT.
    1.  `enabled` is `true`
    2.  `oper-status` is "`UP`"
    3.  `admin-status` is "`UP`"
    4.  `last-change` is greater than` last-change timestamp `in step 4.
    5.  `carrier-transitions` is `1 `more than` carrier-transitions `in step 4.
11.  Use gNMI get operation to fetch the state value for `oper-status` on control switch.
12.  Expect that `oper-status` is "`UP`" on the control switch.
13.  Perform traffic validation test with control switch being the source and SUT being the destination using the interface under test.
    1.  Using P4RT packet I/O, send N IP packets from the control switch to the SUT.
    2.  Using gNMI get operations, fetch the state value of `out-pkts` on the control switch and `in-pkts` on SUT.
    3.  Expect that `out-pkts` on the control switch and the `in-pkts` on the SUT are both incremented by N from the previous values in 7(b). This indicates that the port under test has been successfully enabled on SUT.

### Test 2: ON_CHANGE Test

The following steps will be performed:

1.  Use gNMI get operation to fetch the state values for `oper-status` and `admin-status`.
2.  Expect that:
    1.  `oper-status` is "`UP`".
    2.  `admin-status` is "`UP`".
3.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `oper-status` and `admin-status `paths.
4.  Use gNMI set operation to disable the port.
    1.  `enabled` is `false`.
5.  Expect that the test receives `oper-status` and `admin-status` change notifications from the switch (or a single notification).
6.  Expect the following values in the notification(s):
    1.  `oper-status` is "`DOWN`".
    2.  `admin-status` is "`DOWN`".
7.  Use gNMI set operation to enable the port.
    1.  `enabled` is `true`.
8.  Expect that the test receives `oper-status` and `admin-status` change notifications from the switch (or a single aggregated notification).
9.  Expect the following values in the notification(s):
    1.  `oper-status` is "`UP`".
    2.  `admin-status` is "`UP`".

## Port speed tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/ethernet/config/port-speed
-   /interfaces/interface[name=<port>]/ethernet/state/port-speed
-   /interfaces/interface[name=<port>]/state/oper-status

### Test 1: Set supported speed

The following steps will be performed:

1.  Use gNMI get operations to fetch the state value of `autoneg` and `port-speed` for port under test and `oper-status` for all front panel ports on SUT.
2.  Expect that `autoneg` is `false` and `oper-status` is "`UP`" for port under test on SUT.
3.  Use gNMI set operation to configure a supported speed (different than current speed) on a port on SUT.
    1.  `port-speed` is `<supported_speed>`
4.  Use gNMI get operations to fetch the state values for `port-speed` and `oper-status` of port under test on SUT.
5.  Expect the following state values for port under test, indicating write operations have taken effect on SUT.
    1.  `port-speed` is `<supported_speed>`
    2.  `oper-status` is "`DOWN`"
6.  Use gNMI get operation to fetch `oper-status` of port under test on the control switch.
7.  Expect that `oper-status` is "`DOWN`".
8.  Use gNMI set operation to configure the same speed as configured in step 3 for the port under test on the control switch.
    1.  `port-speed` is `<supported_speed>`
9.  Use gNMI get operations to fetch the state values for `port-speed` and `oper-status` for port under test on control switch.
10.  Expect the following state values, indicating write operations have taken effect on the control switch.
    1.  `port-speed` is `<supported_speed>`
    1.  `oper-status` is "`UP`"
11.  Use gNMI get operation to fetch `oper-status` for all front panel ports on SUT.
12.  Expect that `oper-status` is "`UP`" for port under test and same as previous value in step 1 for all other front panel ports on SUT.
13.  Restore original port speed on SUT and control switch and verify that port under test is operationally up and oper-status of all other front panel ports has not changed.

### Test 2: Set unsupported speed

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operation to fetch the state path value for `port-speed `for port under test and `oper-status` for all front panel ports`.`
2.  Use gNMI set operation to configure an unsupported speed on a port.
    1.  `port-speed` is "`<unsupported_speed>`"
3.  Expect gNMI set operation to fail as the speed is not a supported port speed.
4.  Use gNMI get operations to fetch the state values for `port-speed`  for port under test and `oper-status `for all front panel ports.
5.  Expect the following state values:
    1.  `port-speed` is `<same as original port-speed>` in step 1 for port under test
    2.  `oper-status` is "`UP`" for port under test and same as previous value in step 1 for all other front panel ports.

### Test 3: ON_CHANGE Test

The following steps will be performed for the port under test:

1.  Use gNMI get operation to fetch the state path value for `port-speed `and` oper-status.` Expect that:
    1.  `oper-status` is "`UP`".
2.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `port-speed` and `oper-status` paths.
3.  Use gNMI set operation to configure a supported speed on the port which is different from the current `port-speed` fetched in step 1.
    1.  `port-speed` is "`<supported_speed>`".
4.  Expect that the test receives  `port-speed` and `oper-status` change notifications from the switch (or a single aggregated notification) with:
    1.  `port-speed = <supported_speed>` configured in step 3.
    2.  `oper-status` is "`DOWN`".
5.  Use gNMI set operation to restore original speed on the port.
    1.  `port-speed` is "`<original_speed>`".
6.  Expect that the test receives  `port-speed` and `oper-status` change notifications from the switch (or a single aggregated notification) with:
    1.  `port-speed = <original_speed>` fetched in step 1.
    2.  `oper-status` is "`UP`".

## Port MTU tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/config/mtu
-   /interfaces/interface[name=<port>]/state/mtu

### Test 1: Set supported MTU
Using dual switch setup with two paired ports, the following steps will be performed:

1.  Use gNMI get operation to fetch the state value for `mtu` on SUT ports.
2.  Use gNMI set operations to modify the MTU on SUT on port under test.
    1.  `mtu` is `1500`
3.  Use gNMI get operation to fetch the state value for `mtu` on SUT.
4.  Expect the following state values, indicating write operations have taken effect on SUT.
    1.  `mtu` is `1500`
5.  Enable collecting packets back on control switch.
6.  Using P4RT packet I/O, send N packets of size > SUT mtu from control switch to SUT to be routed out of port under test on SUT. Expect no packets to be routed back to control switch.
7.  Using P4RT packet I/O, send N packets of size < SUT mtu from control switch to SUT to be routed out of port under test on SUT. Expect all packets to be routed back to control switch.
8.  Repeat steps 1-7 for MTU values of `5120 `and` 9216`.
9.  Restore original MTU in step 1 on the SUT.

### Test 2: Set invalid MTU

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operations to fetch the state values for `mtu`.
2.  Use gNMI set operations to modify the config paths.
    1.  `mtu` is `20000`
3.  Expect the above set operation to fail.
4.  Use gNMI get operations to fetch the state values for `mtu`.
5.  Expect the following state values.
    1.  `mtu` is `<same as previous mtu>`
    2.  `oper-status` is "`UP`"
6.  Repeat steps 2 through 4 with each of the following invalid MTU values.
    1.  `mtu` is `0`
    2.  `mtu` is `65536`

### Test 3: Verify traffic during MTU change

Using traffic generator setup, the following steps will be performed:

1.  Use P4RT interface to configure L3 forwarding rule that forwards `dest-ip` traffic via port under test (say `Ethernet0`).
2.  Use gNMI set operation to configure MTU of `Ethernet0` to 4K:
    1.  `mtu` is `4500`.
3.  Use gNMI get operation to fetch the state value of `out-pkts` on `Ethernet0`.
4.  Send 4K size packets from traffic generator to SUT via any port except `Ethernet0 `continuously.
5.  Verify that the packets are being forwarded from SUT to traffic generator:
    1.  Use gNMI get operation to fetch the state value of `out-pkts` on `Ethernet0`.
        1.  Verify that `out-pkts `> `out-pkts `in step 3.
    2.  If available, use traffic generator APIs to verify that all 4K traffic is being received back by the traffic generator.
6.  Use gNMI set operation to change the MTU of `Ethernet0` to 9K:
    1.  `mtu` is `9198`.
7.  Verify that no packet has been dropped by the switch after changing the MTU:
    1.  Use traffic generator APIs to verify that all 4K traffic is being received back by the traffic generator.
8.  Stop sending packets from the traffic generator.
9.  Restore original MTU on the SUT.

## Port loopback mode tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/config/loopback-mode
-   /interfaces/interface[name=<port>]/state/loopback-mode

### Test 1: Enable/Disable loopback mode

Using dual switch setup, the following steps will be performed:

1.  Use gNMI set operation to enable `loopback-mode` on SUT.
    1.  `loopback-mode` is `true`
2.  Use gNMI get operation to fetch the state value for `loopback-mode` on SUT.
3.  Expect that `loopback-mode` is `true`.
4.  The above configuration will cause a link flap so wait for the port to come back up.
    1.  Use gNMI get operation to fetch the state value for oper-status on SUT:
        1.  Expect that `oper-status` is `UP`.

5.  Perform traffic validation to verify that packets are being looped back from the SUT:
    1.  Using gNMI get operations, fetch the state value of `in-pkts` and `out-pkts` on SUT, and `in-pkts` on control switch.
    2.  Using P4RT packet I/O interface, send `N` IP packets from SUT to the control switch via port under test.
    3.  Using gNMI get operation, fetch the state value  of `in-pkts` on control switch.
        1.  Expect that `in-pkts` is same as `in-pkts` in step 5a.
    4.  Using gNMI get operations, fetch the state value of `in-pkts` and `out-pkts` on SUT.
        1.  Expect that `in-pkts` and `out-pkts` on SUT are incremented by `N`. This indicates that packets egressing from the SUT are looped back from SUT and received on the same port.

6.  Use gNMI set operation, disable `loopback-mode` on SUT.
    1.  `loopback-mode` is `false`
7.  Use gNMI get operation to fetch the state value for `loopback-mode` on SUT.
    1.  `loopback-mode` is `false`
8.  The above configuration will cause a link flap so wait for the port to come back up.
    1.  Use gNMI get operation to fetch the state value for oper-status on SUT:
        1.  Expect that `oper-status` is `UP`.

9.  Perform traffic validation to verify that packets are not being looped back from the SUT to the control switch:
    1.  Using gNMI get operations, fetch the state value of `in-pkts` and `out-pkts` on SUT, and `in-pkts` on control switch.
    2.  Using P4RT packet I/O interface, send `N` IP packets from SUT to the control switch via port under test.
    3.  Using gNMI get operation, fetch the state value  of `in-pkts` on control switch.
        1.  Expect that `in-pkts` `=` `N` `+` `in-pkts` in step 9a.
    4.  Using gNMI get operations, fetch the state value of `in-pkts` and `out-pkts` on SUT.
        1.  Expect that `out-pkts = N + out-pkts` in step 9a.
        2.  Expect that `in-pkts` is same as `in-pkts` in step 9a. This indicates that packets egressing from the SUT are not looped back to the SUT.

## Port bookkeeping attributes tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/config/id
-   /interfaces/interface[name=<port>]/state/id
-   /interfaces/interface[name=<port>]/config/name
-   /interfaces/interface[name=<port>]/state/name
-   /interfaces/interface[name=<port>]/config/description
-   /interfaces/interface[name=<port>]/state/description
-   /interfaces/interface[name=<port>]/config/fully-qualified-interface-name
-   /interfaces/interface[name=<port>]/state/fully-qualified-interface-name
-   /interfaces/interface[name=<port>]/config/type
-   /interfaces/interface[name=<port>]/state/type

### Test 1: Set all bookkeeping attributes
Using single switch setup, the following steps will be performed:

1.  Use gNMI set operations to modify the config paths.
    1.  `id` is `1`
    2.  `name` is "`Ethernet0`"
    3.  `description` is "`test_description`"
    4.  `fully-qualified-interface-name` is "`ju1u1m1.ibs40.net.google.com:eth-1/2/1`"
    5.  `type` is "`ethernetCsmacd`"
2.  Use gNMI get operations to fetch the state values for all bookkeeping attributes.
3.  Expect that they are the same as configured.

### Test 2: Set invalid name

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operations to fetch the state value for `name`.
2.  Use gNMI set operation to modify the `name`.
    1.  `name` is "`EthernetXYZ`"
3.  Expect gNMI set operation to fail since name value is not valid.
    1.  Valid name values are "`Ethernet([1-3][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])`"
4.  Use gNMI get operation to fetch the state value for `name`.
5.  Expect that state value is the same as step 1.

### Test 3: Set invalid type

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operations to fetch the state value for `type`.
2.  Use gNMI set operations to modify the config paths.
    1.  `type` is `"ieee8023adLag"`
3.  Expect gNMI set operation to fail since type value is not supported. 
4.  Use gNMI get operations to fetch the state value for `type`.
5.  Expect that the state value is the same as the original indicating that no change has occurred.

### Test 4: ON_CHANGE id Test

Using single switch setup, the following steps will be performed:

1.  Use gNMI set operation to configure `id` of a port:
    1.  `id` is `1`.
2.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `id` path.
3.  Use gNMI set operation to modify id of the port:
    1.  `id` is `100`.
4.  Expect that the test receives  `id` change notification from the switch with:
    1.  `id = 100`.

## Port Information tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/ethernet/state/mac-address
-   /interfaces/interface[name=<port>]/state/hardware-port
-   /interfaces/interface[name=<port>]/state/management
-   /interfaces/interface[name=<port>]/state/cpu
-   /interfaces/interface[name=<port>]/state/serdes_config_qualified

### Test 1: Get port MAC address

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operation to fetch the state value for `mac-address `for each front panel port.
2.  Expect the following values:
    1.  `mac-address` is in a valid format `xx::xx::xx::xx::xx::xx`
    1.  `mac-address `is unique for all the front panel ports

### Test 2: Get port flags

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operation to fetch the state value for `management `and` cpu `for each front panel port.
2.  Expect that both the state values are `false`.

### Test 3: Get hardware-port

Using single switch setup, the following steps will be performed:

1.  Fetch the expected port name to front panel port number mapping.
    1.  This information can be embedded into the switch model present in the test framework and can be fetched from this model.
2.  Use gNMI get operation to fetch the state value for `hardware-port `for each front panel port.
3.  Expect that the state value of `hardware-port` is in the form of "`1/<front_panel_port_number>`" where `<front_panel_port_number> `matches the port name to front panel port number mapping fetched in step 1.

### Test 4: Get serdes-config-qualified

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operation to fetch the state value for `serdes_config_qualified` for each interface.
2.  Expect the value is populated.
3.  Use gNMI get to fetch the `/components/component[name=<transceiver>]/state/empty` value for the matching transceiver
4.  If the transcever is populated, expect the value is true.

## Port component tests

The tests in this section cover the following gNMI paths.

-   /components/component[name=<physical_port>]/config/name
-   /components/component[name=<physical_port>]/state/name
-   /components/component[name=<physical-port>]/state/parent
-   /components/component[name=<physical_port>]/port/config/port-id
-   /components/component[name=<physical_port>]/port/state/port-id
-   /components/component[name=<physical_port>]/subcomponents/subcomponent[name=<transceiver-id>]/config/name
-   /components/component[name=<physical_port>]/subcomponents/subcomponent[name=<transceiver-id>]/state/name
-   /interfaces/interface[name=<port>]/state/transceiver

### Test 1: Set port component information

Using single switch setup, the following steps will be performed:

1.  Use gNMI set operations to configure the name and `port-id` of physical port "`1/1`".
    1.  `name` is "`1/1`"
    2.  `port-id` is `1`
2.  Use gNMI get operation to fetch the state values for `name, port-id `and` parent` of physical port "`1/1`".
3.  Expect the following values:
    1.  `name` is "`1/1`"
    2.  `port-id` is `1`
    3.  `parent` is "`integrated_circuit0`"
  
### Test 3: Set invalid name

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operation to fetch the state value for `name` of physical port "`1/1`".
2.  Use gNMI set operations to configure invalid `name` of physical port "`1/1`". 
    1.  `name` is "`1/XYZ`"
3.  Expect that the above gNMI set operation fails.
4.  Use gNMI get operation to fetch the state value for `name` of physical port "`1/1`".
5.  Expect that the state value for `name` is unchanged i.e. `name` in step 4 is same as that in step 1.

### Test 4: Set port transceiver subcomponent

Using single switch setup, the following steps will be performed:

1.  Use gNMI get operations to fetch the state values of `hardware-port` for each front panel port. The `hardware-port` represents the `physical_port` for the port component.
2.  Use gNMI set operation to configure the transceiver subcomponent `name` for each `physical_port` fetched in step 1.
    1.  `name` is "`Ethernet0`" for `physical_port` = "`1/1`".
    2.  `name` is "`Ethernet1`" for `physical_port` = "`1/2`" and so on.
3.  Use gNMI get operation to fetch the state values for transceiver subcomponent `name` and front panel port `transceiver`.
4.  Expect the following values:
    1.  Transceiver subcomponent `name` is "`Ethernet0`" for `physical_port` = "`1/1`".
        1.  `physical_port` = "`1/1`" maps to front panel port "Ethernet0" (from step 1). Therefore, `transceiver` for front panel port "`Ethernet0`" is "`Ethernet0`".
    1.  Transceiver subcomponent `name` is "`Ethernet1`" for `physical_port` = "`1/2`" and so on.
        1.  `physical_port` = "`1/2`" maps to front panel port "`Ethernet8`" and "`Ethernet12`" (from step 1). Therefore, `transceiver` for front panel ports "`Ethernet8`" and "`Ethernet12`" is "`Ethernet1`".


## Port link training tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/ethernet/config/link-training
-   /interfaces/interface[name=<port>]/ethernet/state/link-training

These tests require the test to know the port connection type (copper or optical) between the SUT and control switch.

### Test 1: Set link training for copper port

The following steps will be performed:

1.  Use gNMI set operations to disable copper port under test on SUT and control switch.
2.  Use gNMI set operations to disable `link-training` on SUT and  enable `link-training`  on control switch.
3.  Use gNMI set operations to enable the ports on SUT and control switch.(Disabling and re-enabling port will retrigger link-training to be applied on the port.)
4.  Use gNMI get operation to fetch the state value of `link-training` and `oper-status` on SUT.
5.  Expect that `oper-status` is "`DOWN`" since link-training is only applied on one side and `link-training` is` "false"`
6.  Use gNMI set operations to enable `link-training` on SUT.
7.  Use gNMI get operations to fetch the state values for `link-training` and `oper-status` on SUT and control switch.
8.  Expect that `oper-status` is "`UP`" since link-training is now applied on both sides and `link-training` is` "true"

`## Port hold-time tests

The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/hold-time/config/up
-   /interfaces/interface[name=<port>]/hold-time/config/down
-   /interfaces/interface[name=<port>]/hold-time/state/up
-   /interfaces/interface[name=<port>]/hold-time/state/down
-   /interfaces/interface[name=<port>]/state/counters/carrier-transitions

These set of tests require port flapping. Few ways a port can be caused to flap are:

-   Configure a PHY register that causes link reset. Tests using this method need to SSH into the switch and vendor-dependent methodologies (e.g. BCM shell).
-   Disable and enable port. Although this can be done using gNMI operations, tests using this method might require longer hold-times.

These tests assume that when hold-time `down` is configured, the port does not go down immediately upon receiving a port down notification. Instead, the switch waits for hold-time `down` amount of time for the port to come up and marks it down if the state does not change before the hold-time down expires.

### Test 1: Disable hold-time up and hold-time down

Using dual switch setup, the following steps will be performed:

1.  Use gNMI set operations to disable hold-time `up` and `down`.
    1.  `up` is `0`
    2.  `down` is `0`
2.  Use gNMI get operation to fetch the state values for hold-time `up` and `down`. Expect that:
    1.  `up` is `0`
    2.  `down` is `0`
3.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
4.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `oper-status` path.
5.  Cause the port to flap `N` times continuously on the control switch. The link flapping should be performed at intervals greater than 5 seconds to ensure that no link state transition is missed.
6.  Expect that the test receives `2 x N` `oper-status` change notifications from the switch.
7.  Use gNMI get operation to fetch the state values for `oper-status` and `carrier-transitions`.
8.  Expect that:
    1.  `oper-status` is "`UP`".
    2.  `carrier-transitions` is `2 x N` times more than the value fetched in step 3.

### Test 2: Disable hold-time up, Enable hold-time down

Using dual switch setup, the following steps will be performed:

1.  Use gNMI set operations to disable hold-time `up` and configure hold-time `down`.
    1.  `up` is `0`
    2.  `down` is `10000` i.e. 10 seconds
2.  Use gNMI get operation to fetch the state values for hold-time `up` and `down`. Expect that:
    1.  `up` is `0`
    2.  `down` is `10000`
3.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
4.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `oper-status` path.
5.  Test scenario of port flapping such that port comes up before hold-time `down` expires:
    1.  Cause the port to flap (ensure port comes up before hold-time `down` expires) `t` times continuously on the control switch.
    2.  Expect that the test receives no `oper-status` change notification since the port comes up before hold-time `down` expires.
    3.  Use gNMI get operation to fetch the state values for `oper-status` and `carrier-transitions`.
    4.  Expect that:
        1.  `oper-status` is "`UP`" since hold-time `down` is configured.
        2.  `carrier-transitions` is same as the value fetched in step 3 since the port state did not change.

6.  Test scenario of port flapping such that port comes up after hold-time `down` expires:
    1.  Use gNMI set operation to disable the port on the control switch.
        1.  `admin-status` is "`DOWN`".
    2.  Expect that 1 `oper-status` notification is received after hold-time `down` expires with `oper-status` as "`DOWN`".
    3.  Use gNMI set operation to enable the port.
        1.  `admin-status` is "`UP`".
    4.  Expect that 1 `oper-status` notification is received immediately with `oper-status` as "`UP`" since hold-time `up` is 0.
    5.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
    6.  Expect that:
        1.  `carrier-transitions` is `2` more than the value fetched in step 5c.

### Test 3: Enable hold-time up, Disable hold-time down

Using dual switch setup, the following steps will be performed:

1.  Use gNMI set operations to configure hold-time `up` and disable hold-time `down`.
    1.  `up` is `10000` i.e. 10 seconds
    2.  `down` is `0`
2.  Use gNMI get operation to fetch the state values for hold-time `up` and `down`. Expect that:
    1.  `up` is `10000`
    2.  `down` is `0`
3.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
4.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `oper-status` path.
5.  Test scenario of a single Up -> Down -> Up transition:
    1.  Use gNMI set operation to disable the port on the control switch.
        1.  `admin-status` is "`DOWN`".
    2.  Expect that 1 `oper-status` notification is received immediately with `oper-status` as "`DOWN`" since hold-time `down` is 0.
    3.  Use gNMI set operation to enable the port.
        1.  `admin-status` is "`UP`".
    4.  Expect that 1 `oper-status` notification is received after hold-time `up` expires with `oper-status` as "`UP`".
    5.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
    6.  Expect that:
        1.  `carrier-transitions` is `2` more than the value fetched in step 3.

6.  Test scenario of a continuous Up -> Down -> Up transitions:
    1.  Cause the port to flap `N` times continuously on the control switch.
    2.  Expect that `1 oper-status` change notification is received immediately with `oper-status` as "`DOWN`" since hold-time `down` is 0.
    3.  Expect that 1 `oper-status` change notification is received with `oper-status` as "`UP`" after hold-time `up` expires after the last link flap.
    4.  Use gNMI get operation to fetch the state values for `oper-status` and `carrier-transitions`.
    5.  Expect that:
        1.  `oper-status` is "`UP`"
        2.  `carrier-transitions` is `2 `more than the value fetched in step 5e.

### Test 4: Enable hold-time up and down

Using dual switch setup, the following steps will be performed:

1.  Use gNMI set operations to configure hold-time `up` and `down`.
    1.  `up` is `10000` i.e. 10 seconds
    2.  `down` is `5000` i.e. 5 seconds
2.  Use gNMI get operation to fetch the state values for hold-time `up` and `down`. Expect that:
    1.  `up` is `10000`
    2.  `down` is `5000`
3.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
4.  Use gNMI subscribe (ON_CHANGE) operation to subscribe to `oper-status` path.
5.  Test scenario of a single Up -> Down -> Up transition:
    1.  Use gNMI set operation to disable the port on the control switch.
        1.  `admin-status` is "`DOWN`".
    2.  Expect that 1 `oper-status` notification is received after hold-time `down` expires with `oper-status` as "`DOWN`".
    3.  Use gNMI set operation to enable the port.
        1.  `admin-status` is "`UP`".
    4.  Expect that 1 `oper-status` notification is received after hold-time `up` expires with `oper-status` as "`UP`".
    5.  Use gNMI get operation to fetch the state value for `carrier-transitions`.
    6.  Expect that:
        1.  `carrier-transitions` is `2` more than the value fetched in step 3.

6.  Test scenario of a continuous Up -> Down -> Up transitions:
    1.  Cause the port to flap `N` times continuously on the control switch.
    2.  Expect that no` oper-status` change notification is received since hold-time `down` has been configured.
    3.  Use gNMI get operation to fetch the state values for `oper-status` and `carrier-transitions`.
    4.  Expect that:
        1.  `oper-status` is "`UP`"
        2.  `carrier-transitions` is same as the value fetched in step 5e.

## FEC Configuration Tests
The tests in this section cover the following gNMI paths.

-   /interfaces/interface[name=<port>]/ethernet/config/fec-mode
-   /interfaces/interface[name=<port>]/ethernet/state/fec-mode

### Test 1: Set valid FEC mode

Using dual switch setup, the following steps will be performed:

1.  Save the current system configuration
2.  Use gNMI get operations to get the list of all interfaces in the system
3.  For each interface
    1.  get the current speed, number of lanes of the interface
        1.  speed is /interfaces/interface[name=<port>]/ethernet/state/port-speed
        2.  lanes are /interfaces/interface[name=<port>]/state/physical-channel
    2.  based on the current interface speed and number of lanes, get the supported FEC modes
            The map of valid values:
            1.  400G (4 or 8 lane) - RS544-2xN
            2.  200G (2 or 4 lanes) - RS544-2xN, RS544
            3.  100G (1 lane) - RS544-2xN, RS544
            4.  100G (2 lane) - RS544, RS528
            5.  100G (4 lane) - RS528, None
            6.  40G - None
            7.  10G - None

    3.  for each valid FEC mode, configure the FEC setting on both the SUT and control switch
    4.  read back the FEC configuration for the port, verify it matches
    5.  verify the port is up
4.  Restore the original system configuration

### Test 2: Set invalid FEC mode

1.  Save the current system configuration
2.  Use gNMI get operations to get the list of all interfaces in the system
3.  For each interface
    1.  get the current speed, number of lanes of the interface
    2.  based on the current interface speed and number of lanes, get an unsupported FEC mode
        1.  A map of valid invalid is (note: just picking a different value from the map above may not work as TH3 and TH4G have different capabilities):
            1.  400G (4 or 8 lane) - None/FC/RS528
            2.  200G (2 or 4 lanes) - None/FC/RS528
            3.  100G (1 lane) - None/FC/RS528
            4.  100G (2 lane) - RS544-2xN/FC
            5.  100G (4 lane) - FC/RS544/RS544-2xN
            6.  40G - RS528/RS544/RS544-2xN
            7.  10G - RS528/RS544/RS544-2xN

    3.  configure the unsupported FEC mode on the SUT
    4.  read back the FEC configuration for the port, verify it remains unchanged (note: may be unset)
    5.  verify port remains up
4.  Restore the original system configuration
