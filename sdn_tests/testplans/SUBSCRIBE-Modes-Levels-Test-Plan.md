# Overview

This document aims to outline the approach for testing the functionality of different SUBSCRIBE modes of the gNMI protocol as part of OpenConfig end-to-end testing. Subscriptions in gNMI can be periodic or event driven. Modifiers can also be applied to request heartbeat updates or filter out unchanged values.

This document also covers testing for different subscription levels. The covered subscription levels are root, subtree and leaf. They will be tested for each subscription mode.

# Background

gNMI is responsible for monitoring, streaming telemetry, and configuration management. Sonic-Gnmi streaming telemetry is based on the standard OpenConfig model.

SUBSCRIBE is broken into 3 modes with further submodes for STREAM:

-   ONCE
    -   Provides a single response with all requested data and closes the connection.
-   POLL
    -   Provides an updated response each time a *poll request* is received.
-   STREAM
    -   ON_CHANGE
        -   Only certain nodes support this mode. Provides an updated response that is triggered by an update to the backend database.
    -   SAMPLE
        -   Provides an updated response that is triggered by a timer.
    -   TARGET_DEFINED
        -   A mixture of ON_CHANGE and SAMPLE updates. Preference is for ON_CHANGE if it is supported.

-   Optional Flags
    -   Updates_only - Does not provide initial data
    -   Heartbeat_interval - Provide full data based on timer. Used to override other flags.
    -   Suppress_redundant - Do not provide data that has not changed since last update.

Not all modes are supported for a subscription level/point. Below is a summary of the expected support at each level as well as different optional flags:

<table>
  <thead>
    <tr>
      <th></th>
      <th><br>
ONCE</th>
      <th><br>
POLL</th>
      <th><br>
ON_CHANGE</th>
      <th><br>
SAMPLE</th>
      <th><br>
TARGET_DEFINED</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
Root </td>
      <td><br>
Yes</td>
      <td><br>
Yes</td>
      <td><br>
No</td>
      <td><br>
Yes</td>
      <td><br>
Yes (same as SAMPLE)</td>
    </tr>
    <tr>
      <td><br>
Subtree</td>
      <td><br>
YES</td>
      <td><br>
YES</td>
      <td><br>
No</td>
      <td><br>
Yes</td>
      <td><br>
Yes (same as SAMPLE)</td>
    </tr>
    <tr>
      <td><br>
Leaf</td>
      <td><br>
Yes</td>
      <td><br>
Yes</td>
      <td><br>
Depends on Requirements</td>
      <td><br>
Yes</td>
      <td><br>
Yes (can be SAMPLE or ON_CHANGE depends on the node)</td>
    </tr>
    <tr>
      <td><br>
updates_only</td>
      <td><br>
yes</td>
      <td><br>
yes</td>
      <td><br>
yes</td>
      <td><br>
yes</td>
      <td><br>
yes</td>
    </tr>
    <tr>
      <td><br>
heartbeat_interval</td>
      <td><br>
no</td>
      <td><br>
no</td>
      <td><br>
yes</td>
      <td><br>
yes</td>
      <td><br>
yes</td>
    </tr>
    <tr>
      <td><br>
suppress_redundant</td>
      <td><br>
no</td>
      <td><br>
no</td>
      <td><br>
no</td>
      <td><br>
Yes</td>
      <td><br>
Yes (if it is a Sample leaf)</td>
    </tr>
  </tbody>
</table>

For TARGET_DEFINED subscription, current Sonic-Gnmi implementation will use SAMPLE on the whole subtree if any node in the subtree doesn't support ON_CHANGE. So for root and subtree level TARGET_DEFINED subscription, only SAMPLE is covered. Mixed-use of ON_CHANGE and SAMPLE may be added in the future if it is required and implemented.

# gNMI Feature Requirements to be tested

It is important to address any gaps to the gNMI specification in Sonic-Gnmi. This test plan focuses on the verification of functional aspects of the Subscribe RPC of different types and levels. Other gNMI features are covered in other test plans.

# E2E Test Cases

## SUBSCRIBE ONCE

### Expectation

The correct data is returned and is followed by a sync_response and a closed connection. Prior to executing a test, send a GET request to establish a viable interface name ${INTERFACE} and then for the same path to establish the correct data.

### Tests

-    Simple ONCE

Condition to test: Simple ONCE subscription

1.  Root level subscription

Xpath: /openconfig
Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { origin: "openconfig" prefix {target:"YANG"} mode:ONCE encoding: PROTO subscription: { path: {} }}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify updates have all the supported top-containers:</li>
</ul>
<br>
interfaces, components, qos, system<br>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>The connection is closed</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

2.  Top container level subscription
Xpath: /openconfig/${CONTAINER}
${CONTAINER} is one of [ "interfaces", "components", "qos", "system"]

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:ONCE encoding: PROTO subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"${CONTAINER}" } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>The connection is closed</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

3.  Subtree level subscription with key
Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config

Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:ONCE encoding: PROTO subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>The connection is closed</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

4.  Leaf level subscription

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config/enabled

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:ONCE encoding: PROTO subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} elem: {name: "enabled"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/enabled is returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>The connection is closed</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   ONCE w/ Updates Only

    -   Condition to test: ONCE subscription with updates_only
    -   For each of the tested cases in Simple ONCE:
1.  subscribe with { updates_only: true }.
2.  In step 2 validation, only need to check sync_response

> Example:\
Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config\
Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:ONCE encoding: PROTO updates_only: true subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>The connection is closed</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## SUBSCRIBE POLL

### Expectation

Correct data is returned each time a POLL request is sent. Prior to executing a test, send a GET request to establish a viable interface name ${INTERFACE} and then for the same path to establish the correct data.  Any un-declared responses during these tests should be considered a failure.

### Tests

-   Simple POLL

Condition to test: Simple POLL request with multiple POLLs

1.  Root level subscription

> Xpath: /openconfig\
Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { origin: "openconfig" prefix {target:"YANG"} mode:POLL encoding: PROTO subscription: { path: {} }}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify updates have all the supported top-containers:</li>
</ul>
<br>
interfaces, components, qos, system<br>
<ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify updates have all the supported top-containers:</li>
</ul>
<br>
interfaces, components, qos, system</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify updates have all the supported top-containers:</li>
</ul>
<br>
interfaces, components, qos, system</td>
    </tr>
  </tbody>
</table>

2.  Top container level subscription

> Xpath: /openconfig/${CONTAINER}\
${CONTAINER} is one of [ "interfaces", "components", "qos", "system"]

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:POLL encoding: PROTO subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"${CONTAINER}" } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* are returned.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* are returned.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

3.  Subtree level subscription with key

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:POLL encoding: PROTO subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

4.  Leaf level subscription

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config/enabled

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:POLL encoding: PROTO subscription: {
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} elem: {name: "enabled"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/enabled are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/enabled is returned.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Poll</td>
      <td><p><pre>
poll:{}
</pre></p></td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/enabled is returned.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   POLL w/ Updates Only

Condition to test: Same as Simple Poll but with updates only.\
For each test case in Simple POLL:

1.  Subscribe with { updates_only: true }
2.  The step 2 validation only needs to check sync_response.

For example:\

Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:POLL encoding: PROTO updates_only:true … }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Poll</td>
      <td><p><pre>
same
</pre></p></td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><br>
same</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Poll</td>
      <td><p><pre>
same
</pre></p></td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><br>
same</td>
    </tr>
  </tbody>
</table>

## SUBSCRIBE STREAM: SAMPLE

### Expectation

Correct data is sent on a requested interval. Heartbeat_interval, supress_redundant, and updates_only are all respected. Prior to executing a test, send a GET request to establish a viable interface name ${INTERFACE} and then for the same path to establish the correct data. Any un-declared responses during these tests should be considered a failure.

### Tests

-   Simple SAMPLE

> Condition to test: Simple SUBSCRIPTION with interval ${T}. This test should be repeated for at least two values of T. Suggested use of `2000000000, 3000000000, and 4000000000 for values of 2-4 seconds respectively.`

1.  Root level subscription

> Xpath: /openconfig\
Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { origin: "openconfig" prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: SAMPLE sample_interval: ${T} path: {} }}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify updates have all the supported top-containers:</li>
</ul>
<br>
interfaces, components, qos, system<br>
<ul>
<li>A sync_response is received.</li>
</ul>
<ul>
<li>Verify that the /openconfig/* is returned two more times in less than 3*T time.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

2.  Top container level subscription

> Xpath: /openconfig/${CONTAINER}\
${CONTAINER} is one of [ "interfaces", "components", "qos", "system"]

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: {  mode: SAMPLE sample_interval: ${T} path: { origin: "openconfig" elem: { name:"${CONTAINER}" } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* is returned two more times in less than 3*T time.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

3.  Subtree level subscription with key

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: SAMPLE
</pre></p>

<p><pre>
sample_interval: ${T} path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" } elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* is returned two more times in less than 3*T time.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

4.  Leaf level subscription

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config/enabled

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: SAMPLE
</pre></p>

<p><pre>
sample_interval: ${T} path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} elem: {name: "enabled"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/enabled is returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* is returned two more times in less than 3*T time.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   SAMPLE w/ invalid sample_interval
    -   Condition to test: Switch should reject invalid intervals. The unit for intervals is nano seconds and a 0 indicates as fast as possible. A 1 ns interval should always be considered infeasible.
    -   Test for each test case in Simple SAMPLE and use validation below.
    -   Validation:
        -   Verify that an InvalidArgument is returned

-   SAMPLE w/ updates_only

Condition to test: Simple SUBSCRIPTION with updates_only.

1.  Test each case in [Simple SAMPLE]with the following modifications:
-   With fixed sample_interval: 3000000000
-   With updates_only: true
-   Validation in step 2 for sync_response only

Example: Xpath: /openconfig/${CONTAINER}\
${CONTAINER} is one of [ "interfaces", "components", "qos", "system"]

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: {  mode: SAMPLE sample_interval: 3000000000 updates_only: true path: { origin: "openconfig" elem: { name:"${CONTAINER}" } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Initial updates received</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

2.  Test with MTU change

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO
</pre></p>

<p><pre>
Updates_only: true
</pre></p>

<p><pre>
subscription: {
</pre></p>

<p><pre>
mode: SAMPLE
</pre></p>

<p><pre>
sample_interval: 3000000000
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 3 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set MTU to current-1</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the interfaces/interface/[name=${INTERFACE}]/config/mtu new value is received within 3 seconds.</li>
</ul>
</td>
    </tr>
    <tr>
      <td></td>
      <td><br>
Restore</td>
      <td><ul>
<li>Set MTU back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   SAMPLE w/ supress_redundant

Condition to test: Simple SUBSCRIPTION with supress_redundant.

1.  Test each case with the following modifications:
-   With supress_redundant: true
-   Add two more steps to validate update with changed value only

Example:\Xpath: /openconfig/${CONTAINER}\
${CONTAINER} is one of [ "interfaces", "components", "qos", "system"]

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: {  mode: SAMPLE sample_interval: 3000000000 supress_redundant: true path: { origin: "openconfig" elem: { name:"${CONTAINER}" } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>A sync_response is received</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 10 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>No updates received </li>
</ul>
<br>
OR<br>
<ul>
<li>The updated value(s) must be different with previously received value(s) if there is.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

2.  Test with MTU changes

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO
</pre></p>

<p><pre>
subscription: {
</pre></p>

<p><pre>
mode: SAMPLE
</pre></p>

<p><pre>
sample_interval: 3000000000
</pre></p>

<p><pre>
suppress_redundant: true
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 3 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set MTU to current-1</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the interfaces/interface/[name=${INTERFACE}]/config/mtu new value is received within 3 seconds.</li>
</ul>
</td>
    </tr>
    <tr>
      <td></td>
      <td><br>
Restore</td>
      <td><ul>
<li>Set MTU back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   SAMPLE w/ supress_redundant & heartbeat_interval

Condition to test: Simple SUBSCRIPTION with supress_redundant.

1.  Test with MTU change

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO
</pre></p>

<p><pre>
subscription: {
</pre></p>

<p><pre>
mode: SAMPLE
</pre></p>

<p><pre>
sample_interval: 3000000000
</pre></p>

<p><pre>
suppress_redundant: true
</pre></p>

<p><pre>
heartbeat_interval: 5000000000
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 5 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned again</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Wait</td>
      <td><br>
Wait for 5 seconds</td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned again</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
7</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set MTU to current-1</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
8</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the interfaces/interface/[name=${INTERFACE}]/config/mtu new value is received within 3 seconds.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
9</td>
      <td><br>
Restore</td>
      <td><ul>
<li>Set MTU back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

2.  No subscribe level testing for this scenario.

-   SAMPLE w/ deleted Subtree

> Condition to test: Same as Simple SAMPLE but remove a subtree node and verify it is removed from the response

-   SAMPLE w/ deleted Leaf

> Condition to test: Same as Simple SAMPLE but remove a subtree node and verify it is removed from the response

## SUBSCRIBE STREAM: ON_CHANGE

### Expectation

The correct data should be returned on change. Prior to executing a test, send a GET request to establish a viable interface name ${INTERFACE} and then for the same path to establish the correct data. Updates only, and the heartbeat interval shall be respected. Any un-declared responses during these tests should be considered a failure.

### Tests

-   Simple ON_CHANGE

Condition to test: Simple SUBSCRIPTION with ON_CHANGE

1.  Test with MTU change

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO
</pre></p>

<p><pre>
subscription: {
</pre></p>

<p><pre>
mode: ON_CHANGE
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"}
</pre></p>

<p><pre>
elem: {name: "mtu"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><br>
Wait for 3 seconds</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set MTU to current-1</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the interfaces/interface/[name=${INTERFACE}]/config/mtu new value is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Restore</td>
      <td><ul>
<li>Set MTU back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   ON_CHANGE w/ invalid path
    -   Condition to test: Switch should reject unsupported paths. The following paths don't support ON_CHANGE and should be tested:
        -   Root
        -   Top-Containers

> /openconfig/interfaces\
/openconfig/components\
/openconfig/qos\
/openconfig/system

        -   Counters

1.  Path without ON_CHANGE support

> Xpath: one of the following:

-   /openconfig
-   /openconfig/interfaces
-   /openconfig/components
-   /openconfig/qos
-   /openconfig/system
-   /openconfig/interfaces/interface[name={$INTERFACE}/state/counters/in-broadcast-pkts

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO
</pre></p>

<p><pre>
subscription: {
</pre></p>

<p><pre>
mode: ON_CHANGE
</pre></p>

<p><pre>
path: { $xpath }
</pre></p>

<p><pre>
elem: {name: "state"}
</pre></p>

<p><pre>
elem: {name: "counters"}
</pre></p>

<p><pre>
elem: {name: "in-broadcast-pkts"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><br>
Verify that an InvalidArgument is returned</td>
    </tr>
  </tbody>
</table>

-   ON_CHANGE w/ updates_only

Condition to test: Simple SUBSCRIPTION with updates_only.

1.  Test MTU change

Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO Updates_only: true subscription: { mode: ON_CHANGE path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" } elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>A sync_response is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 3 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set MTU to current-1</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the interfaces/interface/[name=${INTERFACE}]/config/mtu new value is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Restore </td>
      <td><ul>
<li>Set MTU back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

####

-   ON_CHANGE w/ heartbeat_interval

Condition to test: Simple SUBSCRIPTION with heartbeat

1.  Test MTU change

Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO
</pre></p>

<p><pre>
subscription: {
</pre></p>

<p><pre>
mode: ON_CHANGE
</pre></p>

<p><pre>
heartbeat_interval: 5000000000
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 5 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set MTU to current-1</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the interfaces/interface/[name=${INTERFACE}]/config/mtu new value is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
7</td>
      <td><br>
Restore </td>
      <td><ul>
<li>Set MTU back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## SUBSCRIBE STREAM: TARGET_DEFINED

### Expectation

Some paths should behave like ON_CHANGE and others on SAMPLE. The correct data should be returned on the expected trigger. Prior to executing a test, send a GET request to establish a viable interface name ${INTERFACE} and then for the same path to establish the correct data. Any un-declared responses during these tests should be considered a failure.

-   TARGET DEFINED w/ SAMPLE

> Condition to test: TARGET_DEFINED for sampled path. The requested path for a counter should always create a SAMPLE subscription.

1.  Root level subscription

> Xpath: /openconfig\
Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { origin: "openconfig" prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: TARGET_DEFINED path: {} }}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify updates have all the supported top-containers:</li>
</ul>
<br>
interfaces, components, qos, system<br>
<ul>
<li>A sync_response is received.</li>
</ul>
<ul>
<li>Verify that the /openconfig/* is returned two more times in less than 10 seconds.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

2.  Top container level subscription

> Xpath: /openconfig/${CONTAINER}\
${CONTAINER} is one of [ "interfaces", "components", "qos", "system"]

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: {  mode: TARGET_DEFINED path: { origin: "openconfig" elem: { name:"${CONTAINER}" } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>Verify that the top container /openconfig/${CONTAINER}/* is returned two more times in less than 10 seconds.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

3.  Subtree level subscription with key

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: TARGET_DEFINED path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" } elem: {name: "config"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* are returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* is returned two more times in less than 10 seconds.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

4.  Leaf level subscription

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}/config/enabled

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: TARGET_DEFINED path: { origin: "openconfig" elem: { name:"interfaces" }
</pre></p>

<p><pre>
elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" }
</pre></p>

<p><pre>
elem: {name: "config"} elem: {name: "enabled"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/enabled is returned.</li>
</ul>
<ul>
<li>A sync_response is received</li>
</ul>
<ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/config/* is returned two more times in less than 10 seconds.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   TARGET_DEFINED w/ ON_CHANGE

Condition to test: TARGET_DEFINED for on_change path

1.  Test interface oper-status change

> Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/state/oper-status

> Test Procedure

<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: TARGET_DEFINED
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" } elem: {name: "state"}
</pre></p>

<p><pre>
elem: {name: "oper-status"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify that the interfaces/interface/[name=${INTERFACE}]/state/oper-status is returned.</li>
</ul>
<ul>
<li>A sync_response is received.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 3 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set oper-status to down</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the new status is returned</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Restore </td>
      <td><ul>
<li>Set oper-status back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

-   TARGET_DEFINED w/ on subtree

Condition to test: TARGET_DEFINED for on_change and sample path

1.  Test interface oper-status change on subtree
Xpath: /openconfig/interfaces/interface[name=${INTERFACE}]/state

### Test Procedure
<table>
  <thead>
    <tr>
      <th><br>
1</th>
      <th><br>
Subscribe</th>
      <th><p><pre>
subscribe: { prefix {target:"YANG"} mode:STREAM encoding: PROTO subscription: { mode: TARGET_DEFINED
</pre></p>

<p><pre>
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "${INTERFACE}" } elem: {name: "state"} } } } }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
2</td>
      <td><br>
Validate</td>
      <td><br>
Verify that the interfaces/interface/[name=${INTERFACE}]/state is returned.<br>
<br>
A sync_response is received.</td>
    </tr>
    <tr>
      <td><br>
3</td>
      <td><br>
Wait</td>
      <td><ul>
<li>Wait for 3 seconds</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
4</td>
      <td><br>
Trigger</td>
      <td><ul>
<li>set oper-status to down</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
5</td>
      <td><br>
Validate</td>
      <td><ul>
<li>Verify the new status is returned</li>
</ul>
</td>
    </tr>
    <tr>
      <td><br>
6</td>
      <td><br>
Restore </td>
      <td><ul>
<li>Set oper-status back at the end of the test.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>
