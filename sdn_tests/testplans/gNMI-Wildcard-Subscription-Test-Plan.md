# **Objective**

This document outlines gNMI wildcard subscription feature testing for Sonic-Gnmi, and defines test cases for paths that support wildcards subscription.


# **Overview**

Wildcard subscription allows gNMI clients to subscribe to paths with wildcard keys. Wildcard subscription must have the following support:



1. Be able to subscribe to all the current nodes/paths matching the wildcard key
2. Be able to subscribe to newly created nodes/paths matching the wildcard key
3. Be able to receive update for deleted key which matches the wildcard key


This test plan focuses on wildcard feature requirements above. The purpose is not to test full gNMI subscription features. gNMI subscription feature testing should be covered by other test plans. For example, we will test leaf value change with ON\_CHANGE subscription, but will not test all defined enumeration values.


## Covered Wildcard Subscription Features


### ON\_CHANGE Wildcard Subscription



1. Initial updates
2. Update\_only
3. Leaf value change
4. Leaf node deletion
5. New key creation
6. Old key deletion


### TARGET\_DEFINED Wildcard Subscription



1. Initial updates
2. Update\_only
3. Leaf value changes
4. Leaf node deletion
5. New key creation
6. Old key deletion
7. Fallback to SAMPLE subscription

## **Covered Paths**


### Paths with ON_CHANGE

<table>
  <tbody>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/admin-status</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/id </em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/oper-status</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/health-indicator</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/hardware-port</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/ethernet/state/port-speed</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/ethernet/state/negotiated-port-speed</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/components/component/integrated-circuit/state/node-id</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/components/component[name=*]/software-module/state/module-type</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/components/component/state/parent</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/components/component[name=*]/state/type</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/components/component[name=*]/state/oper-status</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/components/component[name=*]/state/software-version</em></td>
    </tr>
    <tr>
      <td><em>/system/alarms/alarm[id=*]/state/severity</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/qos/interfaces/interface[name=*]/output/queues/queue/state/id</em></td>
    </tr>
  </tbody>
</table>

## Paths with TARGET_DEFINED

<table>
  <tbody>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-broadcast-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-multicast-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/out-unicast-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/out-broadcast-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/out-multicast-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-octets</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/out-octets</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-discards</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/out-discards</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-errors</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/out-errors</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/interfaces/interface[name=*]/state/counters/in-fcs-errors</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/qos/interfaces/interface[name=*]/output/queues/queue/state/transmit-pkts</em></td>
    </tr>
    <tr>
      <td><em>/openconfig/qos/interfaces/interface[name=*]/output/queues/queue/state/transmit-octets</em></td>
    </tr>
    <tr>
      <td><em>/qos/interfaces/interface[name=*]/output/queues/queue/state/dropped-pkts</em></td>
    </tr>
  </tbody>
</table>


  ### Initial Setup

The testbed is initially setup as follows:



*   SUT is installed with the image under test using push-imager. The corresponding config is generated and pushed to initialize all relevant modules of the switch ASIC (ports, buffers etc)
*   The peripheral devices connected to the SUT (control switch, Ixia or hosts) are initialized.
    *   Control switch - installed using push-imager and configured. The stack (GPINs vs SC) running on the control switch is decided by the install test at run time depending on the suite of tests.
    *   Ixia - Initialized using Smartlab’s Ixia driver.
    *   Hosts - Initialized using Biglab’s traffic service to run Sandblaster.


# Test Strategy

Since wildcard subscription features are the same regardless of paths, we will describe the testing procedure for each feature, plus the input and expected output for each step. Then we can develop corresponding test cases for covered paths. For each test case, only the test preparation, input, and expected output need to be specified.

For subscription feature testing, we need to trigger DUT to generate updates. The following need to be specified as well for the test:



*   Operations(configurations, controls) to trigger state changes or updates.
*   Expected output of these operations for validation. 

We call such a set of information WS\_TDSET. Each WS\_TDSET define a test step data unit, which may includes:



1. Operations
*   SubscribeRequest
*   Configuration push to DUT
*   Controls to the control switch
*   Controls to the traffic generator
2. Timeout
*   A timeout value for the operation to finish
3. Expectation
*   Expected update(s) from DUT (path & value)

Note:



1. For a single path, most (if not all) features can be tested in one combined execution to save execution time and restore the switch state.
2. Component testing has been done for all the supported paths using DB manipulation. 
3. Triggers for some paths are marked as TBD. Need to work with the backend path owners to figure them out.


## Common Features for ON\_CHANGE and TARGET\_DEFINED

For TARGET\_DEFINED subscription, Sonic-Gnmi uses SAMPLE mode for paths with no ON\_CHANGE support. Most features are the same for ON\_CHANGE and TARGET\_DEFINED(SAMPLE) subscriptions, with the difference of update speed. By adjusting the timeout value of the update, we can use the same set of feature tests for both subscription modes.


#### WS-CF-1 sync\_response and updates\_only


##### Test Scenario

Verify sync\_response with no initial updates



1. There should always be a sync\_response for SubscribeRequest.
2. There shouldn’t be any initial update.

##### Input & WS\_TDSETs

```
Path to be tested.
Example: /openconfig/interfaces/interface[name=*]/state/admin-status
WS_TDSET:
*   `timeout`
*   `Configs to initialize DUT`
*   `SubscribeRequest`
```
##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <td><p><pre>
path
</pre></p></td>
      <td><code>Path to be tested.<br>
<br>
<em>Example: </code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></td>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<br>
<ul>
<li><code>SubscribeRequest</code></li>
</ul>
<p><pre>
Optional. Only needed if the test requires a specific SubscribeRequest
</pre></p></td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Send SubscribeRequest with updates_only = true
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
Wait for sync_response
</pre></p></td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
<ul>
<li><code>No update received</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

####

#### WS-CF-2 sync_response with Initial Updates

##### Test Scenario

Verify initial updates and sync_response:

1.  There should always be a sync_response for SubscribeRequest.
2.  The initial updates should include all paths matching the wildcard path.


##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th>
<em></code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>
<ul>
<li><code>timeout</code></li>
<li><code>Configs to initialize DUT</code></li>
<li><code>SubscribeRequest</code></li>
</ul>
</td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Initialize DUT with tdset1 if needed (optional)
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
Retrieve DUT initial state for validation
</pre></p>

<ul>
<li><code>Get Initial state of DUT using GetRequest on the subtree node with wildcard key</code></li>
</ul>
<p><pre>
Example: /openconfig/interfaces/interface
</pre></p>

<br>
<ul>
<li><code>From the GetResponse, extract all paths and values that match tested wildcard path (expected updates)</code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
3
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Send ON_CHANGE SubscribeRequest to DUT with updates_only = false</code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
4
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Collect updates in to $updates </code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
5
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Validate DUT $updates against expected updates from step 2</code></li>
</ul>
</td>
      <td><ul>
<li><code>Every expected update has matched DUT update</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#### WS-CF-3 Leaf Value Change

##### Test Scenario

Verify gNMI update when the value of a leaf node changes.

-   The update should match the changed value.

Refer
[gNMI spec](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#3523-sending-telemetry-updates)
for the requirements. \
This test can be done after WS-CF-1 to save setup time.

##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<ul>
<li><code>Configs to initialize DUT</code></li>
</ul>
<ul>
<li><code>SubscribeRequest</code></li>
</ul>
</td>
      <td></td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<ul>
<li><code>Configs or control switch operations to trigger value
change</code></li>
</ul>
<ul>
<li><code>Expected leaf value</code></li>
</ul>
</td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Initialize DUT with tdset1 if needed
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Send SubscribeRequest with updates_only=false to DUT </code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
3
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Collect initial updates into $init_updates, which may be
used in step 4 to derive changed values</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
<ul>
<li><code>Receive DUT updates</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
4
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Apply operations to trigger one leaf node value
change</code></li>
</ul>
<ul>
<li><code>The leaf node may be fixed, or randomly picked</code></li>
</ul>
<p><pre>
The changed value may be based on $init_updates from step3
</pre></p></td>
      <td><ul>
<li><code>Operation(s) succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
5
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Wait and validate DUT update</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive DUT update with expected value.</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

####

#### WS-CF-4 Leaf Node Deletion

##### Test Scenario

Verify gNMI update when an existing leaf node is removed.

-   A delete update should be received for the leaf node.

Refer
[gNMI spec](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#3523-sending-telemetry-updates)
for the requirements. \
This test can be done after WS-CF-1 to save setup time.

##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th>
<em></code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<ul>
<li><code>Configs to initialize DUT </code></li>
</ul>
<ul>
<li><code>SubscribeRequest</code></li>
</ul>
</td>
 <td></td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<ul>
<li><code>Configs or control switch operations to remove a matched
leaf node</code></li>
</ul>
<ul>
<li><code>Expected delete update (path)</code></li>
</ul>
</td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Initialize DUT with tdset1 if needed
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Send SubscribeRequest with updates_only=false to DUT </code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
3
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Collect initial updates into $init_updates, which may be
used in step 4 to pick leaf node</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
<ul>
<li><code>Receive DUT updates</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
4
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Apply operations to remove one leaf node</code></li>
</ul>
<p><pre>
The leaf node may be fixed, or randomly picked
</pre></p></td>
      <td><ul>
<li><code>Operation(s) succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
5
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Wait and validate DUT update (delete)</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive DUT delete update with removed node</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

####

#### WS-CF-5 New Key Creation
##### Test Scenario

Verify gNMI update when a matched new key and leaf node (subtree) are
created.

Refer
[gNMI spec](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#3523-sending-telemetry-updates)
for the requirements.

##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th>
<em></code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<ul>
<li><code>Configs to initialize DUT </code></li>
</ul>
<ul>
<li><code>SubscribeRequest</code></li>
</ul>
</td>
      <td></td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
<ul>
<li><code>Configs or control switch operations to trigger new key and
subscribed leaf node being created</code></li>
</ul>
<ul>
<li><code>Expected leaf value</code></li>
</ul>
</td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Initialize DUT with tdset1 if needed
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Send SubscribeRequest with updates_only=false to DUT </code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
3
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Collect initial updates into $init_updates, which may be
used in step 4 to derive new node</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
<ul>
<li><code>Receive DUT updates</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
4
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Apply operations to create a new key with subscribed leaf
node</code></li>
</ul>
</td>
      <td><ul>
<li><code>Operation(s) succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
5
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Wait and validate DUT update</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive DUT update with newly created key and value</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

####

#### WS-CF-6 Old Key Deletion

##### Test Scenario

Verify gNMI update when a matched key (subtree) is removed.

-   Create a new key with subscribed leaf node
-   Verify receiving update for new leaf node

Refer
[gNMI spec](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#3523-sending-telemetry-updates)
for the requirements. \
**This test should be combined with WS-CF-5 to save time and restore the
original switch state.**

##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th><
<em></code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout </code></li>
</ul>
<ul>
<li><code>Configs to initialize DUT</code></li>
</ul>


<ul>
<li><code>SubscribeRequest</code></li>
</ul>
</td>
      <td></td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>Configs or control switch operations to remove a matched key
(subtree)</code></li>
</ul>
<ul>
<li><code>Expectation: expected delete update (path)</code></li>
</ul>
<ul>
<li><code>timeout</code></li>
</ul>
</td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Initialize DUT with tdset1 if needed
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Send SubscribeRequest with updates_only=false to DUT </code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
3
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Collect initial updates into $init_updates, which may be used in step 4 to pick deleted key</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
<ul>
<li><code>Receive DUT updates</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
4
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Apply operations to remove a matched key(subtree)</code></li>
</ul>
<p><pre>
The picked key may be based on $init_updates from step3, or the newly created key in WS-CF-5 if the tests are combined
</pre></p></td>
      <td><ul>
<li><code>Operation(s) succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
5
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Wait and validate DUT update</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive DUT delete update on the removed key and leaf</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## TARGET_DEFINED Specific Features

#### WS-TF-1 Use SAMPLE for TARGET_DEFINED

##### Test Scenario

Verify TARGET_DEFINED subscription uses SAMPLE (with periodic updates)

for the requirements.

##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th><
<em></code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>
<ul>
<li><code>timeout</code></li>
<li><code>Configs to initialize DUT</code></li>
<li><code>SubscribeRequest</code></li>
</ul>
</td>
      <td></td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
</td>
      <td></td>
    </tr>
    <tr>
      <td><p><pre>
tdset3
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<ul>
<li><code>timeout</code></li>
</ul>
</td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Initialize DUT with tdset1 if needed
</pre></p></td>

<td>
<ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Send TARGET_DEFINED SubscribeRequest to DUT</code></li>
</ul>
</td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
3
</pre></p></td>
      <td><p><pre>
tdset1
</pre></p>

<ul>
<li><code>Wait for sync_response and initial updates	</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive sync_response</code></li>
</ul>
<ul>
<li><code>Receive updates</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
5
</pre></p></td>
      <td><p><pre>
tdset2
</pre></p>

<ul>
<li><code>Wait for periodic updates</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive updates</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
6
</pre></p></td>
      <td><p><pre>
tdset3:
</pre></p>

<ul>
<li><code>Wait for periodic updates</code></li>
</ul>
</td>
      <td><ul>
<li><code>Not timed out</code></li>
</ul>
<ul>
<li><code>Receive updates</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## Negative Testing

#### WS-NF-1 Subscribe to paths without wildcard subscription support

##### Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
Path to be tested.
</pre></p></th>
      <th>
<em>Example: </code>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
Subscription mode
</pre></p></td>
      <td><p><pre>
ON_CHANGE and/or TARGET_DEFINED
</pre></p></td>
      <td></td>
    </tr>
  </tbody>
</table>

##### Test Steps

<table>
  <thead>
    <tr>
      <th></th>
      <th>Operation</th>
      <th>Expected Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
1
</pre></p></td>
      <td><p><pre>
Send SubscribeRequest with updates_only = true
</pre></p></td>
      <td><ul>
<li><code>Succeed</code></li>
</ul>
</td>
    </tr>
    <tr>
      <td><p><pre>
2
</pre></p></td>
      <td><p><pre>
Wait for response
</pre></p></td>
      <td><ul>
<li><code>Error response</code></li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#

# Test Cases (Per Path)

### ON_CHANGE Paths

### /openconfig/interfaces/interface[name=*]/state/admin-status

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>
<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

2.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>
<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

3.  WS-CF-3 Leaf Value Change
Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<br>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/config/enabled
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{ "openconfig-interfaces:enabled": $enable }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$enable
</pre></p></td>
      <td><p><pre>
false if picked $ifname admin-status is "UP"
</pre></p>

<p><pre>
true  if picked $ifname admin-status is "DOWN"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"UP    if $enable is true
</pre></p>

<p><pre>
"DOWN" if $enable is false
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

4.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-interfaces:interfaces":{"interface":[{"name":"$ifname","config":{"name":"$ifname", "enabled":true}}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"UP"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<br>
<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/id

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/config/id
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{ "openconfig-pins-interfaces:id": $id }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$id
</pre></p></td>
      <td><p><pre>
Random uint32
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$id
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/config/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates or use the same from WS-CF-3
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-interfaces:interfaces":{"interface":[{"name":"$ifname","config":{"name":"$ifname", "id":$id}}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$id
</pre></p></td>
      <td><p><pre>
Random uint32
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$id
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/admin-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

###

### /openconfig/interfaces/interface[name=*]/state/oper-status

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th>/openconfig/interfaces/interface[name=*]/state/oper-status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><br>
/openconfig/interfaces/interface[name=*]/state/oper-status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to Control Switch
</pre></p></th>
      <th><ul>
<li><code>Update Path</code></li>
</ul>
<p><pre>
/openconfig/interfaces/interface[name=$ifname]/config/enabled
</pre></p>

<ul>
<li><code>Payload</code></li>
</ul>
<p><pre>
{ "openconfig-interfaces:enabled": $enable }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates (Ethernet0, Ethernet1, …)
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$enable
</pre></p></td>
      <td><p><pre>
false if picked $ifname oper-status is "UP"
</pre></p>

<p><pre>
true  if picked $ifname oper-status is "DOWN"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"UP    if $enable is true
</pre></p>

<p><pre>
"DOWN" if $enable is false
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion

> Not Applicable

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-interfaces:interfaces":{"interface":[{"name":"$ifname","config":{"name":"$ifname", "enabled":true}}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"UP"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/health-indicator

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/config/health-indicator
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{ "openconfig-pins-interfaces:health-indicator": $hind }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$hind
</pre></p></td>
      <td><p><pre>
Randomly picked from [ "GOOD, "BAD" ]
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates (Ethernet0, Ethernet1, …)
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$hind
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/config/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-interfaces:interfaces":{"interface":[{"name":"$ifname","config":{"name":"$ifname", "enabled":true}, "openconfig-pins-interfaces:health-indicator":"openconfig-pins-interfaces:GOOD}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"openconfig-pins-interfaces:GOOD"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/health-indicator
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/hardware-port

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion
Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Refer to go/gpins-gnmi-port-mgmt-test-plan
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/ethernet/state/mac-address

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><br>
/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config/mac-address
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-if-ethernet:mac-address":"$mac"}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$mac
</pre></p></td>
      <td><p><pre>
"06:05:04:03:02:01"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$mac
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-interfaces:interfaces":{"interface":[{"name":"$ifname","config":{"name":"$ifname", "ethernet":{"config":{"mac-address":"$mac"}}}}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$mac
</pre></p></td>
      <td><p><pre>
"06:05:04:03:02:01"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$mac
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/ethernet/state/negotiated-port-speed

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-if-ethernet:config":{"port-speed":"openconfig-if-ethernet:SPEED_100GB","auto-negotiate":true}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-if-ethernet:config":{"port-speed":"$speed", "auto-negotiate":false}}
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Ethernet0
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$speed
</pre></p></td>
      <td><p><pre>
Random pick from:
</pre></p>

<p><pre>
openconfig-if-ethernet:SPEED_1GB
</pre></p>

<p><pre>
openconfig-if-ethernet:SPEED_10GB
</pre></p>

<p><pre>
openconfig-if-ethernet:SPEED_100GB
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$speed
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion (N/A)

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-if-ethernet:config":{"port-speed":"$speed","auto-negotiate":true}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$speed
</pre></p></td>
      <td><p><pre>
"openconfig-if-ethernet:SPEED_10GB"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$speed
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/negotiated-port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/ethernet/state/port-speed

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config/port-speed
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-if-ethernet:port-speed":"$speed"}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$speed
</pre></p></td>
      <td><p><pre>
Random pick from:
</pre></p>

<p><pre>
openconfig-if-ethernet:SPEED_1GB
</pre></p>

<p><pre>
openconfig-if-ethernet:SPEED_10GB
</pre></p>

<p><pre>
openconfig-if-ethernet:SPEED_100GB
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$speed
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/config/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Randomly picked from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/interfaces
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-interfaces:interfaces":{"interface":[{"name":"$ifname","config":{"name":"$ifname", "ethernet":{"config":{"port-speed":"$speed"}}}}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
Loopback1234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$speed
</pre></p></td>
      <td><p><pre>
"openconfig-if-ethernet:SPEED_10GB"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$speed
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/ethernet/state/mac-address
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
"Loopback1234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/ethernet/state/port-speed
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/components/component[name=*]/integrated-circuit/state/node-id

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/components/component[name=$cname]/integrated-circuit/config/node-id
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{ ""openconfig-pins-platform-node:node-id": $nid }
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$nid
</pre></p></td>
      <td><p><pre>
Randomly generated node id
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
Randomly picked integrated-circuit name from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/integrated-circuit/stateg/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$nid
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion
Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/components/component[name=$cname]/integrated-circuit/config/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
Randomly picked integrated-circuit name from $init_updates
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/components
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-platform:components":{"component":[{"name":"$cname","config":{"name":"$cname"},"integrated-circuit":{"node-id":"$nid"}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
integrated_circuit01234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$nid
</pre></p></td>
      <td><p><pre>
Randomly generated int64
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
$nid
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
dset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/components/component[name=$cname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
"integrated_circuit01234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/integrated-circuit/state/node-id
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/components/component[name=*]/software-module/state/module-type

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/software-module/state-module-type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/software-module/state-module-type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change (N/A)

1.  WS-CF-4 Leaf Node Deletion (N/A)

1.  WS-CF-5 New Key Creation (N/A)

1.  WS-CF-6 Old Key Deletion (N/A)

### /openconfig/components/component/state/parent

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/parent
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/parent
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change (N/A)

1.  WS-CF-4 Leaf Node Deletion (N/A)

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/parent
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/components
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-platform:components":{"component":[{"name":"$cname","config":{"name":"$cname"},"integrated-circuit":{"node-id":"$nid"}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
integrated_circuit01234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$nid
</pre></p></td>
      <td><p><pre>
Randomly generated int64
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/state/parent
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"chassis"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/parent
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
dset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/components/component[name=$cname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
"integrated_circuit01234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/parent
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/components/component[name=*]/state/type

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change (N/A)

1.  WS-CF-4 Leaf Node Deletion (N/A)

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/components
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-platform:components":{"component":[{"name":"$cname","config":{"name":"$cname"},"integrated-circuit":{"node-id":"101234"}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
integrated_circuit01234
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/state/type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"openconfig-platform-types:INTEGRATED_CIRCUIT"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
dset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/components/component[name=$cname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
"integrated_circuit01234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/type
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/components/component[name=*]/state/oper-status

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Update Path
</pre></p>

<p><pre>
/openconfig/components
</pre></p>

<p><pre>
Payload
</pre></p>

<p><pre>
{"openconfig-platform:components":{"component":[{"name":"$cname","config":{"name":"$cname"},"integrated-circuit":{"node-id":"$nid"}]}}}
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
integrated_circuit01234
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$nid
</pre></p></td>
      <td><p><pre>
Randomly generated int64
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=$cname]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"openconfig-platform-types:UNSET"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
dset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/components/component[name=$cname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
"integrated_circuit01234"
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/oper-status
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/components/component[name=*]/state/software-version

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/software-version
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/components/component[name=*]/state/software-version
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change (N/A)

1.  WS-CF-4 Leaf Node Deletion (N/A)

1.  WS-CF-5 New Key Creation (N/A)

1.  WS-CF-6 Old Key Deletion (N/A)

### /openconfig/system/alarms/alarm[id=*]/state/severity

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/system/alarms/alarm[id=*]/state/severity
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/system/alarms/alarm[id=*]/state/severity
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change (N/A)
1.  WS-CF-4 Leaf Node Deletion (N/A)
1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/system/alarms/alarm[id=*]/state/severity
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Use gNOI to set $cname to ERROR state
</pre></p>

<br>
<p><pre>
Refer to go/gpins-gnmi-alarms-e2e-test-plan
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$cname
</pre></p></td>
      <td><p><pre>
Random pick from [ p4rt, orchagent, syncd, telemetry, host ]
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/system/alarms/alarm[id=$alarmid]/state/severity
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$alarmid
</pre></p></td>
      <td><p><pre>
ignore
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
"openconfig-alarm-types:CRITICAL"
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

## TARGET_DEFINED Paths

Since all required TARGET_DEFINED paths are counters, which don't support
ON_CHANGE. So the TARGET_DEFINED subscription will become SAMPLE subscription.

Currently all paths which need TARGET_DEFINED support are counters. So all of
them will share the same test cases other than the value change triggering part.
We will define detailed test cases for one, and only specify the triggers for
the rest of the counters.

### /openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts

1.  WS-CF-1 sync_response and updates_only

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-2 sync_response with Initial Updates

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-4 Leaf Node Deletion (N/A)
1.  WS-CF-5 New Key Creation

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
time
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one leaf node
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-CF-6 Old Key Deletion

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to remove one subtree(key)
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
Delete Path
</pre></p>

<p><pre>
/openconfig/interfaces/interface[name=$ifname]
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
$ifname
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected delete update
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/hardware-port
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

1.  WS-TF-1 Use SAMPLE for TARGET_DEFINED

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
2000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset3
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
2000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/in-broadcast-pkts

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-broadcast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-broadcast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/in-multicast-pkts

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-multicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-multicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/out-unicast-pkts

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/out-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/out-unicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/out-broadcast-pkts

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/out-broadcast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/out-broadcast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/out-multicast-pkts

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/out-multicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/out-multicast-pkts
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/in-octets

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-octets
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-octets
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/out-octets

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/out-octets
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/out-octets
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/in-discards

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-discards
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-discards
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/out-discards

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/out-discards
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/out-discards
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/in-errors

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-errors
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-errors
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/out-errors

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/out-errors
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/out-errors
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/interfaces/interface[name=*]/state/counters/in-fcs-errors

1.  WS-CF-3 Leaf Value Change

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/counters/in-fcs-errors
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
tdset1
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
3000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

</td>
    </tr>
    <tr>
      <td><p><pre>
tdset2
</pre></p></td>
      <td><p><pre>
WS_TDSET:
</pre></p>


<table>
  <thead>
    <tr>
      <th><p><pre>
timeout
</pre></p></th>
      <th><p><pre>
1000ms
</pre></p></th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

<p><pre>
Configs or control switch operations to trigger value change
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
SetRequest to DUT
</pre></p></th>
      <th><p><pre>
TBD
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
SetRequest to Control Switch
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
    <tr>
      <td><p><pre>
Control to Traffic Generator
</pre></p></td>
      <td><p><pre>
TBD
</pre></p></td>
    </tr>
  </tbody>
</table>

<p><pre>
Expected leaf value
</pre></p>

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=$ifname]/state/counters/in-fcs-errors
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
value
</pre></p></td>
      <td><p><pre>
Increased
</pre></p></td>
    </tr>
  </tbody>
</table>

</td>
    </tr>
  </tbody>
</table>

### /openconfig/qos/interfaces/interface[name=*]/output/queues/queue/state/transmit-pkts

## Negative Testing

**/openconfig/interfaces/interface[name=*]/state/ethernet**

1.  WS-NF-1 Subscribe to paths without wildcard subscription support

Input & WS_TDSETs

<table>
  <thead>
    <tr>
      <th><p><pre>
path
</pre></p></th>
      <th><p><pre>
/openconfig/interfaces/interface[name=*]/state/ethernet
</pre></p></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><p><pre>
Subscription mode
</pre></p></td>
      <td><p><pre>
ON_CHANGE
</pre></p></td>
    </tr>
  </tbody>
</table>

