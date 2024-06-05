# Overview

This document aims to outline the approach for testing the stress and latency of gNMI GET/SET operations supported by the gNMI protocol as part of GPINs OpenConfig end-to-end testing. 

# Background

With SONiC as the network operating system (NOS) for GPINS, gNMI is responsible for monitoring, streaming telemetry, and configuration management.  Broadcom's Unified Management Framework (UMF) provides gNMI streaming telemetry based on the standard OpenConfig model.

The gNMI client can invoke a GET,  and/or SET request. The SET operations can be further categorized into UPDATE, REPLACE, and DELETE operations.

# gNMI Protocol Testing

The current approach to test the gNMI protocol features is to leverage the existing or planned end-to-end tests to be written for the gNMI paths. The idea is to reduce the duplication of test cases and use the ones already planned for verifying the paths to test the protocol features at the same time.\
For example, any of the tests that use a GET/SET request for any of the config leafs can be extended to also test the config subtrees. \
As to the question of which of the path tests are to be used for which feature test, that is still TBD based on the completion and review of all the path E2E tests.

# Purpose

The purpose of the gNMI stress and latency tests is to test the robustness of the gNMI server and capture various system metrics as a report at the end of the testing. The validation for the correctness of the data is out of the scope since the payload in the response ( data ) is application specific. The application (feature owner) can consume the report and set the threshold for the gNMI operations based on the platforms. 

# E2E Stress Test Cases

The purpose of the gNMI stress test is to validate the robustness of the telemetry service and overall performance. The stress testing will not validate the correctness of the data that is being received from the server.  Since the gNMI performance is dependent on the platform, the tests will not enforce the threshold to be validated as part of the validation, instead the tests will gather the metrics and produce the performance report at the end of the tests. The final report will be analyzed and checked against the platform specific requirements. There will also be periodic sanity checks during the test to capture test failures early.

The robustness is validated through the following methods

-   Monitoring the CPU load for the gNMI server
-   Validation for the any unwanted process termination during the test
-   Monitoring the memory usage of the system during the test
-   Validate that the responses are received in the client from the gNMI server.

## SET UPDATE operation

### Expectation

The expectation is for the gNMI server to process the valid update request and populate the leaf nodes with the values specified in the request payload and return the valid response to the client. If the leaf nodes are not present in the payload then the server should not populate them with the default values and leave those leaf values as-is(not modify them). The gNMI specification description can be found [here](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#344-modes-of-update-replace-versus-update).

## SET REPLACE operation

### Expectation

The expectation is for the gNMI server to process the valid replace request and populate the leaf nodes with the values specified in the request payload and return the valid response to the client. If the leaf nodes are not present in the payload then the server should populate them with the default values. The gNMI specification description can be found [here](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#344-modes-of-update-replace-versus-update).

## SET DELETE operation

### Expectation

The expectation is for the gNMI server to process the valid delete request and remove those nodes from the system. The server should send a valid response to the client once the request has been processed successfully.

## GET operation

### Expectation

The GET response should contain the value of the request nodes. The expectation is for the gNMI server to process the valid get request and should send a valid response containing the values of the request nodes. Only the PROTO and JSON encodings are currently supported in the GPINS.

## Subscribe operation

### Expectation

-   The system should be able to handle concurrent subscribe requests with different modes (ONCE/POLL/STREAM).
-   The system should be able to reject invalid path( unsupported path )subscriptions. When the gNMI server implements the feature to silently accept the subscription for the unsupported path, the expectation for the unsupported path will change. This feature might be implemented in Q4 21.

-   GET, SET(update, delete, replace), Subscription

    -   Covered Subtrees

<table>
  <thead>
    <tr>
      <th><em>/</em></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><em>/interfaces</em></td>
    </tr>
    <tr>
      <td><em>/components</em></td>
    </tr>
    <tr>
      <td><em>/qos</em></td>
    </tr>
    <tr>
      <td><em>/system</em></td>
    </tr>
    <tr>
      <td><em>/lacp</em></td>
    </tr>
  </tbody>
</table>

The following test cases randomly select the set of paths from the above supported subtrees, the tests also randomly select the gNMI operations to validate the robustness of the system.\
The key values are also randomly selected based on the testbed information. For example, the interface key for the interface module paths are randomly selected from the list of available interfaces in the testbed. The list of paths are randomly selected from the supported paths in go/gpins-openconfig.

The infrastructure provides a fuzzing API to randomly select the list of paths, keys and gNMI operations to be validated along with the expected responses. The set of paths, keys, payload and expected response messages are provided as the artifact to the test cases.

The list of paths will also include the paths which are not supported by the UMF and invalid keys. These paths are used in the test cases to validate the negative testing and gNMI server's performance metrics.

The first few runs of these stress tests are used to establish the baseline benchmarks for each gNMI operation and for each test case. The baseline benchmarks are stored in the table along with the list of gNMI paths, payloads, keys and expected response. There will be another test which runs at the end of each test which analyzes the performance report against the baseline benchmarks for that system.The test will fail if the performance exceeds the benchmarks.

We use up to 2 pictor clients, 6 SFE clients( 3 over inband and 3 over outerband ) for the gNMI service. The test plan assumes that max needed clients are 5(2 set and subscribe clients and 3 get/subscribe clients) for the stress testing based on the production use case.

**Challenges:**

-   The test infrastructure needs to support creating multiple gNMI clients and establish the connection to the gNMI server.
-   The test infrastructure/gNMI server should provide an ability to turn off the master arbitration feature so that more than one client can simultaneously configure the OC paths for the purpose of stress testing. Using the same connection ID from both set clients will allow both clients to do the gNMI set requests.
-   The paths, payload for the paths and expected response messages should be stored in the map along with supported gNMI operations so that we can use fuzzing to randomly select the path, gNMI operations for the below test cases.

All the below tests will do the global set replace with a sanitized configuration prior to doing the actual test so that the testing payload will be guaranteed to be different from the current configurations. All the number such as 10 request or 5 clients are configurable for each test case

### Infrastructure

-   Augment a YANG path to collect the CPU usage, memory availability and program termination monitoring during the test.
-   Implement the gNMI FE/BE for those paths to collect the data and respond back to the request.

### Tests

-   Send a valid request for an existing leaf ( burst of requests for 10 different leafs with different payload )
    -   Condition to test:

> Send 10 different requests for different leafs at a burst

    -   Validation:

> Verify that all the requests have been successful and response messages reflect that.

-   Send a valid request for an existing leaf ( burst of requests for 10 different leafs with different payload from 5 different subtrees )
    -   Condition to test:

> Send 5 different requests for different leafs at a burst

    -   Validation:

> Verify that all the requests have been successful and response messages reflect that.

-   Send a valid request for an existing leaf from multiple clients
    -   Condition to test:

> Send 5 different requests for different leafs from 5 different clients

    -   Validation:

> Verify that all the requests have been successful and response messages reflect that.

-   Send a valid request for root with very short timeout value( broken client )
    -   Condition to test:

> The connection expected to close before the response received from the server

    -   Validation:

> Verify that the client closes the connection and gracefully exits.

-   Send a valid request for a single leaf multiple times from a single client
    -   Condition to test:

> Set the incremental value for a single leaf over 100 times from single client

    -   Validation:

> Verify that each request has been fully processed and expected response is received, verify that the state leaf also reflect the configured value

-   Send a valid get requests for a single leaf multiple times from a single client
    -   Condition to test:

> Set the incremental value for a single leaf over the 30 minutes period from single client

    -   Validation:

> Verify that each request has been fully processed and expected response is received, verify that the state leaf also reflect the configured value

# E2E Latency Test Cases

The purpose of the gNMI latency testing is to produce a latency report for various types of the gNMI operations on GPINs platform. The latency report can be viewed through a dashboard. The latency will be measured in milliseconds. The latency measurement will be an internal clock on the test server rather than relying on the gNMI response timestamp. All the Latency measurement tests will use only one guitar cluster( the one which is closest to the DUT )

The end to end latency is measured from the test server in the place where we invoke the gNMI request. The latency measurement will be implemented as a text fixture. All the gNMI based GPINs E2E tests will use the latency test fixture in their test cases to measure the latency for that tests. The fixture measures the latency of the gNMI server end to end irrespective of the test validation of the functionality or the feature under test.

The first few(5) runs are used to establish a baseline benchmark for the GPINs E2E latency report. The applications owners ( responsible for each feature ) will decide the expected latency threshold based on the report. Once the baseline benchmark is established for each gNMI operation, the future runs are going to be compared against the baseline benchmarks. The sandcastle config push latency report can be used as a guideline for the gNMI set operations.

The plan is to implement a latency measurement as part of the Ondatra get/set API so that It will be no-op for the test writer and it will collect the E2E latency for all the GPINS GNMI E2E tests. Ondata will provide project based bindings where the latency measurement for a given operations can be pushed in to the database and dashboard can set up to view the data that are stored in the DB

The following is the proposed DB-schema.

<table>
  <thead>
    <tr>
      <th>Table Name: GPINs GNMI Latency<br>
Field:<br>
<ul>
<li>gNMI Operation ( String )</li>
</ul>
<ul>
<li>YANG node ( String )</li>
</ul>
<ul>
<li>Time stamp (MM-DD-YYYY, HH-MM)</li>
</ul>
<ul>
<li>Dut Name ( String )</li>
</ul>
<ul>
<li>GPINs Software Version ( String )</li>
</ul>
<ul>
<li>E2E Latency ( unit: ms )</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

## Dashboard for the DB

-   ONCE Subscription
    -   Covered Paths

<table>
  <thead>
    <tr>
      <th><em>/</em></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><em>/interfaces</em></td>
    </tr>
    <tr>
      <td><em>/components</em></td>
    </tr>
    <tr>
      <td><em>/qos</em></td>
    </tr>
    <tr>
      <td><em>/system</em></td>
    </tr>
  </tbody>
</table>

-   SAMPLE Subscription
    -   Covered Paths

    <table>
  <thead>
    <tr>
      <th><em>/</em><br>
    </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><em>/interfaces</em><br>
    </td>
    </tr>
    <tr>
      <td><em>/components</em><br>
    </td>
    </tr>
    <tr>
      <td><em>/qos</em><br>
    </td>
    </tr>
    <tr>
      <td><em>/system</em><br>
    </td>
    </tr>
  </tbody>
    </table>

    -   Covered SAMPLE period

> 2s, 5s, 10s,

-   ON_CHANGE Subscription
    -   Covered Paths

<table>
  <thead>
    <tr>
      <th><em>/openconfig/interfaces/interface[name=*]/state/admin-status</em></th>
    </tr>
  </thead>
  <tbody>
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

-   TARGET_DEFINED Subscription
    -   Covered Paths

<table>
  <thead>
    <tr>
      <th><em>/</em></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><em>/interfaces</em></td>
    </tr>
    <tr>
      <td><em>/components</em></td>
    </tr>
    <tr>
      <td><em>/qos</em></td>
    </tr>
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
