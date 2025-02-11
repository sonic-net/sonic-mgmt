# SONiC Switch Latency Test

## Test Objective

This test aims to measure the latency introduced by a switch under the fully loaded condition.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle full traffic loads under stress. Plus all traffic generators in the testbed must be time synchronized.

## Notice

Currently, we are testing exclusively in store-and-forward mode.

## Test Steps

1. Switch wiring: All DUT ports are connected to traffic generators, directly or indirectly.

2. Configure traffic items on the traffic generators to ensure that every port of the DUT receives traffic flow. For example, For each of the four traffic generators: define two topologies, each containing four **physical** ports. Configure and bring up Layer 2 and Layer 3 protocols for both topologies. Define two uni-directional traffic items in IXIA-1, one traffic item is destined for IXIA-2, the other traffic item is destined for IXIA-4. Set each traffic item’s rate to 60% of the line rate, with a packet size of 1024 bytes. Define two uni-directional traffic items in IXIA-2, one traffic item is destined for IXIA-1, the other traffic item is destined for IXIA-3.  So on and so forth.

3. Start all the traffic items simultaneously and run them for 1 minute. Record latency statistics and compare latency differences between the two traffic items sourced from each traffic generator.

4. Repeat the test with packet sizes ranging from 86 bytes to 8096 bytes to analyze how packet size impacts latency.

5. Increase each traffic item's rate from 60% to 70%, 80%, and 90% of the line rate, respectively. Repeat the above three steps. Observe how latency changes in relation to packet loss. Note: Latency measurements may be skewed due to packet loss, as lost packets are counted as having infinite latency. This issue should be addressed to ensure accurate results.

## Metrics Processing

  ![metrics](./datapoints.png)

For each of the above results, save the latency figures in nanoseconds to a database via the telemetry interface provided by the SONiC team. An example of how to use the interface is provided in telemetry folder. The metrics are stored as data points in our database.

  In addition to the common labels below

     ```python
     METRIC_LABEL_TESTBED: Final[str] = "test.testbed"
     METRIC_LABEL_TEST_BUILD: Final[str] = "test.os.version"
     METRIC_LABEL_TEST_CASE: Final[str] = "test.testcase"
     METRIC_LABEL_TEST_FILE: Final[str] = "test.file"
     METRIC_LABEL_TEST_JOBID: Final[str] = "test.job.id"
     ```

  The following labels should also be provided:

     ```python
     METRIC_LABEL_DEVICE_ID: Final[str] = "device.id"
     METRIC_LABEL_DEVICE_INGRESS_PORT_ID: Final[str] = "device.ingress_port.id"
     METRIC_LABEL_DEVICE_EGRESS_PORT_ID: Final[str] = "device.egress_port.id"
     METRIC_LABEL_TRAFFIC_RATE: Final[str] = "traffic.rate"               # Measured as a percentage of the line rate
     METRIC_LABEL_TRAFFIC_LOSS_RATE: Final[str] = "traffic.loss_rate"     # Measured as a percentage of total traffic
     METRIC_LABEL_TRAFFIC_PACKET_SIZE: Final[str] = "traffic.packet_size" # Measured in bytes
     ```

  Categorize latency results into multiple bins based on time intervals. Analyze the distribution to better understand latency characteristics.
