# SONiC Switch Latency Test

- [SONiC Switch Latency Test](#sonic-switch-latency-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Case 1: Full-mesh Latency Test](#test-case-1-full-mesh-latency-test)
  - [Test case 2: Latency Test with Oversubscribed Port](#test-case-2-latency-test-with-oversubscribed-port)
  - [Metrics Processing](#metrics-processing)

## Test Objective

This test aims to measure the latency introduced by a switch under the fully loaded condition.

## Test Setup

> **Notice**: Currently, we are testing exclusively in store-and-forward mode.

1. **Maximize Traffic Load on DUT**

   This test uses all traffic generator ports defined in the test topology to generate the maximum possible traffic volume, stressing the DUT to capture its latency behavior under full load.

   - **Switch wiring**: All DUT ports must be connected to traffic generators—either directly or through intermediary devices.

2. **Establish BGP Sessions and Routes**

   Follow the steps outlined in the multi-tier BGP test plan to:
   - Set up the necessary IPv6 BGP sessions
   - Advertise the desired IPv6 routes

3. **Configure Traffic Flows**

   Set up traffic items on the traffic generators to ensure:
   - Every DUT port receives traffic
   - Every route on the DUT is exercised

   For example:
   - For each of the four traffic generators, define two topologies, each containing four **physical** ports.
   - Configure and enable Layer 2 and Layer 3 protocols for both topologies.
   - In IXIA-1, define two uni-directional traffic items:
     - One targeting IXIA-2
     - One targeting IXIA-4
     - Both set to full mesh mode
     - Each at 60% line rate, with a packet size of 1024 bytes

   - Similarly, in IXIA-2, define traffic items targeting IXIA-1 and IXIA-3.
   - Repeat the pattern across all traffic generators to establish a robust traffic matrix.

## Test Case 1: Full-mesh Latency Test

1. **Baseline Latency Measurement**
   - Start all the traffic items simultaneously and run them for 1 minute. Record latency statistics.
   - Record latency statistics from each traffic item.
   - Compare latency differences between the two traffic items sourced from each traffic generator.
2. **Packet Size Variation**
   - Repeat the baseline test using different frame sizes: 64 bytes, 1024 bytes, 4096 bytes, and 8192 bytes.
   - Analyze how packet size affects latency.
3. **Traffic Rate Scaling**
   - Increase each traffic item’s rate from 60% to 70%, 80%, and 90% of the line rate.
   - For each traffic rate, repeat the baseline and packet size variation tests.
   - Observe how latency and packet loss change with increased traffic load.
4. **RFC2889 Mode Evaluation**
   - Enable the RFC2889 flag in the traffic generator settings.
   - Repeat all previous tests under this mode.
   - Measure whether this setting has any impact on latency or packet loss.

## Test case 2: Latency Test with an Oversubscribed Port

This test is conducted in a one-tier network to evaluate latency under an oversubscribed state.

1. Assume the DUT has X ports connected to traffic generators. Assume the DUT has X ports connected to traffic generators. Select the last port on a traffic generator as the Rx port, and designate the remaining (X-1) ports as Tx ports.
2. Define (X-1) traffic items, each assigned to a different Tx port, using a frame size of 86 bytes. Set each traffic stream's rate to `(line_rate × 110%) / X` to create an oversubscribed condition.
3. Start all the traffic items simultaneously and run them for 1 minute. Record latency statistics.
4. Repeat the test with frame size 1024 bytes, 4096 bytes, and 8192 bytes.
5. Analyze the results by comparing latency measurements across different frame sizes, identifying any patterns or anomalies, and determining how oversubscription affects latency performance.

## Metrics Processing

Latency data is collected and stored periodically. The diagram below illustrates how it is organized in the database. For more details, refer to `test_reporting/telemetry/README.md`.

![metrics](./datapoints.png)

For each of the above results, report the latency figures in nanoseconds to a database via the telemetry FinalMetricsReporter provided by the SONiC team. An example of how to use the interface is provided in telemetry folder. The metrics are stored as data points in our database.

| User Interface Label                     | Label Key in DB          | Example Value       |
| ---------------------------------------- | ------------------------ | ------------------- |
| `METRIC_LABEL_DEVICE_ID`                 | device.id                | switch-A            |
| `METRIC_LABEL_DEVICE_INGRESS_PORT_ID`    | device.port.id           | Ethernet8           |
| `METRIC_LABEL_DEVICE_EGRESS_PORT_ID`     | device.queue.id          | Ethernet257         |
| `METRIC_LABEL_DEVICE_TG_TRAFFIC_RATE`    | tg.traffic_rate          | 50                  |
| `METRIC_LABEL_DEVICE_TG_FRAME_BYTES`     | tg.frame_bytes           | 4096                |
| `METRIC_LABEL_DEVICE_TG_RFC2889_ENABLED` | tg.rfc2889.enabled       | FLAG.ON             |

| User Interface Metric Name               | Metric Name in DB        | Example Value       |
| ---------------------------------------- | ------------------------ | ------------------- |
| `METRIC_NAME_LATENCY_L3_MIN_NS`          | latency.l3.min.ns        | 5891                |
| `METRIC_NAME_LATENCY_L3_MAX_NS`          | latency.l3.max.ns        | 7620                |
| `METRIC_NAME_LATENCY_L3_AVG_NS`          | latency.l3.avg.ns        | 6387                |

Categorize latency results into multiple bins based on time intervals. Analyze the distribution to better understand latency characteristics.
