# SONiC Switch Loss Threshold Test

- [SONiC Switch Loss Threshold Test](#sonic-switch-loss-threshold-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Steps](#test-steps)
  - [Metrics Processing](#metrics-processing)

## Test Objective

This test aims to determine the maximum traffic rate that results in 0% packet loss across different packet sizes. By identifying this threshold, we can assess the switch's forwarding capability and validate its performance under various traffic conditions.

## Test Setup

This test is designed to be flexible and applicable to various network setups for evaluating traffic loss thresholds. It can be used to assess different configurations, such as one-tier and multi-tier networks. If testing the setup described in `BGP_IPv6_test.md`, ensure the testbed is properly configured by following the procedures outlined in that plan.

1. **Establish BGP Sessions and Advertise Routes**
   Follow the steps in the multi-tier BGP test plan to:
   - Configure the required IPv6 BGP sessions between the DUT and its neighbors.
   - Advertise the intended set of IPv6 routes to ensure full route visibility.

2. **Define Full-Mesh Traffic Flows**
   - Set up full-mesh traffic flows on the traffic generators so that all DUT ports are actively involved.
   - Target all advertised routes to maximize coverage.

Once the setup is complete, proceed with traffic generation, monitoring, and analysis to measure performance and identify potential issues such as traffic loss or imbalance.

## Test Steps

1. Set packet size to 8192 bytes and begin testing. Start with 100% of the line rate and check for packet loss. If any traffic flow experiences packet loss, reduce the traffic rate to 10% of the line rate and test again. Continue adjusting the traffic rate using a binary search approach to determine the maximum rate at which 0% packet loss is observed.
2. Repeat step 3 for packet sizes of 86 bytes, 1536 bytes, and 4096 bytes.
3. For each of the above results, save the percentile figures to a database via the telemetry interface provided by the SONiC team. An example of how to use the interface is provided in telemetry folder.

## Metrics Processing

The traffic loss threshold is evaluated once per switch and is reported by FinalMetricsReporter. For more details, refer to `test_reporting/telemetry/README.md`.

| User Interface Label                     | Label Key in DB          | Example Value       |
| ---------------------------------------- | ------------------------ | ------------------- |
| `METRIC_LABEL_DEVICE_ID`                 | device.id                | switch-A            |
| `METRIC_LABEL_DEVICE_TG_FRAME_BYTES`     | tg.frame_bytes           | 4096                |

| User Interface Metric Name               | Metric Name in DB        | Example Value       |
| ---------------------------------------- | ------------------------ | ------------------- |
| `METRIC_NAME_NO_LOSS_MAX_RATE`           | no_loss_max_rate         | 59                  |
