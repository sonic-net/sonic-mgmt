# SONiC Switch Loss Threshold Test

- [SONiC Switch Loss Threshold Test](#sonic-switch-loss-threshold-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Steps](#test-steps)

## Test Objective

This test aims to determine the maximum traffic rate that results in 0% packet loss across different packet sizes. By identifying this threshold, we can assess the switch's forwarding capability and validate its performance under various traffic conditions.

## Test Setup

This test is designed to be flexible and applicable to various network setups for evaluating traffic loss thresholds. It can be used to assess different configurations, such as one-tier and multi-tier networks. If testing the setup described in BGP_IPv6_test.md, the testbed should first be configured following the procedures outlined in that test plan. Once the setup is complete, the test can proceed with traffic generation, monitoring, and analysis to evaluate performance and identify any potential issues.

## Test Steps

1. Define full-mesh traffic flows on the traffic generators.
2. Set packet size to 8192 bytes and begin testing. Start with 100% of the line rate and check for packet loss. If any traffic flow experiences packet loss, reduce the traffic rate to 10% of the line rate and test again. Continue adjusting the traffic rate using a binary search approach to determine the maximum rate at which 0% packet loss is observed.
3. Repeat step 3 for packet sizes of 86 bytes, 1536 bytes, and 4096 bytes.
4. For each of the above results, save the percentile figures to a database via the telemetry interface provided by the SONiC team. An example of how to use the interface is provided in telemetry folder.

## Metrics Processing

The traffic loss threshold is evaluated once per setup and is reported by FinalMetricsReporter. For more details, refer to test_reporting/telemetry/README.md.

In addition to the common labels below

```python
METRIC_LABEL_TEST_CASE: Final[str] = "test.testcase"
METRIC_LABEL_TEST_FILE: Final[str] = "test.file"
```

The following metric labels and metric name should also be provided:

```python
METRIC_LABEL_DEVICE_ID: Final[str] = "device.id"
METRIC_LABEL_TRAFFIC_PACKET_SIZE: Final[str] = "traffic.packet_size" # Measured in bytes

METRIC_NAME_TRAFFIC_LOSS_RATE: Final[str] = "traffic.loss_rate"      # Measured as a percentage of total traffic
```
