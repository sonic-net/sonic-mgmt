# Snappi-based FCS Error Handling Test

1. [1. Test Objective](#1-test-objective)
2. [2. Testbed Topology](#2-testbed-topology)
3. [3. Test parameters](#3-test-parameters)
4. [4. Test Cases](#4-test-cases)
   1. [4.1. Test Case 1: Line-rate FCS-error traffic test](#41-test-case-1-line-rate-fcs-error-traffic-test)
   2. [4.2. Test Case 2: FCS-error isolation test](#42-test-case-2-fcs-error-isolation-test)
      1. [4.2.1. 1-to-1 parallel links](#421-1-to-1-parallel-links)
      2. [4.2.2. Mixed-traffic on a single port](#422-mixed-traffic-on-a-single-port)
5. [5. Metrics to collect](#5-metrics-to-collect)
   1. [5.1. Common metrics labels](#51-common-metrics-labels)
   2. [5.2. Traffic generator metrics](#52-traffic-generator-metrics)
   3. [5.3. DUT metrics](#53-dut-metrics)

## 1. Test Objective

This test aims to validate that a SONiC switch:

- Drops **100%** of Ethernet frames with FCS errors on ingress at line rate.
- Assesses the impact of traffic with FCS error. Valid frames should be unaffected by the presence of FCS errors on the same or different ports.

## 2. Testbed Topology

This tests expects the testbed to be built using the `nut-single-dut` topology, following the [Multi-device multi-tier testbed HLD](../../testbed/README.testbed.NUT.md), which allows us to test the FCS error in a flexible way.

```mermaid
graph TD
    subgraph "Device Under Test"
        P1[Port 1]
        P2[Port 2]
        P3[Port 3]
        PN[Port N]
    end
    TG[Traffic Generator]
    TG <-->|Traffic| P1
    TG <-->|Traffic| P2
    TG <-->|Traffic| P3
    TG <-->|Traffic| PN
```

## 3. Test parameters

The FCS error handling tests are parameterized to allow flexible testing across different scenarios. The following parameters can be adjusted:

| Parameter           | Description                           | Valid Values                     |
|---------------------|---------------------------------------|----------------------------------|
| `fcs_error_type`    | FCS corruption mode                   | `zero`, `random`                 |
| `tx_port_count`     | Number of concurrent ingress TG ports | see test case for details        |
| `frame_bytes`       | Ethernet frame length (bytes)         | 128, 256, 1024, 1518, 4096, 8192 |
| `ip_version`        | IPv4, or IPv6                         | `IPv4`, `IPv6`                   |
| `test_duration_sec` | Traffic transmission time (Seconds)   | 60                               |

## 4. Test Cases

### 4.1. Test Case 1: Line-rate FCS-error traffic test

For each combination of test parameters, the following steps are executed:

1. Select the first `tx_port_count` traffic generator ports as TX ports.
   - When `max` is selected for `tx_port_count`, use all the available TG ports as TX ports, except the last port.
   - Besides `max`, 1, 3 and 7 ports will be supported as `tx_port_count`.
2. Select the next available traffic generator port as the RX port.
3. Configurate the traffic stream on traffic generator with the following parameters:
   - **FCS error type**: `fcs_error_type` (e.g., `zero`, `random`).
   - **Packet size**: `frame_bytes`.
   - **IP version**: `ip_version`.
   - **Line rate**: 100% of the port speed.
4. Start traffic stream at **100% line rate** for `test_duration`.
5. Stop traffic and Retrieve stats from the traffic generator and DUT.
6. Validate the results, and pass the test if the following conditions are met:
   - Traffic generator RX port should receive **0 frames**.
   - DUT ingress RX error counter must equal the Tx frame count.

### 4.2. Test Case 2: FCS-error isolation test

#### 4.2.1. 1-to-1 parallel links

For each combination of test parameters, the following steps are executed:

1. Select first 2x `tx_port_count` TG ports as TX ports:
   - When `max` is selected for `tx_port_count`, use the first 2/3 of the available TG ports as TX ports, and the last 1/3 as RX ports.
   - Besides `max`, 1, 2, 4 and 8 ports will be supported as `tx_port_count`.
2. Select the next `tx_port_count` available traffic generator port as the RX port.
3. Configure two traffic flows on the TX ports interleaved (first port index is 0):
   - **Flow-Bad**: On all even ports, bad-FCS frames at 100% line rate.
   - **Flow-Good**: On all odd ports, good-FCS frames at 100% line rate.
   - Each pair of TX ports should send traffic to the same RX port (e.g., TX1 & TX2 → RX1, TX3 & TX4 → RX2).
4. Clear all switch counters.
5. Start all traffic flows concurrently at **100% line rate** for `test_duration`.
6. Stop traffic and retrieve stats from the traffic generator and DUT.
7. Report the following stats using metrics interface:
   - Traffic rate of Flow-Good and Flow-Bad on all RX ports.
8. Validate the results and fail the test if the following conditions are met:
   - Any RX port received any bad-FCS frames.
   - DUT ingress RX error counter delta matches total bad-FCS TX frame count across all ports.

#### 4.2.2. Mixed-traffic on a single port

For each combination of test parameters, the following steps are executed:

1. Select the first 2x `tx_port_count` TG ports as TX ports:
   - When `max` is selected for `tx_port_count`, use the first 2/3 of the available TG ports as TX ports, and the last 1/3 as RX ports.
   - Besides `max`, 1, 2, 4 and 8 ports will be supported as `tx_port_count`.
2. Select the next `tx_port_count` available traffic generator port as the RX port.
3. Configure two traffic flows on each TX port:
   - **Flow-Good**: good-FCS frames at 50% line rate.
   - **Flow-Bad**: bad-FCS frames at 50% line rate.
   - Each pair of TX ports should send traffic to the same RX port (e.g., TX1 & TX2 → RX1, TX3 & TX4 → RX2) with interleaved transmission.
4. Clear all switch counters.
5. Start both traffic flows concurrently on all ports for `test_duration`.
6. Stop traffic and retrieve stats from the traffic generator and DUT.
7. Report the following stats using metrics interface:
   - Traffic rate of Flow-Good and Flow-Bad on all RX ports.
8. Validate the results and fail the test if the following conditions are met:
   - Any RX port received any bad-FCS frames (Flow-Bad).
   - DUT ingress RX error counter delta matches total bad-FCS TX frame count across all ports.

## 5. Metrics to collect

### 5.1. Common metrics labels

All metrics collected during the tests will include the following labels to provide context and facilitate filtering:

| Label Name                                  | Label                         | Description                          | Example          |
|---------------------------------------------|-------------------------------|--------------------------------------|------------------|
| `METRIC_NAME_TG_IP_VERSION`                 | tg.ip_version                 | IP version                           | 4, 6             |
| `METRIC_NAME_TG_FCS_ERROR_TYPE`             | tg.fcs_error_type             | FCS error type                       | `zero`, `random` |
| `METRIC_NAME_TG_FRAME_BYTES`                | tg.frame_bytes                | Ethernet frame length in bytes       | 1518             |
| `METRIC_NAME_TG_TX_PORT_COUNT`              | tg.tx_port_count              | Number of TX ports after calculation | 1, 4, 200        |
| `METRIC_NAME_TEST_PARAMS_TX_PORT_COUNT`     | test.params.tx_port_count     | Number of TX ports                   | 1, 4, max        |
| `METRIC_NAME_TEST_PARAMS_TEST_DURATION_SEC` | test.params.test_duration_sec | Traffic transmission time in seconds | 60               |

### 5.2. Traffic generator metrics

The following metrics will be collected during test execution to validate FCS error handling and measure performance:

| Metric Name                   | Metric Name in DB | Description                              | Example |
|-------------------------------|-------------------|------------------------------------------|---------|
| `METRIC_NAME_TG_TX_GOOD_UTIL` | tg.tx.good.util   | Total TX utilization of good-FCS traffic | 95.33   |
| `METRIC_NAME_TG_RX_GOOD_UTIL` | tg.rx.good.util   | Total RX utilization of good-FCS traffic | 62.53   |
| `METRIC_NAME_TG_TX_BAD_UTIL`  | tg.tx.bad.util    | Total TX utilization of bad-FCS traffic  | 95.33   |
| `METRIC_NAME_TG_RX_BAD_UTIL`  | tg.rx.bad.util    | Total RX utilization of bad-FCS traffic  | 0.00    |

### 5.3. DUT metrics

| Metric Name                   | Metric Name in DB | Example        |
|-------------------------------|-------------------|----------------|
| `METRIC_NAME_PORT_STATE`      | port.state        | OPER_STATUS.UP |
| `METRIC_NAME_PORT_RX_BPS`     | port.rx.bps       | 26.38          |
| `METRIC_NAME_PORT_RX_UTIL`    | port.rx.util      | 0.00           |
| `METRIC_NAME_PORT_RX_OK`      | port.rx.ok        | 5190           |
| `METRIC_NAME_PORT_RX_ERR`     | port.rx.err       | 0              |
| `METRIC_NAME_PORT_RX_DROP`    | port.rx.drop      | 248            |
| `METRIC_NAME_PORT_RX_OVERRUN` | port.rx.overrun   | 0              |
| `METRIC_NAME_PORT_TX_BPS`     | port.tx.bps       | 9.76           |
| `METRIC_NAME_PORT_TX_UTIL`    | port.tx.util      | 0.00           |
| `METRIC_NAME_PORT_TX_OK`      | port.tx.ok        | 4896           |
| `METRIC_NAME_PORT_TX_ERR`     | port.tx.err       | 0              |
| `METRIC_NAME_PORT_TX_DROP`    | port.tx.drop      | 10             |
| `METRIC_NAME_PORT_TX_OVERRUN` | port.tx.overrun   | 0              |

Besides the common metrics labels, the following metrics labels will also be collected from the DUT to provide context and facilitate filtering:

| Label Name                    | Label Name in DB | Example   |
|-------------------------------|------------------|-----------|
| `METRIC_LABEL_DEVICE_ID`      | device.id        | switch-A  |
| `METRIC_LABEL_DEVICE_PORT_ID` | device.port.id   | Ethernet8 |
