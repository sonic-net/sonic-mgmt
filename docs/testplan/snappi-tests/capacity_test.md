# SONiC Switch Capacity Test


- [SONiC Switch Capacity Test](#sonic-switch-capacity-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Steps](#test-steps)
  - [Label Structure](#label-structure)
    - [Common labels for all metrics](#common-labels-for-all-metrics)
    - [Metric labels](#metric-labels)
      - [PSU Metrics](#psu-metrics)
      - [Sensor Temperature Metrics](#sensor-temperature-metrics)
      - [Queue Metrics](#queue-metrics)
      - [Interface Metrics](#interface-metrics)

## Test Objective

This test aims to assess the true capacities of SONiC switches.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific setup wiring, settings, or configuration. The running script will track port counters, queue watermark, power usage, and sensor temperature of all SONiC switches in a testbed. One use case involves a two-tier network, where we establish BGP sessions between T0 and T1 switches and scale the number of IP routes. We use the first half of the ports as the Tx ports and the other half as the Rx ports. After starting the traffic, we run the script to periodically check the health status of all SONiC switches.

## Test Steps

1. Run all traffic generators at full line rate, injecting traffic into SONiC devices to maximize stress. The test duration is configurable, with a default setting of 15 minutes.
2. Using the switch commands or RPC (Remote Procedure Call), collect all SONiC switches’ metrics listed in the next section. The data sampling rate is also configurable with a default value of every 1 minute.
3. Save the sampled raw data to a database via the periodic metrics reporter interface provided by the SONiC team in `test_reporting` folder. The metrics are structured as data points in our database. An example of how to use the interface is provided in `telemetry` folder.

![overview](./capacity_test_diagram.png)

## Label Structure

The collected metrics are structured in the database using two sets of labels

### Common labels for all metrics

These labels are shared across all metrics within one test job and must be included with every metric.

| Label                     | Example Value               |
| ------------------------- | --------------------------- |
| `METRIC_LABEL_TESTBED`    | TB-XYZ                      |
| `METRIC_LABEL_TEST_BUILD` | 2024.1103                   |
| `METRIC_LABEL_TEST_CASE`  | mock-case                   |
| `METRIC_LABEL_TEST_FILE`  | mock-test.py                |
| `METRIC_LABEL_TEST_JOBID` | mock-case_20250412_23:34:58 |

### Metric labels

These labels identify the specific device and component from which a metric is collected.

#### Interface Metrics

The `show interface counters` is used on the switch to retrieve interface metrics. The outputs include drop counters. The following labels are expected to be provided:

| Label                                 | Example Value      |
| ------------------------------------- | ------------------ |
| `METRIC_LABEL_DEVICE_ID`              | switch-A           |
| `METRIC_LABEL_DEVICE_PORT_ID`         | Ethernet8          |

| Metric Name                           | Example Value      |
| ------------------------------------- | ------------------ |
| `METRIC_NAME_PORT_STATE`              | OPER_STATUS.UP     |
| `METRIC_NAME_PORT_RX_BPS`             | 26.38              |
| `METRIC_NAME_PORT_RX_UTILIZATION`     | 0.00               |
| `METRIC_NAME_PORT_RX_OK_COUNTER`      | 5190               |
| `METRIC_NAME_PORT_RX_ERR_COUNTER`     | 0                  |
| `METRIC_NAME_PORT_RX_DROP_COUNTER`    | 248                |
| `METRIC_NAME_PORT_RX_OVERRUN_COUNTER` | 0                  |
| `METRIC_NAME_PORT_TX_BPS`             | 9.76               |
| `METRIC_NAME_PORT_TX_UTILIZATION`     | 0.00               |
| `METRIC_NAME_PORT_TX_OK_COUNTER`      | 4896               |
| `METRIC_NAME_PORT_TX_ERR_COUNTER`     | 0                  |
| `METRIC_NAME_PORT_TX_DROP_COUNTER`    | 10                 |
| `METRIC_NAME_PORT_TX_OVERRUN_COUNTER` | 0                  |

#### Queue Metrics

The `show queue watermark unicast` or  `show queue watermark multicast` is used on the switch to retrieve queue metrics. The following labels are expected to be provided:

| Label                            | Example Value  |
| -------------------------------- | -------------- |
| `METRIC_LABEL_DEVICE_ID`         | switch-A       |
| `METRIC_LABEL_DEVICE_PORT_ID`    | Ethernet8      |
| `METRIC_LABEL_DEVICE_QUEUE_ID`   | MC1            |
| `METRIC_LABEL_DEVICE_QUEUE_CAST` | multicast      |

| Metric Name                      | Example Value  |
| -------------------------------- | -------------- |
| `METRIC_NAME_QUEUE_WATERMARK`    | 7620           |

#### PSU Metrics

The `show platform psu` command is used on the switch to retrieve PSU metrics. The following labels are expected to be provided:

| Label                             | Example Value    |
| --------------------------------- | ---------------- |
| `METRIC_LABEL_DEVICE_ID`          | switch-A         |
| `METRIC_LABEL_DEVICE_PSU_ID`      | PSU 1            |
| `METRIC_LABEL_DEVICE_PSU_MODEL`   | PWR-ABCD         |
| `METRIC_LABEL_DEVICE_PSU_SERIAL`  | 1Z011010112349Q  |
| `METRIC_LABEL_DEVICE_PSU_HW_REV`  | 02.00            |

| Metric Name                       | Example Value    |
| --------------------------------- | ---------------- |
| `METRIC_NAME_PSU_VOLTAGE`         | 12.09            |
| `METRIC_NAME_PSU_CURRENT`         | 18.38            |
| `METRIC_NAME_PSU_POWER`           | 222.00           |
| `METRIC_NAME_PSU_STATUS`          | PSU_STATUS.OK    |
| `METRIC_NAME_PSU_LED`             | LED_STATE.GREEN  |

#### Sensor Temperature Metrics

The `show platform temperature` command is used on the switch to retrieve sensor temperatuer metrics. Among the outputs, the "CPU temp sensor" and "Switch Card temp sensor" are of particular interest. The following labels are expected to be provided:

| Label                                  | Example Value       |
| -------------------------------------- | ------------------- |
| `METRIC_LABEL_DEVICE_ID`               | switch-A            |
| `METRIC_LABEL_DEVICE_SENSOR_ID`        | Cpu temp sensor     |

| Metric Name                            | Example Value       |
| -------------------------------------- | ------------------- |
| `METRIC_NAME_TEMPERATURE_READING`      | 29.5                |
| `METRIC_NAME_TEMPERATURE_HIGH_TH`      | 95                  |
| `METRIC_NAME_TEMPERATURE_LOW_TH`       | 0                   |
| `METRIC_NAME_TEMPERATURE_CRIT_HIGH_TH` | 115                 |
| `METRIC_NAME_TEMPERATURE_CRIT_LOW_TH`  | -5                  |
| `METRIC_NAME_TEMPERATURE_WARNING`      | WARNING_STATUS.TRUE |
