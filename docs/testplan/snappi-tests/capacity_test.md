# SONiC Switch Capacity Test

## Test Objective

This test aims to assess the true capacities of SONiC switches.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific setup wiring, settings, or configuration. The running script will track power usage, temperature, queue watermark, and health state of all SONiC switches in a testbed.

## Test Steps

1. Run all traffic generators at full line rate, injecting traffic into SONiC devices to maximize stress. The test duration is configurable, with a default setting of 1 hour.
2. Using the switch commands or RPC (Remote Procedure Call), collect all SONiC switches’ metrics listed in the next section. The data sampling rate is also configurable with a default value of every 1 minute.
3. Save the sampled raw data to a database via the telemetry interface provided by the SONiC team in test_reporting folder. The metrics are structured as data points in our database. An example of how to use the interface is provided in telemetry folder.

     ![overview](./capacity_test_diagram.png)

## The collected metrics are structured in the database using two sets of labels

- **Common labels for all metrics**: These labels are shared across all metrics within one test job and must be included with every metric.

     | Label                      | Example Value              |
     |----------------------------|--------------------|
     | `METRIC_LABEL_TESTBED`     | TB-XYZ             |
     | `METRIC_LABEL_TEST_BUILD`  | 2024.1103          |
     | `METRIC_LABEL_TEST_CASE`   | mock-case          |
     | `METRIC_LABEL_TEST_FILE`   | mock-test.py       |
     | `METRIC_LABEL_TEST_JOBID`  | 2024_1225_0621     |

- **Metric labels**: These labels identify the specific device and component from which a metric is collected.

  ### PSU Metrics

     The `show platform psu` command is used on the switch to retrieve PSU metrics. The following labels are expected to be provided:

     | Label                          | Example Value       |
     |--------------------------------|---------------------|
     | `METRIC_LABEL_DEVICE_ID`       | switch-A            |
     | `METRIC_LABEL_DEVICE_PSU_ID`   | PSU 1               |
     | `METRIC_LABEL_DEVICE_PSU_MODEL`| PWR-ABCD            |
     | `METRIC_LABEL_DEVICE_PSU_SERIAL`| 1Z011010112349Q    |
     | `METRIC_LABEL_DEVICE_PSU_HW_REV`| 02.00              |

  ### Sensor Temperature Metrics

     The `show platform temperature` command is used on the switch to retrieve sensor temperatuer metrics. Among the outputs, the "CPU temp sensor" and "Switch Card temp sensor" are of particular interest. The following labels are expected to be provided:

     | Label                          | Example Value       |
     |--------------------------------|---------------------|
     | `METRIC_LABEL_DEVICE_ID`       | switch-A            |
     | `METRIC_LABEL_DEVICE_SENSOR_ID`| Cpu temp sensor     |

  ### Queue Metrics

     The `show queue watermark` is used on the switch to retrieve queue metrics. The following labels are expected to be provided:

     | Label                          | Example Value       |
     |--------------------------------|---------------------|
     | `METRIC_LABEL_DEVICE_ID`       | switch-A            |
     | `METRIC_LABEL_DEVICE_PORT_ID`  | Ethernet8           |
     | `METRIC_LABEL_DEVICE_QUEUE_ID` | 1                   |
     | `METRIC_LABEL_DEVICE_QUEUE_CAST`| multicast          |

  ### Interface Metrics

     The `show interface counters` is used on the switch to retrieve interface metrics. The outputs include drop counters. The following labels are expected to be provided:

     | Label                          | Example Value       |
     |--------------------------------|---------------------|
     | `METRIC_LABEL_DEVICE_ID`       | switch-A            |
     | `METRIC_LABEL_DEVICE_PORT_ID`  | Ethernet8           |
