# SONiC Switch QoS DWRR Test

- [SONiC Switch QoS DWRR Test](#sonic-switch-qos-dwrr-test)
  - [Introduction](#introduction)
  - [Acronyms](#acronyms)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Steps](#test-steps)

## Introduction

This document outlines the test plan for validating the Deficit Weighted Round Robin (DWRR) scheduling mechanism on a SONiC switch.

## Acronyms

The following acronyms are used in this document:

| Acronym | Definition                           |
|---------|--------------------------------------|
| DSCP    | Differentiated Services Code-Point   |
| DWRR    | Deficit Weighted Round Robin         |
| QoS     | Quality of Service                   |
| WRED    | Weighted Random Early Detection      |

## Test Objective

This test aims to validate that the DUT correctly prioritizes traffic based on QoS rules and DWRR-based scheduling, ensuring proportional bandwidth allocation across multiple traffic classes.

## Test Setup

This test does not assume or enforce a specific QoS configuration; any QoS configuration can be applied. It is only applicable to single-tier networks. In this phase, only queues marked lossy are expected in this test. To test every port on the switch, full connectivity is necessary to ensure complete coverage of all DUT ports.

## Test Steps

1. Retrieve the queue, priority to queue mappings, and scheduler configurations of the first port from config_DB. For example:

    ```json
    "QUEUE": {
        "Ethernet0|0": {
            "scheduler": "scheduler.0"
        },
        "Ethernet0|1": {
            "scheduler": "scheduler.1"
        },
        "Ethernet0|2": {
            "scheduler": "scheduler.2"
        }
    },
    "TC_TO_QUEUE_MAP": {
        "AZURE": {
            "0": "0",
            "1": "1",
            "2": "2",
            "3": "3",
            "4": "4",
            "5": "5",
            "6": "6",
            "7": "7"
        }
    },
    "SCHEDULER": {
        "scheduler.0": {
            "type": "DWRR",
            "weight": "5"
        },
        "scheduler.1": {
            "type": "DWRR",
            "weight": "15"
        },
        "scheduler.2": {
            "type": "DWRR",
            "weight": "20"
        }
    }
    ```

   **Please note that this is just an example. Our test code should be designed to be general and adaptable, accommodating any number of queues, and various scheduler configurations.**

2. Identify the traffic generator and its corresponding port connected to the DUT port under test—this serves as the Rx port for the traffic flows. Then, on a separate traffic generator that is not connected to the DUT port, pick X ports, where X corresponds to the number of queues in the retrieved configuration. These serve as the Tx ports for the traffic flows. Define X traffic flows at line rate, ensuring their DSCP values align with the priority settings on the DUT.
3. Start the X number of traffic flows simultaneously and let them run for 1 minute.
4. Collect the Rx traffic rate and packet loss rate for each traffic flow, then stop the traffic.  Collect the queue stats of the DUT port under test.
5. Verify that the observed results match the expected test outcomes.

   The DWRR algorithm allocates bandwidth proportionally based on the weights assigned to the schedulers. The total bandwidth is divided according to the ratio of the weights. In the above configuration example,

   ```plaintext
   scheduler.0: weight = 5
   scheduler.1: weight = 15
   scheduler.2: weight = 20
   ```

   Sum of Weights: 5 + 15 + 20 = 40

   Each scheduler gets a fraction of the bandwidth proportional to its weight:

   ```plaintext
   scheduler.0:  5/40 × 100% = 12.5% of the total available bandwidth
   scheduler.1: 15/40 × 100% = 37.5% of the total available bandwidth
   scheduler.2: 20/40 × 100% = 50.0% of the total available bandwidth
   ```

6. Use queue counters to cross-validate the results. Note that the exact bandwidth share may slightly differ from the expected value due to ASIC-specific DWRR implementations or hardware limitations.
7. Modify the traffic items so that they have ascending packet sizes. Re-run the test and analyze whether packet size impacts the results.
8. Move to the next port of the DUT and repeat the above steps until all ports have been tested.
9. Start all traffic flows across all ports to place the DUT under stress. Verify if the Rx traffic rates remain as expected under full load.

## Metrics

Save the QoS DWRR test result to a database via the final metrics reporter interface provided by the SONiC team in `test_reporting` folder. An example of how to use the interface is provided in `telemetry` folder.

| User Interface Label                   | Label Key in DB          | Example Value       |
| -------------------------------------- | ------------------------ | ------------------- |
| `METRIC_LABEL_DEVICE_ID`               | device.id                | switch-A            |
| `METRIC_LABEL_DEVICE_PORT_ID`          | device.port.id           | Ethernet8           |
| `METRIC_LABEL_DEVICE_QUEUE_ID`         | device.queue.id          | MC1                 |

| User Interface Metric Name             | Metric Name in DB        | Example Value       |
| -------------------------------------- | ------------------------ | ------------------- |
| `METRIC_NAME_QOS_DWRR`                 | qos.dwrr                 | FINAL_STATUS.PASS   |
