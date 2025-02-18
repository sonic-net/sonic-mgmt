# SONiC Switch QoS DWRR Test

| Acronym | Definition                           |
|---------|--------------------------------------|
| DSCP    | Differentiated Services Code-Point   |
| DWRR    | Deficit Weighted Round Robin         |
| ECN     | Explicit Congestion Notification     |
| QoS     | Quality of Service                   |
| WRED    | Weighted Random Early Detection      |

## Table of Contents

- [Test Objective](#test-objective)
- [Test Setup](#test-setup)
- [Test Steps](#test-steps)

## Test Objective

This test aims to validate that the DUT correctly prioritizes traffic based on QoS rules and DWRR-based scheduling, ensuring proportional bandwidth allocation across multiple traffic classes.
The test is designed to be configuration-agnostic, meaning it does not require or impose a specific QoS configuration. Instead, it provides a flexible framework that allows testing of various QoS configurations and policies. The sole assumption is that only lossy QoS setting is expected in this test.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle full traffic loads under stress.

## Test Steps

1. Retrieve the queue and scheduler configurations of the first port from config_DB. For example:

    ```plaintext
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

2. Identify the traffic generator and its corresponding port connected to the DUT port under test—this serves as the Rx port for the traffic flows. Then, on a separator traffic generator that is not connected to the DUT port, pick X ports, where X corresponds to the number of queues in the retrieved configuration. These serve as the Tx ports for the traffic flows. Define X traffic flows at line rate, ensuring their DSCP values align with the priority settings on the DUT.
3. Start the X number of traffic flows simultaneously and let them run for 1 minute.
4. Collect the Rx traffic rate and packet loss rate for each traffic flow, then stop the traffic.
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

6. Move to the next port of the DUT and repeat the above steps until all ports have been tested.
7. Start all traffic flows across all ports to place the DUT under stress. Verify if the Rx traffic rates remain as expected under full load.
