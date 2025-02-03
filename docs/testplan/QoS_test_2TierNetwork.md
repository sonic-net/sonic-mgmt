# Test Objective
This test aims to validate that the DUT in a two-tier network correctly prioritizes traffic based on QoS rules and DWRR-based scheduling, ensuring proportional bandwidth allocation across multiple traffic classes.
The test is designed to be configuration-agnostic, meaning it does not assume or impose a specific QoS configuration. Instead, it provides a flexible framework that allows testing of various QoS configurations and policies.

# Test Setup
![Test Setup](./2TierNetwork.png)

1.	The testbed consists of four IXIA traffic generators (synchronized using a time-sync metronome) and five SONiC switches, where the BT1 switch is the Device Under Test (DUT).
2.	Each of the four BT0 switches is connected to the DUT via eight DAC cables. There are no direct connections between any two BT0 switches.
3.	Each BT0 switch is also connected to one IXIA traffic generator via eight optical cables. Similarly, there are no direct connections between any two IXIA devices.
4.	Both switches and IXIAs support four port breakout modes: 8x100Gbps, 4x200Gbps, 2x400Gbps, and 1x800Gbps. However, they must operate in the same mode. In 8x100Gbps mode, each cable supports eight links. In 4x200Gbps mode, each cable supports four links. So on and so forth.
5.	The routing configuration of the BT0 switches should ensure that all data traffic go through the DUT.

# Test Steps

1. Retrieve the queue, scheduler, and WRED profile configurations of the port under test from config_DB. For example:
```
    "QUEUE": {
        "Ethernet0|0": {
            "scheduler": "scheduler.0"
        },
        "Ethernet0|1": {
            "scheduler": "scheduler.1",
            "wred_profile": "AZURE_LOSSLESS"
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
    },
    "WRED_PROFILE": {
        "AZURE_LOSSLESS": {
            "ecn": "ecn_all",
            "green_drop_probability": "5",
            "green_max_threshold": "2097152",
            "green_min_threshold": "1048576",
            "red_drop_probability": "5",
            "red_max_threshold": "2097152",
            "red_min_threshold": "1048576",
            "wred_green_enable": "true",
            "wred_red_enable": "true",
            "wred_yellow_enable": "true",
            "yellow_drop_probability": "5",
            "yellow_max_threshold": "2097152",
            "yellow_min_threshold": "1048576"
        },
        "AZURE_LOSSY": {
            "ecn": "ecn_none",
            "green_drop_probability": "10",
            "green_max_threshold": "1048576",
            "green_min_threshold": "524288",
            "red_drop_probability": "15",
            "red_max_threshold": "1048576",
            "red_min_threshold": "524288",
            "wred_green_enable": "true",
            "wred_red_enable": "true",
            "wred_yellow_enable": "true",
            "yellow_drop_probability": "20",
            "yellow_max_threshold": "1048576",
            "yellow_min_threshold": "524288"
        }
    }

```
**Please note that this is just an example. Our test code should be designed to be general and adaptable, accommodating any number of queues, any combination of lossy and lossless traffic, and various scheduler configurations.**

2. In IXIA, define X traffic flows, where X is the number of queues in the retrieved configuration. The Rx port of these traffic flows should be connected to the PUT, while the Tx ports should be connected elsewhere, not to the PUT. Configure the traffic flows with DSCP values mapped to the priorities set on the DUT.


3. Start all traffic flows simultaneously and let them run for 1 minute.


4. Collect the Rx traffic rate and packet loss rate for each traffic flow, then stop the traffic.


# Expected Test Results
The DWRR algorithm allocates bandwidth proportionally based on the weights assigned to the schedulers. The total bandwidth is divided according to the ratio of the weights.

In the above configuration example,
```
scheduler.0: weight = 5
scheduler.1: weight = 15
scheduler.2: weight = 20
```

Sum of Weights: 5 + 15 + 20 = 40

Each scheduler gets a fraction of the bandwidth proportional to its weight:
```
scheduler.0:  5/40 × 100% = 12.5% of the total available bandwidth
scheduler.1: 15/40 × 100% = 37.5% of the total available bandwidth
scheduler.2: 20/40 × 100% = 50.0% of the total available bandwidth
```

**​Please note that in this example, queue 1 is configured as a lossless queue with WRED enabled via the AZURE_LOSSLESS profile, therefore no packets are dropped. The sender will be throttled to the allocated rate by temporarily halting the transmission.**

# Acronyms
```
DSCP: Differentiated Services Code-Point
DUT:  Device Under Test
DWRR: Deficit Weighted Round Robin
ECN:  Explicit Congestion Notification
PUT:  Port Under Test
QoS:  Quality of Service
WRED: Weighted Random Early Detection
```
