# SONiC Switch ECN Test

- [SONiC Switch ECN Test](#sonic-switch-ecn-test)
  - [Overview](#overview)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Cases](#test-cases)
    - [ECN Marking at Egress – Lossy Queue Scenario](#ecn-marking-at-egress--lossy-queue-scenario)
    - [ECN Marking at Egress – Lossless Queue Scenario](#ecn-marking-at-egress--lossless-queue-scenario)
    - [ECN marking accuracy – Lossless Queue Scenario](#ecn-marking-accuracy--lossless-queue-scenario)
  - [Metrics](#metrics)

## Overview

In a traditional TCP/IP network, congestion is typically detected through packet loss. When network congestion occurs, routers and switches begin dropping packets as their buffers become full, signaling to the sender that the network is overloaded. Relying solely on packet loss as a congestion signal has several limitations.

- First, packet loss is a relatively late indicator of congestion. By the time packets are being dropped, the network is already experiencing significant stress, which can degrade application performance and increase latency.
- Second, not all packet loss is caused by congestion. In wireless networks, for example, packets may be lost due to interference, signal attenuation, or hardware errors, which can lead to false congestion signals and unnecessary reduction in transmission rates. This can significantly degrade throughput in environments where losses are not congestion-related.
- Third, packet loss-based detection lacks granularity and control. It provides little insight into the severity or location of congestion, making it difficult for senders to respond optimally. Moreover, it does not offer early warnings or predictive cues that could enable proactive congestion avoidance.

Because of these limitations, modern networks increasingly supplement or replace packet loss-based congestion detection with more proactive and informative mechanisms — ECN. Explicit Congestion Notification (ECN) is an enhancement to TCP/IP congestion control that allows congestion to be signaled without dropping packets. Instead of relying on packet loss, ECN uses marking within the IP header to indicate congestion. The process works as follows:

- ECN-Capable Transport (ECT) Marking: The sender marks packets as ECN-capable (ECT) in the IP header.
- Congestion Notification: If a router or switch experiences congestion, instead of dropping packets, it marks the Congestion Experienced (CE) bit in the IP header.
- Receiver Acknowledgment: The receiver detects the CE mark and informs the sender via an ECN-Echo (ECE) flag in the TCP acknowledgment.
- Sender Response: Upon receiving an ECN-Echo, the sender reduces its congestion window (CWND) to slow down transmission, similar to traditional congestion control, but without losing packets.

This proactive mechanism improves network efficiency by preventing packet drops and reducing retransmission overhead. The primary algorithm governing ECN behavior is the Random Early Detection (RED) with ECN marking. RED dynamically marks packets with ECN-CE based on the queue depth. As the queue length increases, the marking probability rises, signaling congestion before significant queuing delays occur. The RED algorithm is defined by three key parameters:

- 𝐾min – the minimum threshold: When the average queue length is below this value, RED does not mark any packets. This helps avoid unnecessary congestion signals during normal traffic conditions.
- 𝐾max – the maximum threshold: When the average queue length exceeds this value, RED marks all incoming packets with the ECN-CE codepoint (or drops them if ECN is not enabled), indicating severe congestion.
- 𝑃max – the maximum marking (or dropping) probability: This determines the likelihood of marking a packet when the average queue length is between 𝐾min and 𝐾max. As the queue length grows within this range, the marking probability gradually increases from 0 up to 𝑃max, allowing RED to signal congestion in a controlled and probabilistic manner.

Together, these parameters allow RED to provide early, gradual congestion signals to end systems — helping prevent buffer overflows, reduce packet loss, and smooth out traffic flow. The marking probability is determined as follows:

- When the instantaneous queue length is below Kmin, the marking probability is 0%.
- When the queue length exceeds Kmax, the marking probability reaches 100%.
- Otherwise, the marking probability follows the formula: Marking Probability = (queue_length − 𝐾min)/(𝐾max − 𝐾min) × 𝑃max

The figure in [ECN-test-plan.md](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/ECN-test-plan.md) illustrates the theoretical ECN marking probability as a function of queue length. Commodity switches can implement RED at ingress (when packets are enqueued into the switch buffer) or at egress (when packets are dequeued from the buffer). Compared to ingress RED/ECN, egress RED/ECN provides lower feedback delay, leading to faster congestion response.

## Test Objective

The test aims to validate the ECN behaviors of the SONiC DUT based on the Random Early Detection (RED) algorithm.

## Test Setup

In multi-tier network architectures, traffic often traverses multiple switches — for example, from a leaf switch to a spine switch, then to another leaf. Congestion can occur at any point along this path, and dynamic path selection mechanisms like ECMP (Equal-Cost Multi-Path) introduce further variability by distributing flows across different links and devices. Because of this variability, the test framework cannot reliably isolate or guarantee the exact point of congestion. This uncertainty makes it difficult to attribute ECN-CE (Congestion Experienced) markings to a specific queue or switch.

In contrast, single-tier networks provide a more controlled and predictable environment. Traffic typically flows through a single switch, making the congestion point deterministic. This simplifies validation: ECN-CE markings can be reliably traced back to a specific queue on the DUT, resulting in clear and verifiable test outcomes.

**Port and Queue Coverage**
To thoroughly test ECN behavior across the switch, full connectivity is required. This ensures all ports on the DUT are exercised, allowing congestion to be induced and ECN behavior to be validated across every port and queue.

**Queue and WRED Configuration**
To properly test ECN behavior, the test must account for the ECN marking configuration applied to each queue. This includes retrieving:

- The WRED thresholds: 𝐾max, 𝐾min and 𝑃max
- Queue index and traffic class to queue mappings

These parameters are available in the CONFIG_DB. For example:

```json
    "QUEUE": {
        "Ethernet0|0": {
            "scheduler": "scheduler.0"
        },
        "Ethernet0|1": {
            "scheduler": "scheduler.1",
            "wred_profile": "AZURE_LOSSY"
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
            "ecn": "ecn_all",
            "red_drop_probability": "5",
            "red_max_threshold": "51000",
            "red_min_threshold": "50000",
            "wred_red_enable": "true"
        }
    }
```

## Test Cases

### ECN Marking at Egress – Lossy Queue Scenario

This test aims to verify that ECN-CE marks are correctly applied on packets exiting lossy queues when congestion occurs. The steps are as follows:

1. **Test Port Selection**
   - Choose the first Ethernet port on the DUT as the port under test.
   - Identify the connected traffic generator port — this will serve as the Rx port.
   - Select two additional traffic generator ports to serve as Tx ports.

2. **Traffic Configuration**
   - Define two unidirectional traffic flows, each originating from one Tx port and targeting the Rx port.
   - Set each traffic flow to operate at 60% of the line rate.
   - Assign DSCP values to the flows to ensure they map to the intended lossy queue on the DUT.

3. **Start Packet Capture**
   - Initiate packet capture on the traffic generator's Rx port to monitor ECN-CE markings.

4. **Traffic Execution**
   - Start the data traffic and run the test for 1 minute.
   - Stop traffic and packet capture afterward.

5. **Validation Criteria**
   - The **first** data packet received should have the ECN-CE mark set.
   - The **last** data packet received should **not** have the ECN-CE mark.

6. Move to the next DUT port and repeat the above steps until all ports have been tested. To improve efficiency, we can test the same logical port across all physical port concurrently.

### ECN Marking at Egress – Lossless Queue Scenario

This test case aims to validate ECN marking on egress traffic from lossless queues under congestion. Ensure that marking reflects the configured ECN thresholds. Below are the test steps.

1. Start PFC PAUSE storm to fully block the lossless priority at the DUT.
2. Test data traffic: Identify the traffic generator and its corresponding port connected to the DUT port under test — this serves as the Rx port for the traffic flow. Then, on a separator traffic generator that is not connected to the DUT port, pick a Tx port on the generator to send traffic. Define a traffic flows at line rate, ensuring their DSCP values align with the priority settings on the DUT. The number of packets should be fixed at 2 × 𝐾max, with each packet being 1KB in size.
3. Start packet capture on the traffic generator Rx port.
4. From the traffic generator Tx port, send 2 × 𝐾max data packets to the receiver,  ensuring the packets are mapped to the right priority on the DUT.
5. Once all the test data packets are transmitted, stop pausing the egress traffic of the DUT port.
6. Stop the packet capture after all packets are received.
7. Verify the following:
   - traffic generator Rx port must receive 2 × 𝐾max test data packets.
   - The first test data packet received should be ECN marked.
   - When the number of packets in a queue is below 𝐾min, no packets are marked. Therefore, the last test data packet received should not be ECN-marked.
8. Move to the next DUT port and repeat the above steps until all ports have been tested. To improve efficiency, we can test the same logical port across all physical port concurrently.

### ECN marking accuracy – Lossless Queue Scenario

This test aims to verify the ECN marking accuracy on the DUT by comparing the actual ECN marking probability with the theoretical value. The steps are as follows:

1. Follow the first six steps of the previous test case, with the only change being that (𝐾max + 10) packets are sent instead of 2 × 𝐾max.
2. Verify the following:
   - All (𝐾max + 10) packets must be received at the Rx port.
   - According to the egress ECN marking algorithm, the queue length associated with the data packet i (i = 1, 2, … 𝐾max + 10) should be (𝐾max + 10 – i) KB.
   - For a given instantaneous queue length q, the expected ECN marking behavior is as follows:
     - for the first 10 packets, the number of packets in the Tx queue is greater than 𝐾max. So their theoretical ECN marking probability should be 100%.
     - For the next (𝐾max − 𝐾min) packets, 𝐾min <= q < 𝐾max, the theoretical ECN marking probability should not exceed 𝑃max%. As q decreases from 𝐾max to Kmin, the ECN marking probability should linearly decrease from 𝑃max to 0.
     - For the last 𝐾min packets, q < 𝐾min. So, none of the packets should be ECN marked.
3. Repeat the test 200 times to ensure statistical accuracy.
4. After 200 iterations, compare the theoretical ECN marking probability with the actual marking results for different queue lengths.
5. Move to the next DUT port and repeat all steps until all ports are tested. To improve efficiency, we can test the same logical port across all physical port concurrently.

## Metrics

Save the ECN test result to a database via the final metrics reporter interface provided by the SONiC team in `test_reporting` folder. An example of how to use the interface is provided in `telemetry` folder.

| User Interface Label                   | Label Key in DB          | Example Value       |
| -------------------------------------- | ------------------------ | ------------------- |
| `METRIC_LABEL_DEVICE_ID`               | device.id                | switch-A            |
| `METRIC_LABEL_DEVICE_PORT_ID`          | device.port.id           | Ethernet8           |

| User Interface Metric Name             | Metric Name in DB        | Example Value       |
| -------------------------------------- | ------------------------ | ------------------- |
| `METRIC_NAME_ECN_EGRESS_MARKING`       | ecn.egress_marking       | FINAL_STATUS.PASS   |
| `METRIC_NAME_ECN_ACCURACY_MARKING`     | ecn.accuracy_marking     | FINAL_STATUS.FAIL   |
