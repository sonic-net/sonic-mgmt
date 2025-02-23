# SONiC Switch ECN Test

- [SONiC Switch ECN Test](#sonic-switch-ecn-test)
  - [Overview](#overview)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Cases](#test-cases)
    - [ECN marking at egress](#ecn-marking-at-egress)
    - [ECN marking accuracy](#ecn-marking-accuracy)

## Overview

In a traditional TCP/IP network, congestion is detected through packet loss. When network congestion occurs, routers and switches drop packets when their buffers fill up.
Explicit Congestion Notification (ECN) is an enhancement to TCP/IP congestion control that allows congestion to be signaled without dropping packets. Instead of relying on packet loss, ECN uses marking within the IP header to indicate congestion. The process works as follows:

- ECN-Capable Transport (ECT) Marking: The sender marks packets as ECN-capable (ECT) in the IP header.
- Congestion Notification: If a router or switch experiences congestion, instead of dropping packets, it marks the Congestion Experienced (CE) bit in the IP header.
- Receiver Acknowledgment: The receiver detects the CE mark and informs the sender via an ECN-Echo (ECE) flag in the TCP acknowledgment.
- Sender Response: Upon receiving an ECN-Echo, the sender reduces its congestion window (CWND) to slow down transmission, similar to traditional congestion control, but without losing packets.

This proactive mechanism improves network efficiency by preventing packet drops and reducing retransmission overhead. The primary algorithm governing ECN behavior is the Random Early Detection (RED) with ECN marking. RED dynamically marks packets with ECN-CE based on the queue depth. As the queue length increases, the marking probability rises, signaling congestion before significant queuing delays occur. The RED algorithm is defined by three key parameters:

- 𝐾min – the minimum threshold
- 𝐾max – the maximum threshold
- 𝑃max – the maximum marking (or dropping) probability

The marking probability is determined as follows:

- When the instantaneous queue length is below Kmin, the marking probability is 0%.
- When the queue length exceeds Kmax, the marking probability reaches 100%.
- Otherwise, the marking probability follows the formula: Marking Probability = (queue_length − 𝐾min)/(𝐾max − 𝐾min) × 𝑃max

The figure in ECN-test-plan.md illustrates the theoretical ECN marking probability as a function of queue length. Commodity switches can implement RED at ingress (when packets are enqueued into the switch buffer) or at egress (when packets are dequeued from the buffer). Compared to ingress RED/ECN, egress RED/ECN provides lower feedback delay, leading to faster congestion response.

## Test Objective

The test aims to validate the ECN behaviors of the SONiC DUT based on the Random Early Detection (RED) algorithm.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection.

## Test Cases

### ECN marking at egress

This test case aims to verify the DUT’s dequeue based ECN marking behavior (Egress marking). Below are the test steps.

1. Retrieve the queue index, priority to queue mappings, 𝐾max, 𝐾min and 𝑃max configurations of the DUT's first port from config_DB. For example:

    ```json
    "QUEUE": {
        "Ethernet0|0": {
            "scheduler": "scheduler.0"
        },
        "Ethernet0|1": {
            "scheduler": "scheduler.1"
            "wred_profile": "AZURE_WRED"

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
      "AZURE_WRED": {
          "ecn": "ecn_all",
          "red_drop_probability": "5",
          "red_max_threshold": "51000",
          "red_min_threshold": "50000",
          "wred_red_enable": "true"
      }
    }
    ```

2. Pause the egress traffic of the port on the DUT by using RPC sai_thrift_port_tx_disable().
3. Test data traffic: Identify the traffic generator and its corresponding port connected to the DUT port under test — this serves as the Rx port for the traffic flow. Then, on a separator traffic generator that is not connected to the DUT port, pick a Tx port on the generator to send traffic. Define a traffic flows at line rate, ensuring their DSCP values align with the priority settings on the DUT. The number of packets should be fixed at 2 × 𝐾max, with each packet being 1KB in size.
4. Start packet capture on the traffic generator Rx port.
5. From the traffic generator Tx port, send 2 × 𝐾max data packets to the receiver,  ensuring the packets are mapped to the right priority on the DUT..
6. Once all the test data packets are transmitted, stop pausing the egress traffic of the DUT port.
7. Stop the packet capture after all packets are received.
8. Verify the following:
   - traffic generator Rx port must receive 2 × 𝐾max test data packets.
   - The first test data packet received should be ECN marked.
   - The last test data packet received should not be ECN marked.
9. Move to the next DUT port and repeat the above steps until all ports have been tested. To improve efficiency, we can test the same logical port across all physical port concurrently.

### ECN marking accuracy

This test aims to verify the ECN marking accuracy on the DUT by comparing the actual ECN marking probability with the theoretical value. The steps are as follows:

1. Follow the first seven steps of the previous test case, with the only change being that (𝐾max + 10) packets are sent instead of 2 × 𝐾max.
2. Verify the following:
   - All (𝐾max + 10) packets must be received at the Rx port.
   - According to the egress ECN marking algorithm, the queue length associated with the data packet i (i = 1, 2, … 𝐾max + 10) should be (𝐾max + 10 – i) KB.
   - If the instantaneous queue length is q,
     - for the first 10 packets, q >= 𝐾max. So their theoretical ECN marking probability should be 100%.
     - For the next (𝐾max − 𝐾min) packets, 𝐾min <= q < 𝐾max, the theoretical ECN marking probability should not exceed 𝑃max%. As q decreases from 𝐾max to Kmin, the ECN marking probability should linearly decrease from 𝑃max to 0.
     - For the last 𝐾min packets, q < 𝐾min. So, none of the packets should be ECN marked.
3. Repeat the test 200 times to ensure statistical accuracy.
4. After 200 iterations, compare the theoretical ECN marking probability with the actual marking results for different queue lengths.
5. Move to the next DUT port and repeat all steps until all ports are tested. To improve efficiency, we can test the same logical port across all physical port concurrently.
