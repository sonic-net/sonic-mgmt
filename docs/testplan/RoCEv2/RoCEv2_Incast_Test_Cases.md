**RoCEv2 Incast Test Cases**

_Benchmark Methodology for AI Fabric Training Networks_

IETF BMWG Draft Reference

Version 1.0 | July 2026

**Table of Contents**

Contents

[INTRODUCTION: RoCEv2 incast fundamentals and test objectives 3](#_Toc234921055)

[TEST CASE 1: MANY-TO-ONE INCAST without DCQCN 4](#_Toc234921056)

[TEST CASE 2: MANY-TO-ONE INCAST with DCQCN 7](#_Toc234921057)

[TEST CASE 3: MIXED INCAST without DCQCN enabled 10](#_Toc234921058)

[TEST CASE 4: HIERARCHICAL INCAST 13](#_Toc234921059)

# INTRODUCTION: RoCEv2 incast fundamentals and test objectives

**What is RoCEv2 Incast?**

Incast is a network traffic pattern where multiple senders simultaneously transmit data to a single receiver. In RoCEv2 fabrics, this pattern is common in AI training workloads - particularly during collective operations like All-Reduce and All-Gather, where gradients from multiple GPUs converge on a single aggregation node. The simultaneous arrival of high-bandwidth flows at one port creates buffer pressure, triggering PFC pauses, ECN marks, and potentially PFC storms or head-of-line blocking.

**Test Objectives**

- Validate PFC/ECN behavior under synchronized many-to-one traffic patterns
- Measure buffer exhaustion thresholds and pause frame propagation
- Assess throughput degradation and latency inflation under incast load
- Evaluate head-of-line blocking impact on non-incast traffic (same priority)
- Verify ECN-based congestion control reaction time and fairness
- Test mixed traffic scenarios (lossy + lossless) under incast pressure

# TEST CASE 1: MANY-TO-ONE INCAST without DCQCN

_Standard incast with N senders to 1 receiver_

**Objective**

Measure the behavior of a RoCEv2 fabric when N senders simultaneously transmit to a single receiver by disabling DCQCN . 
Characterize PFC pause generation, ECN marking, throughput collapse, and latency under synchronized load.

**Test Parameters**

| **Parameter**         | **Value**                                 |
| --------------------- | ----------------------------------------- |
| Number of Senders (N) | 8, 16, 32, 64                             |
| Sender Link Rate      | 400 Gbps each                             |
| Receiver Link Rate    | 400 Gbps                                  |
| Traffic Pattern       | Simultaneous start, continuous RDMA WRITE |
| Message Size          | 4 KB, 64 KB, 1 MB                         |
| PFC                   | Enabled (Priority 3)                      |
| DSCP                  | 26                                        |
| ECN                   | Enabled (Threshold: 50% buffer)           |

**Test Procedure**

1\. Configure all senders and receiver with RoCEv2, PFC on priority 3, DSCP value 26, ECN enabled

2\. Pre-allocate receiver memory buffers for RDMA WRITE operations

3\. Synchronize senders to start transmission simultaneously (±1 µs jitter)

4\. Each sender performs continuous RDMA WRITE to the receiver at line rate

5\. Monitor switch buffer occupancy, PFC pause count, ECN mark count

6\. Record receiver throughput, latency, and completion time per sender

7\. Gradually increase N from 8 to 64; repeat for each message size

**Expected Results & Pass Criteria**

| **Metric**          | **Target**                    | **Pass/Fail**    |
| ------------------- | ----------------------------- | ---------------- |
| Receiver Throughput | ≥ 95% of line rate (380 Gbps) | Pass if ≥ 95%    |
| PFC Pause Frames    | < 1000 per second             | Pass if < 1000/s |
| ECN Marked Packets  | < 5% of total packets         | Pass if < 5%     |

# TEST CASE 2: MANY-TO-ONE INCAST with DCQCN

_Standard incast with N senders to 1 receiver_

**Objective**

Measure the behavior of a RoCEv2 fabric when N senders simultaneously transmit to a single receiver by enabling DCQCN . 
Characterize PFC pause generation, ECN marking, throughput collapse, and latency under synchronized load.

**Test Parameters**

| **Parameter**         | **Value**                                 |
| --------------------- | ----------------------------------------- |
| Number of Senders (N) | 8, 16, 32, 64                             |
| Sender Link Rate      | 400 Gbps each                             |
| Receiver Link Rate    | 400 Gbps                                  |
| Traffic Pattern       | Simultaneous start, continuous RDMA WRITE |
| Message Size          | 4 KB, 64 KB, 1 MB                         |
| PFC                   | Enabled (Priority 3)                      |
| DSCP                  | 26                                        |
| ECN                   | Enabled (Threshold: 50% buffer)           |

**Test Procedure**

1\. Configure all senders and receiver with RoCEv2, PFC on priority 3, DSCP value 26, ECN enabled

2\. Pre-allocate receiver memory buffers for RDMA WRITE operations

3\. Synchronize senders to start transmission simultaneously (±1 µs jitter)

4\. Each sender performs continuous RDMA WRITE to the receiver at line rate

5\. Monitor switch buffer occupancy, PFC pause count, ECN mark count

6\. Record receiver throughput, latency, and completion time per sender

7\. Gradually increase N from 8 to 64; repeat for each message size

**Expected Results & Pass Criteria**

| **Metric**                       | **Target**                                                | **Pass/Fail**                                        |
| -------------------------------- | --------------------------------------------------------- | ---------------------------------------------------- |
| Receiver Throughput              | ≥ 95% of line rate (380 Gbps)                             | Pass if ≥ 95%                                        |
| Throughput of each sender ( 8:1) | Each sender should have equal Throughput close to 48 Gbps | Throughput nearly equal to 48 Gbps for all 8 Senders |
| PFC Pause Frames                 | None or very few                                          | None or very few PFC                                 |
| ECN Marked Packets               | < 5% of total packets                                     | Pass if < 5%                                         |

# TEST CASE 3: MIXED INCAST without DCQCN enabled

_Lossy and lossless traffic coexistence_


**Objective**

Validate RoCEv2 incast behavior when lossless traffic (PFC-enabled priority) shares the fabric with lossy traffic (TCP/IP, no PFC). 
Assess whether PFC pauses on the lossless priority spill over to lossy traffic via shared buffer or head-of-line blocking.


**Key Concern: Shared Buffer Head-of-Line Blocking**

When RoCE traffic triggers PFC on Priority 3, the switch may pause the entire port if buffers are shared. This can stall TCP traffic on the same port even though TCP runs on a different priority class. Test validates whether the switch implements per-priority buffering and isolation.

**Test Parameters**

| **Parameter**         | **Value**                                 |
| --------------------- | ----------------------------------------- |
| Number of Senders (N) | 8, 16, 32, 64                             |
| Sender Link Rate      | 400 Gbps each                             |
| Receiver Link Rate    | 400 Gbps                                  |
| Traffic Pattern       | Simultaneous start, continuous RDMA WRITE |
| Message Size          | 4 KB, 64 KB, 1 MB                         |
| PFC                   | Enabled (Priority 3)                      |
| DSCP                  | 26                                        |
| ECN                   | Enabled (Threshold: 50% buffer)           |

**Pass Criteria**

- TCP throughput degradation < 10% during RoCE incast
- No TCP retransmissions triggered by PFC pause on RoCE priority
- RoCE receiver maintains zero packet loss
- Switch buffer occupancy per priority class isolated (no cross-priority spill)
- PFC pause frames only on Priority 3, never on TCP priorities

# TEST CASE 4: HIERARCHICAL INCAST

_Multi-tier switch incast_


Evaluate incast behavior in a multi-tier Clos topology where traffic converges at the spine layer. 
Assess PFC pause propagation across leaf-spine links and measure head-of-line blocking on non-incast traffic.

**Topology Parameters**

| **Parameter**    | **Value**                             |
| ---------------- | ------------------------------------- |
| Leaf Switches    | 4 (each with 16×400G down, 4×400G up) |
| Spine Switches   | 2 (each with 8×400G down)             |
| Senders per Leaf | 8                                     |
| Total Senders    | 32                                    |
| Receiver         | 1 (connected to Spine 1)              |

**Test Parameters**

| **Parameter**         | **Value**                                 |
| --------------------- | ----------------------------------------- |
| Number of Senders (N) | 8, 16, 32, 64                             |
| Sender Link Rate      | 400 Gbps each                             |
| Receiver Link Rate    | 400 Gbps                                  |
| Traffic Pattern       | Simultaneous start, continuous RDMA WRITE |
| Message Size          | 4 KB, 64 KB, 1 MB                         |
| PFC                   | Enabled (Priority 3)                      |
| DSCP                  | 26                                        |

**Test Procedure**

1\. Configure 2-tier Clos topology with PFC/ECN on all inter-switch links

2\. Map 8 senders per leaf; all 32 senders target the single receiver via Spine 1

3\. Start background traffic (non-incast) on same priority class through Leaf 4

4\. Trigger synchronized incast from all 32 senders to receiver

5\. Monitor PFC pause propagation: Leaf→Spine and Spine→Leaf directions

6\. Measure throughput degradation on background traffic (head-of-line blocking)

7\. Record ECN mark propagation and congestion window reduction at senders

8\. Verify no PFC storm - pause frame count should stabilize, not grow exponentially

**Key Measurements**

- PFC pause frame count per link (Leaf-Spine and Spine-Receiver)
- Buffer occupancy at spine switch (target port)
- Background traffic throughput degradation (%)
- ECN-marked packet ratio at each hop
- End-to-end latency for incast vs. background traffic
- PFC pause duration distribution (min/median/max)