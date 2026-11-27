# CCL Network Performance Test Plan

## Overview

This test plan validates Collective Communication Library (CCL) performance on data-center switches and Ethernet fabrics under RoCEv2/RDMA workloads. It measures Job Completion Time (JCT), Algorithm Bandwidth, and Bus Bandwidth across collective algorithms, traffic mixes, frame sizes, message sizes, and DUT load-balancing modes (for the multi-Leaf test, Test Case 8).

**Common traffic parameters (all test cases):**

| Parameter | Value |
|---|---|
| Transport | RoCEv2 |
| IB MTU | 4096 B |
| RDMA Message Size | 128 KB, 1 MB, 1024 MB |
| QPs per rank pair | 1, 4, 8 |
| Congestion control (CC) mode | **PFC** and **PFC + DCQCN** (both tested; see Congestion Control Modes) |
| DSCP – data traffic | 3 (lossless queue 3) |
| DSCP – ACK / NAK | 3 |
| DSCP – CNP | 48 (queue 6) |
| ECN-CE bit | 10 (ECN-Capable Transport) |
| DUT load-balancing | ECMP (5-tuple hash) **and** Packet Spray – Topology B only (Test Case 8); not a test dimension on single-Leaf Topology A |
| Data Size | 160 GB |
| Number of Iterations | 20 |
| Interval Between Iterations | 300 ms |

**Metrics recorded in every test case:**

| Metric | Definition |
|---|---|
| JCT | Time from first packet sent to last ACK received for the collective |
| Algorithm Bandwidth | Collective Size / JCT |
| Bus Bandwidth | Algorithm BW × per-algorithm compensation factor* |
| Packet loss | Must be zero in all CC modes |
| NAK count | NAK frames sent |
| PFC count | PFC PAUSE frames received by sender ports |
| ECN-CE count | ECN-CE marked packets received by receiver ports (N/A in PFC mode) |
| CNP count | CNP frames received by sender ports (N/A in PFC mode) |

\* Compensation factors: AllReduce Ring / HDA: `2(n−1)/n`; AlltoAll: `(n−1)/n`.

---

## Test Topology A – 8-Port Single-Leaf (Single-Algorithm Tests)

- **One Leaf switch (DUT)** with 8 downlink ports connected to the tester at 400 GE or 800 GE.
- All 8 ranks (Rank 0–7) connect directly to the single DUT; no Spine layer is required.
- Queue 3 (DSCP 3) configured per the active CC mode (PFC and/or ECN marking enabled on all switch ports; see Congestion Control Modes).
- Each destination rank is reachable through exactly one egress port, so there is no multipath choice: ECMP and Packet Spray forward identically, DUT load-balancing is **not** a test dimension in Topology A tests.

```
              ┌───────────────────────────┐
              │         Leaf (DUT)        │
              └──┬──┬──┬──┬──┬──┬──┬──┘
                 │  │  │  │  │  │  │  │
                R0 R1 R2 R3 R4 R5 R6 R7
                  (Tester Ports – 400 GE)
```

## Test Topology B – 16-Port Leaf-Spine (Multi-Algorithm Tests)

- **Two Leaf switches** (Leaf-1 and Leaf-2) and **one Spine switch** (Spine).
- Each Leaf provides **8 × 400 GE or 800 GE downlinks** to the tester. **Ranks 0–7**: Leaf-1 · **Ranks 8–15**: Leaf-2.
- Each Leaf connects to the Spine with **8 × 400 GE or 800 GE uplinks** (same speed as the downlinks), giving an **oversubscription ratio of 1:1** (non-blocking). This is the baseline configuration. The actual number of uplinks and the oversubscription ratio must be recorded in the test report; if a ratio other than 1:1 is used, apply the oversubscription note in the Expected Results of Test Case 8.
- Queue 3 (DSCP 3) configured per the active CC mode (PFC and/or ECN marking enabled on all switch ports; see Congestion Control Modes).

```
                 Spine
         / (8 uplinks each) \
          Leaf-1             Leaf-2
          ||||||||           ||||||||
         R0..R7              R8..R15
         (Tester Ports – 400 GE or 800 GE)
```

### Rank-Group Mapping (Multi-Job Test, TC8)

Each job's ranks are **spread across both Leaves**, so every job sends traffic through the Spine and the two jobs compete for the same Leaf-to-Spine uplinks.

| Group | Ranks on Leaf-1 | Ranks on Leaf-2 | Logical rank order (index 0–7) |
|---|---|---|---|
| **Group A** | 0, 1, 2, 3 | 8, 9, 10, 11 | 0, 8, 1, 9, 2, 10, 3, 11 |
| **Group B** | 4, 5, 6, 7 | 12, 13, 14, 15 | 4, 12, 5, 13, 6, 14, 7, 15 |

- The logical rank order defines the Ring neighbor order and the HDA partner pairs (see Test Case 8). It alternates between Leaf-1 and Leaf-2.
- Group A and Group B use **disjoint tester ports**, so any interference between the two jobs can only occur on the Leaf-to-Spine uplinks and the Spine, not on a shared host port.

---

## Congestion Control Modes

Every test case is executed under each of the following two CC modes. The CC mode is set on the DUT and on the tester ports before each run.

| CC Mode | DUT (queue 3) | Tester ports | Expected counters | Loss expectation |
|---|---|---|---|---|
| **PFC** | PFC enabled; ECN marking disabled | DCQCN rate control disabled (no CNP) | PFC count; ECN-CE and CNP N/A | Zero loss required |
| **PFC + DCQCN** | PFC and ECN marking both enabled | DCQCN enabled (CNP DSCP 48) | PFC, ECN-CE and CNP counts | Zero loss required |

Test Cases 1–7 (Topology A) run 9 parameter combinations × 2 CC modes = 18 runs; Test Case 8 (Topology B) runs 18 parameter combinations × 2 CC modes = 36 runs. Zero-loss applies to all runs in both CC modes. Zero-NAK applies to all runs except the Packet Spray sub-cases of Test Case 8 (see below). Counters that belong to a disabled mechanism (ECN-CE and CNP in PFC mode) are reported as N/A.

---

## Parameter Matrix

Test Case 8 (Topology B) iterates all 18 combinations below, in each of the 2 CC modes. On Topology A (single Leaf; Test Cases 1–7) each destination has a single egress port, so ECMP and Packet Spray forward identically and the LB mode is not a test dimension: these test cases run only the 9 ECMP rows (P01–P09), in each of the 2 CC modes, unless otherwise noted. Higher QP counts (4, 8) increase flow entropy and typically improve traffic distribution uniformity across ECMP paths; this effect is most visible for small RDMA message sizes.

| ID | Message Size | LB Mode | QPs per rank pair |
|---|---|---|---|
| P01 | 128 KB | ECMP (5-tuple hash) | 1 |
| P02 | 1 MB | ECMP (5-tuple hash) | 1 |
| P03 | 1024 MB | ECMP (5-tuple hash) | 1 |
| P04 | 128 KB | ECMP (5-tuple hash) | 4 |
| P05 | 1 MB | ECMP (5-tuple hash) | 4 |
| P06 | 1024 MB | ECMP (5-tuple hash) | 4 |
| P07 | 128 KB | ECMP (5-tuple hash) | 8 |
| P08 | 1 MB | ECMP (5-tuple hash) | 8 |
| P09 | 1024 MB | ECMP (5-tuple hash) | 8 |
| P10 | 128 KB | Packet Spray | 1 |
| P11 | 1 MB | Packet Spray | 1 |
| P12 | 1024 MB | Packet Spray | 1 |
| P13 | 128 KB | Packet Spray | 4 |
| P14 | 1 MB | Packet Spray | 4 |
| P15 | 1024 MB | Packet Spray | 4 |
| P16 | 128 KB | Packet Spray | 8 |
| P17 | 1 MB | Packet Spray | 8 |
| P18 | 1024 MB | Packet Spray | 8 |

---

## Test Case 1 – AllReduce Uni-direction Ring

### Objective

- Validate JCT, Algorithm Bandwidth, and Bus Bandwidth for the **AllReduce Uni-direction Ring** algorithm using 8 ranks on a single-Leaf DUT.
- Compare performance across RDMA message sizes.
- Verify zero packet loss and zero NAK under PFC and PFC + DCQCN congestion control; compare the two CC modes.

### Topology

- Uses **Test Topology A** (8 ports, Ranks 0–7, single Leaf DUT).

### Test Steps

1. Configure the DUT with lossless queue 3 mapped to DSCP 3, queue 6 mapped to DSCP 48; configure PFC and/or ECN marking on all ports according to the active CC mode (PFC or PFC + DCQCN).
2. Configure 8 tester ports (Ranks 0–7) with RoCEv2:
   - DSCP data: 3; DSCP ACK/NAK: 3; DSCP CNP: 48.
   - QPs per rank pair as specified (1, 4, or 8); ECN-CE bit 10.
3. Configure **AllReduce Uni-direction Ring** over all 8 ranks (ring order: Rank 0 → 1 → … → 7 → 0). The algorithm executes `2(n−1)` steps in total (`n−1` Reduce-Scatter steps followed by `n−1` All-Gather steps); each step transfers one chunk of size `CollectiveSize / n`.
4. For each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set RDMA message size on all tester ports (QPs per rank pair as specified).
   b. Start the AllReduce Ring collective and run to completion.
   c. Record JCT, Algorithm Bandwidth, Bus Bandwidth, packet loss, NAK count, PFC count, ECN-CE count, CNP count.
5. Repeat Step 4 until all 9 combinations are measured in both CC modes.

### Expected Results

1. All collective passes complete successfully for all 9 parameter combinations in both CC modes.
   - No packet loss observed on the tester.
   - No NAK on the tester.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected; ECN-CE and CNP counts are N/A in PFC mode).
2. Bus Bandwidth = Algorithm Bandwidth × `2(n−1)/n` (n = 8 → factor = 1.75) is recorded per combination. Values should be stable and approach link saturation for large message sizes.


---

## Test Case 2 – AllReduce Halving Doubling (HDA)

### Objective

- Validate JCT, Algorithm Bandwidth, and Bus Bandwidth for **AllReduce Halving Doubling**.
- HDA (recursive-halving reduce-scatter followed by recursive-doubling all-gather) completes in `2·log₂(n)` rounds with non-contiguous rank pairs; verify correct forwarding and congestion control on the single-Leaf DUT.
- Compare results against Test Case 1 to characterize algorithm-level JCT differences.

### Topology

- Uses **Test Topology A** (8 ports, Ranks 0–7, single Leaf DUT).

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AllReduce Halving Doubling** over all 8 ranks (a 3-round recursive-halving reduce-scatter followed by a 3-round recursive-doubling all-gather, 2·log₂(8) = 6 rounds in total; the partner distance halves each round in the reduce-scatter and doubles each round in the all-gather).
4. For each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set RDMA message size (QPs per rank pair as specified).
   b. Start HDA collective and run to completion.
   c. Record all metrics as in Test Case 1, Step 4c.
5. Repeat until all 9 combinations are measured in both CC modes.

### Expected Results

1. All collective passes complete successfully.
   - No packet loss, no NAK.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected; ECN-CE and CNP counts are N/A in PFC mode).
2. Bus Bandwidth = Algorithm Bandwidth × `2(n−1)/n` (n = 8 → factor = 1.75) recorded per combination.
3. **Algorithm comparison (vs. Test Case 1):**
   - For small message sizes (128 KB), HDA should achieve lower JCT than Ring due to fewer synchronization steps (6 rounds vs. 14 steps).
   - For large message sizes (1024 MB), Ring and HDA converge to similar Bus Bandwidth (pipeline dominates).


---

## Test Case 3 – AlltoAll MtoM (Symmetric All-to-All)

### Objective

- Validate JCT, Algorithm Bandwidth, and Bus Bandwidth for **symmetric AlltoAll** where all M = 8 ranks exchange equal-sized chunks with every other rank.
- AlltoAll generates full-mesh traffic within the single Leaf DUT, the most demanding pattern for switch buffer management and PFC/ECN/DCQCN response.

### Topology

- Uses **Test Topology A** (8 ports, Ranks 0–7, single Leaf DUT). M = 8.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AlltoAll MtoM** (M = 8): each rank sends one equal chunk of `CollectiveSize / n` to each of the other 7 ranks simultaneously.
4. For each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set RDMA message size (QPs per rank pair as specified).
   b. Start AlltoAll and run to completion.
   c. Record all metrics.
5. Repeat until all 9 combinations are measured in both CC modes.

### Expected Results

1. All AlltoAll passes complete successfully.
   - No packet loss on the tester.
   - No NAK.
   - PFC count, ECN-CE count, and CNP count are **recorded, not pass/fail criteria**: full-mesh AlltoAll can reach the ECN/PFC thresholds on transient bursts even at ideal load (ECN-CE and CNP counts are N/A in PFC mode). Compare the counts between the two CC modes.
2. Algorithm Bandwidth and Bus Bandwidth (Bus BW = Algorithm BW × `(n−1)/n` for AlltoAll; n = 8 → factor = 0.875) recorded per combination.
3. All DUT egress ports toward receiver ranks should show balanced utilization; deviation across ports < 10%.


---

## Test Case 4 – AlltoAllv (Asymmetric All-to-All)

### Objective

- Test the switch's congestion handling capability under **asymmetric bidirectional AlltoAllv (M ≠ N)**. Group A (M ranks) and Group B (N ranks) exchange traffic with each other simultaneously.
- Because M > N, each rank in Group B receives from M sources while each rank in Group A receives from only N sources — creating incast congestion at Group B and triggering PFC/ECN/DCQCN.
- Verify that the switch correctly applies congestion control to stabilize throughput and maximize bandwidth under each CC mode (PFC, PFC + DCQCN) — with zero packet loss in both modes.
- Compare the congestion response of the two CC modes.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT).
- **Group A**: Ranks 0–6 (M = 7). **Group B**: Rank 7 (N = 1).
- Both groups send to and receive from each other. The Group B rank receives from 7 Group A ranks (7:1 incast); each Group A rank receives from 1 Group B rank (no congestion).

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure all 8 tester ports for bidirectional RoCEv2 traffic (each rank both sends and receives).
3. Configure **AlltoAllv** (M = 7, N = 1): each rank in Group A sends one chunk to every rank in Group B, and each rank in Group B sends one chunk to every rank in Group A; all other send sizes are 0.
4. For each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set RDMA message size (QPs per rank pair as specified).
   b. Start the collective and run to completion.
   c. Record all metrics; note Rx rate on the Group B port (Rank 7) and observe rate stabilization over time.
5. Optionally repeat with other M:N ratios (e.g., M = 5, N = 3) by changing the send-size matrix, to characterize congestion response at different incast levels.

### Expected Results

1. All passes complete successfully with no packet loss in any CC mode.
   - No NAK.
   - Congestion at Group B, by CC mode:
     - **PFC**: PFC PAUSE received by Group A ports (Ranks 0–6); no ECN-CE or CNP. Group A throughput is throttled by PAUSE; record head-of-line blocking effects and rate oscillation.
     - **PFC + DCQCN**: ECN-CE at Rank 7; PFC PAUSE and CNP at Ranks 0–6. Verify DCQCN stabilizes Group A rates and PFC is triggered less than in PFC mode.
2. Group B Rx rate stabilizes and approaches line rate after congestion control converges; Group A Rx rate (from Group B) should be uncongested.
3. DUT egress toward the Group B port (Rank 7) should sustain near line rate after congestion control converges; DUT egress toward Group A ports should be balanced, with each port receiving approximately equal traffic volume.
4. **CC mode comparison:** Record and compare Algorithm Bandwidth, JCT, PFC count and loss between PFC and PFC + DCQCN.


---

## Test Case 5 – AllReduce / AlltoAll + Continuous P2P Traffic

### Objective

- Measure the impact of concurrent continuous **point-to-point (P2P) background traffic** on the JCT and bandwidth of **AllReduce Uni-direction Ring**, **AllReduce Halving Doubling** and **AlltoAll MtoM**. Each collective is a sub-case (5a–5c) and is run on its own with the same P2P background traffic.
- This models a training cluster running data-parallel (AllReduce) and pipeline-parallel or storage (P2P) workloads on the same switch simultaneously.
- HDA uses non-contiguous rank pairs; characterize whether its traffic pattern interacts differently with P2P flows within the single Leaf DUT compared to Ring.
- AlltoAll already drives full-mesh intra-switch traffic; P2P adds further contention and stresses the PFC/ECN/DCQCN mechanisms within the single Leaf DUT.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT). The collective uses all 8 ranks; P2P traffic runs concurrently on the same ports.

| Sub-case | Collective (all 8 ranks) | Standalone baseline |
|---|---|---|
| 5a | AllReduce Uni-direction Ring | Test Case 1 |
| 5b | AllReduce Halving Doubling | Test Case 2 |
| 5c | AlltoAll MtoM | Test Case 3 |

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure the collective of the sub-case over all 8 ranks (same as the baseline test case in the table above).
4. Configure **continuous bidirectional P2P background traffic**:
   - Flow pairs: Rank 0 ↔ Rank 4, Rank 1 ↔ Rank 5, Rank 2 ↔ Rank 6, Rank 3 ↔ Rank 7.
   - DSCP: 3 (same lossless queue as the collective, creating realistic contention).
   - Rate: 10% of line rate per port, constant and non-bursty.
   - P2P traffic starts before the collective and continues throughout.
5. For each sub-case (5a–5c), each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set RDMA message size (QPs per rank pair as specified).
   b. Start P2P background traffic, then start the collective; run the collective to completion.
   c. Record collective JCT, Algorithm BW, Bus BW, and all counters. Record P2P Rx loss separately.
6. Compare the collective JCT per combination against its standalone baseline (table above). Compare 5b against 5a.

### Expected Results

1. The collective passes complete successfully for all 9 combinations in both CC modes, in every sub-case.
   - No packet loss on collective QPs or on P2P streams.
   - No NAK on collective QPs.
   - **5a, 5b:** PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected; ECN-CE and CNP counts are N/A in PFC mode).
   - **5c:** PFC count, ECN-CE count, and CNP count are **recorded, not pass/fail criteria**: full-mesh AlltoAll can reach the ECN/PFC thresholds on transient bursts even at ideal load, and P2P traffic may add queue build-up (ECN-CE and CNP counts are N/A in PFC mode). Compare the counts between the two CC modes.
2. Collective JCT degradation relative to its baseline is recorded per combination. Expected degradation proportional to 10% P2P load; JCT increase should be < 15%.
3. P2P Rx rate remains stable throughout the collective pass with no P2P loss.
4. **Cross-case comparison:** Compare 5a (Ring + P2P) vs. 5b (HDA + P2P) JCT degradation. HDA non-contiguous patterns may experience different buffer pressure within the single DUT.


---

## Test Case 6 – Sequential AlltoAll MtoM → AllReduce Uni-direction Ring

### Objective

- Measure per-phase JCT, transition overhead, and iteration-to-iteration stability when **AlltoAll MtoM** is immediately followed by **AllReduce Uni-direction Ring** on all 8 ranks.
- This models a training iteration in which gradient all-to-all scatter precedes a parameter all-reduce on the same rank group.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT). All 8 ranks participate in both phases.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports (Ranks 0–7) with RoCEv2, DSCP 3 data, DSCP 48 CNP, QPs per rank pair as specified (1, 4, or 8), ECN-CE bit 10.
3. Define a two-phase iteration:
   - **Phase 1**: AlltoAll MtoM over all 8 ranks – run to completion of all messages.
   - **Phase 2**: AllReduce Uni-direction Ring over all 8 ranks – triggered immediately upon Phase 1 completion.
4. For each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set message size (QPs per rank pair as specified).
   b. Run 10 consecutive Phase 1 → Phase 2 iterations.
   c. For each iteration record: Phase 1 JCT, Phase 2 JCT, and all per-phase counters.
5. Compute mean and coefficient of variation (CV) of JCT across the 10 iterations per combination.

### Expected Results

1. All phases complete successfully across all 10 iterations and 9 combinations in both CC modes.
   - No packet loss, no NAK in either phase.
   - PFC count, ECN-CE count, and CNP count are **recorded per phase, not pass/fail criteria**: the AlltoAll phase can reach the ECN/PFC thresholds on transient bursts even at ideal load (ECN-CE and CNP counts are N/A in PFC mode).
2. **Phase 1 (AlltoAll)** JCT stable across 10 iterations; CV < 5% per combination.
3. **Phase 2 (AllReduce Ring)** JCT stable across 10 iterations; CV < 5% per combination.


---

## Test Case 7 – Sequential AlltoAll MtoM → AllReduce Halving Doubling

### Objective

- Same as Test Case 6 with **AllReduce Halving Doubling** as Phase 2.
- Characterize whether HDA's non-contiguous rank-pair traffic pattern encounters transient congestion immediately following an AlltoAll phase.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT). All 8 ranks participate in both phases.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 6, Step 2.
3. Define a two-phase iteration:
   - **Phase 1**: AlltoAll MtoM over all 8 ranks – run to completion.
   - **Phase 2**: AllReduce Halving Doubling over all 8 ranks – triggered immediately upon Phase 1 completion.
4. For each CC mode (PFC, PFC + DCQCN) and each of the 9 parameter combinations (P01–P09):
   a. Set message size (QPs per rank pair as specified).
   b. Run 10 consecutive Phase 1 → Phase 2 iterations.
   c. Record per-iteration: Phase 1 JCT, Phase 2 JCT, and all per-phase counters.
5. Compute mean and CV of JCT per combination.

### Expected Results

1. All phases complete successfully across all 10 iterations and 9 combinations in both CC modes.
   - No packet loss, no NAK.
   - PFC count, ECN-CE count, and CNP count are **recorded per phase, not pass/fail criteria**: the AlltoAll phase can reach the ECN/PFC thresholds on transient bursts even at ideal load (ECN-CE and CNP counts are N/A in PFC mode).
2. Phase 1 (AlltoAll) JCT stable; CV < 5% per combination.
3. Phase 2 (HDA) JCT stable; CV < 5% per combination.
4. **Cross-case comparison (TC-6 vs. TC-7):** The Phase 2 JCT difference between TC-6 (Ring) and TC-7 (HDA) should match the TC-1 vs. TC-2 standalone delta. A significantly larger gap indicates that HDA's non-contiguous traffic pattern amplifies residual AlltoAll congestion. Record and compare.


---

## Test Case 8 – Concurrent AllReduce + AlltoAll MtoM

### Objective

- Validate JCT and bandwidth when an **AllReduce** job and an **AlltoAll MtoM** job run simultaneously on two separate rank groups whose ranks are **interleaved across Leaf-1 and Leaf-2**, so both jobs share the Leaf-to-Spine uplinks and the Spine. Group A's algorithm is **Uni-direction Ring** (sub-case 8a) or **Halving Doubling** (sub-case 8b).
- This models multi-job co-location where different training jobs use different collective algorithms concurrently.
- Verify that inter-Leaf traffic is distributed across the Leaf uplinks (ECMP vs. Packet Spray) and that cross-job interference on the Spine stays within the JCT degradation limit.
- HDA's rank-pair communication loads the Leaf-to-Spine uplinks differently from Ring; compare Spine utilization and JCT between 8a and 8b.

### Topology

- Uses **Test Topology B** (16 ports, 2 Leaf + 1 Spine); record the number of uplinks per Leaf and the oversubscription ratio (baseline: 8 uplinks, 1:1).
- Rank groups as defined in **Rank-Group Mapping** (Topology B):
  - **Group A** (AllReduce): Ranks 0–3 (Leaf-1) + Ranks 8–11 (Leaf-2), logical order 0, 8, 1, 9, 2, 10, 3, 11.
    - **8a (Ring):** ring order 0 → 8 → 1 → 9 → 2 → 10 → 3 → 11 → 0. Every ring hop crosses the Spine (4 flows Leaf-1 → Leaf-2, 4 flows Leaf-2 → Leaf-1).
    - **8b (HDA):** logical index 0–7 maps to Ranks 0, 8, 1, 9, 2, 10, 3, 11.
  - **Group B** (AlltoAll MtoM): Ranks 4–7 (Leaf-1) + Ranks 12–15 (Leaf-2). Each rank sends to 3 same-Leaf peers and 4 cross-Leaf peers.

| Sub-case | Group A algorithm | Group A baseline | Group B baseline |
|---|---|---|---|
| 8a | AllReduce Uni-direction Ring | Test Case 1 | Test Case 3 |
| 8b | AllReduce Halving Doubling | Test Case 2 | Test Case 3 |

### Test Steps

1. Configure all DUTs (2 Leaf + 1 Spine) with lossless queue 3 (DSCP 3), queue 6 (DSCP 48); configure PFC and/or ECN on all ports according to the active CC mode (PFC or PFC + DCQCN). Verify all Leaf-to-Spine uplinks are active and record the number of uplinks and the oversubscription ratio.
2. Configure all 16 tester ports (Ranks 0–15) with RoCEv2, DSCP 3 data, DSCP 48 CNP, QPs per rank pair as specified (1, 4, or 8), ECN-CE bit 10. Group A and Group B use **independent, non-overlapping QP identifiers**.
3. Configure **Group A**: AllReduce (Ring for 8a, Halving Doubling for 8b) over Ranks 0, 8, 1, 9, 2, 10, 3, 11 (in this order; for HDA, logical index 0–7).
4. Configure **Group B**: AlltoAll MtoM over Ranks 4, 12, 5, 13, 6, 14, 7, 15.
5. For each sub-case (8a, 8b), each CC mode (PFC, PFC + DCQCN) and each of the 18 parameter combinations (P01–P18):
   a. Set DUT load-balancing and RDMA message size for both groups.
   b. Start Group A and Group B **simultaneously**.
   c. Record per-group JCT and all per-group counters independently.
   d. Record per-port Tx/Rx bytes on all uplinks of Leaf-1 and Leaf-2 and on the corresponding Spine ports, in both directions (Leaf → Spine and Spine → Leaf), to verify load distribution across uplinks.
6. Compare Group A and Group B JCT against the baselines in the table above, using for each combination the Topology A baseline with the same message size and QPs per rank pair. (Baselines run on a single Leaf; the difference therefore includes the extra Leaf-Spine-Leaf hop and the cross-job interference.)
7. Compare 8b against 8a: per-uplink utilization, uplink balance and Group B JCT, using the same rank groups and logical order.

### Expected Results

1. Both collectives complete successfully for all 18 combinations in both CC modes, in every sub-case.
   - No packet loss in either group, in all sub-cases: the DUTs report zero packet drops, and every message is eventually delivered.
   - **ECMP sub-cases:** no NAK in either group.
   - **Packet Spray sub-cases:** With RC QPs, an out-of-order packet normally triggers a NAK and go-back-N retransmission, so the NAK count is **not** required to be zero. Record the NAK count per group.
   - PFC count, ECN-CE count, and CNP count are **recorded per group, not pass/fail criteria**: AlltoAll bursts and the shared uplinks can trigger ECN marking and PFC even at 1:1 (ECN-CE and CNP counts are N/A in PFC mode). Compare the counts between the two CC modes and between ECMP and Packet Spray.
2. **Spine is exercised:** uplink and Spine port counters show non-zero traffic in both directions in every run. Cross-Leaf traffic from both groups is visible in the Spine counters.
3. **Group A** JCT degradation vs. its baseline (Test Case 1 for 8a, Test Case 2 for 8b) is < 20% (both groups share Spine capacity).
4. **Group B** JCT degradation vs. Test Case 3 is < 20%.
5. **Uplink balance:** for each direction (Leaf → Spine and Spine → Leaf), the deviation of per-uplink byte count from the mean across the uplinks of that Leaf is < 10%.
   - Required for Packet Spray.
   - For ECMP, record the deviation; with 1 QP per rank pair the number of flows is small and hash collisions may exceed 10% (higher QP counts are expected to improve uniformity).
6. **LB mode comparison:** Packet Spray spreads each group's flows across uplinks, reducing the risk of a hot-spot. Record per-uplink utilization and JCT for ECMP vs. Packet Spray.
7. **Cross-case comparison (8a vs. 8b):** HDA crosses the Spine in only some of its rounds, whereas Ring crosses the Spine on every hop. Differences in Group B JCT degradation and in Spine uplink utilization between 8a and 8b indicate whether HDA's Spine-link occupancy pattern causes more or less interference with AlltoAll than Ring does. Record and compare.
8. **Oversubscription other than 1:1:** if fewer than 8 uplinks per Leaf are used (e.g., 2:1), uplink congestion is expected, with correspondingly higher PFC / ECN-CE / CNP counts; the 20% JCT limit in items 3–4 is then recorded as a measurement and re-evaluated against the ratio used.
