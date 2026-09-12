# CCL Network Performance Test Plan

## Overview

This test plan validates Collective Communication Library (CCL) performance on data-center switches and Ethernet fabrics under RoCEv2/RDMA workloads. It measures Job Completion Time (JCT), Algorithm Bandwidth, and Bus Bandwidth across collective algorithms, traffic mixes, frame sizes, message sizes, and DUT load-balancing modes.

**Common traffic parameters (all test cases):**

| Parameter | Value |
|---|---|
| Transport | RoCEv2 |
| IB MTU | 4096 B **and** 8192 B |
| RDMA Message Size | 128 KB, 1 MB, 1024 MB |
| QPs per rank pair | 1, 4, 8 |
| Congestion control | PFC + ECN (DCQCN) – always enabled |
| DSCP – data traffic | 3 (lossless queue 3) |
| DSCP – ACK / NAK | 3 |
| DSCP – CNP | 48 (queue 6) |
| ECN-CE bit | 01 or 10 (ECN-Capable Transport) |
| DUT load-balancing | ECMP (5-tuple hash) **and** Packet Spray |
| Data Size | 160 GB |
| Number of Iterations | 20 |

**Metrics recorded in every test case:**

| Metric | Definition |
|---|---|
| JCT | Time from first packet sent to last ACK received for the collective |
| Algorithm Bandwidth | Collective Size / JCT |
| Bus Bandwidth | Algorithm BW × per-algorithm compensation factor* |
| Packet loss | Must be zero |
| Reorder count | Out-of-order packets |
| NAK count | NAK frames sent |
| PFC count | PFC PAUSE frames received by sender ports |
| ECN-CE count | ECN-CE marked packets received by receiver ports |
| CNP count | CNP frames received by sender ports |

\* Compensation factors: AllReduce Ring / HDA: `2(n−1)/n`; AlltoAll: `1`.

---

## Test Topology A – 8-Port Single-Leaf (Single-Algorithm Tests)

- **One Leaf switch (DUT)** with 8 downlink ports connected to the tester at 400 GE or 800 GE.
- All 8 ranks (Rank 0–7) connect directly to the single DUT; no Spine layer is required.
- Lossless queue 3 (DSCP 3) with PFC and ECN enabled on all switch ports.
- DUT load-balancing is configured per test step as either ECMP (5-tuple hash) or Packet Spray (applies to intra-switch forwarding paths).

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
- Each Leaf provides **8 × 400 GE or 800 GE downlinks** to the tester and connects to the Spine via uplinks.
- **Ranks 0–7**: Leaf-1 · **Ranks 8–15**: Leaf-2.
- Lossless queue 3 (DSCP 3) with PFC and ECN enabled on all switch ports.

```
            Spine
           /     \
        Leaf-1  Leaf-2
         ||||    ||||
       R0..R7  R8..R15
        (Tester Ports – 400 GE or 800 GE)
```

---

## Parameter Matrix

Every test case iterates the following 36 combinations unless otherwise noted. Higher QP counts (4, 8) increase flow entropy and typically improve traffic distribution uniformity across ECMP paths; this effect is most visible for small RDMA message sizes.

| ID | IB MTU | Message Size | LB Mode | QPs per rank pair |
|---|---|---|---|---|
| P01 | 4096 B | 128 KB | ECMP (5-tuple hash) | 1 |
| P02 | 4096 B | 1 MB | ECMP (5-tuple hash) | 1 |
| P03 | 4096 B | 1024 MB | ECMP (5-tuple hash) | 1 |
| P04 | 8192 B | 128 KB | ECMP (5-tuple hash) | 1 |
| P05 | 8192 B | 1 MB | ECMP (5-tuple hash) | 1 |
| P06 | 8192 B | 1024 MB | ECMP (5-tuple hash) | 1 |
| P07 | 4096 B | 128 KB | Packet Spray | 1 |
| P08 | 4096 B | 1 MB | Packet Spray | 1 |
| P09 | 4096 B | 1024 MB | Packet Spray | 1 |
| P10 | 8192 B | 128 KB | Packet Spray | 1 |
| P11 | 8192 B | 1 MB | Packet Spray | 1 |
| P12 | 8192 B | 1024 MB | Packet Spray | 1 |
| P13 | 4096 B | 128 KB | ECMP (5-tuple hash) | 4 |
| P14 | 4096 B | 1 MB | ECMP (5-tuple hash) | 4 |
| P15 | 4096 B | 1024 MB | ECMP (5-tuple hash) | 4 |
| P16 | 8192 B | 128 KB | ECMP (5-tuple hash) | 4 |
| P17 | 8192 B | 1 MB | ECMP (5-tuple hash) | 4 |
| P18 | 8192 B | 1024 MB | ECMP (5-tuple hash) | 4 |
| P19 | 4096 B | 128 KB | Packet Spray | 4 |
| P20 | 4096 B | 1 MB | Packet Spray | 4 |
| P21 | 4096 B | 1024 MB | Packet Spray | 4 |
| P22 | 8192 B | 128 KB | Packet Spray | 4 |
| P23 | 8192 B | 1 MB | Packet Spray | 4 |
| P24 | 8192 B | 1024 MB | Packet Spray | 4 |
| P25 | 4096 B | 128 KB | ECMP (5-tuple hash) | 8 |
| P26 | 4096 B | 1 MB | ECMP (5-tuple hash) | 8 |
| P27 | 4096 B | 1024 MB | ECMP (5-tuple hash) | 8 |
| P28 | 8192 B | 128 KB | ECMP (5-tuple hash) | 8 |
| P29 | 8192 B | 1 MB | ECMP (5-tuple hash) | 8 |
| P30 | 8192 B | 1024 MB | ECMP (5-tuple hash) | 8 |
| P31 | 4096 B | 128 KB | Packet Spray | 8 |
| P32 | 4096 B | 1 MB | Packet Spray | 8 |
| P33 | 4096 B | 1024 MB | Packet Spray | 8 |
| P34 | 8192 B | 128 KB | Packet Spray | 8 |
| P35 | 8192 B | 1 MB | Packet Spray | 8 |
| P36 | 8192 B | 1024 MB | Packet Spray | 8 |

---

## Test Case 1 – AllReduce Uni-direction Ring

### Objective

- Validate JCT, Algorithm Bandwidth, and Bus Bandwidth for the **AllReduce Uni-direction Ring** algorithm using 8 ranks on a single-Leaf DUT.
- Compare performance across IB MTU sizes, RDMA message sizes, and DUT load-balancing modes (ECMP vs. Packet Spray).
- Verify zero packet loss and zero NAK under PFC + ECN congestion control; record reorder count.

### Topology

- Uses **Test Topology A** (8 ports, Ranks 0–7, single Leaf DUT).

### Test Steps

1. Configure the DUT with lossless queue 3 mapped to DSCP 3, queue 6 mapped to DSCP 48; enable PFC and ECN marking on all ports.
2. Configure 8 tester ports (Ranks 0–7) with RoCEv2:
   - DSCP data: 3; DSCP ACK/NAK: 3; DSCP CNP: 48.
   - QPs per rank pair as specified (1, 4, or 8); ECN-CE bit 01 or 10.
3. Configure **AllReduce Uni-direction Ring** over all 8 ranks (ring order: Rank 0 → 1 → … → 7 → 0). The algorithm executes `n−1` Reduce-Scatter steps followed by `n−1` All-Gather steps; each step transfers one chunk of size `CollectiveSize / (n−1)`.
4. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing to the specified LB Mode.
   b. Set IB MTU and RDMA message size on all tester ports.
   c. Start the AllReduce Ring collective and run to completion.
   d. Record JCT, Algorithm Bandwidth, Bus Bandwidth, packet loss, reorder count, NAK count, PFC count, ECN-CE count, CNP count.
5. Repeat Step 4 until all 36 combinations are measured.

### Expected Results

1. All collective passes complete successfully for all 36 parameter combinations.
   - No packet loss observed on the tester.
   - No NAK and no sequence error on the tester.
   - Reorder count must be zero for ECMP sub-cases. For Packet Spray sub-cases, reorder is expected; record reorder depth.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected).
2. Bus Bandwidth = Algorithm Bandwidth × `2(n−1)/n` (n = 8 → factor = 1.75) is recorded per combination. Values should be stable and approach link saturation for large message sizes.
3. **IB MTU comparison:** Bus Bandwidth at 8192 B MTU should be equal to or higher than at 4096 B MTU, particularly for small message sizes (reduced header overhead per byte).
4. **LB mode comparison:** Record and compare Algorithm Bandwidth for ECMP vs. Packet Spray across all message sizes.


---

## Test Case 2 – AllReduce Halving Doubling (HDA)

### Objective

- Validate JCT, Algorithm Bandwidth, and Bus Bandwidth for **AllReduce Halving Doubling**.
- HDA completes in `log₂(n)` rounds with non-contiguous rank pairs; verify correct forwarding and congestion control on the single-Leaf DUT.
- Compare results against Test Case 1 to characterize algorithm-level JCT differences.

### Topology

- Uses **Test Topology A** (8 ports, Ranks 0–7, single Leaf DUT).

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AllReduce Halving Doubling** over all 8 ranks (log₂(8) = 3 rounds; communication partners double in distance each round).
4. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size.
   b. Start HDA collective and run to completion.
   c. Record all metrics as in Test Case 1, Step 4d.
5. Repeat until all 36 combinations are measured.

### Expected Results

1. All collective passes complete successfully.
   - No packet loss, no NAK, no sequence error.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected).
2. Bus Bandwidth = Algorithm Bandwidth × `2(n−1)/n` (factor = 1.75, n = 8) recorded per combination.
3. **Algorithm comparison (vs. Test Case 1):**
   - For small message sizes (128 KB), HDA should achieve lower JCT than Ring due to fewer synchronization steps (3 rounds vs. 14 steps).
   - For large message sizes (1024 MB), Ring and HDA converge to similar Bus Bandwidth (pipeline dominates).
4. LB mode comparison as in Test Case 1.


---

## Test Case 3 – AlltoAll MtoM (Symmetric All-to-All)

### Objective

- Validate JCT, Algorithm Bandwidth, and Bus Bandwidth for **symmetric AlltoAll** where all M = 8 ranks exchange equal-sized chunks with every other rank.
- AlltoAll generates full-mesh traffic within the single Leaf DUT, the most demanding pattern for switch buffer management and ECN/PFC response.

### Topology

- Uses **Test Topology A** (8 ports, Ranks 0–7, single Leaf DUT). M = 8.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AlltoAll MtoM** (M = 8): each rank sends one equal chunk of `CollectiveSize / n` to each of the other 7 ranks simultaneously.
4. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size.
   b. Start AlltoAll and run to completion.
   c. Record all metrics.
5. Repeat until all 36 combinations are measured.

### Expected Results

1. All AlltoAll passes complete successfully.
   - No packet loss on the tester.
   - No NAK, no sequence error.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected).
2. Algorithm Bandwidth and Bus Bandwidth (Bus BW ≈ Algorithm BW × 1 for AlltoAll) recorded per combination.
3. All DUT egress ports toward receiver ranks should show balanced utilization; deviation across ports < 10%.
4. **LB mode comparison:** Record Algorithm Bandwidth for ECMP vs. Packet Spray and compare across message sizes.


---

## Test Case 4 – AlltoAll MtoN (Asymmetric All-to-All)

### Objective

- Test the switch's congestion handling capability under **asymmetric bidirectional AlltoAll (M ≠ N)**. Group A (M ranks) and Group B (N ranks) exchange traffic with each other simultaneously.
- Because M > N, each rank in Group B receives from M sources while each rank in Group A receives from only N sources — creating incast congestion at Group B and triggering PFC/ECN/DCQCN.
- Verify that the switch correctly applies congestion control to stabilize throughput and maximize bandwidth — with zero packet loss.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT).
- **Group A**: Ranks 0–5 (M = 6). **Group B**: Ranks 6–7 (N = 2).
- Both groups send to and receive from each other. Each Group B rank receives from 6 Group A ranks (3:1 incast); each Group A rank receives from 2 Group B ranks (no congestion).

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure all 8 tester ports for bidirectional RoCEv2 traffic (each rank both sends and receives).
3. Configure **AlltoAll MtoN** (M = 6, N = 2): each rank in Group A sends one chunk to every rank in Group B, and each rank in Group B sends one chunk to every rank in Group A.
4. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size.
   b. Start the collective and run to completion.
   c. Record all metrics; note Rx rate on Group B ports (Ranks 6–7) and observe rate stabilization over time.
5. Optionally repeat with other M:N ratios (e.g., M = 5, N = 3) to characterize congestion response at different incast levels.

### Expected Results

1. All passes complete successfully with no packet loss.
   - No NAK, no sequence error.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - Congestion at Group B: ECN-CE marking received by Group B ports (Ranks 6–7); PFC PAUSE and CNP received by Group A ports (Ranks 0–5). Verify DCQCN causes Group A send rates to stabilize.
2. Group B Rx rate stabilizes and approaches line rate after congestion control converges; Group A Rx rate (from Group B) should be uncongested.
3. DUT egress toward Group B should be balanced; both Group B ports receive approximately equal traffic volume.
4. **LB mode comparison:** Record and compare Algorithm Bandwidth for ECMP vs. Packet Spray.


---

## Test Case 5 – AllReduce Uni-direction Ring + Continuous P2P Traffic

### Objective

- Measure the impact of concurrent continuous **point-to-point (P2P) background traffic** on **AllReduce Uni-direction Ring** JCT and bandwidth.
- This models a training cluster running data-parallel (AllReduce) and pipeline-parallel or storage (P2P) workloads on the same switch simultaneously.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT). AllReduce uses all 8 ranks; P2P traffic runs concurrently on the same ports.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AllReduce Uni-direction Ring** over all 8 ranks.
4. Configure **continuous bidirectional P2P background traffic**:
   - Flow pairs: Rank 0 ↔ Rank 4, Rank 1 ↔ Rank 5, Rank 2 ↔ Rank 6, Rank 3 ↔ Rank 7.
   - DSCP: 3 (same lossless queue as AllReduce, creating realistic contention).
   - Rate: 10% of line rate per port, constant and non-bursty.
   - P2P traffic starts before the AllReduce and continues throughout.
5. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size.
   b. Start P2P background traffic, then start AllReduce Ring; run AllReduce to completion.
   c. Record AllReduce JCT, Algorithm BW, Bus BW, and all counters. Record P2P Rx loss separately.
6. Compare AllReduce JCT per combination against Test Case 1 baseline (AllReduce Ring without P2P).

### Expected Results

1. AllReduce Ring passes complete successfully for all 36 combinations.
   - No packet loss on AllReduce QPs.
   - No NAK, no sequence error on AllReduce QPs.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - No packet loss on P2P streams.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected).
2. AllReduce JCT degradation relative to Test Case 1 is recorded per combination. Expected degradation proportional to 10% P2P load; JCT increase should be < 15%.
3. P2P Rx rate remains stable throughout the AllReduce pass with no P2P loss.
4. **LB mode comparison:** Record and compare JCT degradation for ECMP vs. Packet Spray.


---

## Test Case 6 – AllReduce Halving Doubling + Continuous P2P Traffic

### Objective

- Same objective as Test Case 5 with **AllReduce Halving Doubling** as the collective.
- HDA uses non-contiguous rank pairs; characterize whether its traffic pattern interacts differently with P2P flows within the single Leaf DUT compared to Ring.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT).

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AllReduce Halving Doubling** over all 8 ranks (same as Test Case 2).
4. Configure the same continuous P2P background traffic as Test Case 5, Step 4 (10% line rate, DSCP 3, bidirectional cross-rank pairs).
5. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size.
   b. Start P2P, then start HDA; run HDA to completion.
   c. Record HDA JCT, all bandwidth metrics, and all counters.
6. Compare against Test Case 2 (HDA standalone) and Test Case 5 (Ring + P2P).

### Expected Results

1. All HDA passes complete successfully.
   - No packet loss on HDA QPs.
   - No NAK, no sequence error.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - No packet loss on P2P streams.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected).
2. HDA JCT degradation vs. Test Case 2 baseline recorded; expected < 15% for 10% P2P load.
3. **Cross-case comparison:** Compare TC-5 (Ring + P2P) vs. TC-6 (HDA + P2P) JCT degradation. HDA non-contiguous patterns may experience different buffer pressure within the single DUT.
4. **LB mode comparison:** Record and compare JCT degradation for ECMP vs. Packet Spray.


---

## Test Case 7 – AlltoAll MtoM + Continuous P2P Traffic

### Objective

- Measure the impact of concurrent continuous P2P background traffic on **AlltoAll MtoM** JCT and bandwidth.
- AlltoAll already drives full-mesh intra-switch traffic; P2P adds further contention and stresses ECN/PFC mechanisms within the single Leaf DUT.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT).

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 1, Step 2.
3. Configure **AlltoAll MtoM** over all 8 ranks (same as Test Case 3).
4. Configure the same continuous P2P background traffic as Test Case 5, Step 4.
5. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size.
   b. Start P2P, then start AlltoAll; run AlltoAll to completion.
   c. Record AlltoAll JCT, bandwidth metrics, and all counters. Record P2P loss separately.
6. Compare AlltoAll JCT per combination against Test Case 3 baseline.

### Expected Results

1. AlltoAll passes complete successfully for all 36 combinations.
   - No packet loss on AlltoAll or P2P streams.
   - No NAK, no sequence error on AlltoAll QPs.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero (no incast congestion expected).
2. AlltoAll JCT degradation vs. Test Case 3 recorded; expected < 15% for 10% P2P load.
3. Under combined AlltoAll + P2P load, verify no loss occurs on either traffic type. PFC may be triggered if P2P traffic causes queue buildup; record PFC count.
4. **LB mode comparison:** Record and compare JCT degradation for ECMP vs. Packet Spray.


---

## Test Case 8 – Concurrent AllReduce Uni-direction Ring + AlltoAll MtoM

### Objective

- Validate JCT and bandwidth when **AllReduce Uni-direction Ring** and **AlltoAll MtoM** run simultaneously on separate rank groups sharing the same 16-port Leaf-Spine fabric.
- This models multi-job co-location where different training jobs use different collective algorithms concurrently.

### Topology

- Uses **Test Topology B** (16 ports, 2 Leaf + 1 Spine).
- **Group A** (AllReduce Ring): Ranks 0–7 (Leaf-1).
- **Group B** (AlltoAll MtoM): Ranks 8–15 (Leaf-2).

### Test Steps

1. Configure all DUTs (2 Leaf + 1 Spine) with lossless queue 3 (DSCP 3), queue 6 (DSCP 48); enable PFC and ECN on all ports. Verify all Leaf-to-Spine uplinks are active.
2. Configure 16 tester ports:
   - Ranks 0–7: RoCEv2, DSCP 3 data, DSCP 48 CNP, QPs per rank pair as specified (1, 4, or 8), ECN-CE bit 01 or 10.
   - Ranks 8–15: identical configuration with independent QP identifiers.
3. Configure **Group A**: AllReduce Uni-direction Ring over Ranks 0–7.
4. Configure **Group B**: AlltoAll MtoM over Ranks 8–15.
5. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and RDMA message size for both groups.
   b. Start Group A and Group B **simultaneously**.
   c. Record per-group JCT and all per-group counters independently.
   d. Record Spine egress packet counts to verify load is distributed across both Leaf uplinks.
6. Compare Group A JCT against Test Case 1 baseline; compare Group B JCT against Test Case 3 baseline.

### Expected Results

1. Both collectives complete successfully for all 36 combinations.
   - No packet loss, no NAK, no sequence error in either group.
   - Reorder: zero for ECMP; expected and recorded per group for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero in both groups (no incast congestion expected).
2. **Group A** JCT degradation vs. Test Case 1 is < 20% (shared Spine capacity between both Leaf pairs).
3. **Group B** JCT degradation vs. Test Case 3 is < 20%.
4. Spine egress traffic should be distributed across uplinks; verify total inter-Leaf load; deviation < 10%.
5. **LB mode comparison:** Packet Spray spreads each group's flows across uplinks, reducing the risk of a hot-spot. Record Spine uplink utilization for ECMP vs. Packet Spray.


---

## Test Case 9 – Concurrent AllReduce Halving Doubling + AlltoAll MtoM

### Objective

- Same as Test Case 8 with **AllReduce Halving Doubling** as Group A's algorithm.
- HDA's non-contiguous rank-pair communication may distribute Spine-link load differently from Ring; compare Spine utilization and JCT against TC-8.

### Topology

- Uses **Test Topology B** (16 ports, 2 Leaf + 1 Spine).
- **Group A** (HDA): Ranks 0–7 (Leaf-1). **Group B** (AlltoAll): Ranks 8–15 (Leaf-2).

### Test Steps

1. Configure all DUTs as in Test Case 8, Step 1.
2. Configure 16 tester ports as in Test Case 8, Step 2.
3. Configure **Group A**: AllReduce Halving Doubling over Ranks 0–7.
4. Configure **Group B**: AlltoAll MtoM over Ranks 8–15.
5. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and message size for both groups.
   b. Start both groups simultaneously.
   c. Record per-group JCT, all counters.
6. Compare Group A against Test Case 2 (HDA standalone); Group B against Test Case 3 (AlltoAll standalone).
7. Compare overall Spine utilization against Test Case 8 (Ring + AlltoAll concurrent).

### Expected Results

1. Both collectives complete successfully for all 36 combinations.
   - No packet loss, no NAK, no sequence error in either group.
   - Reorder: zero for ECMP; expected and recorded per group for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero per group (no incast congestion expected).
2. Group A JCT degradation vs. Test Case 2 is < 20%.
3. Group B JCT degradation vs. Test Case 3 is < 20%.
4. Spine uplinks carry balanced inter-Leaf load; deviation < 10%.
5. **Cross-case comparison (TC-8 vs. TC-9):** Differences in Group B JCT degradation between TC-8 and TC-9 indicate whether HDA's Spine-link occupancy pattern causes more or less interference with AlltoAll than Ring does. Record and compare.
6. **LB mode comparison:** Record per-Spine utilization for ECMP vs. Packet Spray per combination.


---

## Test Case 10 – Sequential AlltoAll MtoM → AllReduce Uni-direction Ring

### Objective

- Measure per-phase JCT, transition overhead, and iteration-to-iteration stability when **AlltoAll MtoM** is immediately followed by **AllReduce Uni-direction Ring** on all 8 ranks.
- This models a training iteration in which gradient all-to-all scatter precedes a parameter all-reduce on the same rank group.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT). All 8 ranks participate in both phases.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports (Ranks 0–7) with RoCEv2, DSCP 3 data, DSCP 48 CNP, QPs per rank pair as specified (1, 4, or 8), ECN-CE bit 01 or 10.
3. Define a two-phase iteration:
   - **Phase 1**: AlltoAll MtoM over all 8 ranks – run to completion of all messages.
   - **Phase 2**: AllReduce Uni-direction Ring over all 8 ranks – triggered immediately upon Phase 1 completion.
4. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and message size.
   b. Run 10 consecutive Phase 1 → Phase 2 iterations.
   c. For each iteration record: Phase 1 JCT, Phase 2 JCT, and all per-phase counters.
5. Compute mean and coefficient of variation (CV) of JCT across the 10 iterations per combination.

### Expected Results

1. All phases complete successfully across all 10 iterations and 36 combinations.
   - No packet loss, no NAK, no sequence error in either phase.
   - Reorder: zero for ECMP; expected and recorded per phase for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero per phase (no incast congestion expected).
2. **Phase 1 (AlltoAll)** JCT stable across 10 iterations; CV < 5% per combination.
3. **Phase 2 (AllReduce Ring)** JCT stable across 10 iterations; CV < 5% per combination.
4. **LB mode comparison:** ECMP may exhibit higher JCT variance iteration-to-iteration due to flow-hash re-establishment after phase transitions. Packet Spray should provide more consistent per-iteration results.


---

## Test Case 11 – Sequential AlltoAll MtoM → AllReduce Halving Doubling

### Objective

- Same as Test Case 10 with **AllReduce Halving Doubling** as Phase 2.
- Characterize whether HDA's non-contiguous rank-pair traffic pattern encounters transient congestion or reordering immediately following an AlltoAll phase.

### Topology

- Uses **Test Topology A** (8 ports, single Leaf DUT). All 8 ranks participate in both phases.

### Test Steps

1. Configure the DUT as in Test Case 1, Step 1.
2. Configure 8 tester ports as in Test Case 10, Step 2.
3. Define a two-phase iteration:
   - **Phase 1**: AlltoAll MtoM over all 8 ranks – run to completion.
   - **Phase 2**: AllReduce Halving Doubling over all 8 ranks – triggered immediately upon Phase 1 completion.
4. For each of the 36 parameter combinations (P01–P36):
   a. Set DUT load-balancing, IB MTU, and message size.
   b. Run 10 consecutive Phase 1 → Phase 2 iterations.
   c. Record per-iteration: Phase 1 JCT, Phase 2 JCT, and all per-phase counters.
5. Compute mean and CV of JCT per combination.

### Expected Results

1. All phases complete successfully across all 10 iterations and 36 combinations.
   - No packet loss, no NAK, no sequence error.
   - Reorder: zero for ECMP; expected and recorded for Packet Spray.
   - PFC count, ECN-CE count, and CNP count should be zero per phase (no incast congestion expected).
2. Phase 1 (AlltoAll) JCT stable; CV < 5% per combination.
3. Phase 2 (HDA) JCT stable; CV < 5% per combination.
4. **Cross-case comparison (TC-10 vs. TC-11):** The Phase 2 JCT difference between TC-10 (Ring) and TC-11 (HDA) should match the TC-1 vs. TC-2 standalone delta. A significantly larger gap indicates that HDA's non-contiguous traffic pattern amplifies residual AlltoAll congestion. Record and compare.
5. **LB mode comparison:** Packet Spray should provide more consistent per-iteration Phase 2 results compared to ECMP.

