# MMU Threshold Probing Framework Design

[sai-qos-tests]: https://github.com/sonic-net/sonic-mgmt/blob/master/tests/saitests/py3/sai_qos_tests.py

## 1. Background & Problem Statement

The legacy QoS SAI tests in [sai_qos_tests.py][sai-qos-tests] suffer from deeply intertwined Platform-Independent (PI) and Platform-Dependent (PD) code:

| Pain Point | Description | Impact |
|------------|-------------|--------|
| **Regression from PI/PD mixing** | Platform-specific code changes frequently break other platforms | Endless regression cycles |
| **No PR test support** | Syntax errors and logic bugs only discovered in nightly runs | Delayed issue detection |
| **Difficult troubleshooting** | Test failures require extensive experience to diagnose | Low debug efficiency |

### 1.1 The Scale of the Problem

A systematic analysis reveals **80+ PD code instances** scattered across 20 test cases:

| PD Cause | Count | Description |
|----------|-------|-------------|
| Validate | 28 | Platform-specific counter checks, threshold margins, watermark types |
| Leakout | 27 | TX leakout compensation varies by ASIC (Memory-Based vs Cell-Based) |
| Parameter | 11 | Platform-specific parameters (`pkts_num_margin`, `cell_occupancy`, etc.) |
| Other | 14 | Dst port detect, packet builder, TX disable, dequeue, etc. |
| **Total** | **80** | |

### 1.2 Code Evidence

The same "send packets" operation requires three different code paths:

```python
# sai_qos_tests.py:1934-1947
if hwsku in ('DellEMC-Z9332f-M-O16C64', 'DellEMC-Z9332f-O32') or 'Arista-7060X6' in hwsku:
    send_packet(self, src_port_id, pkt, (pkts_num_egr_mem +
                pkts_num_leak_out + pkts_num_trig_pfc) // cell_occupancy - 1 - margin)
elif 'cisco-8000' in asic_type:
    fill_leakout_plus_one(self, src_port_id, dst_port_id, pkt, ...)
    send_packet(self, src_port_id, pkt, (pkts_num_leak_out +
                pkts_num_trig_pfc) // cell_occupancy - 2 - margin)
else:
    send_packet(self, src_port_id, pkt, (pkts_num_leak_out +
                pkts_num_trig_pfc) // cell_occupancy - 1 - margin)
```

**Real regression example:** [PR #8500](https://github.com/sonic-net/sonic-mgmt/pull/8500) — after 30+ review conversations and local testing, still caused an endless loop on non-Cisco platforms due to intertwined PI/PD code.

## 2. Design Goals

| Goal | Description |
|------|-------------|
| **Modularity** | Separate PI logic from PD details |
| **Platform Independence** | Execute across ASICs with minimal per-platform code |
| **Maintainability** | Isolate PD code for easy updates |
| **Testability** | Support PR-level testing |
| **Observability** | Structured diagnostic output |
| **Compatibility** | Preserve PTF interfaces for incremental migration |

### 2.1 The Solution: MMU Threshold Probing

To achieve these goals, the framework takes a fundamentally different approach:

1. **Discovering thresholds dynamically** — eliminates hard-coded parameters
2. **Absorbing platform variance through precision tolerance** — no explicit leakout compensation
3. **Separating PI algorithm from PD execution** — clean architectural boundary




## 3. Design Overview

This design is presented in two parts:

| Part | Focus | Sections |
|------|-------|----------|
| **Part I: Concept & Methodology** | Theory | 3.1 Probing vs Legacy Verify, 3.2 Design Rationale, 3.3 Examples, 3.4 Composite Probing |
| **Part II: Implementation & Architecture** | Code | 3.5 Core Roles, 3.6 StreamManager, 3.7 Demo, 3.8 Testability, 3.9 Headroom Pool |

---

## Part I: Concept & Methodology

> This part explains the probing algorithm (§3.1), the design decisions behind it (§3.2), 
> and demonstrates how it works with real examples (§3.3).

---

### 3.1 Probing vs Legacy Verify

#### The Fundamental Paradigm Shift

Traditional MMU threshold testing ([legacy verify][sai-qos-tests]) and the new probing approach represent two fundamentally different testing philosophies:

| Aspect | Legacy Verify | Probing |
|--------|---------------|---------|
| **Philosophy** | Verify a known answer | Discover an unknown threshold |
| **Input** | Pre-calculated threshold value | Any starting point (typically pool size for convenience) |
| **Output** | Pass/Fail | Discovered threshold (precision-controlled) |

**Legacy Verify Approach:**
```
Pre-calculated Value → Send corresponding Packets → Check relevant Counter → Verification Pass/Fail
```
The test passes only if the hardware behavior exactly matches pre-calculated expectations—fragile under noise.

**Probing Approach:**
```
Probe Upper Bound → Probe Lower Bound → Probe Threshold
```
The test discovers the threshold with controlled precision—no pre-calculation needed, platform-independent, robust under noise.

#### The Three-Phase Probing Algorithm

Probing uses a three-phase algorithm to discover the threshold:

| Phase | Purpose | Algorithm |
|-------|---------|-----------|
| **Phase 1: Upper Bound Probing** | Find a value that definitely triggers the event (e.g., PFC XOFF, ingress drop) | Exponential growth (×2) |
| **Phase 2: Lower Bound Probing** | Find a value that definitely does NOT trigger | Logarithmic reduction (÷2) |
| **Phase 3: Threshold Probing** | Narrow down to acceptable precision | Binary search with noise tolerance |

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                       Three-Phase Probing Algorithm                              │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  0                                                                    pool_size  │
│  ├──────────────────────────────────────────────────────────────────────────┤    │
│                                                                                  │
│  Phase 1: Upper Bound Probing (×2 growth)                                        │
│  ─────────────────────────────────────────────────────────────────────►          │
│                                                                      ↓           │
│                                                               upper_bound        │
│                                                                                  │
│  Phase 2: Lower Bound Probing (÷2 reduction)                                     │
│  ◄────────────────────────────────────────────────────────────────────           │
│       ↓                                                                          │
│  lower_bound                                                                     │
│                                                                                  │
│  Phase 3: Threshold Probing (with Precision Control)                             │
│                                                                                  │
│  Step 1: [lower ────────────────────────────────────────────────── upper]        │
│           L                         mid                              U           │
│           ├─────────────────────────┼────────────────────────────────┤           │
│                                     ↓ triggered? Yes → U = mid                   │
│                                                                                  │
│  Step 2: [L ────────────────────────U]                                           │
│           ├───────────┼─────────────┤                                            │
│                       ↓ triggered? No → L = mid                                  │
│                                                                                  │
│  Step 3:              [L ─────────── U]                                          │
│                        ├─────┼─────┤                                             │
│                              ↓ precision met                                     │
│                        threshold_range                                           │
│                           [L, U]                                                 │
│                              │                                                   │
│                              ↓                                                   │
│                    candidate = (L+U)/2                                           │
│                                                                                  │
│  Termination: range_size ≤ candidate × precision_ratio (e.g., 5%)                │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

#### Phase Details

**Phase 1: Upper Bound Probing**

Purpose: Find a value that **definitely triggers** the event. This establishes a reliable ceiling for the search.

- **Starting point**: Typically `pool_size` for convenience—if the threshold is configured correctly, `pool_size` should trigger. But any value works since the algorithm doubles (×2) on each iteration.
- **Growth strategy**: Exponential (×2) ensures we find an upper bound in O(log n) iterations even if starting far below the threshold.
- **Abnormal exit**: If the candidate exceeds an impossibly large value (e.g., 10× the largest switch memory on market), abort with configuration error—no valid threshold exists.

**Phase 2: Lower Bound Probing**

Purpose: Find a value that **definitely does NOT trigger**. This establishes a reliable floor for the search.

- **Starting point**: Begin from `upper_bound` and halve (÷2) repeatedly.
- **Reduction strategy**: Logarithmic (÷2) ensures we find a lower bound in O(log n) iterations. If Phase 1 required multiple ×2 iterations, those intermediate probed values already tell us "not triggered"—Phase 2 can reuse this history directly and skip redundant probing.
- **Termination**: Stop when we find a value that does not trigger—this becomes `lower_bound`.

**Phase 3: Threshold Probing**

Purpose: Narrow the `[lower_bound, upper_bound]` range to acceptable precision and discover the threshold.

- **Core algorithm**: Binary search—repeatedly probe the midpoint `(L+U)/2`, then narrow the range based on whether the event is triggered.
- **Enhancements on top of binary search**:

1. **Precision Control for Platform Independence**
   - Terminate when `range_size ≤ candidate × precision_ratio` (e.g., 5%)
   - Platform-specific effects like leakout (typically 10-100 cells) are naturally absorbed within precision tolerance (e.g., ±500 cells for 20K threshold)
   - No need for explicit leakout compensation code

2. **Multi-Verification for Noise Filtering**
   - Each candidate is checked multiple times (default: 5 attempts)
   - All attempts must agree for the result to be trusted
   - Transient interference is filtered out through repetition

3. **Backtracking with Parameter Adjustment**
   - When verification produces inconsistent results (e.g., 3 Yes, 2 No), the algorithm backtracks to the previous search state
   - On retry, the algorithm supports slightly adjusting the search window boundaries to produce a different midpoint, avoiding repeated probing of the same problematic value
   - This mechanism prevents sporadic noise from causing probe failure, improving test reliability without manual intervention

#### Design Rationale: Why Threshold Range

This section explains the key design decisions behind the probing algorithm.

**1. "Good Enough" Precision, Not Exact Point**

We don't need to find the exact threshold value. A threshold range with sufficient precision (e.g., 5%) is enough to:
- Verify that the MMU configuration is correct
- Confirm that the MMU feature (PFC, drop, etc.) functions as expected

Chasing an "exact" threshold is unnecessary for our testing purpose—what matters is whether the threshold falls within an acceptable range.

**2. Platform Independence Through Precision Tolerance**

By accepting a precision-controlled range instead of an exact point, we naturally absorb platform-specific effects like leakout (typically 10-100 cells, easily within 5% tolerance of a 20K threshold). No explicit handling code is needed.

Additionally, the probing algorithm uses **uniform probe packets** (fixed 64-byte length, consistent protocol) across all platforms. The same algorithm, same packet, same logic—no per-platform customization required. This uniformity is a key aspect of platform independence.

**3. Noise Immunity Through Multi-Verification**

Each candidate value is verified multiple times (default: 5 attempts). All attempts must agree for the result to be trusted. This simple mechanism quickly filters out transient noise (counter jitter, timing variance) without complex noise modeling.

**4. Flexible Usage: Three Values for Different Purposes**

The final threshold range `[lower, upper]` provides three values for different purposes:

| Value | Meaning | Typical Usage |
|-------|---------|---------------|
| `lower_bound` | A value that does NOT trigger the event | Use as "short-of-threshold" baseline for subsequent tests |
| `upper_bound` | A value that definitely triggers the event | Use as "must-reach-threshold" baseline for subsequent tests |
| `candidate` (midpoint) | Approximate threshold with bounded precision | Use for evaluating MMU configuration and feature behavior |

This flexibility allows the same probing result to serve different downstream needs.

### 3.2 Design Rationale

The key design decisions explained above can be summarized as:

| Design Decision | Benefit | How It Works |
|-----------------|---------|--------------|
| **Precision tolerance** | Platform independence | Leakout, margins absorbed within 5% tolerance |
| **Uniform probe packets** | No per-platform customization | Fixed 64-byte packets = 1 cell on all platforms |
| **Multi-verification** | Noise immunity | 5 attempts must agree; filters transient noise |
| **Threshold range output** | Flexible usage | Lower/upper/candidate serve different test needs |

This design eliminates the platform-dependent code paths shown in §1 Background—no more `if hwsku in...` branches, no more `pkts_num_leak_out` parameters, no more magic margin numbers.

### 3.3 Probing Examples

#### Example 1: PFC XOFF Threshold Probing

From actual test execution on Mellanox-SN4600C-C64 (pool_size=357,717 cells):

```
Phase 1 - Upper Bound Probing:
  Iter 1.1: 357717 → PFC triggered ✓ (Upper bound found)

Phase 2 - Lower Bound Probing:
  Iter 2.1: 178858 → triggered
  Iter 2.2: 89429  → NOT triggered ✓ (Lower bound found)

Phase 3 - Threshold Range Probing:
  Iter 3.1: [89429-357717]  → mid=223573 → triggered → [89429-223573]
  Iter 3.2: [89429-223573]  → mid=156501 → dismissed → [156502-223573]
  Iter 3.3: [156502-223573] → mid=190037 → triggered → [156502-190037]
  Iter 3.4: [156502-190037] → mid=173269 → triggered → [156502-173269]
  Iter 3.5: [156502-173269] → mid=164885 → triggered → [156502-164885]
  Iter 3.6: [156502-164885] → mid=160693 → triggered → [156502-160693]
  Iter 3.7: [156502-160693] → range=4191 < 158597×5%=7930 ✓ (Precision met)

Result: PFC XOFF threshold range = [156502, 160693], candidate ≈ 158,597 cells
Total time: ~220 seconds
```

#### Example 2: Ingress Drop Threshold Probing

From actual test execution on Arista-7260CX3-D108C10 (pool_size=160,236 cells):

```
Phase 1 - Upper Bound Probing:
  Iter 1.1: 160236 → drop triggered ✓

Phase 2 - Lower Bound Probing:
  Iter 2.1: 80118  → triggered
  Iter 2.2: 40059  → triggered
  Iter 2.3: 20029  → NOT triggered ✓

Phase 3 - Threshold Range Probing:
  Iter 3.1: [20029-160236] → mid=90132  → triggered → [20029-90132]
  Iter 3.2: [20029-90132]  → mid=55080  → triggered → [20029-55080]
  Iter 3.3: [20029-55080]  → mid=37554  → triggered → [20029-37554]
  Iter 3.4: [20029-37554]  → mid=28791  → triggered → [20029-28791]
  Iter 3.5: [20029-28791]  → mid=24410  → triggered → [20029-24410]
  Iter 3.6: [20029-24410]  → mid=22219  → triggered → [20029-22219]
  Iter 3.7: [20029-22219]  → mid=21124  → triggered → [20029-21124]
  Iter 3.8: [20029-21124]  → mid=20576  → triggered → [20029-20576]
  Iter 3.9: [20029-20576]  → range=547 < 20302×5%=1015 ✓ (Precision met)

Result: Ingress Drop threshold range = [20029, 20576], candidate ≈ 20,302 cells
Total time: 184 seconds
```

**Observations:**
- Two different platforms (SN4600C vs 7260CX3), two different pool sizes
- Same 3-phase algorithm adapts to different buffer configurations automatically
- No platform-specific code needed—the algorithm discovers thresholds dynamically
- Example 1: Total iterations = 1 + 2 + 7 = 10 iterations
- Example 2: Total iterations = 1 + 3 + 9 = 13 iterations

### 3.4 Composite Probing: Dependent Thresholds

The basic 3-phase probing algorithm works well for independent thresholds like PFC XOFF and Ingress Drop. However, some MMU thresholds have **dependency relationships** that require a more sophisticated approach—this is where Composite Probing becomes essential.

#### 3.4.1 The Scenario: Why Composite Probing?

**Dependent Thresholds** are thresholds that cannot be probed in isolation—they require other thresholds to be triggered first as prerequisite conditions:

| Threshold Type | Dependency | Challenge |
|----------------|------------|-----------|
| **PFC XON** | Requires PFC XOFF triggered first | XON only observable after XOFF is active |
| **Headroom Pool** | Requires multiple PG headrooms filled | Pool exhaustion needs cumulative PG filling |

**Headroom Pool** is the most complex case: it's a shared buffer across multiple Priority Groups (PGs). To probe the total pool, we must:
1. Probe PG_i's individual headroom (Ingress Drop - PFC XOFF)
2. Fill PG_i to its headroom limit
3. Probe PG_j's headroom (with PG_i already filled)
4. Continue for all participating lossless PGs
5. Sum all individual headrooms = Total Headroom Pool

*Note: Only lossless PGs (typically PG3, PG4 for DSCP 3, 4) participate in headroom pool probing.*

This sequential dependency makes Headroom Pool probing a perfect case study for Composite Probing.

#### 3.4.2 The Challenge: Error Accumulation

When probing dependent thresholds, **precision errors accumulate at each stage**. This is the fundamental challenge.

Consider Headroom Pool probing with range-based predecessor values:

```
PG Headroom = Ingress_Drop_Threshold - PFC_XOFF_Threshold

If both thresholds are ranges (not exact values):
  PG_Headroom_Error = Ingress_Drop_Error + PFC_XOFF_Error

For N Priority Groups:
  Headroom_Pool_Error = N × PG_Headroom_Error
                      = N × (Ingress_Drop_Error + PFC_XOFF_Error)
```

The error grows **linearly with the number of PGs**—potentially reaching hundreds of percent!

#### 3.4.3 Visual Evidence: Why Error Accumulates

The following diagram illustrates why Range-Based approach causes error accumulation while Point Probing eliminates it:

![Headroom pool probe](img/headroom-pool-probe.png)

**Range-Based (Option 1):** The upper bounds of PFC XOFF and Ingress Drop ranges form non-parallel curves. The varying distance between them yields inaccurate PG headroom at each PG, and errors accumulate as PGs increase.

**Point Probing (Option 2):** Precise threshold points form parallel lines. The consistent distance yields accurate PG headroom, with near-zero cumulative error regardless of PG count.

#### 3.4.4 Options Analysis

We analyzed two approaches to handle this challenge:

**Option 1: Range-Based Approach**
- Use the upper bound from predecessor threshold probing as the "true" value
- Simpler implementation, no additional probing time
- But: cumulative errors can become unacceptable

**Option 2: Step-by-Step Point Probing**
- After Threshold Range Probing, add step-by-step probing (1 packet/step) from lower bound
- Discover the exact threshold point, then proceed with dependent threshold probing
- More time, but: near-zero cumulative error

**Quantitative Comparison** (from actual ASIC analysis):

| ASIC | PG Num | Headroom Pool | Option 1 (5%) | Option 1 (100-cell) | Option 2 |
|------|--------|---------------|---------------|---------------------|----------|
| TH   | 4      | 5,041 cells   | 31.0% error   | 7.9% error          | ~0% error |
| TH2  | 20     | 9,408 cells   | 218.1% error  | 21.2% error         | ~0% error |
| TD3  | 11     | 6,336 cells   | 528.6% error  | 17.3% error         | ~0% error |
| TH5  | 25     | 43,328 cells  | 388.6% error  | 5.8% error          | ~0% error |

*Note: Option 1 with percentage-based precision (5%) shows unacceptable errors. Even with fixed 100-cell range precision (absolute range size rather than percentage-based), errors remain significant for high PG counts.*

#### 3.4.5 Our Choice: Step-by-Step Point Probing

For Headroom Pool and other dependent thresholds, we choose **Option 2**.

The core idea is simple: after Threshold Range Probing narrows down to a small range (e.g., 100-200 cells), we probe each value one by one (1 packet increment per step) until we find the exact threshold point. We call this **Threshold Point Probing**—in contrast to Threshold Range Probing which outputs a range, Threshold Point Probing outputs a precise point value.

**Rationale:**
- Headroom Pool probing is inherently time-consuming (multiple PGs, sequential filling)
- The additional Point Probing time is acceptable with proper optimization:
  - **Fixed range convergence**: Threshold Range Probing converges to ~100-200 cells, bounding Point Probing to at most 100-200 steps
  - **Incremental buffer filling**: Each step adds only 1 packet to existing buffer (no flush-and-resend from zero), minimizing per-step overhead (~2-3 seconds per packet)
- Near-zero error is worth the time investment for mission-critical MMU validation

**The Algorithm:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│           Headroom Pool Probing with Threshold Point Probing                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  For each lossless Priority Group (PG_i, PG_j, ...):                        │
│  ═══════════════════════════════════════════════════                        │
│                                                                             │
│  Step 1: PFC XOFF Threshold Range Probing                                   │
│          → Range: [lower_xoff, upper_xoff]                                  │
│                                                                             │
│  Step 2: PFC XOFF Threshold Point Probing (1 packet/step)                   │
│          → Point value: exact_xoff                                          │
│                                                                             │
│  Step 3: Ingress Drop Threshold Range Probing                               │
│          → Range: [lower_drop, upper_drop]                                  │
│                                                                             │
│  Step 4: Ingress Drop Threshold Point Probing (1 packet/step)               │
│          → Point value: exact_drop                                          │
│                                                                             │
│  Step 5: Calculate PG headroom                                              │
│          → PG_headroom = exact_drop - exact_xoff  (precise!)                │
│                                                                             │
│  Step 6: Fill this PG to its headroom, proceed to next PG                   │
│                                                                             │
│  Final: Headroom_Pool = Σ PG_headroom  (near-zero cumulative error)         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 3.4.6 Key Strategies

| Strategy | Purpose | How It Works |
|----------|---------|--------------|
| **Threshold Point Probing** | Eliminate predecessor errors | Required for Headroom Pool |
| **Fixed range convergence** | Bound Point Probing iterations | 100-200 cells max range before Point Probing |
| **Probe from lower_bound** | Ensure reliable state transition | Start from verified "unreached" state, increment until "reached" |
| **Incremental buffer filling** | Avoid re-sending overhead | Each step adds 1 packet to existing buffer; no flush between steps |

With Threshold Point Probing, the Composite Probing approach transforms the error profile from "linearly accumulating" to "constant bounded"—making dependent threshold probing practical and reliable.

#### 3.4.7 Real Example: Headroom Pool Probing on Arista-7260CX3

From actual test execution (27 lossless PGs configured, pool exhaustion detected at PG #21):

**PG #1 (First PG — Full Headroom Available):**
```
[PFC XOFF Probing]
  Phase 1: Upper bound = 160236 (1 iter)
  Phase 2: Lower bound = 20029 (3 iters)
  Phase 3: Range = [20029, 20097] (11 iters, 158.68s)
  Phase 4: Point = 20036 (7 steps, 18.95s)

[Ingress Drop Probing]
  Phase 1: Upper bound = 160236 (1 iter)
  Phase 2: Lower bound = 20035 (1 iter, reuses PFC XOFF result!)
  Phase 3: Range = [20515, 20582] (11 iters, 158.87s)
  Phase 4: Point = 20523 (8 steps, 21.09s)

→ PG #1 Headroom = 20523 - 20036 = 487 cells
  Accumulated: 487 cells
```

**PG #2 (Second PG — Pool Still Abundant):**
```
[PFC XOFF Probing]
  Phase 1: Upper bound = 20036 (1 iter, starts from PG #1's filled level!)
  Phase 2: Lower bound = 10018 (1 iter)
  Phase 3: Range = [10018, 10096] (7 iters, 100.82s)
  Phase 4: Point = 10021 (3 steps, 11.16s)

[Ingress Drop Probing]
  Phase 1: Upper bound = 20523 (1 iter)
  Phase 2: Lower bound = 10020 (1 iter, reuses PFC XOFF result!)
  Phase 3: Range = [10431, 10512] (7 iters, 100.69s)
  Phase 4: Point = 10508 (77 steps, 161.46s)

→ PG #2 Headroom = 10508 - 10021 = 487 cells
  Accumulated: 974 cells
```

*Note: PG #2 starts with half the threshold values of PG #1 (10021 vs 20036) because PG #1 has already consumed ~487 cells from the shared pool. But PG #2 still gets full 487 cells headroom.*

**PG #20 (Pool Nearly Exhausted):**
```
[PFC XOFF Probing]
  Phase 1: Upper bound = 6 (1 iter, only 6 cells available!)
  Phase 2: Lower bound = 3 (1 iter)
  Phase 3: Range = [3, 6] (skipped—too small)
  Phase 4: Point = 6 (3 steps, 11.81s)

[Ingress Drop Probing]
  Phase 1: Upper bound = 493 (1 iter)
  Phase 2: Lower bound = 5 (1 iter)
  Phase 3: Range = [128, 188] (3 iters, 46.62s)
  Phase 4: Point = 181 (53 steps, 113.58s)

→ PG #20 Headroom = 181 - 6 = 175 cells
  Accumulated: 9429 cells
```

*Note: By PG #20, the pool is nearly exhausted. PFC XOFF threshold dropped from 20036 (PG #1) to just 6 cells! Headroom shrinks from 487 to 175 cells.*

**PG #21 (Pool Exhaustion Detected):**
```
[PFC XOFF Probing]
  Phase 1: Upper bound = 6 (1 iter)
  Phase 2: Lower bound = 3 (1 iter)
  Phase 3: Range = [3, 6] (skipped)
  Phase 4: Point = 6 (3 steps, 11.84s)

[Ingress Drop Probing]
  Phase 1: Upper bound = 181 (1 iter)
  Phase 2: Lower bound = 5 (1 iter)
  Phase 3: Range = [5, 93] (1 iter, 15.59s)
  Phase 4: Point = 7 (2 steps, 9.79s)

→ PG #21 Headroom = 7 - 6 = 1 cell (Pool exhausted!)
  Accumulated: 9430 cells
```

*Note: PG #21's headroom = 1 cell indicates pool exhaustion. The algorithm detects this and terminates probing.*

**Final Result:**
```
============================================================
FINAL RESULTS
============================================================
PGs probed: 21
Status: ✓ SUCCESS - Pool exhaustion detected
Total Headroom Pool Size: 9429 cells
Total test time: 5629 seconds (~94 minutes)
```

*Note: As more PGs are filled, remaining headroom shrinks. When PG headroom reaches 1 cell, the pool is exhausted and probing terminates.*

#### 3.4.8 Point Probing Step Size Optimization

The Point Probing step size directly impacts both accuracy and test time. Extensive testing on Broadcom TH2 with Headroom Pool probing validated different configurations. The test required **21 PGs to fully exhaust the headroom pool** (160K cells total, ~487 cells per PG).

**Physical Hardware Test Results** (Arista 7260CX3, Expected pool size: 9,408 cells):

| Step Size | Pool Size | Error | Error Rate | Test Time | Status |
|-----------|-----------|-------|------------|-----------|--------|
| 1 | 9,429 | +21 cells | 0.22% | 90.0 min | [x] High precision |
| **2** | **9,445** | **+37 cells** | **0.39%** | **61.8 min** | [x] **Optimal balance** |
| 4 | 9,466 | +58 cells | 0.62% | 55.2 min | [x] Good time |
| 6 | 9,514 | +106 cells | 1.13% | 52.2 min | [ ] **Exceeds tolerance** |

**Note on Step 1 error**: The +21 cells error comes from probing methodology—each PG's Ingress Drop threshold requires sending one additional packet beyond the threshold to confirm drop detection. With 21 PGs, this results in 21 extra cells in the total pool measurement. This is a systematic offset that could be compensated by subtracting the PG count from the final result later.

**Recommendation: Step Size = 2**

Based on extensive testing, **step_size = 2** provides the best balance between accuracy and test time. Step 1 offers only marginal precision improvement (0.22% vs 0.39%) at significant time cost (+46% slower). Step 4 saves only ~10% time but sacrifices 50% accuracy. Step 6 exceeds the 100-cell precision tolerance and is not recommended.

---

## Part II: Implementation & Architecture

> This part covers the code structure: the four core roles (§3.5), StreamManager abstraction (§3.6), 
> a demo implementation (§3.7), testability support (§3.9), and the Headroom Pool case study (§3.8).

---

### 3.5 Code Framework: Four Core Roles

The probing framework is built around four core roles with clear separation of concerns:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Four Core Roles                                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ ProbingBase │    │  Algorithm  │    │  Executor   │    │  Observer   │  │
│  │ (Orchestra- │──▶│  (Phase 1-4 │───▶│  (Test Env  │    │  (Logging & │  │
│  │  tor)       │    │   Logic)    │    │   Adapter)  │    │   Metrics)  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│        │                  │                  │                  ▲          │
│        │                  │                  │                  │          │
│        │                  └──────────────────┴──────────────────┘          │
│        │                         reports to Observer                       │
│        │                                                                   │
│        └───────────────────────────────────────────────────────────────────│
│              orchestrates all components                                   │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

#### 3.5.1 Role Definitions

| Role | Responsibility | Key Files |
|------|----------------|-----------|
| **ProbingBase** | Test case orchestration, PTF integration, parameter parsing, workflow coordination | `probing_base.py` |
| **Algorithm** | Pure probing logic for each phase (Upper Bound, Lower Bound, Threshold Range, Threshold Point) | `*_probing_algorithm.py` |
| **Executor** | Test Environment adapter: send packets, read counters, detect probe-target-specific events (PFC triggered, ingress drop occurred, etc.) | `*_probing_executor.py` |
| **Observer** | Logging, timing metrics, result reporting, visual tabular report generation | `probing_observer.py` |

#### 3.5.2 Design Principles

**1. Algorithm-Executor Separation**

The Algorithm classes contain pure probing logic with no test environment dependencies. They interact with the test environment through the `ProbingExecutorProtocol` interface:

```python
class ProbingExecutorProtocol(Protocol):
    def check(self, src_port: int, dst_port: int, value: int, 
              attempts: int = 1, drain_buffer: bool = True) -> Tuple[bool, bool]: ...
    # Returns (success, reached)
    # - success: verification completed without errors
    # - reached: threshold reached (i.e., event triggered: PFC XOFF, drop, ECN mark, etc.)
```

This separation enables:
- Unit testing algorithms without physical testbed
- Swapping executors for different environments (physical/mock)
- Reusing the same algorithm across different probe targets (PFC XOFF, Ingress Drop, etc.)

*Note: The probing mechanism itself eliminates most platform-specific code through precision tolerance and dynamic discovery. Executors are organized by probe target (e.g., `PfcXoffProbingExecutor`, `IngressDropProbingExecutor`), not by platform—the same executor works across all platforms.*

**2. Observer Pattern for Reporting**

All components report to Observer, which handles:
- Console and trace logging
- Per-iteration timing breakdown
- Tabular report generation (markdown format—easy to copy/paste into docs)
- Final result summary

**3. Template Method in ProbingBase**

`ProbingBase.runTest()` defines the workflow skeleton:

```python
def runTest(self):
    config = self.get_probe_config()      # subclass provides
    self.setup_traffic()                   # subclass implements
    self.buffer_ctrl = BufferOccupancyController(...)
    self.probe()                           # subclass implements
```

Subclasses serve as orchestrators for different probe targets:
- `PfcXoffProbing` — orchestrates PFC XOFF threshold probing
- `IngressDropProbing` — orchestrates Ingress Drop threshold probing
- `HeadroomPoolProbing` — orchestrates Headroom Pool probing (composite)

Each subclass's `probe()` method is responsible for:
1. **Instantiating** Algorithm, Executor, and Observer with target-specific parameters (e.g., counter type, detection logic)
2. **Orchestrating** the 4-phase probing sequence (Upper Bound → Lower Bound → Threshold Range → optional Threshold Point)
3. **Coordinating** data flow between components (passing bounds from one phase to the next)

See §3.7.2 for a concrete example of component assembly in `PfcXoffProbing.probe()`.

#### 3.5.3 Simplified UML Overview

To clarify how the four core roles collaborate, here's a minimal class diagram and sequence diagram. Details like parameters and helper methods are omitted for clarity.

**Class Diagram (Simplified)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Simplified Class Relationships                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────┐                                                      │
│  │    ProbingBase    │  ◄─────── PfcXoffProbing, IngressDropProbing, ...    │
│  │   (Orchestrator)  │                                                      │
│  └─────────┬─────────┘                                                      │
│            │ owns & coordinates                                             │
│            ▼                                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        Algorithm Layer                               │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │   │
│  │  │UpperBound    │ │LowerBound    │ │ThresholdRange│ │ThresholdPoint│ │   │
│  │  │Algorithm     │ │Algorithm     │ │Algorithm     │ │Algorithm     │ │   │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │   │
│  │         │                │                │                │         │   │
│  │         └────────────────┴────────────────┴────────────────┘         │   │
│  │                          │ uses                                      │   │
│  └──────────────────────────┼───────────────────────────────────────────┘   │
│                             ▼                                               │
│            ┌────────────────────────────────┐                               │
│            │   «interface»                  │                               │
│            │  ProbingExecutorProtocol       │                               │
│            │  ─────────────────────────     │                               │
│            │  + check(src, dst, value) →    │                               │
│            │        (success, reached)      │                               │
│            └────────────────┬───────────────┘                               │
│                             │ implemented by                                │
│            ┌────────────────┴────────────────┐                              │
│            ▼                                 ▼                              │
│  ┌───────────────────┐            ┌───────────────────┐                     │
│  │PfcxoffProbing     │            │IngressDropProbing │                     │
│  │Executor           │            │Executor           │                     │
│  └───────────────────┘            └───────────────────┘                     │
│                                                                             │
│  ┌───────────────────┐                                                      │
│  │  ProbingObserver  │  ◄──── All components report to Observer             │
│  └───────────────────┘                                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Sequence Diagram (Simplified)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              Simplified Probing Sequence (One Iteration)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ProbingBase          Algorithm            Executor           Observer      │
│      │                    │                    │                  │         │
│      │  probe(...)        │                    │                  │         │
│      │──────────────────▶│                    │                  │         │
│      │                    │                    │                  │         │
│      │                    │  check(value)      │                  │         │
│      │                    │──────────────────▶│                  │         │
│      │                    │                    │                  │         │
│      │                    │                    │  [send packets,  │         │
│      │                    │                    │   read counters] │         │
│      │                    │                    │                  │         │
│      │                    │  (success, reached)                   │         │
│      │                    │◄───────────────────│                  │         │
│      │                    │                    │                  │         │
│      │                    │  report_iteration(...)                │         │
│      │                    │─────────────────────────────────────▶│         │
│      │                    │                    │                  │         │
│      │                    │  [adjust bounds,   │                  │         │
│      │                    │   repeat or exit]  │                  │         │
│      │                    │                    │                  │         │
│      │  result            │                    │                  │         │
│      │◄───────────────────│                    │                  │         │
│      │                    │                    │                  │         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Takeaway**: ProbingBase orchestrates the flow, Algorithm contains pure probing logic, Executor bridges to the test environment, and Observer collects metrics. Algorithms interact with the environment only through the `ProbingExecutorProtocol` interface—this separation enables testability and reuse across probe targets.

#### 3.5.4 Why These Four Roles?

The four-role design directly addresses the legacy pain points identified in §1:

| Role | What It Isolates | Legacy Problem Solved |
|------|------------------|----------------------|
| **Algorithm** | Pure probing logic (binary search, precision control) | Legacy code has no reusable algorithm—just hardcoded fill-and-verify. Now the same `ThresholdRangeProbingAlgorithm` works for PFC XOFF, Ingress Drop, Headroom Pool and Egress Drop, etc ... |
| **Executor** | Test environment interaction | Legacy code directly calls `send_packet()`, `read_counters()` throughout. Now Algorithm sees only `check(value) → reached`— test environment details hidden. |
| **ProbingBase** | PTF lifecycle (`setUp`, `tearDown`, `runTest`) | Test framework coupling mixed with business logic. Now subclasses only implement `setup_traffic()` and `probe()`. |
| **Observer** | Logging and metrics | `print()`, `log_message()`, `sys.stderr.write()` scattered everywhere. Now all output goes through one point—change format once, applies everywhere. |

**Key Benefit: Algorithm + Executor Separation Enables Multi-Environment Testing**

```python
# Physical testbed
executor = PhysicalPfcXoffProbingExecutor(...)

# Unit Test: sim with known threshold
executor = SimPfcXoffProbingExecutor(threshold=1000)

# Same algorithm code, different executor—works across all environments
algorithm = ThresholdRangeProbingAlgorithm(executor, observer)
result = algorithm.probe(...)
```

This separation is why PR-level testing becomes possible: algorithms can be validated in seconds without physical DUT.

**Design Note: Platform Independence Through Probing, Not Abstraction**

The probing mechanism itself eliminates the need for platform-specific code:
- **Precision tolerance** absorbs leakout variance (typically 10-100 cells within 5% tolerance)
- **Dynamic discovery** replaces hardcoded threshold parameters
- **Uniform probe packets** (64-byte) work identically across all ASICs

As a result, executors are organized **by probe target** (PFC XOFF, Ingress Drop), not by platform—the same `PfcXoffProbingExecutor` works across Broadcom, Nvidia, and Cisco based ASICs without modification.

For future extensibility, the design supports **capability-based checks** within executors if needed (e.g., checking specific counter support), rather than per-platform branching. This keeps the architecture clean while accommodating edge cases.

### 3.6 StreamManager: Traffic Flow Abstraction

In §3.5.2, we mentioned that subclasses implement `setup_traffic()` to prepare test flows. But what exactly does "setup traffic" mean?

For probing, we need to:
- Define traffic flows (src port → dst port, with specific DSCP/PG mapping)
- Construct packets with correct MAC/IP addresses
- Resolve actual RX ports (especially in LAG scenarios where traffic may arrive on any member port)

`StreamManager` abstracts these concerns:

```python
stream_mgr = StreamManager(
    packet_constructor=construct_ip_pkt,
    rx_port_resolver=get_rx_port  # Handles LAG member port detection
)

# Define flow: src_port=11 → dst_port=1, DSCP=3 (maps to PG3)
stream_mgr.add_flow(FlowConfig(
    src_port=PortInfo(port_id=11, mac="...", ip="10.0.0.1"),
    dst_port=PortInfo(port_id=1, mac="...", ip="10.0.0.2"),
    dscp=3
))

# Generate packets for all defined flows:
# 1. Uses packet_constructor to create uniform 64-byte probe packets
# 2. Calls rx_port_resolver to detect actual RX port (critical for LAG scenarios)
# 3. Caches packets for reuse across probing iterations
stream_mgr.generate_packets()
```

**Usage Scenario 1: Executor Sends Traffic by Flow Keys Only**

When the executor needs to fill the buffer, it only describes the **traffic path characteristics** (which src port, which dst port, which PG/queue)—no need to construct packets or manage flow details:

```python
# In Executor.check() — just describe "where" and "how much"
def check(self, src_port, dst_port, value, **traffic_keys):
    # Only need: src_port, dst_port, and traffic_keys (e.g., pg=3)
    # StreamManager handles packet lookup internally
    pkt = self.stream_mgr.get_packet(src_port, dst_port, **traffic_keys)
    send_packet(self.ptftest, src_port, pkt, value)
    ...
```

The executor is freed from packet construction details—it simply says "send N packets from port A to port B for PG 3", and StreamManager provides the correct packet. This separation keeps Algorithm/Executor code clean and focused on probing logic.

**Usage Scenario 2: Probing Subclass Iterates Flows for Multi-PG Probing**

For complex scenarios like Headroom Pool (probing multiple PGs sequentially), the probing subclass simply iterates through all defined flows:

```python
# In HeadroomPoolProbing.probe() — just iterate flows
for i, (flow_key, flow_config) in enumerate(self.stream_mgr.flows.items()):
    src_port_id, dst_port_id, traffic_keys = flow_key
    pg = traffic_keys.get('pg')
    
    # Probe this PG — no need to construct traffic details here
    pfc_point = self.probe_pfc_xoff(src_port_id, dst_port_id, pg=pg)
    drop_point = self.probe_ingress_drop(src_port_id, dst_port_id, pg=pg)
    ...
```

The probing subclass doesn't need to worry about: which port maps to which PG, how to construct packets for each flow, or what MAC/IP addresses to use. All traffic definitions are centralized in StreamManager during `setup_traffic()`—the probing logic just iterates and probes.

**Key benefits:**
- **Separation of traffic concerns** — Probe-target-specific traffic patterns (flow topology, DSCP/PG mapping, port configurations) are extracted from Algorithm/Executor/Observer. The probing algorithm focuses purely on binary search logic, without dealing with traffic setup details.
- **Uniform probe packets implementation** — StreamManager enforces consistent 64-byte probe packets across all platforms (see §3.2). The `packet_constructor` generates identical packet format regardless of ASIC type—this uniformity is a key enabler of platform independence.
- **Centralized flow management** — All flow definitions in one place, easy to review and modify
- **Automatic LAG handling** — `rx_port_resolver` detects actual member port for counter reading
- **Packet caching** — Packets constructed once, reused across iterations

### 3.7 Demo: Creating a PFC XOFF Probing Test

To create a new probing test, a developer needs to implement just two methods in a `ProbingBase` subclass: `setup_traffic()` and `probe()`. Let's walk through the PFC XOFF probing implementation.

#### 3.7.1 Implement setup_traffic()

The `setup_traffic()` method defines traffic flows using StreamManager (§3.6):

```python
class PfcXoffProbing(ProbingBase):
    def setup_traffic(self):
        # Create StreamManager with packet constructor and LAG resolver
        self.stream_mgr = StreamManager(
            packet_constructor=construct_ip_pkt,
            rx_port_resolver=get_rx_port
        )
        
        # Define the probe flow: src → dst with specific PG
        self.stream_mgr.add_flow(FlowConfig(
            src_port=PortInfo(port_id=self.src_port_id, mac=src_mac, ip=src_ip),
            dst_port=PortInfo(port_id=self.dst_port_id, mac=dst_mac, ip=dst_ip),
            dscp=self.dscp,  # Maps to specific PG
            pg=self.pg
        ))
        
        # Generate uniform 64-byte probe packets
        self.stream_mgr.generate_packets()
```

**Key points:**
- All traffic configuration is centralized here—Algorithm/Executor never touch packet details
- `generate_packets()` creates uniform probe packets and resolves LAG member ports

#### 3.7.2 Implement probe()

The `probe()` method assembles the four core roles and orchestrates the 4-phase probing:

```python
def probe(self):
    # ===== Assemble the Four Core Roles =====
    executor = PfcXoffProbingExecutor(stream_mgr=self.stream_mgr, ...)
    observer = ProbingObserver(name="pfc_xoff", phase_number=1)
    
    # ===== Run 4-Phase Probing Sequence =====
    # Phase 1: Find upper bound (value that triggers PFC)
    upper_algo = UpperBoundProbingAlgorithm(executor, observer)
    upper = upper_algo.probe(self.src_port, self.dst_port, initial=self.pool_size)
    
    # Phase 2: Find lower bound (value that does NOT trigger)
    lower_algo = LowerBoundProbingAlgorithm(executor, observer)
    lower = lower_algo.probe(self.src_port, self.dst_port, upper_bound=upper)
    
    # Phase 3: Binary search to precision target
    range_algo = ThresholdRangeProbingAlgorithm(executor, observer, precision=0.05)
    result = range_algo.probe(self.src_port, self.dst_port, lower, upper)
    
    return result  # Contains lower_bound, upper_bound, candidate
```

**Key points:**
- Executor handles "how to detect PFC XOFF"—Algorithm only knows "check(value) → triggered?"
- Same Algorithm classes are reused for Ingress Drop, Headroom Pool, etc.
- Each phase passes its result to the next phase

#### 3.7.3 The Result: Observer's Tabular Report

After probing completes, Observer generates a structured table—copy-paste ready for documentation or issue tracking. Here's actual output from Arista-7260CX3 (pool_size=160,236 cells):

```
================================================================================
[pfc_xoff] Starting threshold probing
  src_port=1, dst_port=0
  pool_size=160236
  precision_target_ratio=0.05
================================================================================

Upper Bound Probing
  PFC Upper bound = 160236

Lower Bound Probing
  PFC Lower bound = 20029

Threshold Range Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|--------|
| 1.3.1    | 20029     | 90132     | 160236    | init  | reached      | 17.90    | 17.90     |
| 1.3.2    | 20029     | 55080     | 90132     | <-U   | reached      | 15.75    | 33.65     |
| 1.3.3    | 20029     | 37554     | 55080     | <-U   | reached      | 14.48    | 48.13     |
| 1.3.4    | 20029     | 28791     | 37554     | <-U   | reached      | 13.91    | 62.04     |
| 1.3.5    | 20029     | 24410     | 28791     | <-U   | reached      | 13.66    | 75.70     |
| 1.3.6    | 20029     | 22219     | 24410     | <-U   | reached      | 13.48    | 89.18     |
| 1.3.7    | 20029     | 21124     | 22219     | <-U   | reached      | 13.42    | 102.60    |
| 1.3.8    | 20029     | 20576     | 21124     | <-U   | reached      | 13.38    | 115.98    |
| 1.3.9    | 20029     | 20302     | 20576     | <-U   | reached      | 13.49    | 129.47    |
| 1.3.10   | 20029     | 20165     | 20302     | <-U   | reached      | 13.36    | 142.82    |
| 1.3.11   | 20029     | 20097     | 20165     | <-U   | reached      | 13.35    | 156.17    |
| 1.3.12   | 20029     | 20063     | 20097     | <-U   | skipped      | 0.00     | 156.17    |
  PFC Range = [20029, 20097]

================================================================================
RESULT: Threshold Range = [20029, 20097], Candidate = 20063 cells
Precision: 0.34% (target: 5.00%)  PASSED
Total iterations: 12 | Total time: 156.17s
================================================================================
```

**What this report shows:**
- **Per-iteration breakdown**: Each binary search step with Lower/Upper bounds and Candidate value
- **Step column**: Shows algorithm action (init, <-U for upper shrinking, L-> for lower growing, /2 for halving, +N for point probing increment)
- **Check result**: `reached` = threshold reached, `unreached` = not reached, `skipped` = precision met
- **Timing**: Time(s) for current iteration, Total(s) for cumulative time

#### 3.7.4 Inside Algorithm and Executor

To complete the picture, let's look inside the Algorithm and Executor—how they collaborate through the `ProbingExecutorProtocol` interface (§3.5.2).

**Algorithm: Binary Search with Backtracking**

The Algorithm contains only probing logic—no test environment knowledge:

```python
class ThresholdRangeProbingAlgorithm:
    # executor, observer, precision_target_ratio set in __init__
    
    def run(self, src_port, dst_port, lower_bound, upper_bound, **traffic_keys):
        # Stack-based backtracking for noise resilience
        range_stack = [(lower_bound, upper_bound)]
        
        while range_stack:
            range_start, range_end = range_stack[-1]
            candidate = (range_start + range_end) // 2
            range_size = range_end - range_start
            
            # Precision target reached — return result
            if range_size <= candidate * self.precision_target_ratio:
                return (range_start, range_end)
            
            # Algorithm only knows: "check this value, tell me if triggered"
            success, triggered = self.executor.check(src_port, dst_port, candidate, **traffic_keys)
            self.observer.on_iteration_complete(candidate, range_start, range_end, triggered)
            
            if not success:
                range_stack.pop()  # Backtrack on verification failure
            elif triggered:
                range_stack.append((range_start, candidate))      # Search left half
            else:
                range_stack.append((candidate + 1, range_end))    # Search right half (+1!)
        
        return (None, None)  # Stack exhausted
```

**Executor: 5-Step Hardware Interaction**

The Executor implements `check()` with probe-target-specific detection logic:

```python
class PfcXoffProbingExecutor:
    def check(self, src_port, dst_port, value, **traffic_keys):
        # Step 1: Drain — Clear existing buffer
        self.drain_buffer([dst_port])
        self.hold_buffer([dst_port])
        
        # Step 2: Base — Read baseline counter
        baseline = self._read_pfc_counters(src_port)
        
        # Step 3: Inject — Send probe packets
        pkt = self.stream_mgr.get_packet(src_port, dst_port, **traffic_keys)
        send_packet(self.ptftest, src_port, pkt, value)
        
        # Step 4: Refresh — Wait for counter update
        time.sleep(COUNTER_REFRESH_DELAY)
        
        # Step 5: Latest — Check if PFC triggered
        current = self._read_pfc_counters(src_port)
        triggered = (current - baseline) > 0
        
        return (True, triggered)  # (success, triggered)
```

*Note: Each step (Drain, Base, Inject, Refresh, Latest) is timed by Observer—this is how the timing breakdown columns in §3.7.3's table are measured.*

**Key insight**: The Algorithm sees only `check(value) → triggered`—it doesn't know about packets, counters, or timing. This separation is why the same `ThresholdRangeProbingAlgorithm` works for PFC XOFF, Ingress Drop, and any future probe target.

### 3.8 Composable Design: Headroom Pool

With the core framework understood, we can now see how Headroom Pool probing composes these building blocks—demonstrating the framework's composability.

#### 3.8.1 Recap: Headroom Pool Probing Principle

As explained in §3.4, Headroom Pool probing requires probing each PG's PFC XOFF and Ingress Drop thresholds sequentially, filling each PG's headroom before proceeding to the next. This composite, sequential nature—plus the mandatory use of Threshold Point Probing (Phase 4) to avoid error accumulation—makes it a good case study for framework composability.

#### 3.8.2 Implement setup_traffic()

Headroom Pool uses a different traffic pattern than single-threshold probing: **N src → 1 dst** (multiple source ports, each with its own PG, all targeting the same destination port).

```python
class HeadroomPoolProbing(ProbingBase):
    def setup_traffic(self):
        self.stream_mgr = StreamManager(
            packet_constructor=construct_ip_pkt,
            rx_port_resolver=get_rx_port
        )
        
        # Define N flows: each src_port → dst_port with a different PG
        for i, src_port_id in enumerate(self.src_port_ids):
            pg = self.lossless_pgs[i]  # e.g., PG3, PG4, ...
            self.stream_mgr.add_flow(FlowConfig(
                src_port=PortInfo(port_id=src_port_id, mac=src_macs[i], ip=src_ips[i]),
                dst_port=PortInfo(port_id=self.dst_port_id, mac=dst_mac, ip=dst_ip),
                dscp=pg_to_dscp(pg),
                pg=pg
            ))
        
        self.stream_mgr.generate_packets()
```

**Key difference from §3.7.1**: Multiple flows are defined (one per PG), all sharing the same destination port. This N-to-1 pattern is essential for filling the shared headroom pool.

#### 3.8.3 Implement probe()

The `probe()` method iterates through PGs, reusing the same Algorithm and Executor components for each:

```python
def probe(self):
    total_headroom = 0
    
    for pg_index, (flow_key, flow_config) in enumerate(self.stream_mgr.flows.items()):
        src_port, dst_port, traffic_keys = flow_key
        pg = traffic_keys['pg']
        
        # ========== PFC XOFF Probing (4 phases, same as §3.7) ==========
        pfc_executor = ExecutorRegistry.create_executor("pfc_xoff", executor_env=self.EXECUTOR_ENV, ...)
        pfc_observer = ProbingObserver(name=f"pfc_xoff_pg{pg}")
        
        pfc_upper = UpperBoundProbingAlgorithm(pfc_executor, pfc_observer).run(...)
        pfc_lower = LowerBoundProbingAlgorithm(pfc_executor, pfc_observer).run(...)
        pfc_range = ThresholdRangeProbingAlgorithm(pfc_executor, pfc_observer).run(...)
        pfc_point = ThresholdPointProbingAlgorithm(pfc_executor, pfc_observer).run(...)
        
        # ========== Ingress Drop Probing (4 phases) ==========
        drop_executor = ExecutorRegistry.create_executor("ingress_drop", executor_env=self.EXECUTOR_ENV, ...)
        drop_observer = ProbingObserver(name=f"ingress_drop_pg{pg}")
        
        drop_upper = UpperBoundProbingAlgorithm(drop_executor, drop_observer).run(...)
        drop_lower = LowerBoundProbingAlgorithm(drop_executor, drop_observer).run(...)
        drop_range = ThresholdRangeProbingAlgorithm(drop_executor, drop_observer).run(...)
        drop_point = ThresholdPointProbingAlgorithm(drop_executor, drop_observer).run(...)
        
        # ========== Calculate and Accumulate Headroom ==========
        pg_headroom = drop_point - pfc_point
        total_headroom += pg_headroom
        
        # ========== Persist Buffer State for Next PG ==========
        self.buffer_ctrl.persist_buffer_occupancy(src_port, dst_port, drop_point, pg=pg)
        
        # ========== Check Pool Exhaustion ==========
        if pg_headroom <= 1:
            self.observer.console(f"Pool exhausted at PG #{pg_index + 1}")
            break
    
    return total_headroom
```

**Key observations:**
- Same Algorithm classes (`UpperBoundProbingAlgorithm`, etc.) are reused—only the executor differs between PFC XOFF and Ingress Drop
- `ThresholdPointProbingAlgorithm` (Phase 4) is mandatory for each probe to avoid error accumulation
- The loop terminates when `pg_headroom <= 1`, indicating pool exhaustion
- `persist_buffer_occupancy()` is called after each PG—this is critical; see §3.8.4

#### 3.8.4 BufferOccupancyController: Why persist_buffer_occupancy()?

Looking at the `probe()` code above, you'll notice `self.buffer_ctrl.persist_buffer_occupancy(...)` after each PG. Why is this necessary?

**The Problem**: When probing PG #2, we need PG #1's buffer (e.g., 487 cells) to remain filled. But each probing iteration drains and refills the buffer. Without state persistence, PG #1's cells would be lost.

**The Solution**: `BufferOccupancyController` tracks and auto-restores buffer state:

```python
buffer_ctrl = BufferOccupancyController(
    hold_buf_fn=sai_thrift_port_tx_disable,
    drain_buf_fn=sai_thrift_port_tx_enable,
    stream_mgr=stream_mgr
)

# After probing PG #1: "remember" its buffer state
buffer_ctrl.persist_buffer_occupancy(src_port=5, dst_port=1, pkt_count=487, pg=3)

# When probing PG #2, each iteration automatically restores PG #1's 487 packets first
# Then sends PG #2's probe packets on top
```

**Auto-restore mechanism**: When `send_traffic()` is called during PG #2 probing, the controller automatically restores any gap between expected and actual buffer state. This ensures each PG sees the cumulative effect of all previous PGs—critical for accurate Headroom Pool measurement.

#### 3.8.5 The Result: Observer's Summary Report

After probing completes, Observer generates structured reports for each PG. Here's actual output from Arista-7260CX3 (27 lossless PGs configured), showing PG #1 as a complete example:

**PG #1 (First PG — Full Headroom Available):**

```
============================================================
PG #1/27: src=10, dst=81, pg=3
============================================================

[PFC XOFF] Probing threshold...

Upper Bound Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 1.1.1    | NA        | NA        | 160236    | init  | reached      | 11.76    | 11.76     |
  PFC Upper bound = 160236

Lower Bound Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 1.2.1    | 80118     | NA        | 160236    | init  | reached      | 8.85     | 8.85      |
| 1.2.2    | 40059     | NA        | 160236    | /2    | reached      | 7.49     | 16.34     |
| 1.2.3    | 20029     | NA        | 160236    | /2    | unreached    | 6.77     | 23.11     |
  PFC Lower bound = 20029

Threshold Range Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 1.3.1    | 20029     | 90132     | 160236    | init  | reached      | 18.47    | 18.47     |
| 1.3.2    | 20029     | 55080     | 90132     | <-U   | reached      | 15.99    | 34.46     |
| ...      | ...       | ...       | ...       | ...   | ...          | ...      | ...       |
| 1.3.11   | 20029     | 20097     | 20165     | <-U   | reached      | 13.54    | 158.68    |
| 1.3.12   | 20029     | 20063     | 20097     | <-U   | skipped      | 0.00     | 158.68    |
  PFC Range = [20029, 20097]

Threshold Point Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 1.4.1    | 20029     | 20030     | 20097     | +1    | unreached    | 6.74     | 6.74      |
| 1.4.2    | 20029     | 20031     | 20097     | +1    | unreached    | 2.05     | 8.79      |
| ...      | ...       | ...       | ...       | ...   | ...          | ...      | ...       |
| 1.4.7    | 20029     | 20036     | 20097     | +1    | reached      | 2.03     | 18.95     |
  PFC Precise point = 20036

[Ingress Drop] Probing threshold...
  (Similar 4-phase probing...)
  Drop Precise point = 20523

[Result] PG #1 Headroom = 20523 - 20036 = 487 cells
         Total accumulated = 487 cells
```

**Subsequent PGs** follow the same pattern. As the pool depletes, threshold values drop dramatically:

| PG  | PFC XOFF | Ingress Drop | Headroom | Accumulated | Note |
|-----|----------|--------------|----------|-------------|------|
| #1  | 20,036   | 20,523       | 487      | 487         | Full headroom available |
| #2  | 10,021   | 10,508       | 487      | 974         | Starts from PG #1's filled level |
| ... | ...      | ...          | ...      | ...         | |
| #19 | 6        | 493          | 487      | 9,254       | PFC XOFF threshold = 6 cells! |
| #20 | 6        | 181          | 175      | 9,429       | Headroom shrinking |
| #21 | 6        | 7            | 1        | 9,430       | **Pool exhausted** |

**PG #21 — Pool Exhaustion Detected:**

```
[Ingress Drop] Probing threshold...

Threshold Point Probing
| Iter     | Lower     | Candidate | Upper     | Step  | IngressDrop  | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 2.4.1    | 6         | 6         | 93        | +1    | unreached    | 7.89     | 7.89      |
| 2.4.2    | 6         | 7         | 93        | +1    | reached      | 2.01     | 9.90      |
  Drop Precise point = 7
  Headroom = 7 - 6 = 1

[Pool Exhausted] Headroom = 1 cell (<= 1) — Terminating probing
```

**Final Summary:**

```
================================================================================
RESULT: Headroom Pool Size = 9,429 cells
Status: [PASS] Pool exhaustion detected at PG #21 (headroom = 1 cell)
Total PGs probed: 21 | Total time: 5621s (~94 min)
================================================================================
```

---

This composable design demonstrates a key benefit of the framework: complex probing scenarios can be built by assembling existing building blocks—the same Algorithm, Executor, and Observer **classes**. Each PG iteration creates fresh instances, but no new class code is needed. The orchestration logic in `probe()` is the only thing that differs between simple PFC XOFF probing (§3.7) and composite Headroom Pool probing.

### 3.9 Testability: Sim Test Support

The framework supports three complementary test strategies: **Unit Tests (UT)**, **Integration Tests (IT)**, and **PR Tests**.

#### 3.9.1 Test Strategy Overview

All three test types use sim executors to eliminate physical testbed dependency:

| Test Type | Purpose | Location | Example Count |
|-----------|---------|----------|---------------|
| **Unit Test (UT)** | Method-level validation with strict assertions | `tests/saitests/mock/ut/` | 66 tests |
| **Integration Test (IT)** | Full probe workflow simulation with permissive assertions | `tests/saitests/mock/it/` | 62 tests |
| **PR Test** | Pre-merge validation in VS environment reusing IT infrastructure within physical test pipeline | `tests/qos/` (physical test path) | ~3 smoke tests |

**Execution speed**: All three are fast—UT/IT execute in sub-second to single-digit seconds locally. For example, IT's 24 PFC Xoff tests complete in 0.21 seconds.

#### 3.9.2 Unit Tests: Traditional Method-Level Validation

UT tests validate individual components in isolation—using traditional pytest framework to verify outputs, intermediate states, and component interactions.

**Coverage**: 66 tests across algorithms, executors, observers, and supporting components. Even sim executors themselves have UT tests to validate simulation correctness.

**Example 1: Iteration Count & Exact Results Validation**

```python
# tests/saitests/mock/ut/test_threshold_range_probing_algorithm.py

def test_run_binary_search_shrinks_left():
    """Test binary search shrinking left when threshold triggered"""
    
    # Create sim executor: threshold at ~400 (triggered at 500, not at 300)
    mock_executor = MagicMock(spec=ProbingExecutorProtocol)
    mock_executor.check.side_effect = [
        (True, True),   # check(500) → triggered → search [100, 500]
        (True, False),  # check(300) → dismissed → search [300, 500]
    ]
    
    mock_observer = MagicMock(spec=ProbingObserver)
    
    # Algorithm under test (real implementation)
    algo = ThresholdRangeProbingAlgorithm(
        mock_executor, mock_observer, 
        precision_target_ratio=0.01  # 1% precision
    )
    
    # Execute: search for threshold in [100, 900]
    lower, upper, _ = algo.run(
        src_port=24, dst_port=28, 
        lower_bound=100, upper_bound=900, pg=3
    )
    
    # ===== Validates: Iteration count =====
    # Verify binary search progression (O(log n) behavior)
    calls = mock_executor.check.call_args_list
    assert calls[0][0][2] == 500  # First midpoint: (100 + 900) / 2
    assert calls[1][0][2] == 300  # Second midpoint: (100 + 500) / 2
    
    # ===== Validates: Intermediate states & component interactions =====
    # Verify observer tracking (intermediate state correctness)
    observer_calls = mock_observer.on_iteration_start.call_args_list
    assert observer_calls[0][0] == (1, 500, 100, 900, "init")
    assert observer_calls[1][0] == (2, 300, 100, 500, "<-U")  # Upper shrinking
    
    # ===== Validates: Exact results =====
    # Final range must contain actual threshold
    assert lower == 300 and upper == 500
```

**Example 2: Component Isolation Validation**

```python
# tests/saitests/mock/ut/test_executor_registry.py

def test_create_physical_env():
    """Test ExecutorRegistry.create() with physical environment"""
    
    # ===== Validates: Component isolation =====
    # Test ExecutorRegistry in isolation (no PTF/SAI dependencies)
    
    # Register a physical executor for testing
    @ExecutorRegistry.register('test_physical_exec', 'physical')
    class TestPhysicalExecutor:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
    
    # Mark module as loaded (skip actual import in UT)
    ExecutorRegistry._loaded_modules.add('test_physical_exec_probing_executor')
    
    # Test: create physical executor with kwargs
    executor = ExecutorRegistry.create(
        'test_physical_exec', 'physical', 
        name='test', value=123
    )
    
    # ===== Validates: Exact results =====
    # Verify correct instance created with expected properties
    assert executor is not None
    assert isinstance(executor, TestPhysicalExecutor)
    assert executor.kwargs['name'] == 'test'
    assert executor.kwargs['value'] == 123
    
    # Cleanup
    del ExecutorRegistry._registry[('test_physical_exec', 'physical')]
    ExecutorRegistry._loaded_modules.discard('test_physical_exec_probing_executor')
```

**Example 3: Edge Cases & Precision Boundaries Validation**

```python
# tests/saitests/mock/ut/test_threshold_range_probing_algorithm.py

def test_run_immediate_precision_reached():
    """Test when precision already met on first iteration"""
    
    mock_executor = MagicMock(spec=ProbingExecutorProtocol)
    mock_observer = MagicMock(spec=ProbingObserver)
    
    # Algorithm under test
    algo = ThresholdRangeProbingAlgorithm(
        mock_executor, mock_observer,
        precision_target_ratio=0.05  # 5% precision
    )
    
    # ===== Validates: Edge cases =====
    # Edge case: precision already met (range_size=20 <= candidate×5%=25)
    lower, upper, _ = algo.run(
        src_port=24, dst_port=28,
        lower_bound=490, upper_bound=510, pg=3
    )
    
    # ===== Validates: Precision boundaries =====
    # Verify range unchanged (already within tolerance)
    assert lower == 490 and upper == 510
    
    # ===== Validates: Iteration count =====
    # Verify no unnecessary checks (0 iterations when precision met)
    mock_executor.check.assert_not_called()
    
    # ===== Validates: Intermediate states & component interactions =====
    # Verify observer reported SKIPPED
    mock_observer.on_iteration_complete.assert_called_once()
    call_args = mock_observer.on_iteration_complete.call_args[0]
    assert call_args[2].value == IterationOutcome.SKIPPED.value
```

**What UT validates**:
- [x] **Exact results**: Threshold must be in final range, precision must be met
- [x] **Precision boundaries**: `(upper - lower) <= threshold × precision_ratio`
- [x] **Iteration count**: Binary search O(log n) behavior
- [x] **Edge cases**: Zero threshold, max threshold, single-value range, precision already met
- [x] **Component isolation**: Test one component at a time without dependencies
- [x] **Intermediate states & component interactions**: Observer tracking, event sequencing, state transitions

#### 3.9.3 Sim Executor: The Key Enabler

**Bridge to Integration Tests**: Before exploring how Integration Tests simulate complete probe workflows (§3.9.4), we need to understand the foundation that enables both UT and IT to run without physical hardware. As mentioned in §3.9.1, all three test types rely on sim executors—this section explains their design and why they are essential.

**Why Sim Executor?**

Probe targets are hardware-dependent (PFC counters, drop counters, buffer state)—we need to simulate threshold detection to enable testing without physical switches.

**Minimal Sim Strategy**:

Sim Executor follows a **minimal sim strategy**: simulate only `check()` method, let everything else run real.

```python
# Normal scenario - base sim executor
@ExecutorRegistry.register(executor_type="pfc_xoff", executor_env="sim")
class SimPfcXoffProbingExecutor:
    """Only threshold detection is simulated; algorithms/observer run real"""
    
    def __init__(self, observer, name, actual_threshold=500, **kwargs):
        self.observer = observer
        self.name = name
        self.actual_threshold = actual_threshold
    
    def check(self, src_port, dst_port, value, **traffic_keys):
        """Simulate threshold detection"""
        triggered = value >= self.actual_threshold
        return (True, triggered)  # (success, triggered)


# Noisy scenario - separate class
class NoisySimPfcXoffProbingExecutor(SimPfcXoffProbingExecutor):
    """Simulates counter jitter (±10 cells)"""
    
    def check(self, src_port, dst_port, value, **traffic_keys):
        effective_threshold = self.actual_threshold + random.randint(-10, 10)
        triggered = value >= effective_threshold
        return (True, triggered)


# Intermittent scenario - separate class
class IntermittentSimPfcXoffProbingExecutor(SimPfcXoffProbingExecutor):
    """Simulates hardware failure (30% failure rate)"""
    
    def check(self, src_port, dst_port, value, **traffic_keys):
        if random.random() < 0.3:
            return (False, False)  # Verification failed
        triggered = value >= self.actual_threshold
        return (True, triggered)
```

**Design Note**: Scenario classes inherit from base sim executor for **code reuse** (`__init__`, shared attributes), not protocol enforcement. Each class could independently implement `ProbingExecutorProtocol`—inheritance simply avoids repeating common initialization logic across scenarios.

**ExecutorRegistry: Decorator-Based Registration**

All executors (physical/mock/scenario) register via decorator with **3-parameter signature**: `(executor_type, env, scenario)`.

```python
# Physical executor (real hardware interaction)
@ExecutorRegistry.register(executor_type="pfc_xoff", executor_env="physical")
class PhysicalPfcXoffProbingExecutor:
    def check(self, src_port, dst_port, value, **traffic_keys):
        # Real: send packets, read PFC counters, detect trigger
        pkt = self.stream_mgr.get_packet(src_port, dst_port, **traffic_keys)
        send_packet(self.ptftest, src_port, pkt, value)
        return self._detect_pfc_triggered(src_port)

# Sim executor - normal scenario (scenario defaults to None)
@ExecutorRegistry.register(executor_type="pfc_xoff", executor_env="sim")
class SimPfcXoffProbingExecutor:
    def check(self, src_port, dst_port, value, **traffic_keys):
        triggered = value >= self.actual_threshold
        return (True, triggered)

# Sim executor - noisy scenario (third parameter = scenario name)
@ExecutorRegistry.register(executor_type="pfc_xoff", executor_env="sim", scenario="noisy")
class NoisySimPfcXoffProbingExecutor(SimPfcXoffProbingExecutor):
    def check(self, src_port, dst_port, value, **traffic_keys):
        effective_threshold = self.actual_threshold + random.randint(-10, 10)
        triggered = value >= effective_threshold
        return (True, triggered)

# Sim executor - intermittent failures
@ExecutorRegistry.register(executor_type="pfc_xoff", executor_env="sim", scenario="intermittent")
class IntermittentSimPfcXoffProbingExecutor(SimPfcXoffProbingExecutor):
    def check(self, src_port, dst_port, value, **traffic_keys):
        if random.random() < 0.3:  # 30% failure rate
            return (False, False)  # Simulate hardware error
        return super().check(src_port, dst_port, value, **traffic_keys)
```

Probe/test code selects executors via `create()` method:

```python
# IT: Environment-agnostic probe code (uses default scenario)
executor = ExecutorRegistry.create('pfc_xoff', executor_env=self.EXECUTOR_ENV, ...)
# If executor_env='physical' → PhysicalPfcXoffProbingExecutor
# If executor_env='sim'     → SimPfcXoffProbingExecutor (scenario=None)

# IT: Scenario-specific tests (via scenario parameter)
executor = ExecutorRegistry.create('pfc_xoff', executor_env='sim', scenario='noisy', ...)
# → NoisySimPfcXoffProbingExecutor

executor = ExecutorRegistry.create('pfc_xoff', executor_env='sim', scenario='intermittent', ...)
# → IntermittentSimPfcXoffProbingExecutor
```

Registry key structure: `(executor_type, env, scenario)` where `scenario` defaults to `None`.

This pattern enables:
- **Extensibility**: Add executors by decorating new classes
- **Type safety**: Registry enforces `ProbingExecutorProtocol` conformance
- **IT compatibility**: All executors accessible via registry (no direct instantiation)
- **Environment switching**: One parameter (`executor_env`) switches sim ↔ physical

#### 3.9.4 Integration Tests: Near-Physical Test Simulation

IT simulates the complete physical test workflow using pytest-mocked components, achieving behavior nearly identical to physical tests but with minute-level execution.

**IT Test Structure**:

IT tests use `probe_test_helper.py` to mock PTF/SAI dependencies (packet injection, thrift interfaces, buffer control) and provide probe creation helpers:

```python
# tests/saitests/mock/it/test_pfc_xoff_probing.py

from probe_test_helper import setup_test_environment, create_pfc_xoff_probe_instance
setup_test_environment()  # Mocks PTF/SAI, adds probe path

class TestPfcXoffProbing:
    def test_pfc_xoff_normal_scenario(self):
        probe = create_pfc_xoff_probe_instance(actual_threshold=500)
        probe.runTest()
```

**What Is NOT Mocked (Runs Real Code)**:

- [x] **Probe class**: `PfcXoffProbing.setUp()` / `runTest()` execute as-is
- [x] **Algorithms**: Binary search, backtracking, precision control—real implementation
- [x] **Observer**: Real markdown tables, timing metrics, iteration tracking
- [x] **Result calculations**: Real precision validation, range checks
- [x] **Sim Executor** (§3.9.3): Real sim logic (scenario simulation)

**Result: IT Workflow ≈ Physical Test Workflow**

Compare IT vs Physical test—only difference is `executor_env` parameter and mocked dependencies:

```python
# --- Physical Test (real testbed) ---
# tests/saitests/test_pfc_xoff_probing.py

class TestPfcXoffProbing(SaiTest):  # PTF test framework
    def runTest(self):
        probe = PfcXoffProbing()
        probe.setUp(test_params={'src_port': 1, 'dst_port': 0, 'pg': 3})
        # executor_env defaults to 'physical'
        result = probe.runTest()  # Minutes (real hardware)


# --- Integration Test (pytest-mocked) ---
# tests/saitests/mock/it/test_pfc_xoff_probing.py

class TestPfcXoffProbing:  # pytest framework
    def test_pfc_xoff_basic(self):
        probe = create_pfc_xoff_probe_instance(
            test_params={'src_port': 1, 'dst_port': 0, 'pg': 3},
            executor_env='sim'  # Only difference!
        )
        result = probe.runTest()  # Sub-second (sim executor)
```

**Actual IT Output: Same Observer Tables as Physical Tests**

When running IT tests, the sim executor produces identical Observer output to physical tests—only execution time differs. Here's example output from a PFC XOFF probing IT test:

```
================================================================================
[pfc_xoff] Starting threshold probing
  src_port=1, dst_port=0
  pool_size=160236
  precision_target_ratio=0.05
================================================================================

Upper Bound Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 1.1.1    | NA        | NA        | 160236    | init  | reached      | 0.00     | 0.00      |
  PFC Upper bound = 160236

Lower Bound Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|-----------|
| 1.2.1    | 80118     | NA        | 160236    | init  | unreached    | 0.00     | 0.00      |
  PFC Lower bound = 80118

Threshold Range Probing
| Iter     | Lower     | Candidate | Upper     | Step  | PfcXoff      | Time(s)  | Total(s)  |
|----------|-----------|-----------|-----------|-------|--------------|----------|--------|
| 1.3.1    | 80118     | 120177    | 160236    | init  | reached      | 0.00     | 0.00      |
| 1.3.2    | 80118     | 100147    | 120177    | <-U   | reached      | 0.00     | 0.00      |
| 1.3.3    | 80118     | 90132     | 100147    | <-U   | reached      | 0.00     | 0.00      |
| 1.3.4    | 80118     | 85125     | 90132     | <-U   | unreached    | 0.00     | 0.00      |
| 1.3.5    | 85125     | 87628     | 90132     | L->   | unreached    | 0.00     | 0.00      |
| 1.3.6    | 87628     | 88880     | 90132     | L->   | unreached    | 0.00     | 0.00      |
| 1.3.7    | 88880     | 89506     | 90132     | L->   | reached      | 0.00     | 0.00      |
| 1.3.8    | 88880     | 89193     | 89506     | <-U   | skipped      | 0.00     | 0.00      |
  PFC Range = [88880, 89506]

================================================================================
RESULT: Threshold Range = [88880, 89506], Candidate = 89193 cells
Precision: 0.70% (target: 5.00%)  PASSED
Total iterations: 8 | Total time: 0.01s
================================================================================
```

**Key Observation**: The Observer output structure (tables, iteration details, precision validation) is **identical** to physical tests (see §3.8.5 for physical Headroom Pool output). The only differences:
- **Time**: Sub-second (0.00-0.01s per iteration) vs. minutes for physical hardware
- **Threshold values**: Configurable via `actual_threshold` parameter vs. discovered from real hardware

This demonstrates that IT tests provide **complete workflow validation** without physical testbed dependency.

**What IT Validates**:

- [x] **Observer output**: Markdown tables display correctly
- [x] **Flow execution**: All 4 phases complete without errors
- [x] **Algorithm convergence**: No infinite loops, proper termination
- [x] **Scenario support**: Noisy hardware, intermittent failures, wrong config
- [ ] **NOT exact threshold values** (permissive assertions—UT already validates precision)

**IT Coverage**: 62 tests simulating physical test scenarios

| Probe Type | IT Tests | Coverage |
|------------|----------|----------|
| **PFC Xoff Probing** | 24 | Single/multi queue, noisy scenarios, precision ratios, boundary cases |
| **Ingress Drop Probing** | 23 | PG probing, counter types, algorithm variants |
| **Headroom Pool Probing** | 15 | Basic scenarios, Point Probing, error accumulation |

**Why IT Matters**:

Before IT, syntax errors and logic bugs were caught only in nightly physical testbed runs (12-24h feedback delay). With IT, developers get **minute-level feedback** during local development—same workflow, just mocked dependencies.

#### 3.9.5 PR Tests: Leveraging IT for Pre-Merge Validation

PR tests (`tests/qos/test_qos_probe.py`) are a **special subset of IT tests** designed for CI pre-merge validation in VS (Virtual Switch) environments.

**How PR Tests Reuse IT Infrastructure**:

```python
# tests/qos/test_qos_probe.py

# Import IT mocking infrastructure (setup_test_environment from probe_test_helper)
from tests.saitests.mock.it.probe_test_helper import setup_test_environment
setup_test_environment()

# Import probe class and helper after mocks are ready
from tests.saitests.mock.it.probe_test_helper import create_pfc_xoff_probe_instance

def test_pfc_xoff_basic():
    """PR Test: Smoke test for PFC Xoff probing"""
    # Reuses IT's mocked PTF/SAI components from setup_test_environment()
    probe = create_pfc_xoff_probe_instance(
        num_queues=1,
        algorithm='range',
        executor_env='sim'
    )
    result = probe.runTest()
    assert result is not None
```

**IT vs PR Test Difference**:

| Aspect | Integration Tests (IT) | PR Tests |
|--------|----------------------|----------|
| **Purpose** | Comprehensive workflow validation | Pre-merge smoke tests |
| **Coverage** | 62 tests (all scenarios) | ~3 tests (typical cases only) |
| **Execution** | Local development (`pytest tests/saitests/mock/it/`) | CI pipeline (GitHub PR checks) |
| **Environment** | Developer machine | VS environment (Azure Pipelines) |
| **Selection** | All IT tests | Subset of IT tests (smoke) |

**PR Test Workflow**:

1. Developer submits PR with probe code changes
2. CI triggers PR tests in VS environment
3. PR tests import IT mocking infrastructure
4. Selected IT smoke tests execute (typical scenarios only)
5. Feedback in **minutes** (vs. 12-24h for physical testbed)
6. After PR merge, nightly physical testbed validates on real hardware

**Test Coverage Summary**:

| Component | UT Tests | IT Tests | PR Tests | Physical Tests |
|-----------|----------|----------|----------|----------------|
| **Algorithms** | 27 | Integrated | - | Full validation |
| **PFC Xoff Probing** | 12 | 24 | 1 smoke | Full validation |
| **Ingress Drop Probing** | 11 | 23 | 1 smoke | Full validation |
| **Headroom Pool Probing** | 8 | 15 | 1 smoke | Full validation |
| **Supporting Components** | 8 | 0 | - | - |
| **Total** | 66 | 62 | ~3 | Production |

**Development Feedback Loop**:

```
Local Development:  UT (seconds) → IT (minutes)
PR Submission:      PR tests (minutes, CI)
Post-Merge:         Physical tests (12-24h, nightly)
```

This three-tier architecture enables **rapid iteration** without sacrificing **production confidence**.

---
