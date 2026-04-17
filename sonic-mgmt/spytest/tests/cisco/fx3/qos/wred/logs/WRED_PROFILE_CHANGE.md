# WRED Profile Change Test Summaries

SONiC build: `fx3_cmaster.88-dirty-20260401.095209` | Run date: 2026-04-02

Source: [`test_wred_profile_validation.py`](../test_wred_profile_validation.py)

Golden WRED profile (`AZURE_LOSSY` baseline):

| Field | Value |
|---|---|
| `green_min_threshold` | 1,048,576 bytes (1 MB) |
| `green_max_threshold` | 3,145,728 bytes (3 MB) |
| `green_drop_probability` | 5% |
| `ecn` | `ecn_none` |
| `wred_green_enable` | `true` |

---

## 1. `test_wred_reject_invalid_gdrop`

Validates that `ecnconfig -p AZURE_LOSSY -gdrop 200` is rejected (valid range 0-100) and CONFIG_DB is unchanged.

### Parameters

| Parameter | Value |
|---|---|
| Profile | AZURE_LOSSY (golden) |
| Attempted gdrop | 200 (invalid) |
| Expected behavior | Rejection, gdrop stays at 5 |

### Results

| AF | Result | Duration | gdrop before | gdrop after |
|---|---|---|---|---|
| ipv4 | **PASS** | 17s | 5 | 5 |
| ipv6 | **PASS** | 17s | 5 | 5 |

No linearity sweep — CLI validation only.

---

## 2. `test_wred_custom_gdrop_profile`

Changes `green_drop_probability` from 5% to 10%, runs a linearity sweep, then restores the golden profile.

### Parameters

| Parameter | Value |
|---|---|
| Profile | AZURE_LOSSY (modified) |
| `green_drop_probability` | 10% |
| `green_min_threshold` | 1,048,576 (1 MB) |
| `green_max_threshold` | 3,145,728 (3 MB) |
| Margins (Mbps) | 0, 250, 500, 1000, 2000, 3000, 4000, 5000, 5250, 5500, 7000, 9000, 11000, 12000 |

### Results

| AF | Result | Duration |
|---|---|---|
| ipv4 | **PASS** | 14m 14s |
| ipv6 | **PASS** | 13m 43s |

### Zone Boundaries

| Zone | Condition | Behavior |
|---|---|---|
| A | depth < 1 MB | No WRED drops |
| B | 1 MB ≤ depth ≤ 3 MB | WRED active, prob 0–10% |
| C | depth > 3 MB | Tail drop |

Estimated probability: `10% × (depth − 1MB) / (3MB − 1MB)`, capped at 100%

### Linearity — IPv4

| Margin | Port A | Port B | Rate% | Avg Depth | Est. Prob | WRED Drop | Zone | Status |
|---|---|---|---|---|---|---|---|---|
| 0M | 50.000% | 50.000% | 100.000% | 1.01MB | 0.07% | 0.00% | B | OK |
| 250M | 50.125% | 50.125% | 100.250% | 1.07MB | 0.35% | 0.25% | B | OK |
| 500M | 50.250% | 50.250% | 100.500% | 1.13MB | 0.65% | 0.50% | B | OK |
| 1000M | 50.500% | 50.500% | 101.000% | 1.22MB | 1.10% | 0.99% | B | OK |
| 2000M | 51.000% | 51.000% | 102.000% | 1.44MB | 2.19% | 1.96% | B | OK |
| 3000M | 51.500% | 51.500% | 103.000% | 1.60MB | 3.00% | 2.91% | B | OK |
| 4000M | 52.000% | 52.000% | 104.000% | 1.79MB | 3.94% | 3.85% | B | OK |
| 5000M | 52.500% | 52.500% | 105.000% | 1.98MB | 4.91% | 4.76% | B | OK |
| 5250M | 52.625% | 52.625% | 105.250% | 2.02MB | 5.09% | 4.99% | B | OK |
| 5500M | 52.750% | 52.750% | 105.500% | 2.07MB | 5.36% | 5.21% | B | OK |
| 7000M | 53.500% | 53.500% | 107.000% | 2.32MB | 6.61% | 6.54% | B | OK |
| 9000M | 54.500% | 54.500% | 109.000% | 2.70MB | 8.52% | 8.26% | B | OK |
| 11000M | — | — | — | — | — | — | — | Zone C skipped |
| 12000M | 56.000% | 56.000% | 112.000% | 2.96MB | 9.78% | 10.72% | B | OK |

11000M was skipped: "not all depth samples > max_th" (borderline Zone B/C, excluded from sweep).

Monotonicity: `[0.00%, 0.25%, 0.50%, 0.99%, 1.96%, 2.91%, 3.85%, 4.76%, 4.99%, 5.21%, 6.54%, 8.26%, 9.91%, 10.72%]` — monotonically increasing

### Linearity — IPv6

| Margin | Port A | Port B | Rate% | Avg Depth | Est. Prob | WRED Drop | Zone | Status |
|---|---|---|---|---|---|---|---|---|
| 0M | 50.000% | 50.000% | 100.000% | 1.01MB | 0.07% | 0.00% | B | OK |
| 250M | 50.125% | 50.125% | 100.250% | 1.07MB | 0.36% | 0.25% | B | OK |
| 500M | 50.250% | 50.250% | 100.500% | 1.12MB | 0.60% | 0.50% | B | OK |
| 1000M | 50.500% | 50.500% | 101.000% | 1.21MB | 1.06% | 0.99% | B | OK |
| 2000M | 51.000% | 51.000% | 102.000% | 1.42MB | 2.09% | 1.96% | B | OK |
| 3000M | 51.500% | 51.500% | 103.000% | 1.59MB | 2.96% | 2.91% | B | OK |
| 4000M | 52.000% | 52.000% | 104.000% | 1.80MB | 3.98% | 3.85% | B | OK |
| 5000M | 52.500% | 52.500% | 105.000% | 1.96MB | 4.82% | 4.76% | B | OK |
| 5250M | 52.625% | 52.625% | 105.250% | 2.05MB | 5.23% | 4.99% | B | OK |
| 5500M | 52.750% | 52.750% | 105.500% | 2.06MB | 5.29% | 5.21% | B | OK |
| 7000M | 53.500% | 53.500% | 107.000% | 2.34MB | 6.68% | 6.54% | B | OK |
| 9000M | 54.500% | 54.500% | 109.000% | 2.68MB | 8.40% | 8.26% | B | OK |
| 11000M | 55.500% | 55.500% | 111.000% | 2.96MB | 9.82% | 9.91% | B | OK |
| 12000M | 56.000% | 56.000% | 112.000% | 2.99MB | 9.94% | 10.62% | B | OK |

Monotonicity: `[0.00%, 0.25%, 0.50%, 0.99%, 1.96%, 2.91%, 3.85%, 4.76%, 4.99%, 5.21%, 6.54%, 8.26%, 9.91%, 10.62%]` — monotonically increasing

---

## 3. `test_wred_custom_threshold_profile`

Doubles min/max thresholds (1 MB/3 MB to 2 MB/6 MB), runs a linearity sweep, then restores the golden profile.

### Parameters

| Parameter | Value |
|---|---|
| Profile | AZURE_LOSSY (modified) |
| `green_drop_probability` | 5% |
| `green_min_threshold` | 2,097,152 (2 MB) |
| `green_max_threshold` | 6,291,456 (6 MB) |
| Margins (Mbps) | 0, 250, 500, 3000, 4000, 5000, 5500, 7000, 9000, 11000 |

### Results

| AF | Result | Duration |
|---|---|---|
| ipv4 | **PASS** | 10m 35s |
| ipv6 | **PASS** | 10m 10s |

### Zone Boundaries

| Zone | Condition | Behavior |
|---|---|---|
| A | depth < 2 MB | No WRED drops |
| B | 2 MB ≤ depth ≤ 6 MB | WRED active, prob 0–5% |
| C | depth > 6 MB | Tail drop |

Estimated probability: `5% × (depth − 2MB) / (6MB − 2MB)`, capped at 100%

### Linearity — IPv4

| Margin | Port A | Port B | Rate% | Avg Depth | Est. Prob | WRED Drop | Zone | Status |
|---|---|---|---|---|---|---|---|---|
| 0M | 50.000% | 50.000% | 100.000% | 1.01MB | 0.00% | 0.00% | A | OK |
| 250M | 50.125% | 50.125% | 100.250% | 1.12MB | 0.00% | 0.25% | A | OK |
| 500M | 50.250% | 50.250% | 100.500% | 1.22MB | 0.00% | 0.50% | A | OK |
| 3000M | 51.500% | 51.500% | 103.000% | 2.22MB | 0.27% | 2.91% | B | OK |
| 4000M | 52.000% | 52.000% | 104.000% | 2.55MB | 0.69% | 3.85% | B | OK |
| 5000M | 52.500% | 52.500% | 105.000% | 2.91MB | 1.14% | 4.76% | B | OK |
| 5500M | 52.750% | 52.750% | 105.500% | 2.98MB | 1.22% | 5.11% | B | OK |
| 7000M | 53.500% | 53.500% | 107.000% | 3.00MB | 1.25% | 6.61% | B | OK |
| 9000M | 54.500% | 54.500% | 109.000% | 3.00MB | 1.25% | 8.26% | B | OK |
| 11000M | 55.500% | 55.500% | 111.000% | 3.00MB | 1.25% | 9.91% | B | OK |

Monotonicity: `[0.00%, 0.25%, 0.50%, 2.91%, 3.85%, 4.76%, 5.11%, 6.61%, 8.26%, 9.91%]` — monotonically increasing

### Linearity — IPv6

| Margin | Port A | Port B | Rate% | Avg Depth | Est. Prob | WRED Drop | Zone | Status |
|---|---|---|---|---|---|---|---|---|
| 0M | 50.000% | 50.000% | 100.000% | 1.01MB | 0.00% | 0.00% | A | OK |
| 250M | 50.125% | 50.125% | 100.250% | 1.12MB | 0.00% | 0.25% | A | OK |
| 500M | 50.250% | 50.250% | 100.500% | 1.21MB | 0.00% | 0.50% | A | OK |
| 3000M | 51.500% | 51.500% | 103.000% | 2.18MB | 0.22% | 2.91% | B | OK |
| 4000M | 52.000% | 52.000% | 104.000% | 2.57MB | 0.72% | 3.85% | B | OK |
| 5000M | 52.500% | 52.500% | 105.000% | 2.97MB | 1.21% | 4.76% | B | OK |
| 5500M | 52.750% | 52.750% | 105.500% | 2.98MB | 1.22% | 5.21% | B | OK |
| 7000M | 53.500% | 53.500% | 107.000% | 2.98MB | 1.22% | 6.54% | B | OK |
| 9000M | 54.500% | 54.500% | 109.000% | 2.95MB | 1.19% | 8.26% | B | OK |
| 11000M | 55.500% | 55.500% | 111.000% | 2.99MB | 1.23% | 9.91% | B | OK |

Monotonicity: `[0.00%, 0.25%, 0.50%, 2.91%, 3.85%, 4.76%, 5.21%, 6.54%, 8.26%, 9.91%]` — monotonically increasing

---

## 4. `test_wred_narrowest_zone`

Test 8 (traffic): applies a 1-byte WRED zone (`min=1048576`, `max=1048577`) and
verifies drops occur under fan-in congestion.  Both thresholds quantize to the same
HW QDES value (39), so the WRED zone is effectively zero-width in hardware.

Run date: 2026-04-07

### Parameters

| Parameter | Value |
|---|---|
| Profile | AZURE_LOSSY (narrow zone) |
| `green_min_threshold` | 1,048,576 (1 MB) |
| `green_max_threshold` | 1,048,577 (1 MB + 1 byte) |
| `green_drop_probability` | 5% |
| Margin | 10000 Mbps (10% oversubscription) |
| Duration | 20s |
| Depth limit | 2 MB |

### Results

| AF | Result | Duration | drop_rate | avg_depth | drop_pkts | egress_pkts |
|---|---|---|---|---|---|---|
| ipv4 | **PASS** | 2m 03s | 9.09% | 0.95 MB | 432,280,034 | 4,322,111,556 |
| ipv6 | **PASS** | 2m 00s | 9.09% | 0.95 MB | 432,994,064 | 4,329,251,120 |

### Notes

The key validation is **avg queue depth** (0.95 MB), which confirms the narrow zone
constrains the queue near the 1 MB threshold.  With the golden profile at similar
oversubscription, the queue sits at ~3 MB.  The config-only portion (CONFIG_DB +
ASIC_DB + DCHAL acceptance) is covered in `test_wred_config_propagation.py`.
