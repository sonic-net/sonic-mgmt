# Sampled ERSPAN with truncation test plan

## Rev 0.1

- [Revision](#revision)
- [Definition/Abbrevation](#definitionabbrevation)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)
  - [Capability discovery](#capability-discovery)
  - [Configuration and CLI validation](#configuration-and-cli-validation)
  - [Show CLI](#show-cli)
  - [Dataplane: truncation](#dataplane-truncation)
  - [Dataplane: sampling](#dataplane-sampling)
  - [Dataplane: combined sampling and truncation](#dataplane-combined-sampling-and-truncation)
  - [Dataplane: direction (RX / TX / BOTH)](#dataplane-direction-rx--tx--both)
  - [Session lifecycle](#session-lifecycle)
  - [Backward compatibility](#backward-compatibility)

## Revision

| Rev |     Date    |       Author            |     Change Description                                   |
|:---:|:-----------:|:------------------------|:--------------------------------------------------------|
| 0.1 |  05/21/2026 | Janet Cui               | Initial version                                         |

## Definition/Abbrevation

| **Term**       | **Meaning**                                              |
|----------------|----------------------------------------------------------|
| ERSPAN         | Encapsulated Remote SPAN (GRE-encapsulated mirroring)    |

## Overview

The purpose is to test the new sampled ERSPAN with truncation feature on a SONiC switch DUT.
Two new optional parameters were added to the ERSPAN mirror session: **sample_rate** (1:N sampling)
and **truncate_size** (per-packet byte truncation). Sampling is supported in the **rx**, **tx**, and
**both** mirror directions. This test plan validates capability discovery, CLI/CONFIG_DB plumbing,
and end-to-end dataplane behavior.

## Scope

The test targets a running SONiC with a fully functioning configuration. It verifies that the DUT correctly:
- Advertises sampling and truncation capabilities via STATE_DB.
- Accepts valid sample_rate / truncate_size values via CLI and writes them to CONFIG_DB.
- Rejects out-of-range and invalid values.
- Treats sample_rate=0 / truncate_size=0 as "feature disabled" (field omitted from CONFIG_DB).
- Mirrors only 1 of every N packets when sampling is configured, in the rx, tx, and both directions.
- Truncates each mirrored packet to the configured byte budget, including combined with sampling.

## Testbed

Supported topologies: `t0`.

The DUT must have at least one routable path to the configured ERSPAN destination IP so that the
GRE-encapsulated mirror packet egresses on a port connected to PTF (the collector).

Capability gating (skips are implemented as fixtures in `conftest.py`):
- `skip_if_ingress_sampling_unsupported` - skips if STATE_DB does not report
  `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE = true`.
- `skip_if_egress_sampling_unsupported` - skips if STATE_DB does not report
  `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE = true`.
- `skip_if_any_sampling_unsupported` - skips only if neither ingress nor egress sampling is
  supported (used by CLI/config-only sampling tests).
- `skip_if_truncation_unsupported` - skips if STATE_DB does not report
  `SAMPLEPACKET_TRUNCATION_CAPABLE = true`.
- `skip_if_no_tx_ingress` - skips TX/BOTH dataplane tests when the testbed VLAN does not have a
  spare peer member port to inject the flood traffic (see Setup configuration).

## Setup configuration
Each test (or fixture) creates an ERSPAN session with the specific parameters under test and cleans it up on teardown.

### Port roles (erspan_ports fixture)

The dataplane tests pick three VLAN member ports:
- **source** - the mirror source port; the session is bound to it and its traffic is mirrored.
- **gre_egress** - the monitor/collector port; the GRE-encapsulated ERSPAN copy egresses here and
  is captured by PTF. It also serves as the next-hop for the ERSPAN destination route.
- **tx_ingress** - a spare peer VLAN member used only by TX/BOTH tests to inject broadcast frames
  that the DUT floods back out the source port (egress), triggering the egress mirror. `None` when
  no spare member exists, in which case TX/BOTH tests skip.

### Setup of DUT switch

Each test uses fixtures (defined in `conftest.py`):
- `erspan_capabilities` - reads STATE_DB SWITCH_CAPABILITY once per module.
- `setup_erspan_route` - installs a static route so the ERSPAN destination IP egresses on a
  PTF-connected port.
- `erspan_session` - creates the mirror session with parameters (sample_rate, truncate_size,
  direction) supplied indirectly by the test, waits for STATE_DB status=active, yields, then
  removes the session. Leftover same-named sessions are pre-cleaned via `remove_mirror_session`.

On setup, sessions are created via:
```
sudo config mirror_session erspan add <name> <src_ip> <dst_ip> <dscp> <ttl> \
     [gre_type] [queue] [src_port] [direction] \
     [--sample_rate <N>] [--truncate_size <bytes>]
```

On teardown:
```
sudo config mirror_session remove <name>
```

### Dataplane collection methodology

Mirrored GRE packets are captured on the collector (gre_egress) port and identified by a 3-tuple
match on the outer headers - `outer IP.src == session.src_ip`, `outer IP.dst == session.dst_ip`,
and `GRE.proto == session.gre_type`. This three-tuple uniquely identifies frames from the session
under test and is robust against ASIC-specific ERSPAN encapsulation differences (e.g. extra
ERSPAN II/III header bytes between GRE and the inner frame).

Sampling tests send `NUM_SAMPLES * N` packets (where `NUM_SAMPLES = 100` and `N = sample_rate`) so
the expected mirrored count is `~NUM_SAMPLES = 100` regardless of `N`, and assert the observed count
is within `[95, 105]` (`NUM_SAMPLES +- 5%`, via `MIN_EXPECTED_SAMPLES` / `MAX_EXPECTED_SAMPLES`).
This is a deliberately tight tolerance: under a binomial approximation
(`sigma = sqrt(NUM_SAMPLES) = 10`), +-5% is only ~0.5 sigma, so the single-run pass rate is modest
and the tests rely on reruns (or a larger `NUM_SAMPLES`) for CI stability, in exchange for detecting
any `sample_rate` misprogramming of >=5%.

## Test cases

### Capability discovery

#### Test case test_switch_capability_reported_boolean
**Objective:** Verify STATE_DB advertises each mirror capability key defined in the HLD with a
valid boolean value.

**Parametrized keys:** `PORT_INGRESS_MIRROR_CAPABLE`, `PORT_EGRESS_MIRROR_CAPABLE`,
`PORT_INGRESS_SAMPLE_MIRROR_CAPABLE`, `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE`,
`SAMPLEPACKET_TRUNCATION_CAPABLE`.

**Steps:**
- Read `STATE_DB SWITCH_CAPABILITY|switch`.
- For each key, assert it exists and its value is `true` or `false`.

**Pass criteria:** Each capability key exists with a valid boolean value.

### Configuration and CLI validation

#### Test case test_create_erspan_session_with_sample_rate
**Objective:** Valid `sample_rate` is accepted and written to CONFIG_DB.

**Steps:**
- Run `config mirror_session erspan add ... --sample_rate 50000`.
- Read `CONFIG_DB MIRROR_SESSION|<name>`.

**Pass criteria:** CLI exits 0; CONFIG_DB field `sample_rate` equals the configured value.

#### Test case test_create_erspan_session_with_truncate_size
**Objective:** Valid `truncate_size` is accepted and written to CONFIG_DB.

**Pass criteria:** CLI exits 0; CONFIG_DB field `truncate_size` equals the configured value.

#### Test case test_create_erspan_session_with_both
**Objective:** Both parameters can be configured together on the same session.

**Pass criteria:** Both fields present in CONFIG_DB with the correct values.

#### Test case test_remove_erspan_session_with_sampling
**Objective:** Session removal cleans up a sampling-enabled session completely.

**Steps:** Create a session with `--sample_rate 256`, remove it, check CONFIG_DB key existence.

**Pass criteria:** `MIRROR_SESSION|<name>` no longer exists in CONFIG_DB (redis `exists` == 0).

#### Test case test_invalid_sample_rate_rejected
**Objective:** Out-of-range `sample_rate` is rejected at the CLI layer.

**Parametrized values:** `1` (below the valid minimum).

**Pass criteria:** CLI exits non-zero; no entry written to CONFIG_DB.

#### Test case test_invalid_truncate_size_rejected
**Objective:** Out-of-range `truncate_size` is rejected at the CLI layer.

**Parametrized values:** `32`, `63`, `9217`.

**Pass criteria:** CLI exits non-zero; no entry written to CONFIG_DB.

#### Test case test_sample_rate_zero_disables_sampling
**Objective:** `--sample_rate 0` is accepted by the CLI and semantically equivalent to omitting
the flag (orchagent treats absence as "no sampling").

**Pass criteria:** CLI exits 0; `sample_rate` field is **not** written to CONFIG_DB (redis hget
returns empty).

#### Test case test_truncate_size_zero_disables_truncation
**Objective:** `--truncate_size 0` is accepted by the CLI and semantically equivalent to omitting
the flag.

**Pass criteria:** CLI exits 0; `truncate_size` field is **not** written to CONFIG_DB.

### Show CLI

#### Test case test_show_mirror_session_displays_new_columns
**Objective:** `show mirror_session` displays the configured sampling and truncation values.

Requires both sampling and truncation support (skipped otherwise).

**Steps:**
- Create a session with `--sample_rate 512 --truncate_size 128`.
- Run `show mirror_session`.
- Locate the row for this session and split it into fields.

**Pass criteria:** Exactly one row exists for the session, and its fields list `512`
and `128` as whole tokens.

### Dataplane: truncation

#### Test case test_erspan_truncation_packet_size
**Objective:** Verify ERSPAN truncation across packet sizes relative to `truncate_size`.
`truncate_size` with no `sample_rate` implies 1:1 sampling, so every probe packet is mirrored,
making the per-packet length check deterministic.

**Parametrized (truncate_size, pktlen) combinations:**

| truncate_size | pktlen | relation              | expected mirrored inner length |
|:-------------:|:------:|:----------------------|:-------------------------------|
| 128           | 1500   | pktlen > truncate     | truncated to 128               |
| 256           | 1500   | pktlen > truncate     | truncated to 256               |
| 128           | 64     | pktlen < truncate     | full 64                        |
| 256           | 64     | pktlen < truncate     | full 64                        |
| 128           | 128    | pktlen == truncate    | full 128                       |
| 256           | 256    | pktlen == truncate    | full 256                       |

**Steps:**
- Create an ERSPAN session with `truncate_size` only.
- Send `TRUNCATION_PROBE_COUNT` packets of length `pktlen` from the source port.
- Capture ERSPAN GRE packets on the collector port.

**Pass criteria:** Exactly `TRUNCATION_PROBE_COUNT` frames are mirrored (1:1), and each mirrored
frame length is within `MIRROR_LEN_TOLERANCE` of `(~62B encap overhead + min(pktlen, truncate_size))`.

### Dataplane: sampling

#### Test case test_erspan_sampling_rx_direction
**Objective:** With `sample_rate=N` (rx/ingress), approximately 1 of every N packets is mirrored.

**Parametrized rates:** `1:256`, `1:512`, `1:1024`.

**Steps:**
- Configure `sample_rate=N` (direction defaults to rx).
- Send `NUM_SAMPLES * N` packets on the source port.
- Collect GRE-encapsulated packets on the collector port using the 3-tuple match.

**Pass criteria:** Observed mirror count is within `[95, 105]` (`NUM_SAMPLES +- 5%`).

#### Test case test_erspan_sampling_config_high_rate
**Objective:** A sample rate (`1:50000`) is accepted by CLI and stored in
CONFIG_DB. This is a **config-only** test - dataplane verification at this rate would require
millions of packets and is left to scale testing.

**Pass criteria:** CLI exits 0; CONFIG_DB `sample_rate` field equals `50000`.

### Dataplane: combined sampling and truncation

#### Test case test_erspan_sampling_rx_with_truncation
**Objective:** Sampling and truncation can be active simultaneously and independently (rx/ingress).

**Steps:** Configure `sample_rate=256` + `truncate_size=128`; send `NUM_SAMPLES * 256` large
(1500B) packets on the source port.

**Pass criteria:** Observed mirror count within `[95, 105]` AND each captured mirror is truncated
to `~62B encap overhead + 128`.

### Dataplane: direction (RX / TX / BOTH)

These tests validate that sampled mirroring is correctly bound for each mirror direction. The RX
direction is already covered by `test_erspan_sampling_rx_direction` / `test_erspan_sampling_rx_with_truncation`
above; the cases below add TX (egress) and BOTH coverage. TX traffic is generated by injecting
broadcast frames on the `tx_ingress` peer port so the DUT floods them out the source port (egress).

#### Test case test_erspan_sampling_tx_direction
**Objective:** TX (egress) sampled mirroring emits ERSPAN at the configured ratio.

**Parametrized rates:** `1:256`, `1:512`, `1:1024` (each with `direction=tx`).

**Steps:**
- Create an ERSPAN session with `sample_rate=N`, `direction=tx`.
- Inject `NUM_SAMPLES * N` broadcast frames on the `tx_ingress` peer port; the DUT floods them out
  the source port (egress), triggering the egress mirror.
- Collect ERSPAN GRE packets on the collector port.

**Pass criteria:** Observed mirror count within `[95, 105]` (`NUM_SAMPLES +- 5%`).

#### Test case test_erspan_sampling_tx_with_truncation
**Objective:** TX (egress) sampling and truncation work together.

**Steps:** Configure `sample_rate=256`, `truncate_size=128`, `direction=tx`; inject `NUM_SAMPLES * 256`
large (1500B) broadcast frames on the `tx_ingress` peer port.

**Pass criteria:** Observed mirror count within `[95, 105]` AND each mirrored frame is truncated to
`~62B encap overhead + 128`.

#### Test case test_erspan_sampling_both_direction
**Objective:** `direction=both` mirrors both ingress- and egress-triggered traffic.

**Parametrized rates:** `1:256`, `1:512`, `1:1024` (each with `direction=both`).

**Steps:**
- Create an ERSPAN session with `sample_rate=N`, `direction=both`.
- RX leg: inject `NUM_SAMPLES * N` frames on the source port (ingress mirror).
- TX leg: inject `NUM_SAMPLES * N` broadcast frames on the `tx_ingress` peer port; the DUT floods
  them out the source port (egress mirror).
- Collect ERSPAN GRE packets on the collector port for each leg.

**Pass criteria:** Each leg's observed mirror count is within `[95, 105]` (`NUM_SAMPLES +- 5%`),
proving both the ingress and egress bindings are active.

#### Test case test_erspan_sampling_both_with_truncation
**Objective:** `direction=both` sampling and truncation work together on both legs.

**Steps:** Configure `sample_rate=256`, `truncate_size=128`, `direction=both`; run the RX leg
(inject on source port) and TX leg (inject broadcast on the peer port) with large (1500B) frames.

**Pass criteria:** Each leg's observed mirror count is within `[95, 105]` AND every mirrored frame
on each leg is truncated to `~62B encap overhead + 128`.

### Session lifecycle

#### Test case test_erspan_session_remove_stops_mirroring
**Objective:** Removing the mirror session immediately stops mirroring.

**Steps:**
- Create a session with `sample_rate=256`, verify it is active.
- Remove the session.
- Send 1000 packets on the source port and verify no mirror copies arrive.

**Pass criteria:** After removal, the collector receives zero GRE-encapsulated packets within the
timeout window.

### Backward compatibility

Backward compatibility (a session with neither `sample_rate` nor `truncate_size` behaves as a
classic full-mirror ERSPAN session) is exercised indirectly:
- `test_sample_rate_zero_disables_sampling` and `test_truncate_size_zero_disables_truncation`
  confirm the `0` / omitted cases leave the fields out of CONFIG_DB.
- The `pktlen < truncate_size` and `pktlen == truncate_size` cases of
  `test_erspan_truncation_packet_size` confirm full (untruncated) frames are mirrored when the
  packet does not exceed the budget.
