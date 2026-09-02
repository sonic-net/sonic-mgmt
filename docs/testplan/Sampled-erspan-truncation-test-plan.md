# Sampled ERSPAN with truncation test plan

## Rev 0.1

**Table of Contents**

- [1 Revision](#1-revision)
- [2 Definition/Abbreviation](#2-definitionabbreviation)
- [3 Overview](#3-overview)
- [4 Scope](#4-scope)
- [5 Testbed](#5-testbed)
- [6 Setup configuration](#6-setup-configuration)
  - [6.1 Port roles (erspan_ports fixture)](#61-port-roles-erspan_ports-fixture)
  - [6.2 Setup of DUT switch](#62-setup-of-dut-switch)
  - [6.3 Unicast probe delivery](#63-unicast-probe-delivery)
  - [6.4 Dataplane collection methodology](#64-dataplane-collection-methodology)
- [7 Test cases](#7-test-cases)
  - [7.1 Capability discovery](#71-capability-discovery)
  - [7.2 Configuration and CLI validation](#72-configuration-and-cli-validation)
  - [7.3 Show CLI](#73-show-cli)
  - [7.4 Dataplane validation](#74-dataplane-validation)
  - [7.5 Session lifecycle](#75-session-lifecycle)
  - [7.6 Backward compatibility](#76-backward-compatibility)

## 1 Revision

| Rev |     Date    |       Author            |     Change Description                                   |
|:---:|:-----------:|:------------------------|:--------------------------------------------------------|
| 0.1 |  05/21/2026 | Janet Cui               | Initial version                                         |

## 2 Definition/Abbreviation

| **Term**       | **Meaning**                                              |
|----------------|----------------------------------------------------------|
| ERSPAN         | Encapsulated Remote SPAN (GRE-encapsulated mirroring)    |

## 3 Overview

The purpose is to test the new sampled ERSPAN with truncation feature on a SONiC switch DUT.
Two new optional parameters were added to the ERSPAN mirror session: **sample_rate** (1:N sampling)
and **truncate_size** (per-packet byte truncation). Sampling is supported in the **rx**, **tx**, and
**both** mirror directions. This test plan validates capability discovery, CLI/CONFIG_DB plumbing,
and end-to-end dataplane behavior.

## 4 Scope

The test targets a running SONiC with a fully functioning configuration. It verifies that the DUT correctly:
- Advertises sampling and truncation capabilities via STATE_DB.
- Accepts valid sample_rate / truncate_size values via CLI and writes them to CONFIG_DB.
- Rejects out-of-range and invalid values.
- Treats sample_rate=0 / truncate_size=0 as "feature disabled" (field omitted from CONFIG_DB).
- Mirrors only 1 of every N packets when sampling is configured, in the rx, tx, and both directions.
- Truncates each mirrored packet to the configured byte budget, including combined with sampling.

## 5 Testbed

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
  spare peer member port to inject the TX probe traffic.

## 6 Setup configuration
Each test (or fixture) creates an ERSPAN session with the specific parameters under test and cleans it up on teardown.

### 6.1 Port roles (erspan_ports fixture)

The dataplane tests pick three VLAN member ports:
- **source** - the mirror source port; the session is bound to it and its traffic is mirrored.
- **gre_egress** - the monitor/collector port; the GRE-encapsulated ERSPAN copy egresses here and
  is captured by PTF. It also serves as the next-hop for the ERSPAN destination route.
- **tx_ingress** - a spare peer VLAN member used only by TX/BOTH tests to inject unicast frames
  addressed to `PROBE_UNICAST_DST_MAC`; the DUT forwards them out the source port only (egress),
  triggering the egress mirror without flooding the VLAN.
  `None` when no spare member exists, in which case TX/BOTH tests skip.

### 6.2 Setup of DUT switch

Each test uses fixtures (defined in `conftest.py`):
- `erspan_capabilities` - reads STATE_DB SWITCH_CAPABILITY once per module.
- `setup_erspan_route` - installs a static route so the ERSPAN destination IP egresses on a
  PTF-connected port.
- `erspan_session` - creates the mirror session with parameters (sample_rate, truncate_size,
  direction) supplied indirectly by the test, waits for STATE_DB status=active, yields, then
  removes the session. Leftover same-named sessions are pre-cleaned via `remove_mirror_session`.
  For every session it also programs a static FDB entry pinning `PROBE_UNICAST_DST_MAC` to the
  source port and removes that entry on teardown.

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

### 6.3 Unicast probe delivery

To keep the amount of probe traffic on the fabric bounded and deterministic, probe frames are sent
as unicast to a synthetic destination MAC (`PROBE_UNICAST_DST_MAC`) that the `erspan_session`
fixture pins to the source port with a static FDB entry.

The single static FDB entry serves both directions:
- **RX (ingress):** frames are injected on the source port with dst = `PROBE_UNICAST_DST_MAC`. They
  are ingress-sampled first, then dropped by same-port forwarding.
- **TX (egress):** frames are injected on the `tx_ingress` peer port with dst =
  `PROBE_UNICAST_DST_MAC`. The FDB entry forwards them out the source port only, where they are
  egress-sampled.

The entry is programmed via `swssconfig` (a static `FDB_TABLE` entry in Vlan`<id>`) at session
setup and removed at teardown.

### 6.4 Dataplane collection methodology

Mirrored GRE packets are captured on the collector (gre_egress) port and identified by a 3-tuple
match on the outer headers - `outer IP.src == session.src_ip`, `outer IP.dst == session.dst_ip`,
and `GRE.proto == session.gre_type`. This three-tuple uniquely identifies frames from the session
under test and is robust against ASIC-specific ERSPAN encapsulation differences (e.g. extra
ERSPAN II/III header bytes between GRE and the inner frame).

Sampling tests send `NUM_SAMPLES * N` packets (where `NUM_SAMPLES = 10000` and `N = sample_rate`) so
the expected mirrored count is `~NUM_SAMPLES = 10000` regardless of `N` (e.g. 1,000,000 packets at
`1:100` and 2,560,000 packets at `1:256`), and assert the observed count is within `[9500, 10500]`
(`NUM_SAMPLES ± 5%`, via `MIN_EXPECTED_SAMPLES` / `MAX_EXPECTED_SAMPLES`).

## 7 Test cases

### 7.1 Capability discovery

Reads `STATE_DB SWITCH_CAPABILITY|switch` and checks each advertised mirror capability key.

| Test case | Objective | Parametrization | Pass criteria |
|-----------|-----------|-----------------|---------------|
| `test_switch_capability_reported_boolean` | Verify STATE_DB advertises each mirror capability key defined in the HLD with a valid boolean value. | Keys: `PORT_INGRESS_MIRROR_CAPABLE`, `PORT_EGRESS_MIRROR_CAPABLE`, `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE`, `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE`, `SAMPLEPACKET_TRUNCATION_CAPABLE`. | Each capability key exists with a valid boolean value (`true`/`false`). |

### 7.2 Configuration and CLI validation

All cases run `config mirror_session erspan add ... <src_port> <direction> [--sample_rate N] [--truncate_size B]`
and then inspect `CONFIG_DB MIRROR_SESSION|<name>`.

| Test case | Objective | Parametrization | Pass criteria |
|-----------|-----------|-----------------|---------------|
| `test_create_erspan_session_config_fields` | Valid `sample_rate` and/or `truncate_size` are accepted and written to CONFIG_DB together with an explicit direction. | `create_kwargs`: `sample_rate` only / `truncate_size` only / both; each x direction `rx`/`tx`/`both`. A direction is skipped when the matching per-direction capability is absent; `truncate_size` cases are skipped when truncation is unsupported. | CLI exits 0; each configured field plus `direction` is present in CONFIG_DB with the expected value. |
| `test_remove_erspan_session_with_sampling` | Session removal cleans up a sampling-enabled session completely. | direction `rx`/`tx`/`both`; created with `--sample_rate 256`. | `MIRROR_SESSION\|<name>` no longer exists in CONFIG_DB (redis `exists` == 0). |
| `test_invalid_sample_rate_rejected` | Out-of-range `sample_rate` is rejected at the CLI layer. | `1` (below the valid minimum). | CLI exits non-zero; no entry written to CONFIG_DB. |
| `test_invalid_truncate_size_rejected` | Out-of-range `truncate_size` is rejected at the CLI layer. | `32`, `63`, `9217`. | CLI exits non-zero; no entry written to CONFIG_DB. |
| `test_sample_rate_zero_disables_sampling` | `--sample_rate 0` is accepted and semantically equivalent to omitting the flag (no sampling). | - | CLI exits 0; `sample_rate` is not written to CONFIG_DB (redis hget returns empty). |
| `test_truncate_size_zero_disables_truncation` | `--truncate_size 0` is accepted and semantically equivalent to omitting the flag. | - | CLI exits 0; `truncate_size` is not written to CONFIG_DB. |
| `test_erspan_sampling_config_high_rate` | A high sample rate (`1:50000`) is accepted and stored. Config-only - dataplane verification at this rate would need millions of packets. | `1:50000` | CLI exits 0; CONFIG_DB `sample_rate` field equals `50000`. |

### 7.3 Show CLI

All cases create a session, run `show mirror_session`, and inspect the session's row.

| Test case | Objective | Parametrization | Pass criteria |
|-----------|-----------|-----------------|---------------|
| `test_show_mirror_session_displays_new_columns` | `show mirror_session` displays the configured sampling and truncation values. Requires both sampling and truncation support (skipped otherwise). | direction `rx`/`tx`/`both`; session created with `--sample_rate 512 --truncate_size 128`. | Exactly one row exists for the session, and its fields list `512` and `128` as whole tokens. |

### 7.4 Dataplane validation

These tests validate sampled and/or truncated mirroring end-to-end on the dataplane; each subsection
maps to exactly one test function. Traffic is generated per mirror direction:
- **RX (ingress):** inject on the source port.
- **TX (egress):** inject unicast frames addressed to `PROBE_UNICAST_DST_MAC` on the `tx_ingress`
  peer port so the DUT forwards them out the source port (egress), triggering the egress mirror.
- **BOTH:** run the RX leg and the TX leg separately, asserting each leg independently.

ERSPAN GRE packets are collected on the collector port using the 3-tuple match. Unless noted, the
observed mirror count must fall within `[9500, 10500]` (`NUM_SAMPLES ± 5%`), and any truncated frame
length is checked within `MIRROR_LEN_TOLERANCE` of `(~62B encap overhead + min(pktlen, truncate_size))`.

#### 7.4.1 Validate ERSPAN truncation across packet sizes
**Test:** `test_erspan_truncation_packet_size`

**Objective:** By sweeping multiple `truncate_size` x packet-length combinations with no `sample_rate`
(so mirroring is 1:1 and every probe packet is mirrored), verify that each mirrored frame is truncated
to the configured budget while frames smaller than the budget pass through untouched. The 1:1 ratio
makes the per-packet length check deterministic.

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

#### 7.4.2 Validate RX sampled mirroring rates
**Test:** `test_erspan_sampling_rx_direction`

**Objective:** By replaying `NUM_SAMPLES * N` packets through the ingress pipeline at rates `1:100`
and `1:256`, verify that RX (ingress) sampling mirrors approximately 1 of every N packets,
landing the observed count in `[9500, 10500]`.

**Steps:**
- Configure `sample_rate=N` (direction defaults to rx).
- Send `NUM_SAMPLES * N` packets on the source port.
- Collect GRE-encapsulated packets on the collector port using the 3-tuple match.

**Pass criteria:** Observed mirror count is within `[9500, 10500]` (`NUM_SAMPLES ± 5%`).

#### 7.4.3 Validate RX sampled mirroring with truncation
**Test:** `test_erspan_sampling_rx_with_truncation`

**Objective:** By running RX (ingress) sampling with truncation, verify that both features
take effect simultaneously: the session samples approximately 1 of every N packets while each
mirrored copy is truncated to the configured size.

**Steps:** Configure `sample_rate=256` + `truncate_size=128`; send `NUM_SAMPLES * 256` large
(1500B) packets on the source port.

**Pass criteria:** Observed mirror count within `[9500, 10500]` AND each captured mirror is truncated
to `~62B encap overhead + 128`.

#### 7.4.4 Validate TX sampled mirroring rates
**Test:** `test_erspan_sampling_tx_direction`

**Objective:** By injecting unicast on the `tx_ingress` peer port so the DUT forwards frames out the
source port (egress), verify that TX (egress) sampling mirrors approximately 1 of every N packets at
rates `1:100` and `1:256`.

**Steps:**
- Create an ERSPAN session with `sample_rate=N`, `direction=tx`.
- Inject `NUM_SAMPLES * N` unicast frames (dst = `PROBE_UNICAST_DST_MAC`) on the `tx_ingress` peer
  port; the DUT forwards them out the source port (egress), triggering the egress mirror.
- Collect ERSPAN GRE packets on the collector port.

**Pass criteria:** Observed mirror count within `[9500, 10500]` (`NUM_SAMPLES ± 5%`).

#### 7.4.5 Validate TX sampled mirroring with truncation
**Test:** `test_erspan_sampling_tx_with_truncation`

**Objective:** By combining TX (egress) sampling with truncation, verify that egress-mirrored copies
are both sampled approximately 1 of every N packets and truncated to the configured size.

**Steps:** Configure `sample_rate=256`, `truncate_size=128`, `direction=tx`; inject `NUM_SAMPLES * 256`
large (1500B) unicast frames on the `tx_ingress` peer port.

**Pass criteria:** Observed mirror count within `[9500, 10500]` AND each mirrored frame is truncated to
`~62B encap overhead + 128`.

#### 7.4.6 Validate BOTH-direction sampled mirroring rates
**Test:** `test_erspan_sampling_both_direction`

**Objective:** By injecting on the source port (RX leg) and injecting unicast on the `tx_ingress`
peer port so the DUT forwards frames out the source port (TX leg), verify that `direction=both`
samples both ingress- and egress-triggered traffic, each leg mirroring approximately 1 of every N
packets at rates `1:100` and `1:256`.

**Steps:**
- Create an ERSPAN session with `sample_rate=N`, `direction=both`.
- RX leg: inject `NUM_SAMPLES * N` unicast frames on the source port;
  they are ingress-sampled then same-port dropped (ingress mirror).
- TX leg: inject `NUM_SAMPLES * N` unicast frames on the `tx_ingress` peer port;
  the DUT forwards them out the source port (egress mirror).
- Collect ERSPAN GRE packets on the collector port for each leg.

**Pass criteria:** Each leg's observed mirror count is within `[9500, 10500]` (`NUM_SAMPLES ± 5%`),
proving both the ingress and egress bindings are active.

#### 7.4.7 Validate BOTH-direction sampled mirroring with truncation
**Test:** `test_erspan_sampling_both_with_truncation`

**Objective:** By running both legs under `direction=both` with truncation enabled, verify that the
ingress- and egress-mirrored copies are each sampled approximately 1 of every N packets and truncated
to the configured size.

**Steps:** Configure `sample_rate=256`, `truncate_size=128`, `direction=both`; run the RX leg
(inject on the source port) and TX leg (inject on the `tx_ingress` peer port) with large (1500B)
unicast frames addressed to `PROBE_UNICAST_DST_MAC`.

**Pass criteria:** Each leg's observed mirror count is within `[9500, 10500]` AND every mirrored frame
on each leg is truncated to `~62B encap overhead + 128`.

### 7.5 Session lifecycle

#### 7.5.1 Validate mirroring stops after ERSPAN session removal
**Test:** `test_erspan_session_remove_stops_mirroring`

**Objective:** By removing an active sampled session and then sending sustained traffic on the source
port, verify that mirroring stops immediately and no further ERSPAN copies reach the collector.

**Steps:**
- Create a session with `sample_rate=256` and wait for it to become active.
- Remove the session.
- Send 1000 100B broadcast packets on the source port and verify no mirror copies arrive.

**Pass criteria:** After removal, the collector receives zero GRE-encapsulated packets within the
timeout window.

### 7.6 Backward compatibility

Backward compatibility (a session with neither `sample_rate` nor `truncate_size` behaves as a
classic full-mirror ERSPAN session) is exercised indirectly:
- `test_sample_rate_zero_disables_sampling` and `test_truncate_size_zero_disables_truncation`
  confirm the `0` / omitted cases leave the fields out of CONFIG_DB.
- The `pktlen < truncate_size` and `pktlen == truncate_size` cases of
  `test_erspan_truncation_packet_size` confirm full (untruncated) frames are mirrored when the
  packet does not exceed the budget.
