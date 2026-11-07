# Sampled ERSPAN with truncation test plan

## Rev 0.2

**Table of Contents**

- [1 Revision](#1-revision)
- [2 Definition/Abbreviation](#2-definitionabbreviation)
- [3 Overview](#3-overview)
- [4 Scope](#4-scope)
- [5 Testbed](#5-testbed)
- [6 Setup configuration](#6-setup-configuration)
  - [6.1 Port selection and roles](#61-port-selection-and-roles)
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
| 0.2 |  10/24/2026 | Janet Cui               | Unified routed testing across topologies                 |

## 2 Definition/Abbreviation

| **Term**       | **Meaning**                                              |
|----------------|----------------------------------------------------------|
| ERSPAN         | Encapsulated Remote SPAN (GRE-encapsulated mirroring)    |

## 3 Overview

The purpose is to test the new sampled ERSPAN with truncation feature on a SONiC switch DUT.
This plan validates ERSPAN **sample_rate** (1:N sampling) and **truncate_size**
(per-packet truncation) in RX, TX and BOTH directions on T0 and T1.

## 4 Scope

The test targets a running SONiC with a fully functioning configuration. It verifies that the DUT correctly:
- Advertises sampling and truncation capabilities via STATE_DB.
- Accepts valid sample_rate / truncate_size values via CLI and writes them to CONFIG_DB.
- Rejects out-of-range and invalid values.
- Treats sample_rate=0 / truncate_size=0 as "feature disabled" (field omitted from CONFIG_DB).
- Mirrors approximately 1 of every N packets when sampling is configured, in the rx, tx, and both directions.
- Truncates each mirrored packet to the configured byte budget, including combined with sampling.

## 5 Testbed

The DUT must have at least one routable path to the configured ERSPAN destination IP so that the
GRE-encapsulated mirror packet egresses on a port connected to PTF (the collector).

Capability gating (skips are implemented as fixtures in `conftest.py`):
- `skip_if_ingress_sampling_unsupported` - skips if STATE_DB does not report
  `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE = true`.
- `skip_if_egress_sampling_unsupported` - skips if STATE_DB does not report
  `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE = true`.
- `sampling_direction` - skips CLI/config cases when the requested direction is unsupported;
  `both` requires ingress and egress sampling capabilities.
- `skip_if_truncation_unsupported` - skips if STATE_DB does not report
  `SAMPLEPACKET_TRUNCATION_CAPABLE = true`.

## 6 Setup configuration

### 6.1 Port selection and roles

Ports are selected from active routed interfaces using their existing peer next hops
and actual DUT-to-PTF mappings. LAG members are grouped as one logical path.
- **source** - the mirror source port; the session is bound to it and its traffic is mirrored.
- **gre_egress** - the collector-facing egress port for ERSPAN copies captured by PTF.
- **tx_ingress** - the peer port used by TX/BOTH tests to inject traffic that leaves the
  mirrored source port.

For a collector LAG, packets are collected from all mapped member ports.

### 6.2 Setup of DUT switch

Each test uses fixtures (defined in `conftest.py`):
- `erspan_capabilities` - reads STATE_DB SWITCH_CAPABILITY once per module.
- `setup_erspan_route` - installs a static route so the ERSPAN destination IP egresses on a
  PTF-connected path using its existing peer next hop.
- `erspan_session` - creates the mirror session with parameters (sample_rate, truncate_size,
  direction), waits for STATE_DB status=active and the selected collector path, then
  removes the session.

Existing interface addresses and peer neighbors are reused, and BGP remains enabled.
Teardown removes test-created routes and sessions while preserving matching pre-existing routes.

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

All topologies use the ingress router MAC and a dedicated probe destination IP:
- **RX:** inject on the source port. A blackhole route discards the original probe while
  ingress mirror copies use the separate collector route.
- **TX:** inject on the peer port. A test route forwards the original probe out the mirrored
  source port toward PTF.

**BOTH** exercises the RX and TX paths separately. Probes use TTL 2 and ERSPAN copies
use TTL 1 to prevent peer routers from forwarding packets back into the test.

### 6.4 Dataplane collection methodology

Mirrored GRE packets are captured on the collector (gre_egress) port and identified by a 3-tuple
match on the outer headers - `outer IP.src == session.src_ip`, `outer IP.dst == session.dst_ip`,
and `GRE.proto == session.gre_type`. Inner IP addresses and TCP ports must also match
the sent probe. The current inner parser supports the GRE `0x8949` layout with a
22-byte metadata prefix; other encapsulation layouts require a compatible decoder.

Sampling tests send `NUM_SAMPLES * N` packets (where `NUM_SAMPLES = 10000` and `N = sample_rate`) so
the expected mirrored count is `~NUM_SAMPLES = 10000` regardless of `N` (e.g. 1,000,000 packets at
`1:100` and 2,560,000 packets at `1:256`), and assert the observed count is within `[9500, 10500]`
(`NUM_SAMPLES * (1 ± SAMPLE_COUNT_TOLERANCE)`, currently ±5%).
Sampling-with-truncation tests send 1500B probes and validate each matching mirror's length.

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

The following cases use the traffic paths in section 6.3 and collection rules in section 6.4.
Length checks apply to each matching mirror frame, using `MIRROR_LEN_TOLERANCE` around
`ENCAP_OVERHEAD + min(pktlen, truncate_size)` (currently estimated 62B overhead, ±8B tolerance).

#### 7.4.1 Validate ERSPAN truncation across packet sizes
**Test:** `test_erspan_truncation_packet_size`

**Objective:** Verify truncation below, at and above the configured size limit, with 1:1 mirroring.

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

**Pass criteria:** At least one matching test mirror is received, and each mirrored
frame length is within `MIRROR_LEN_TOLERANCE` of `(~62B encap overhead + min(pktlen, truncate_size))`.
The sent and collected counts are logged for diagnosis; this case validates truncation,
not lossless 1:1 mirror delivery. Sampling-rate cases retain their count-range assertions.

#### 7.4.2 Validate RX sampled mirroring rates
**Test:** `test_erspan_sampling_rx_direction`

**Objective:** By replaying `NUM_SAMPLES * N` packets through the ingress pipeline at rates `1:100`
and `1:256`, verify that RX (ingress) sampling mirrors approximately 1 of every N packets,
landing the observed count in `[9500, 10500]`.

**Steps:**
- Configure `sample_rate=N` (direction defaults to rx).
- Send `NUM_SAMPLES * N` packets on the source port.
- Collect matching test mirrors on the collector port.

**Pass criteria:** Observed mirror count is within `[9500, 10500]` (`NUM_SAMPLES ± 5%`).

#### 7.4.3 Validate RX sampled mirroring with truncation
**Test:** `test_erspan_sampling_rx_with_truncation`

**Objective:** By running RX (ingress) sampling with truncation, verify that both features
take effect simultaneously: the session samples approximately 1 of every N packets while each
mirrored copy is truncated to the configured size.

**Steps:** Configure `sample_rate=256` + `truncate_size=128`; send `NUM_SAMPLES * 256` large
(1500B) packets on the source port.

**Pass criteria:** Mirror count within `[9500, 10500]` and every frame passes the length check
in section 7.4 with `truncate_size=128`.

#### 7.4.4 Validate TX sampled mirroring rates
**Test:** `test_erspan_sampling_tx_direction`

**Objective:** Verify TX sampling at rates `1:100` and `1:256`.

**Steps:**
- Create an ERSPAN session with `sample_rate=N`, `direction=tx`.
- Inject `NUM_SAMPLES * N` probes on the `tx_ingress` peer port.
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

**Objective:** Verify both mirror directions independently at rates `1:100` and `1:256`.

**Steps:**
- Create an ERSPAN session with `sample_rate=N`, `direction=both`.
- RX leg: inject `NUM_SAMPLES * N` probes on the source port.
- TX leg: inject `NUM_SAMPLES * N` probes on the `tx_ingress` peer port.
- Collect ERSPAN GRE packets on the collector port for each leg.

**Pass criteria:** Each leg's mirror count is within `[9500, 10500]`.

#### 7.4.7 Validate BOTH-direction sampled mirroring with truncation
**Test:** `test_erspan_sampling_both_with_truncation`

**Objective:** Verify sampling and truncation independently in both directions.

**Steps:** Configure `sample_rate=256`, `truncate_size=128`, `direction=both`; run the RX leg
(source port) and TX leg (peer port), each sending `NUM_SAMPLES * 256` 1500B probes.

**Pass criteria:** Each leg's mirror count is within `[9500, 10500]` and every frame passes
the length check in section 7.4 with `truncate_size=128`.

### 7.5 Session lifecycle

#### 7.5.1 Validate mirroring stops after ERSPAN session removal
**Test:** `test_erspan_session_remove_stops_mirroring`

**Objective:** By removing an active sampled session and then sending sustained traffic on the source
port, verify that mirroring stops immediately and no further ERSPAN copies reach the collector.

**Steps:**
- Create a session with `sample_rate=256` and wait for it to become active.
- Remove the session.
- Send 1,000 100-byte test packets from PTF into the mirror source port.
  Verify that the collector receives no matching mirror packets.

**Pass criteria:** After removal, the collector receives zero matching test mirrors within the
timeout window.

### 7.6 Backward compatibility

Backward compatibility (a session with neither `sample_rate` nor `truncate_size` behaves as a
classic full-mirror ERSPAN session) is exercised indirectly:
- `test_sample_rate_zero_disables_sampling` and `test_truncate_size_zero_disables_truncation`
  confirm the `0` / omitted cases leave the fields out of CONFIG_DB.
- The `pktlen < truncate_size` and `pktlen == truncate_size` cases of
  `test_erspan_truncation_packet_size` confirm full (untruncated) frames are mirrored when the
  packet does not exceed the budget.
