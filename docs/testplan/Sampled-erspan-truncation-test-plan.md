# Sampled ERSPAN with truncation test plan

## Rev 0.3

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
| 0.3 |  11/18/2026 |                         | Per-port ERSPAN sampling and truncation                 |

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
- Requires `sample_rate >= 2` on each binding; omitting `truncate_size` disables truncation. Zero is invalid for both fields.
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
- `erspan_gre_metadata_len` - skips dataplane tests on non-Mellanox ASICs.

## 6 Setup configuration

### 6.1 Port selection and roles

CLI/configuration tests select one front-panel physical port, including VLAN members,
without requiring routed peers or reachability checks. Dataplane tests use the three paths below.

Ports are selected from active routed interfaces using their existing peer next hops
and actual DUT-to-PTF mappings. LAG members are grouped as one logical path.
- **source** - the mirror source port; the session is bound to it and its traffic is mirrored.
- **gre_egress** - the collector-facing egress port for ERSPAN copies captured by PTF.
- **tx_ingress** - the peer port used by TX/BOTH tests to inject traffic that leaves the
  mirrored source port.

For a collector LAG, packets are collected from all mapped member ports.
Single-member sources are preferred. Multi-member sources are allowed for RX and
sampled truncation tests; TX/BOTH dataplane tests require a single-member source.

### 6.2 Setup of DUT switch

Each test uses fixtures (defined in `conftest.py`):
- `erspan_capabilities` - reads STATE_DB SWITCH_CAPABILITY once per module.
- `setup_erspan_route` - installs a static route so the ERSPAN destination IP egresses on a
  PTF-connected path using its existing peer next hop.
- `erspan_session` - creates the export and a source binding. Wait for STATE_DB status=active, the selected
  collector path and the per-direction source attachment. Teardown removes bindings before the export.

Existing interface addresses and peer neighbors are reused, and BGP remains enabled.
Teardown removes test-created routes and sessions while preserving matching pre-existing routes.

On setup, sessions are created via:
```
sudo config mirror_session erspan add <name> <src_ip> <dst_ip> <dscp> <ttl> [gre_type] [queue]
sudo config mirror_session sample add <name> <src_port> <rx|tx|both> \
     --sample_rate <N> [--truncate_size <bytes>]
```

On teardown:
```
sudo config mirror_session sample remove <name> <src_port> <rx|tx|both>
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
the sent probe. Inner parsing supports the Mellanox GRE `0x8949` layout with a
22-byte metadata prefix.

Sampling tests send `NUM_SAMPLES * N` packets (where `NUM_SAMPLES = 10000` and `N = sample_rate`) so
the expected mirrored count is `~NUM_SAMPLES = 10000` regardless of `N` (e.g. 1,000,000 packets at
`1:100` and 2,560,000 packets at `1:256`), and assert the observed count is within `[9500, 10500]`
(`NUM_SAMPLES * (1 ± SAMPLE_COUNT_TOLERANCE)`, currently ±5%).
Sampling-with-truncation tests validate each matching mirror's length; section 7.4.1 also covers shorter probes.

## 7 Test cases

The test names below are in [test_erspan_sampling_truncation.py](../../tests/span/test_erspan_sampling_truncation.py).

### 7.1 Capability discovery

Reads `STATE_DB SWITCH_CAPABILITY|switch` and checks each advertised mirror capability key.

| Test case | Objective | Parametrization | Pass criteria |
|-----------|-----------|-----------------|---------------|
| `test_switch_capability_reported_boolean` | Verify STATE_DB advertises each mirror capability key defined in the HLD with a valid boolean value. | Keys: `PORT_INGRESS_MIRROR_CAPABLE`, `PORT_EGRESS_MIRROR_CAPABLE`, `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE`, `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE`, `SAMPLEPACKET_TRUNCATION_CAPABLE`. | Each capability key exists with a valid boolean value (`true`/`false`). |

### 7.2 Configuration and CLI validation

Create the destination-only export with `erspan add`, then configure or remove the binding with `sample add/remove`.
Inspect `MIRROR_SESSION|<name>` for export attributes and `PORT_MIRROR_SAMPLE|<port>|<rx-or-tx>` for the sampling policy.

| Test case | Objective | Parametrization | Pass criteria |
|-----------|-----------|-----------------|---------------|
| `test_create_erspan_session_config_fields` | Verify the binding owns the sampling policy. | Rate 50000 with/without truncation 128; `rx`/`tx`/`both`. | Each binding references the export and stores the expected policy and `admin_state=up`. `both` creates `rx` and `tx` keys. Source, direction and policy fields are absent from the export. |
| `test_remove_erspan_session_with_sampling` | Remove the binding and export separately. | Direction `rx`/`tx`/`both`; `--sample_rate 256`. | Binding keys disappear after `sample remove`; the export remains until `mirror_session remove`. |
| `test_invalid_sample_rate_rejected` | Reject a missing or invalid rate even when truncation is requested. | Missing, `0`, `1`; `--truncate_size 128`. | CLI exits non-zero with a rate error; no binding is written. |
| `test_invalid_truncate_size_rejected` | Out-of-range `truncate_size` is rejected at the CLI layer. | `0`, `32`, `63`, `9217`; `--sample_rate 2`. | CLI exits non-zero with a size error; no binding is written. |
| `test_erspan_sampling_config_high_rate` | A high sample rate (`1:50000`) is accepted and stored. Config-only - dataplane verification at this rate would need millions of packets. | `1:50000` | CLI exits 0; CONFIG_DB `sample_rate` field equals `50000`. |

### 7.3 Show CLI

Create a binding, run `show mirror_session sample`, and inspect its row(s).

| Test case | Objective | Parametrization | Pass criteria |
|-----------|-----------|-----------------|---------------|
| `test_show_mirror_session_displays_new_columns` | `show mirror_session sample` displays each binding's sampling and truncation values. | Direction `rx`/`tx`/`both`; `--sample_rate 512 --truncate_size 128`. | One row per source/direction for the export; each shows `up`, `512`, and `128` in the corresponding columns. |

### 7.4 Dataplane validation

The following cases use the traffic paths in section 6.3 and collection rules in section 6.4.
Length checks apply to each matching mirror frame, using `MIRROR_LEN_TOLERANCE` around
`ENCAP_OVERHEAD + min(pktlen, truncate_size)` (currently estimated 62B overhead, ±8B tolerance).

#### 7.4.1 Validate ERSPAN truncation across packet sizes
**Test:** `test_erspan_truncation_packet_size`

**Objective:** Verify truncation below, at and above the configured size limit, with 1:2 sampling.

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
- Add an RX binding with `--sample_rate 2 --truncate_size <truncate_size>`.
- Send `NUM_SAMPLES * 2` (20,000) packets of length `pktlen` from the source port.
- Capture ERSPAN GRE packets on the collector port.

**Pass criteria:** 9,500–10,500 matching mirrors are received for 20,000 probes, and each mirrored
frame length is within `MIRROR_LEN_TOLERANCE` of `(~62B encap overhead + min(pktlen, truncate_size))`.

#### 7.4.2 Validate RX sampled mirroring rates
**Test:** `test_erspan_sampling_rx_direction`

**Objective:** By replaying `NUM_SAMPLES * N` packets through the ingress pipeline at rates `1:100`
and `1:256`, verify that RX (ingress) sampling mirrors approximately 1 of every N packets,
landing the observed count in `[9500, 10500]`.

**Steps:**
- Add an `rx` binding with `sample_rate=N`.
- Send `NUM_SAMPLES * N` packets on the source port.
- Collect matching test mirrors on the collector port.

**Pass criteria:** Observed mirror count is within `[9500, 10500]` (`NUM_SAMPLES ± 5%`).

#### 7.4.3 Validate RX sampled mirroring with truncation
**Test:** `test_erspan_sampling_rx_with_truncation`

**Objective:** By running RX (ingress) sampling with truncation, verify that both features
take effect simultaneously: the binding samples approximately 1 of every N packets while each
mirrored copy is truncated to the configured size.

**Steps:** Configure `sample_rate=256` + `truncate_size=128`; send `NUM_SAMPLES * 256` large
(1500B) packets on the source port.

**Pass criteria:** Mirror count within `[9500, 10500]` and every frame passes the length check
in section 7.4 with `truncate_size=128`.

#### 7.4.4 Validate TX sampled mirroring rates
**Test:** `test_erspan_sampling_tx_direction`

**Objective:** Verify TX sampling at rates `1:100` and `1:256`.

**Steps:**
- Add a source binding with `sample_rate=N`, `direction=tx`.
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
- Add source bindings with `sample_rate=N`, `direction=both`.
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
port, verify that no further ERSPAN copies reach the collector once the source attachment is cleared.

**Steps:**
- Create the export and an RX binding with `sample_rate=256`; wait for both to become active.
- Remove the binding, then the export, and wait for the source attachment to clear.
- Send 1,000 100-byte test packets from PTF into the mirror source port.
  Verify that the collector receives no matching mirror packets.

**Pass criteria:** After removal, the collector receives zero matching test mirrors within the
3-second collection window.

### 7.6 Backward compatibility

Classic unsampled ERSPAN uses a source on the session itself. For sampled bindings:
- `test_create_erspan_session_config_fields` confirms that omitting `truncate_size` leaves the field out of CONFIG_DB.
- The `pktlen < truncate_size` and `pktlen == truncate_size` cases of
  `test_erspan_truncation_packet_size` confirm sampled frames are not shortened when the packet does not exceed the budget.
