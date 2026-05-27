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
  - [Backward compatibility](#backward-compatibility)
  - [Session lifecycle](#session-lifecycle)

## Revision

| Rev |     Date    |       Author            |     Change Description      |
|:---:|:-----------:|:------------------------|:----------------------------|
| 0.1 |  05/21/2026 | Janet Cui               |       Initial version       |

## Definition/Abbrevation

| **Term**       | **Meaning**                                              |
|----------------|----------------------------------------------------------|
| ERSPAN         | Encapsulated Remote SPAN (GRE-encapsulated mirroring)    |
| Mirror session | A configured port-mirror instance in CONFIG_DB           |
| Source port    | Port whose ingress/egress traffic is being mirrored      |
| Collector      | Remote endpoint that receives the GRE-encapsulated copy  |
| Sample rate    | 1:N ratio; only one of every N packets is mirrored       |
| Truncate size  | Maximum byte length of the mirrored packet               |
| Capability     | Per-ASIC support advertised via STATE_DB SWITCH_CAPABILITY|

## Overview

The purpose is to test the new sampled ERSPAN with truncation feature on a SONiC switch DUT.
Two new optional parameters were added to the ERSPAN mirror session: **sample_rate** (1:N sampling)
and **truncate_size** (per-packet byte truncation). This test plan validates capability discovery,
CLI/CONFIG_DB plumbing, and end-to-end dataplane behavior.

Reference HLDs / PRs:
- HLD: sonic-net/SONiC#2296
- YANG model: sonic-net/sonic-buildimage#26756
- CLI: sonic-net/sonic-utilities#4459
- SwitchOrch / MirrorOrch: sonic-net/sonic-swss#4502

## Scope

The test targets a running SONiC system with a fully functioning configuration. It verifies
that the DUT correctly:
- Advertises sampling and truncation capabilities via STATE_DB.
- Accepts valid sample_rate / truncate_size values via CLI and writes them to CONFIG_DB.
- Rejects out-of-range and invalid combinations of values.
- Mirrors only 1 of every N packets when sampling is configured.
- Truncates each mirrored packet to the configured byte budget.
- Preserves backward compatibility when neither parameter is configured.

The test does **not** cover SPAN (local) mirroring; that is covered by the existing
`Port-mirroring-test-plan.md` and `test_port_mirroring.py`.

## Testbed

Supported topologies: `t0`.

The DUT must have at least one routable path to the configured ERSPAN destination IP so that the
GRE-encapsulated mirror packet egresses on a port connected to PTF (the collector).

Capability gating:
- Tests in the **Dataplane: sampling** section auto-skip if STATE_DB does not report
  `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE = true` (or `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE = true`
  for egress sampling).
- Tests in the **Dataplane: truncation** section auto-skip if STATE_DB does not report
  `SAMPLEPACKET_TRUNCATION_CAPABLE = true`.

## Setup configuration

No persistent pre-configuration is required. Each test (or fixture) creates an ERSPAN session
with the specific parameters under test and cleans it up on teardown.

### Setup of DUT switch

Each test uses fixtures (defined in `conftest.py`):
- `erspan_capabilities` - reads STATE_DB SWITCH_CAPABILITY once per module.
- `setup_erspan_route` - installs a static route so the ERSPAN destination IP egresses on a
  PTF-connected port.
- `erspan_session` - creates the mirror session with parameters supplied by the test, yields,
  then removes the session.

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

## Test cases

### Capability discovery

#### Test case test_sampling_capability_reported
**Objective:** Verify the DUT advertises whether the ASIC supports mirror sampling.

**Steps:**
- Read `STATE_DB SWITCH_CAPABILITY|switch`.
- Assert keys `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE` and `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE`
  are present with boolean values.

**Pass criteria:** Capability key exists and value is `true` or `false`.

#### Test case test_truncation_capability_reported
**Objective:** Verify the DUT advertises whether the ASIC supports mirror truncation.

**Steps:**
- Read `STATE_DB SWITCH_CAPABILITY|switch`.
- Assert key `SAMPLEPACKET_TRUNCATION_CAPABLE` is present with a boolean value.

**Pass criteria:** Capability key exists and value is `true` or `false`.

#### Test case test_all_capabilities_reported
**Objective:** Sanity check that all mirror-related capability keys are present together.

**Pass criteria:** Both capability keys above are reported in the same query.

### Configuration and CLI validation

#### Test case test_create_erspan_session_with_sample_rate
**Objective:** Valid `sample_rate` is accepted and written to CONFIG_DB.

**Steps:**
- Run `config mirror_session erspan add ... --sample_rate 256`.
- Read `CONFIG_DB MIRROR_SESSION|<name>`.

**Pass criteria:** CLI exits 0; CONFIG_DB field `sample_rate` equals `"256"`.

#### Test case test_create_erspan_session_with_truncate_size
**Objective:** Valid `truncate_size` is accepted and written to CONFIG_DB.

**Pass criteria:** CLI exits 0; CONFIG_DB field `truncate_size` equals the configured value.

#### Test case test_create_erspan_session_with_both
**Objective:** Both parameters can be configured together on the same session.

**Pass criteria:** Both fields present in CONFIG_DB with the correct values.

#### Test case test_remove_erspan_session_with_sampling
**Objective:** Session removal cleans up sampling-enabled sessions completely.

**Pass criteria:** CONFIG_DB entry is deleted; no leftover sampling state.

#### Test case test_invalid_sample_rate_rejected
**Objective:** Out-of-range `sample_rate` values are rejected at the CLI layer.

**Parametrized values:** `-1`, `1`, `255`, `8388609`, `"abc"`.

**Pass criteria:** CLI exits non-zero; error message mentions
`"must be 0 or in range 256..8388608"`; no entry is written to CONFIG_DB.

#### Test case test_invalid_truncate_size_rejected
**Objective:** Out-of-range `truncate_size` values are rejected at the CLI layer.

**Parametrized values:** `-1`, `1`, `63`, `9217`, `"abc"`.

**Pass criteria:** CLI exits non-zero; error message mentions
`"must be 0 or in range 64..9216"`; no entry written to CONFIG_DB.

#### Test case test_truncate_without_sample_rate_rejected
**Objective:** Per HLD, `truncate_size` may not be configured without `sample_rate`.

**Pass criteria:** CLI exits non-zero with a clear error message; no entry written.

#### Test case test_sampling_non_rx_direction_rejected
**Objective:** Sampling is only valid for direction `rx` (ingress).

**Steps:** Attempt to create a session with `--sample_rate 256` together with direction `tx`
and direction `both`.

**Pass criteria:** CLI exits non-zero; no entry written to CONFIG_DB.

### Show CLI

#### Test case test_show_mirror_session_displays_new_columns
**Objective:** `show mirror_session` displays the new `Sample Rate` and `Truncate Size`
columns and renders the configured values correctly.

**Steps:**
- Create a session with both parameters.
- Run `show mirror_session`.

**Pass criteria:** Output contains the columns `Sample Rate` and `Truncate Size`; values match
what was configured.

### Dataplane: truncation

#### Test case test_erspan_truncation_large_packet
**Objective:** Packets larger than `truncate_size` are truncated to the configured length.

**Steps:**
- Configure `truncate_size=128` (sample_rate must also be set per HLD).
- Send a 1500-byte ICMP packet on the source port.
- Capture the GRE-encapsulated mirror copy on the collector port.

**Pass criteria:** The mirrored packet length equals `truncate_size` (accounting for the outer
Eth + IP + GRE + ERSPAN header).

#### Test case test_erspan_truncation_small_packet
**Objective:** Packets smaller than `truncate_size` are mirrored intact (no padding).

**Steps:** Send a 100-byte packet with `truncate_size=256`.

**Pass criteria:** Inner mirrored packet length equals the original 100 bytes.

#### Test case test_erspan_truncation_exact_size
**Objective:** Packets exactly equal to `truncate_size` are mirrored intact.

**Pass criteria:** Inner mirrored packet length equals `truncate_size`.

#### Test case test_erspan_no_truncation_without_config
**Objective:** When `truncate_size` is not configured, full packets are mirrored.

**Pass criteria:** Inner mirrored packet length equals the original packet length, regardless
of size.

### Dataplane: sampling

#### Test case test_erspan_sampling_dataplane
**Objective:** With `sample_rate=N`, approximately 1/N of packets are mirrored.

**Steps:**
- Configure `sample_rate=256`.
- Send 10000 ICMP packets on the source port.
- Count GRE-encapsulated packets received on the collector port.

**Pass criteria:** Observed mirror count is within a statistical tolerance (e.g. +/-50%) of the
expected count `10000/256`.

#### Test case test_erspan_sampling_config_high_rate
**Objective:** The maximum supported sample rate (`8388608`) is accepted and the dataplane
operates without errors.

**Pass criteria:** Session is created successfully; no orchagent / syncd errors observed.

#### Test case test_erspan_no_sampling_without_config
**Objective:** When `sample_rate` is not configured, every packet is mirrored (no sampling).

**Steps:** Send 100 packets without sample_rate configured.

**Pass criteria:** All 100 packets observed on the collector (no loss attributable to sampling).

### Dataplane: combined sampling and truncation

#### Test case test_erspan_sampling_with_truncation
**Objective:** Sampling and truncation can be active simultaneously and independently.

**Steps:** Configure `sample_rate=256` + `truncate_size=128`; send 10000 large packets.

**Pass criteria:** Observed mirror count is approximately 10000/256 AND each captured mirror
is truncated to 128 bytes.

### Backward compatibility

The dataplane tests `test_erspan_no_truncation_without_config` and
`test_erspan_no_sampling_without_config` above also serve as backward-compatibility checks:
when neither new parameter is configured, the session behaves as a classic full-mirror ERSPAN
session.

### Session lifecycle

#### Test case test_erspan_session_remove_stops_mirroring
**Objective:** Removing the mirror session immediately stops mirroring.

**Steps:**
- Create a session, send packets, verify mirror copies arrive.
- Remove the session.
- Send packets, verify no mirror copies arrive.

**Pass criteria:** After removal, the collector receives zero GRE-encapsulated packets within
the timeout window.
