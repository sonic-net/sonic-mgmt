# Storm-Control Test Plan

- [Storm-Control Test Plan](#storm-control-test-plan)
  - [Related Documents](#related-documents)
  - [1. Overview](#1-overview)
    - [1.1 Scope](#11-scope)
    - [1.2 Testbed](#12-testbed)
  - [2. Requirements](#2-requirements)
    - [2.1 Functional Requirements](#21-functional-requirements)
    - [2.2 CLI](#22-cli)
    - [2.3 CONFIG_DB Schema](#23-config_db-schema)
  - [3. Test Setup](#3-test-setup)
    - [3.1 Topology](#31-topology)
    - [3.2 Fixtures](#32-fixtures)
    - [3.3 Common Helpers](#33-common-helpers)
  - [4. Test Cases](#4-test-cases)
    - [4.1 Configuration Tests](#41-configuration-tests)
    - [4.2 Functional / Traffic Tests](#42-functional--traffic-tests)
    - [4.3 Trigger / Reboot Tests](#43-trigger--reboot-tests)
    - [4.4 Negative Tests](#44-negative-tests)
    - [4.5 Persistence / Reload Tests](#45-persistence--reload-tests)
    - [4.6 Topology-Member Tests](#46-topology-member-tests)
    - [4.7 Scale Tests](#47-scale-tests)
  - [5. PTF Test Module](#5-ptf-test-module)

## Related Documents

| **Document** | **Link** |
|--------------|----------|
| SONiC storm-control HLD | [Storm-control HLD](https://github.com/sonic-net/SONiC/blob/master/doc/bum_storm_control/bum_storm_control_hld.md) |
| SAI Policer for BUM | [SAI Policer API](https://github.com/opencomputeproject/SAI/blob/master/inc/saipolicer.h) |

## 1. Overview

Storm control protects a SONiC switch from packet storms by rate-limiting **broadcast**, **unknown-unicast (UU)**, and **unknown-multicast (UM)** traffic (collectively, **BUM**) on a per-port basis. The DUT installs an ASIC-level policer per (port, BUM type) tuple with a kbps threshold; ingress BUM traffic exceeding the rate is policed so that only about the configured rate is accepted and flooded to the other VLAN members.

Enforcement is verified from the **forwarded rate**, measured on the DUT side from the egress flood-port `TX_OK` counter (the count of frames the switch actually transmitted out a peer VLAN member). The forwarded rate must settle at about the configured ceiling, within a fixed tolerance. The ingress `RX_DRP` counter is recorded for diagnostics only and never drives the verdict — if the drop counter is unreliable on a given platform the feature can still be confirmed working from the forwarded rate. The verdict is **not** based on the drop fraction: how much is dropped only depends on how far above the ceiling we send (send 3× the ceiling → ~67% dropped), whereas the forwarded rate must always settle near the ceiling.

This test plan validates:

- CLI add / delete / update behavior
- CONFIG_DB schema correctness
- ASIC policer enforcement of the configured rate
- Independence of policers across BUM types and across interfaces
- Resilience across triggers (interface flap, cold/warm/fast reboot, SWSS restart)
- Persistence across `config save` / `config reload`
- Behavior on PortChannel-member and VLAN-member ports
- Scale: configure storm-control on all front-panel ports
- Negative CLI parameter validation

### 1.1 Scope

In scope:

- L2 storm control on physical front-panel interfaces
- All three BUM traffic classes
- CLI, CONFIG_DB, and data-plane behavior


### 1.2 Testbed

| Item | Value |
|------|-------|
| Topology | `t0` |
| Minimum DUT front-panel ports | 2 (single-port cases skip if only 1 port is available) |
| Traffic generator | PTF host (scapy-based) |
| Marker | `pytest.mark.topology("t0")` |

## 2. Requirements

### 2.1 Functional Requirements

| ID | Requirement |
|----|-------------|
| R1 | Each (port, BUM-type, kbps) tuple must be programmable via `config interface storm-control add`. |
| R2 | The same tuple must be removable via `config interface storm-control del`. |
| R3 | A second `add` for an existing (port, BUM-type) tuple must overwrite the kbps value. |
| R4 | `show storm-control` must display all configured entries. |
| R5 | Traffic of the configured BUM class exceeding the kbps threshold must be policed so the *forwarded* rate (measured from an egress flood port's `TX_OK` counter) is capped at about the configured ceiling, within `RATE_TOLERANCE_PCT`. The ingress `RX_DRP` counter is logged for diagnostics only. |
| R6 | Policers for different BUM classes on the same port must operate independently. |
| R7 | Policers on different ports must operate independently. |
| R8 | After `del`, traffic must no longer be rate-limited. |
| R9 | Configuration must survive an interface admin shutdown/startup cycle. |
| R10 | Invalid kbps, missing kbps, invalid BUM type, and unsupported interface types must be rejected by the CLI. |
| R11 | Valid kbps range is 0 to 100,000,000. Values above 100,000,000 must be rejected. |

### 2.2 CLI

```bash
# Add
sudo config interface storm-control add <interface> <broadcast|unknown-unicast|unknown-multicast> <kbps>

# Delete
sudo config interface storm-control del <interface> <broadcast|unknown-unicast|unknown-multicast>

# Show
show storm-control
```

### 2.3 CONFIG_DB Schema

Storm-control entries are stored in the `PORT_STORM_CONTROL` table:

```
PORT_STORM_CONTROL|<interface>|<storm_type>
    kbps : <integer>
```

Example:

```bash
admin@dut:~$ sonic-db-cli CONFIG_DB hgetall "PORT_STORM_CONTROL|Ethernet0|broadcast"
{'kbps': '500'}
```

## 3. Test Setup

### 3.1 Topology

`t0` topology with at least one DUT front-panel port connected to the PTF dataplane. Two ports preferred — single-port cases auto-skip multi-port tests.

```
       +-------+        +-----+
       |  PTF  |--ptfN--| DUT |
       +-------+        +-----+
```

### 3.2 Fixtures

| Fixture | Scope | Purpose |
|---------|-------|---------|
| `ignore_expected_loganalyzer_exceptions` | function (autouse) | Suppress TACACS+ systemctl errors emitted while running `config` commands. |
| `enable_port_counters` | module (autouse) | Run `counterpoll port enable` and clear counters before any test in the module. |
| `storm_control_setup` | module | Resolve the ingress `test_intf` / `ptf_port_idx`, the same-VLAN egress flood ports (`egress_intfs` / `egress_ptf_indices`), an optional `second_intf` for multi-port tests, and the list of all front-panel ports. |

### 3.3 Common Helpers

| Helper | Purpose |
|--------|---------|
| `_add_storm_control` / `_del_storm_control` | Wrap the `config interface storm-control add/del` CLI. |
| `_assert_config_present` | Verify and log `show storm-control` output. |
| `_get_config_db_kbps` / `_config_db_entry_exists` | Read CONFIG_DB state directly via `sonic-db-cli`. |
| `_get_tx_ok` | Parse `show interfaces counters` and return `TX_OK` for an interface — the authoritative forwarded-frame count used for the verdict. |
| `_get_rx_drops` | Parse `show interfaces counters` and return `RX_DRP` for an interface — logged for diagnostics only. |
| `_log_intf_stats` | Log the full counter row before/after each burst. |
| `_clear_counters` | `sonic-clear counters` + wait one poll cycle. |
| `_require_egress` | Return the first same-VLAN egress flood interface name, or skip the functional test if none is available. |
| `_run_storm_traffic` | For each size in `PKT_LENS`: clear counters, invoke the PTF generator `storm_control_ptf_test.StormControlTest`, then verdict the forwarded rate from the egress `TX_OK` delta. |

Tunable constants:

| Constant | Default | Purpose |
|----------|---------|---------|
| `STORM_CTRL_THRESHOLD_KBPS` | `1000` | Policer ceiling programmed for functional tests. |
| `BURST_KBPS` | `3000` (3x threshold) | Paced send rate generated by PTF. |
| `BURST_PKT_COUNT` | `3000` | Packets per burst (per packet size). |
| `PKT_LENS` | `[512, 1518]` | Ethernet frame sizes exercised; every functional burst runs once per size. |
| `RATE_TOLERANCE_PCT` | `10` | Forwarded-rate tolerance: when policing is expected the forwarded rate may exceed the ceiling by up to this percent; when not expected, the forwarded count must be within this percent of everything sent. The default of 10% is derived from typical ASIC policer granularity (token-bucket replenishment intervals) and is conservative enough to accommodate software-based platforms (KVM/VS). Platform-specific overrides can be supplied via a pytest fixture or topology variable if a tighter or looser bound is required for a given ASIC family. |
| `PTF_LOG` | `/tmp/storm_control_ptf.log` | PTF generator log file collected per run. |
| `_CONFIG_SETTLE_SECS` | `1` | Wait for ASIC policer programming. |
| `_COUNTER_SETTLE_SECS` | `15` | Wait for counter DB flush (also applied after each burst before sampling `TX_OK`). |

## 4. Test Cases

### 4.1 Configuration Tests

#### TC 4.1.1 — Add storm-control updates CONFIG_DB (per BUM type)

| Field | Value |
|-------|-------|
| Function | `test_storm_control_config_db_entry_present` |
| Parametrized | `storm_type` in `{broadcast, unknown-unicast, unknown-multicast}` |
| Priority | P1 |

**Steps**
1. `config interface storm-control add <intf> <storm_type> <kbps>`.
2. Read `PORT_STORM_CONTROL|<intf>|<storm_type>` from CONFIG_DB.
3. Assert `kbps` field equals the configured value.
4. Delete the entry in cleanup.

**Pass criteria**: CONFIG_DB contains the entry with the expected kbps.

#### TC 4.1.2 — Delete storm-control removes from CONFIG_DB (per BUM type)

| Field | Value |
|-------|-------|
| Function | `test_storm_control_config_db_entry_removed` |
| Parametrized | `storm_type` in `{broadcast, unknown-unicast, unknown-multicast}` |
| Priority | P1 |

**Steps**
1. Add the storm-control entry.
2. Verify CONFIG_DB key exists.
3. Delete the entry.
4. Assert CONFIG_DB key no longer exists.

#### TC 4.1.3 — `show storm-control` reflects configuration

| Field | Value |
|-------|-------|
| Function | `test_storm_control_show_command` |
| Priority | P1 |

**Steps**
1. Add a broadcast storm-control entry.
2. Run `show storm-control`.
3. Assert interface name, type `broadcast`, and configured kbps all appear in the output.

#### TC 4.1.4 — All three BUM types configurable on one interface

| Field | Value |
|-------|-------|
| Function | `test_storm_control_config_cleanup` |
| Priority | P1 |

**Steps**
1. Add broadcast, unknown-unicast, unknown-multicast entries on the same interface.
2. Verify all three appear in `show storm-control`.
3. Delete all three; verify none remain.

#### TC 4.1.5 — Per-interface kbps is independent

| Field | Value |
|-------|-------|
| Function | `test_storm_control_independent_kbps_per_interface` |
| Priority | P1 |
| Skip | If fewer than 2 ports available |

**Steps**
1. Add broadcast storm-control on `intf1` at `kbps1`.
2. Add broadcast storm-control on `intf2` at `kbps2 != kbps1`.
3. Read CONFIG_DB for both; assert each retains its own kbps.

#### TC 4.1.6 — Re-add with new kbps updates CONFIG_DB

| Field | Value |
|-------|-------|
| Function | `test_storm_control_reconfigure_kbps_update` |
| Priority | P1 |

**Steps**
1. Add broadcast storm-control with `kbps=100`.
2. Add broadcast storm-control on the same interface with `kbps=500`.
3. Read CONFIG_DB; assert kbps equals 500.

#### TC 4.1.7 — Boundary kbps values accepted

| Field | Value |
|-------|-------|
| Function | `test_storm_control_boundary_kbps_values` |
| Parametrized | `kbps` in `{1, 100_000_000}` |
| Priority | P1 |

**Steps**
1. `config interface storm-control add <intf> broadcast <kbps>`.
2. Assert CLI returns exit code `0`.
3. Read `PORT_STORM_CONTROL|<intf>|broadcast` from CONFIG_DB.
4. Assert the `kbps` field equals the configured value exactly.
5. Delete the entry in cleanup.

**Pass criteria**: Both `1` kbps (minimum non-zero per HLD) and `100,000,000` kbps (100 Gbps maximum per HLD) are accepted by the CLI and persisted correctly in CONFIG_DB.

### 4.2 Functional / Traffic Tests

> **Common measurement procedure.** Every functional burst is driven by
> `_run_storm_traffic`, which repeats the following for each frame size in
> `PKT_LENS` (512 B and 1518 B):
>
> 1. `_clear_counters`; record the egress flood port's `TX_OK` and the ingress
>    `RX_DRP` baselines.
> 2. PTF generates `BURST_PKT_COUNT` frames of the BUM type, paced to
>    `BURST_KBPS` (3× the ceiling), from the ingress port. The PTF side only
>    sends — it makes no pass/fail decision.
> 3. Wait `_COUNTER_SETTLE_SECS`; read `TX_OK` again.
>    `forwarded = ΔTX_OK`; `forwarded_kbps = forwarded / BURST_PKT_COUNT × BURST_KBPS`.
> 4. Log the ingress `RX_DRP` delta (diagnostics only).
>
> **Verdict per size:**
> - *Policing expected* → `forwarded > 0` **and**
>   `forwarded_kbps ≤ ceiling × (1 + RATE_TOLERANCE_PCT/100)`.
> - *Not policed* → `forwarded ≥ BURST_PKT_COUNT × (1 − RATE_TOLERANCE_PCT/100)`.
>
> All sizes are run and logged; the test fails at the end listing any size that
> did not pass. The functional test skips if no same-VLAN egress flood port is
> available (`_require_egress`).

#### TC 4.2.1 — Broadcast rate-limited

| Field | Value |
|-------|-------|
| Function | `test_storm_control_broadcast` |
| Priority | P1 |

**Steps**
1. Add broadcast storm-control at `STORM_CTRL_THRESHOLD_KBPS` (1000 kbps).
2. Wait `_CONFIG_SETTLE_SECS`.
3. Run the common measurement procedure with `dst_mac = ff:ff:ff:ff:ff:ff`, policing expected.

**Pass criteria**: for both packet sizes, `forwarded > 0` and the forwarded rate is at or below `ceiling × 1.10` (i.e. capped at ~1000 kbps).

#### TC 4.2.2 — Unknown-unicast rate-limited

| Field | Value |
|-------|-------|
| Function | `test_storm_control_unknown_unicast` |
| Priority | P1 |

Same procedure as TC 4.2.1 with `dst_mac = 02:11:22:33:44:55` (guaranteed FDB miss).

#### TC 4.2.3 — Unknown-multicast rate-limited

| Field | Value |
|-------|-------|
| Function | `test_storm_control_unknown_multicast` |
| Priority | P1 |

Same procedure as TC 4.2.1 with `dst_mac = 01:00:5e:01:01:01` (unknown IPv4 multicast).

#### TC 4.2.4 — All three types rate-limited independently

| Field | Value |
|-------|-------|
| Function | `test_storm_control_all_three_types_rate_limited` |
| Priority | P1 |

**Steps**
1. Add all three storm-control types on the same interface.
2. For each BUM type, run the common measurement procedure with policing expected.

**Pass criteria**: each BUM type's forwarded rate is capped at ~the ceiling (within tolerance) for both packet sizes.

#### TC 4.2.5 — Non-BUM traffic unaffected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_non_bum_traffic_unaffected` |
| Priority | P1 |

**Steps**
1. Configure **only** broadcast storm-control.
2. Run the common measurement procedure sending an unknown-unicast burst, *not policed*.

**Pass criteria**: `forwarded ≥ BURST_PKT_COUNT × (1 − RATE_TOLERANCE_PCT/100)` for both sizes — the broadcast policer does not affect UU traffic.

#### TC 4.2.6 — After delete, traffic is not rate-limited

| Field | Value |
|-------|-------|
| Function | `test_storm_control_disabled_no_rate_limit` |
| Priority | P1 |

**Steps**
1. Add then immediately delete broadcast storm-control.
2. Run the common measurement procedure sending a broadcast burst, *not policed*.

**Pass criteria**: `forwarded ≥ BURST_PKT_COUNT × (1 − RATE_TOLERANCE_PCT/100)` for both sizes — essentially all traffic floods.

#### TC 4.2.7 — Updated kbps is enforced

| Field | Value |
|-------|-------|
| Function | `test_storm_control_updated_kbps_enforced` |
| Priority | P1 |

**Steps**
1. Add broadcast storm-control with a very high threshold (1,000,000 kbps) so traffic is not limited.
2. Re-add with a low ceiling of `500` kbps (well below the 3000 kbps send rate, yet high enough to measure the forwarded count reliably).
3. Run the common measurement procedure sending a broadcast burst, policing expected against the 500 kbps ceiling.

**Pass criteria**: the forwarded rate drops to ~500 kbps (≤ `500 × 1.10`) for both sizes, proving the updated (low) threshold is in effect.

### 4.3 Trigger / Reboot Tests

#### TC 4.3.1 — Interface flap preserves configuration and behavior

| Field | Value |
|-------|-------|
| Function | `test_storm_control_interface_flap` |
| Priority | P1 |

**Steps**
1. Add broadcast storm-control on the interface.
2. `config interface shutdown <intf>` -> wait -> `config interface startup <intf>` -> wait for link up.
3. Read CONFIG_DB; assert kbps unchanged.
4. Run the common measurement procedure (broadcast, policing expected); assert the forwarded rate is still capped at ~the ceiling.

#### TC 4.3.2 — Cold / Warm / Fast reboot persistence

| Field | Value |
|-------|-------|
| Function | `test_storm_control_persistence_across_reboot` |
| Parametrized | `reboot_type` in `{cold, warm, fast}` |
| Priority | P1 |
| Skip | Warm/fast skipped on KVM (`asic_type == "vs"`) |

**Steps**
1. Add broadcast storm-control at `STORM_CTRL_THRESHOLD_KBPS`.
2. `config save -y` to persist to `/etc/sonic/config_db.json`.
3. Invoke `tests/common/reboot.py::reboot(duthost, localhost, reboot_type=...)`.
4. After DUT comes back: read CONFIG_DB; assert kbps preserved.
5. Run the common measurement procedure (broadcast, policing expected); assert the forwarded rate is capped at ~the ceiling.
6. Cleanup: delete the entry and re-save config.

**Pass criteria**: CONFIG_DB entry survives the reboot and the policer is still enforcing the configured rate (forwarded rate ≤ ceiling × 1.10).

#### TC 4.3.3 — SWSS docker restart re-programs policers

| Field | Value |
|-------|-------|
| Function | `test_storm_control_swss_restart` |
| Priority | P1 |

**Steps**
1. Add broadcast storm-control at `STORM_CTRL_THRESHOLD_KBPS` on the test interface.
2. Verify the CONFIG_DB entry is present and `show storm-control` reflects it.
3. Restart the SWSS docker:
   ```bash
   sudo systemctl restart swss
   ```
4. Wait for SWSS to become healthy: poll until `duthost.is_service_fully_started("swss")` returns `True` and `syncd` has re-connected.
5. Wait `_CONFIG_SETTLE_SECS` for ASIC policer re-programming after orchagent reconciliation.
6. Read CONFIG_DB; assert the `PORT_STORM_CONTROL|<intf>|broadcast` entry and kbps value are unchanged.
7. Run the common measurement procedure (`_run_storm_traffic`, broadcast, policing expected); assert the forwarded rate is capped at ~`STORM_CTRL_THRESHOLD_KBPS` (within `RATE_TOLERANCE_PCT`) for both packet sizes in `PKT_LENS`.
8. Cleanup: delete the entry.

**Pass criteria**: After SWSS restarts, orchagent re-replays the storm-control configuration from CONFIG_DB to `syncd`/ASIC, and the policer is fully enforced again — forwarded rate ≤ `ceiling × (1 + RATE_TOLERANCE_PCT/100)` for both packet sizes.

> **Rationale:** HLD section 1.1.4 explicitly lists SWSS docker warm restart as a warm-boot requirement. Unlike a full system reboot (TC 4.3.2), this test isolates the orchagent reconciliation path without restarting the kernel or the dataplane.

### 4.4 Negative Tests

#### TC 4.4.1 — Invalid kbps rejected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_invalid_kbps` |
| Priority | P2 |

**Steps**
For each invalid value in `{"abc", "-1", "100000001"}`:
1. Run `config interface storm-control add <intf> broadcast <bad>`.
2. Assert non-zero return code.
3. Assert no CONFIG_DB entry created.

#### TC 4.4.2 — Zero kbps behavior is platform-conditional

| Field | Value |
|-------|-------|
| Function | `test_storm_control_zero_kbps_platform_behavior` |
| Priority | P2 |

The behavior of `kbps=0` is platform-dependent: some ASICs treat it as "disable policing" (accepted, no policer installed), while others reject it at the CLI level. Both outcomes are valid; this test documents and asserts whichever behavior the platform under test exhibits.

**Steps**
1. Run `config interface storm-control add <intf> broadcast 0`.
2. Record the CLI return code and check for a `PORT_STORM_CONTROL|<intf>|broadcast` CONFIG_DB entry.
3. **If CLI returns non-zero (rejected):** Assert no CONFIG_DB entry was created. Log: `"Platform rejects 0 kbps — pass."`
4. **If CLI returns zero (accepted):** Assert the CONFIG_DB entry exists with `kbps = 0`. Run the common measurement procedure sending a broadcast burst with *not policed* expected — i.e. verify traffic is **not** rate-limited (treating `0` as disable). Log: `"Platform accepts 0 kbps as disable — pass."`
5. Cleanup: if the entry was created, delete it.

**Pass criteria**: Either the CLI rejects `0` kbps cleanly (non-zero RC, no CONFIG_DB change), or it accepts `0` kbps and the dataplane imposes no rate limit, consistent with the platform treating `0` as a disable/no-policer operation.

#### TC 4.4.3 — Invalid storm-control type rejected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_invalid_type` |
| Priority | P2 |

**Steps**
1. Run `config interface storm-control add <intf> bogus-type 100`.
2. Assert non-zero return code.

#### TC 4.4.4 — Missing kbps argument rejected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_missing_kbps` |
| Priority | P2 |

**Steps**
1. Run `config interface storm-control add <intf> broadcast` (no kbps).
2. Assert non-zero return code.

#### TC 4.4.5 — Storm-control on PortChannel rejected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_on_portchannel` |
| Priority | P2 |
| Skip | If no PortChannel interface exists on the testbed |

**Steps**
1. Identify the first PortChannel from `show interfaces portchannel`.
2. Attempt `config interface storm-control add <pc> broadcast 100`.
3. Either:
   - CLI returns non-zero, or
   - CONFIG_DB does **not** contain the entry.

#### TC 4.4.6 — Storm-control on VLAN interface rejected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_on_vlan_intf` |
| Priority | P2 |
| Skip | If no VLAN interface (`VlanXXXX`) exists on the DUT |

**Steps**
1. Identify the first VLAN interface from `show vlan brief` (e.g. `Vlan1000`).
2. Attempt `config interface storm-control add <vlan_intf> broadcast 100`.
3. Either:
   - CLI returns non-zero, or
   - CONFIG_DB does **not** contain a `PORT_STORM_CONTROL|<vlan_intf>|broadcast` entry.

**Pass criteria**: SONiC rejects storm-control configuration on a VLAN interface, consistent with HLD section 2.3 which states "Configuration is not supported on VLAN and port-channel interfaces."

#### TC 4.4.7 — Re-apply identical configuration is idempotent

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_reapply_same_config` |
| Priority | P2 |

SONiC implements `config interface storm-control add` as an upsert (`add == modify`), so a second identical add is expected to succeed silently. This test guards against a regression where the CLI either errors out or corrupts CONFIG_DB on a duplicate add.

**Steps**
1. Add broadcast storm-control with the canonical kbps.
2. Re-issue the identical add.
3. Read CONFIG_DB and assert kbps is unchanged (and well-formed).

#### TC 4.4.8 — `del` with extra kbps argument rejected

| Field | Value |
|-------|-------|
| Function | `test_storm_control_negative_unconfigure_with_kbps` |
| Priority | P4 |

**Steps**
1. Add broadcast storm-control on the interface.
2. Run `config interface storm-control del <intf> broadcast 100` (extra kbps argument).
3. Assert non-zero return code.
4. Assert the original CONFIG_DB entry is still present (the invalid `del` must not have removed it).

### 4.5 Persistence / Reload Tests

#### TC 4.5.1 — `config save` + `config reload` preserves storm-control

| Field | Value |
|-------|-------|
| Function | `test_storm_control_config_db_json_reload` |
| Priority | P1 |

**Steps**
1. Add broadcast storm-control on the interface.
2. `sudo config save -y` (writes to `/etc/sonic/config_db.json`).
3. `sudo config reload -y -f` and wait for services to come back.
4. Read CONFIG_DB; assert kbps preserved.
5. Cleanup: delete and re-save.

### 4.6 Topology-Member Tests

#### TC 4.6.1 — Storm-control on a physical port that is a PortChannel member

| Field | Value |
|-------|-------|
| Function | `test_storm_control_on_portchannel_member_port` |
| Priority | P1 |
| Skip | If no PortChannel member exists on the DUT |

**Steps**
1. Locate any `PORTCHANNEL_MEMBER|<pc>|<intf>` key in CONFIG_DB.
2. Add broadcast storm-control on the *physical member* interface.
3. Assert the CLI succeeded.
4. Assert the CONFIG_DB entry lives under the **physical port**, not under the PortChannel.

**Pass criteria**: SONiC accepts storm-control on a LAG member port and stores the entry against the physical port only.

#### TC 4.6.2 — Storm-control on a VLAN-member interface

| Field | Value |
|-------|-------|
| Function | `test_storm_control_on_vlan_member_intf` |
| Priority | P1 |
| Skip | If no VLAN member interface exists |

**Steps**
1. Locate any `VLAN_MEMBER|<vlan>|<intf>` key in CONFIG_DB where `<intf>` is a front-panel port.
2. Add broadcast storm-control on that interface.
3. Verify CONFIG_DB entry and `show storm-control` output.
4. If the interface maps to a known PTF ingress index and has a same-VLAN egress flood port, run the common measurement procedure (broadcast, policing expected) and assert the forwarded rate is capped at ~the ceiling.

### 4.7 Scale Tests

#### TC 4.7.1 — Storm-control on all front-panel ports

| Field | Value |
|-------|-------|
| Function | `test_storm_control_scale_all_interfaces` |
| Priority | P3 |
| Skip | If fewer than 2 front-panel ports |

CONFIG_DB-only scale check; no traffic is sent in order to keep runtime bounded.

**Steps**
1. For every front-panel port reported by `storm_control_setup["all_intfs"]`, add broadcast storm-control at `STORM_CTRL_THRESHOLD_KBPS`.
2. Assert all `add` commands succeeded.
3. Read CONFIG_DB for each interface; assert all entries are present with the expected kbps.
4. Cleanup: delete every entry that was successfully added.

## 5. PTF Test Module

`ansible/roles/test/files/ptftests/storm_control_ptf_test.py` implements
`StormControlTest`, a **pure traffic generator**. It paces `pkt_count` BUM
frames to `tx_kbps` from the ingress port and exits — it does **not** capture
egress traffic and makes **no** pass/fail decision. The forwarded-rate verdict
is made entirely on the pytest side from the DUT egress `TX_OK` counter, which
is authoritative and immune to PTF dataplane queue limits and capture timing
(an in-PTF post-send drain only ever sees the few frames still queued on the
egress port, not the full flooded stream).

**Parameters** (passed via `ptf_runner`):

| Parameter | Description |
|-----------|-------------|
| `traffic_type` | `broadcast` / `unknown-unicast` / `unknown-multicast` |
| `ingress_port` | PTF dataplane port index to send from |
| `tx_kbps` | Paced send rate in kbps (set to `BURST_KBPS`, i.e. 3× the ceiling) |
| `pkt_count` | Number of frames to send |
| `pkt_len` | Frame size in bytes, min 64 (driven once per value in `PKT_LENS`) |
| `kvm_support` | `True` so traffic runs on KVM / sonic-vs |

Destination MAC mapping:

| Traffic type | DST_MAC |
|--------------|---------|
| broadcast | `ff:ff:ff:ff:ff:ff` |
| unknown-unicast | `02:11:22:33:44:55` (not in FDB) |
| unknown-multicast | `01:00:5e:01:01:01` (unknown IPv4 MC) |

All generated frames are identical (storm-control polices by rate, not by
content). The pacing keeps the policer seeing a steady `tx_kbps` so it forwards
a stable fraction; the count actually forwarded is read from the DUT egress
`TX_OK` delta by `_run_storm_traffic`.
