# PortChannel 400G Member Add GCU Test Plan

## 1. Purpose

This document describes the pytest test that validates adding a removed 400G
PortChannel member back to a T2 chassis linecard using Generic Config Updater
(GCU).

The test starts from a minigraph-derived PortChannel with at least two external
400G member ports. Setup removes one member's port-scoped configuration and
sets that port admin down, then lowers the PortChannel `min_links` value to the
remaining member count. Setup saves and reloads that prepared configuration so
teamd uses the reduced threshold. The test body restores the removed member and the
original running `CONFIG_DB` `min_links` value with GCU. After the restore patch,
the test validates control-plane, ASIC, counter, ACL/Mirror binding, and
dataplane behavior for the restored LAG member.
Teardown always reloads minigraph and saves the regenerated running
configuration, restoring both runtime state and the on-disk config DB files.
Setup also lowers the peer LAG threshold when needed to permit the reduced
member count; cleanup restores that peer setting to its original value.

Test module:

`tests/generic_config_updater/add_cluster/test_portchannel_400G_member_add.py`

Related documents:

- Generic Config Updater add-cluster coverage:
  `docs/testplan/Add-cluster-with-GCU.md`
- Distributed VOQ chassis LAG coverage:
  `docs/testplan/chassis-lag-test-plan.md`

## 2. Applicability

### 2.1 Supported environments

The test runs on T2 testbeds.

Static and runtime gating:

| Mechanism | Requirement |
|-----------|-------------|
| `pytest.mark.topology("t2")` | Topology must be T2 |
| Runtime config | Selected PortChannel must have a configured `min_links` value |

### 2.2 Runtime PortChannel selection

At runtime, the test uses `enum_rand_one_per_hwsku_frontend_hostname`, so pytest
creates one parameter for each frontend LC HWSKU in the testbed. For each
parameter, runtime selection is restricted to frontend LCs with that same HWSKU.
The test scans those same-HWSKU frontend linecards and frontend ASICs until it
finds a qualifying PortChannel. It randomly selects one PortChannel that meets
all of the following conditions:

1. The PortChannel has at least two external member ports.
2. All external members are configured at 400G.
3. All external members are admin up and oper up.
4. The PortChannel is oper up before setup starts.
5. The original PortChannel config has `min_links` configured.
6. That value is greater than the remaining member count, so setup genuinely
   reduces it rather than increasing it or applying an unchanged value.

Internal and backplane member ports are excluded from selection.

The selected members must terminate on one EOS neighbor PortChannel. Setup
uses the existing neighbor inventory and `get_portchannel_by_member` API to
resolve that LAG. Unsupported neighbor types skip before either side is
modified; missing or inconsistent peer membership is a setup failure.

If no PortChannel satisfies these conditions for a HWSKU parameter, that
parameter is skipped before any GCU patch is applied. Other HWSKU parameters can
still run independently.

If every HWSKU parameter in a testbed is skipped, the run provides no functional
GCU member-restore verification on that testbed. That outcome should be treated
as a topology coverage gap, not as evidence that GCU member restore was
validated.

The reusable helper
`find_portchannels_by_member_speed(config_facts, interface_status_map,
portchannel_status_map, speed, ...)` performs the speed-based PortChannel
discovery. This test passes `400000`, and the same helper can be reused by a
future 100G case with `100000`.

## 3. Test Objectives

The test confirms that GCU can restore a selected 400G PortChannel member after
that member was moved to the default admin-down state:

1. Remove one external member from `PORTCHANNEL_MEMBER`.
2. Remove the selected port's port-scoped cluster configuration.
3. Set the selected port admin down.
4. Lower `min_links` to the remaining member count and reload the prepared
   configuration. Require the reduced-member LAG to be operational before GCU
   member addition starts.
5. Add the selected member and port-scoped config back using GCU.
6. Restore the original PortChannel `min_links` value using GCU.
7. Verify the final selected-port `CONFIG_DB` entries, member existence, port
   admin state, and `min_links` value.
8. Verify the PortChannel operational state is up after the removed member is
   restored.
9. Verify teamd/lag state reports the restored member selected.
10. Verify ASIC_DB has SAI LAG_MEMBER objects for all expected members and
    none of those members are egress-disabled.
11. Verify COUNTERS_DB exposes the restored member and LAG counter mappings.
12. Verify ACL and Mirror table bindings still reference the restored LAG.
13. Verify PTF dataplane traffic can hash to the restored member and that the
    restored member TX counters increase from a pre-traffic baseline.

## 4. GCU Patch Behavior

### 4.1 Setup patch: remove one member

Before changing the DUT, snapshot the peer LAG's explicit `min-links` setting.
If it exceeds the remaining member count, lower it to that count using the
neighbor's configuration API and verify running-config read-back. This avoids
the peer keeping the reduced-member LAG unsynchronized. An absent or already
low-enough setting is left unchanged. Peer changes are test preparation, not
part of the DUT GCU patch.

The setup fixture applies GCU patches that:

- remove the selected `PORTCHANNEL_MEMBER` entry
- remove selected-port entries from `DEVICE_NEIGHBOR`
- remove selected-port entries from `INTERFACE`
- remove selected-port entries from `BUFFER_PG`
- remove selected-port entries from `PORT_QOS_MAP`
- remove selected-port entries from `QUEUE`
- remove selected-port entries from `PFC_WD`
- remove selected-port entries from `CABLE_LENGTH|AZURE`
- set `PORT|<member>/admin_status` to `down`
- set `PORTCHANNEL|<portchannel>/min_links` to the remaining member count

The test saves the prepared running configuration and uses the common safe
config reload helper. Config-file backups are not needed: the minigraph
finalizer is registered before any patch and restores running and saved
configuration after both successful tests and setup/test failures. YANG
validation remains enabled.

After this setup reload, the PortChannel must be operationally up, teamd's
active `min_ports` must equal the remaining member count, and every remaining
member must be selected. Failure stops the test before the GCU add patch.

### 4.2 Test patch: add the member back

The test body applies one GCU patch that:

- adds the selected `PORTCHANNEL_MEMBER` entry back from the original running
  config
- restores selected-port entries in `DEVICE_NEIGHBOR`
- restores selected-port entries in `INTERFACE`
- restores selected-port entries in `BUFFER_PG`
- restores selected-port entries in `PORT_QOS_MAP`
- restores selected-port entries in `QUEUE`
- restores selected-port entries in `PFC_WD`
- restores selected-port entries in `CABLE_LENGTH|AZURE`
- restores the selected port's original `admin_status`
- restores the original PortChannel `min_links` value

Each patch is first validated with `config apply-patch -d` before the real GCU
apply.

The restored original `min_links` value is required in running `CONFIG_DB`.
The test does not require a hot update of teamd's threshold: its active
`min_ports` may remain at the prepared value or match the original value on
implementations that support runtime updates. All expected members must be
selected and the PortChannel must be up. There is no save, reload, or reboot
between the GCU restore patch and these assertions. Minigraph reload and save
run afterward as teardown, not as validation of GCU persistence or hitless forwarding.

## 5. Test Procedure

```mermaid
flowchart TD
    A[Select T2 frontend LC and ASIC] --> B[Select up PortChannel with 400G members]
    B --> C[Save original member and min_links config]
    C --> C1[Resolve peer LAG and snapshot its threshold]
    C1 --> C2[Lower peer threshold when needed and verify read-back]
    C2 --> D[Dry-run and apply GCU member remove patch]
    D --> E[Verify member absent and port admin down]
    E --> F[Dry-run and apply GCU min_links update]
    F --> G[Save prepared running config]
    G --> G1[Reload prepared config]
    G1 --> G2[Require LAG up, reduced active threshold, and remaining members selected]
    G2 --> H[Dry-run and apply GCU member add plus min_links restore]
    H --> I[Verify member-scoped config, port admin, and min_links restored]
    I --> J[Assert PortChannel comes up]
    J --> K[Verify teamd, ASIC_DB, COUNTERS_DB, and ACL/Mirror bindings]
    K --> L[Select unused test route and send PTF traffic to restored member]
    L --> M[Verify restored member counters increase]
    M --> N[Always reload minigraph and save regenerated configuration]
    N --> O[Wait for services and BGP recovery]
    O --> P[Restore and verify original peer threshold]
```

### 5.1 Select DUT, ASIC, PortChannel, and member

1. Use `enum_rand_one_per_hwsku_frontend_hostname` to select one frontend DUT
   for a HWSKU parameter.
2. Restrict runtime candidates to frontend DUTs with the same HWSKU.
3. Scan frontend ASIC namespaces on each candidate DUT.
4. Read running config facts and interface status for each ASIC.
5. Select a PortChannel with at least two 400G external oper-up members.
6. Select one member to remove and save the original member and PortChannel
   config values.

### 5.2 Prepare base state

Resolve the peer PortChannel for every selected DUT member and snapshot its
actual configured threshold, rather than assuming it equals the member count.
Register peer recovery before lowering its threshold to the remaining member
count. The fixture dependency keeps the peer threshold reduced through DUT
cleanup and restores it afterward, including when DUT cleanup raises an error.

1. Register unconditional minigraph cleanup before applying any patch.
2. Dry-run and apply the selected-member removal patch.
3. Verify the removed member is absent from `CONFIG_DB` and the member port is
   admin down.
4. Dry-run and apply the `min_links` update to match remaining member count.
5. Verify the reduced `min_links` value in `CONFIG_DB`.
6. Save the prepared running configuration and reload it through the common
   safe reload helper. The already-registered minigraph finalizer restores the
   on-disk files after the test, including on setup failures.
7. Recheck the reduced-member config, require aggregate operational state up,
   and verify teamd's active threshold equals the remaining member count with
   every remaining member selected.

### 5.3 Add the member back

1. Build an add patch from original running config facts.
2. Dry-run and apply the add patch.
3. Verify the member exists in `CONFIG_DB`.
4. Verify the selected port-scoped `CONFIG_DB` entries match the saved original
   config, including `DEVICE_NEIGHBOR`, `INTERFACE`, `BUFFER_PG`,
   `PORT_QOS_MAP`, `QUEUE`, `PFC_WD`, and `CABLE_LENGTH|AZURE`.
5. Verify the selected port admin state matches its original value.
6. Verify PortChannel `min_links` matches the original value.
7. Poll aggregate PortChannel operational state through
   `show interfaces portchannel` and fail if it does not come up.
8. Verify `lag_facts`/teamd state reports:
   - the aggregate PortChannel is up
   - all expected members are configured
   - every expected member, including the restored member, is selected
   - the active threshold is either the prepared reduced value or the original
     value; CONFIG_DB restoration is checked separately
9. Verify ASIC_DB has one `SAI_OBJECT_TYPE_LAG_MEMBER` entry for every expected
   member, none of those members are egress-disabled, and all expected member
   entries reference the same SAI LAG object.
10. Verify COUNTERS_DB has a restored member OID and readable TX counters. If a
    LAG counter object is present, verify its counter hash can be read.
11. Verify existing ACL and Mirror tables that reference the restored
    PortChannel or member still have bindings in CONFIG_DB and APP_DB.
12. Select a PTF source port outside the tested PortChannel with a known
    admin-up and oper-up status.
13. Select an unused temporary IPv4 route from the test candidate list, advertise
    it through the restored member's neighbor ExaBGP port, and wait for all
    resolved route nexthops on the selected ASIC to use the tested PortChannel.
    On converged topologies, use the logical neighbor's original ExaBGP offset
    from `nbrhosts`, rather than the collapsed VM offset.
14. Clear traffic counters and capture a post-clear baseline, then send PTF
    traffic with multiple hash attempts until traffic selects the restored
    member. Vary both the IPv4 source address and TCP source port so attempts
    cover L3-only as well as L4-aware LAG hashing. Do not clear counters between
    attempts.
15. Verify `portstat -j` and COUNTERS_DB TX counter deltas for the restored
    member meet or exceed the sent packet count.
16. Withdraw only the temporary route installed by this test and assert it is
    removed from the selected ASIC.

Shared queue parsing, DB/counter reads, neighbor lookup, and route helpers are
implemented in `add_cluster/portchannel_helpers.py`. Shared validation defaults
are defined in `add_cluster/constants.py`; the tests keep distinct temporary
route candidate lists and their own DUT selection and GCU patch flows.

### 5.4 Cleanup

Cleanup runs after normal completion, assertion failure, or partial setup
failure:

1. Always invoke the existing minigraph recovery helper for the selected DUT,
   even when the GCU test passed and CONFIG_DB already matches the saved values.
2. Use the common `config_reload` helper with `config_source="minigraph"`,
   `safe_reload=True`, and `wait_for_bgp=True`. Its minigraph path runs
   `config load_minigraph -y` and then `config save -y`, regenerating and saving
   the host and ASIC config DB files from the minigraph-derived configuration.
3. Surface recovery errors rather than silently leaving the prepared baseline
   or an unhealthy DUT behind. No additional GCU patch is applied in teardown.
4. Override the shared module-level `setup_env` fixture for this test only.
   Otherwise, its later backup/checkpoint restore could overwrite the minigraph
   configuration just recovered by the function finalizer. Other add-cluster
   tests retain the shared fixture unchanged.
5. The peer fixture restores its exact original `min-links` setting and verifies
   running-config read-back, independently of DUT recovery success. It does
   not save the temporary peer configuration. Peer restoration errors fail
   teardown instead of being silently ignored.

## 6. Loganalyzer Handling

During GCU apply, the test registers selective loganalyzer ignores for expected
transient LAG and buffer-programming errors on the selected DUT.

During unconditional minigraph teardown, the common `config_reload` helper
handles reload-time stabilization and expected reload log handling.

## 7. Pass Criteria

The test passes when:

1. A qualifying 400G external PortChannel is selected, or unsupported testbeds
   are skipped.
2. The setup GCU patches remove the selected member, set it admin down, and
   lower `min_links`. The setup reload produces an operational reduced-member
   LAG with the reduced active teamd threshold before member addition.
3. The test GCU patch adds the selected member back and restores original
   `min_links`.
4. `CONFIG_DB` shows the expected final member existence, selected-port config,
   admin status, and `min_links` value.
5. PortChannel operational state is up after the final member restore.
6. teamd/lag state reports every expected member selected and an active
   threshold matching either the prepared or original value.
7. ASIC_DB exposes SAI LAG_MEMBER objects for the expected LAG members and none
   of those members are egress-disabled.
8. COUNTERS_DB exposes readable restored-member TX counters, and LAG counters
   are readable when the platform exposes a LAG counter object.
9. Existing ACL and Mirror bindings for the restored LAG remain present.
10. PTF traffic can hash to the restored member and the restored member TX
    counters increase.
11. Teardown restores the selected DUT from minigraph and saves the regenerated
    configuration to disk, then waits for services and BGP recovery.
12. If the peer threshold was changed, teardown restores its exact original
    setting and confirms read-back.

Aggregate PortChannel operational state is required both after the setup reload
and after final member restore, through `show interfaces portchannel` and teamd
read-back. Running `CONFIG_DB` must contain the original `min_links` after GCU.
An active teamd threshold remaining at the prepared value is not evidence of
successful runtime threshold restoration; that capability is outside this test.

## 8. Out of Scope

1. Non-T2 topologies.
2. Internal or backplane PortChannels.
3. PortChannels with fewer than two external 400G members.
4. Mixed-speed PortChannel member validation.
5. Removing or adding more than one member in a single test run.
6. Mixed IPv4/IPv6 dataplane traffic coverage; the restored-member traffic
   validation uses a temporary IPv4 route.
7. Full ACL, Everflow, ERSPAN, or other feature traffic behavior over the
   restored LAG. The test validates binding preservation, not every feature's
   forwarding behavior.
8. Negative malformed-patch or fail-safe validation.
9. Persistence across reboot, warm boot, or fast boot.

The items above are intentionally left to LAG dataplane, chassis LAG, generic
hash, feature-specific, and broader GCU negative/fail-safe coverage. This test
focuses on GCU patch dry-run/apply behavior, CONFIG_DB restoration of the
selected member-scoped entries, restored LAG operational state, and a targeted
PTF dataplane hash check for the restored member.
