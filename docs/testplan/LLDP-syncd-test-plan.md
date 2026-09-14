# Test Plan: Verification of `LLDP_ENTRY_TABLE` in SONiC `APPL_DB`

## Objective
To verify that the `LLDP_ENTRY_TABLE` entries in the SONiC `APPL_DB` correctly reflect the interfaces and neighbors learned by `lldpd`, using `lldpctl -f json` as the synchronization input reference.
`LLDP_ENTRY_TABLE` will be used for SONiC SNMP, the data accuracy is important.

## Asynchronous comparison

The source of the initial baseline is stable, nonempty LLDP state, not
`DEVICE_NEIGHBOR` or the presence of an interface in the configuration. For
example, KVM T0 server-facing ports can have configured neighbors without
receiving LLDP, and the management network may have no LLDP-speaking peer.
The same discovery logic applies to KVM and physical switches; it does not
whitelist front-panel names, exclude management interfaces, or branch on the
platform. If `lldpd` reports `eth0`, it must synchronize to the DB and is kept
in the baseline. If no management neighbor is advertised, `eth0` is not
artificially added. It is never administratively flapped.
Use the configured host and ASIC LLDP instances and their corresponding APPL_DBs,
including the host instance that owns management LLDP on multi-ASIC devices.

The module-scoped autouse fixture `capture_and_validate_baseline` calls the
shared convergence helper without a pre-existing expected set. After LLDP
readiness, the helper takes the observed interface names as a candidate and
requires the DB/CLI checks to converge to that candidate. It never derives
the candidate from the DB, so a neighbor missing from the DB cannot silently
disappear from the baseline. Only a successful comparison returns the
immutable `frozenset` for the module.

All tests use that same baseline before and after their action. Subsequent
checks require exact membership: neither missing nor unexpected ports are
accepted, and no test rebuilds or expands the baseline. Only interface names
are frozen, not neighbor content or elapsed ages. Topology completeness and
the correctness of the advertised neighbor identity are separate test concerns.

`wait_for_lldp_convergence` reuses the existing collection/assertion helpers
and `wait_until` in two phases:

1. **LLDP readiness:** require nonempty observed neighbors and the same
   advertised chassis/port signature in three consecutive samples. When a
   baseline is supplied, also require its exact port set. Collection failures
   and signature changes break the streak. Age, local record IDs and neighbor
   enumeration order do not affect stability.
2. **APPL_DB convergence:** each attempt reads LLDP, dumps the DB tables, reads
   the CLI, and reads LLDP again. Reject a sample if the advertised neighbor
   content changed between LLDP reads. Then require all source interface sets
   to match the baseline and the DB fields to match the current LLDP data.
   Do not compare against a frozen phase-one neighbor-content snapshot.

Each phase starts its polling budget once. A source change during phase two
invalidates that sample and retries within the remaining DB-phase budget; it
does not restart phase one or either timeout. Diagnostics identify the phase
and the last observed collection, membership, stability or content failure.
Timeouts and the five-second polling interval are named module constants:

| Call site | Neighbor readiness budget | DB convergence budget |
|---|---|---|
| Initial baseline | 250 seconds | 90 seconds |
| Before each test; after a single-port flap | 90 seconds | 90 seconds |
| After swss/LLDP restart, batched flap or reboot | 300 seconds | 90 seconds |

These are polling budgets; command/transport timeouts and each action's existing
SSH/service/BGP readiness checks are separate. The two LLDP reads bracket an
observation window, not an atomic transaction or a synchronization watermark.
Persistent differences from the captured baseline, including loss of a
previously observed `eth0`, fail even if all three sources agree on the same
incomplete or expanded set. Never accumulate
successful ports across attempts. Retries tolerate delay, not permanent loss.
Deduplicate interface membership, but retain all fanout neighbors and match
the DB's recorded system name, chassis ID and remote port ID for content checks.

## Test Scenarios

### 1. Verify Presence of All Interfaces in `LLDP_ENTRY_TABLE`
- **Objective**: Ensure that all observed LLDP interfaces, including `eth0` when learned, have entries in `LLDP_ENTRY_TABLE`.
- **Steps**:
  1. Execute the command `sonic-db-cli APPL_DB keys 'LLDP_ENTRY_TABLE:*'`.
  2. Initially compare with stable `lldpctl` interface names; in later checks also require the fixed module baseline.
- **Expected Result**: Every required interface has an entry, and all sources agree on membership and content.

### 2. Verify `LLDP_ENTRY_TABLE` Content Against `lldpctl` Output
- **Objective**: Ensure that the content of each interface's `LLDP_ENTRY_TABLE` entry matches the output of `lldpctl -f json`.
- **Steps**:
  1. For each interface, retrieve the LLDP information using `sonic-db-cli APPL_DB hgetall LLDP_ENTRY_TABLE:<interface>`.
  2. Retrieve the LLDP information using `lldpctl -f json` and parse the output.
  3. Compare the data from `LLDP_ENTRY_TABLE` with the corresponding data in the `lldpctl -f json` output.
- **Expected Result**: The data in `LLDP_ENTRY_TABLE` should match the data from `lldpctl -f json` for each interface.

### 3. Verify Interface Flap Handling
- **Objective**: Ensure that `LLDP_ENTRY_TABLE` entries are correctly updated after an interface flap.
- **Steps**:
  1. Simulate an interface flap by running `shutdown` and `no shutdown` commands on an interface.
  2. Repeat tests from scenarios 1 and 2.
- **Expected Result**: The `LLDP_ENTRY_TABLE` should update correctly after the interface flap, and the entries should still match the output of `lldpctl -f json`.

### 4. Verify Behavior After LLDP Service Restart
- **Objective**: Ensure that `LLDP_ENTRY_TABLE` entries are correctly updated after restarting the LLDP service.
- **Steps**:
  1. Restart the LLDP service using the appropriate command.
  2. Repeat tests from scenarios 1 and 2 after the LLDP service has restarted.
- **Expected Result**: The `LLDP_ENTRY_TABLE` entries should be updated correctly after the LLDP service restart and should match the output of `lldpctl -f json`.

### 5. Verify Behavior After System Reboot
- **Objective**: Ensure that `LLDP_ENTRY_TABLE` entries are preserved and accurate after a system reboot.
- **Steps**:
  1. Reboot the SONiC device.
  2. Repeat tests from scenarios 1 and 2 after the system has fully rebooted.
- **Expected Result**: The `LLDP_ENTRY_TABLE` entries should persist across reboots and match the `lldpctl -f json` output.

## Test Data
- **APPL_DB Commands**: `sonic-db-cli APPL_DB keys`, `sonic-db-cli APPL_DB hgetall`
- **LLDP Command**: `lldpctl -f json`
- **Interfaces**: One immutable module baseline, captured from stable LLDP only after DB/CLI synchronization succeeds.

## Conclusion
This test plan outlines the steps required to verify that the `LLDP_ENTRY_TABLE` in SONiC's `APPL_DB` is correctly populated, updated, and persistent under various conditions. The expected outcomes should confirm that the `LLDP_ENTRY_TABLE` is in sync with the LLDP information reported by the `lldpctl` command.
