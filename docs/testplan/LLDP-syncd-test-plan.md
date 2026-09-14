# Test Plan: Verification of `LLDP_ENTRY_TABLE` in SONiC `APPL_DB`

## Objective
To verify that the `LLDP_ENTRY_TABLE` entries in the SONiC `APPL_DB` correctly reflect the LLDP information for all interfaces and are consistent with the output of `lldpctl -f json` under various conditions.
`LLDP_ENTRY_TABLE` will be used for SONiC SNMP, the data accuracy is important.

## Asynchronous comparison

The required interface set is determined independently of learned LLDP state:
all topology-neighbor ports in the frontend ASICs' persistent `DEVICE_NEIGHBOR`
configuration, plus `eth0`. Unused physical ports without a configured neighbor
are not required to advertise LLDP. Do not filter this set by current link state.
This test requires an LLDP-speaking management neighbor, and `eth0` must be
present both before and after the test. It is never administratively flapped.
Use the configured host and ASIC LLDP instances and their corresponding APPL_DBs,
including the host instance that owns management LLDP on multi-ASIC devices.

Before any disruptive action, require the configured interface set to be
present and consistent across all sources. A missing port is a
configuration/environment readiness failure; agreeing on an incomplete set
does not pass. Preserve all additional ports observed in the successful
pre-test sample as recovery requirements too.

`lldp_syncd` periodically copies `lldpd` state into APPL_DB. A single comparison
can therefore observe a new or aged-out neighbor before the DB catches up.
Each comparison attempt reads LLDP, dumps the DB tables, reads the CLI, and
reads LLDP again. The advertised chassis and port information must be unchanged
between the two LLDP reads; elapsed age, local record IDs and neighbor ordering
are not compared. This brackets the sample but is not an atomic transaction.
Interface sets and all checked content must then agree, including `eth0`.

Retry the entire sample for up to 90 seconds, or 300 seconds after disruptive
events. A persistent missing/extra management or front-panel interface, content
mismatch, or continuously changing neighbor state fails with diagnostics.
Never reuse pre-restart LLDP data or accumulate successful ports across retries.
After the event, require the entire pre-test set, including `eth0`, to recover.
Missing ports are reported as recovery failures even if they disappeared from
all three sources. Retries tolerate synchronization delay, not permanent loss.
Deduplicate interface membership, but retain all fanout neighbors and match
the DB's recorded system name, chassis ID and remote port ID for content checks.

## Test Scenarios

### 1. Verify Presence of All Interfaces in `LLDP_ENTRY_TABLE`
- **Objective**: Ensure that all configured topology-neighbor ports and `eth0` have entries in `LLDP_ENTRY_TABLE`.
- **Steps**:
  1. Execute the command `sonic-db-cli APPL_DB keys 'LLDP_ENTRY_TABLE:*'`.
  2. Compare with persistent `DEVICE_NEIGHBOR` ports plus `eth0`, not just the currently observed LLDP interfaces.
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
- **Interfaces**: Persistent `DEVICE_NEIGHBOR` ports plus `eth0`; also retain all additional pre-test LLDP ports.

## Conclusion
This test plan outlines the steps required to verify that the `LLDP_ENTRY_TABLE` in SONiC's `APPL_DB` is correctly populated, updated, and persistent under various conditions. The expected outcomes should confirm that the `LLDP_ENTRY_TABLE` is in sync with the LLDP information reported by the `lldpctl` command.
