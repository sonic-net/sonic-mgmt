# Test Plan: Verification of `LLDP_ENTRY_TABLE` in SONiC `APPL_DB`

## Objective
To verify that the `LLDP_ENTRY_TABLE` entries in the SONiC `APPL_DB` correctly reflect the LLDP information for all interfaces and are consistent with the output of `lldpctl -f json` under various conditions.
`LLDP_ENTRY_TABLE` will be used for SONiC SNMP, the data accuracy is important.

## Test Scenarios

### 1. Verify Presence of All Interfaces in `LLDP_ENTRY_TABLE`
- **Objective**: Ensure that all interfaces present in the system have corresponding entries in the `LLDP_ENTRY_TABLE`.
- **Steps**:
  1. Execute the command `sonic-db-cli APPL_DB keys 'LLDP_ENTRY_TABLE:*'`.
  2. Compare the list of interfaces in `LLDP_ENTRY_TABLE` with the expected list of system interfaces.
- **Expected Result**: Every active interface in the system should have a corresponding entry in the `LLDP_ENTRY_TABLE`.

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
- **Interfaces**: List of interfaces to be tested, retrieved dynamically from the device.

## Conclusion
This test plan outlines the steps required to verify that the `LLDP_ENTRY_TABLE` in SONiC's `APPL_DB` is correctly populated, updated, and persistent under various conditions. The expected outcomes should confirm that the `LLDP_ENTRY_TABLE` is in sync with the LLDP information reported by the `lldpctl` command.
