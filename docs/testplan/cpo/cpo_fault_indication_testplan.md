# Test Plan — CPO Fault Indication

> **Related HLD**: [CPO Fault Indication](https://github.com/noaOrMlnx/SONiC/blob/noaor-cpo-fault-indication/doc/cpo-mellanox/cpo_fault_indication.md).

## 1. Scope and Preconditions

Verify that CPO faults produce WARNING syslog entries, update `STATE_DB.TRANSCEIVER_STATUS_SW|<port>.xcvr_fault`, and reach gNMI on_change subscribers on Chameleon 6s.

- Require a CPO platform (`hwsku.json` declares `port_type: CPO`) with software control (`SAI_INDEPENDENT_MODULE_MODE=1`).
- The suite is restricted to SimX through `conditional_mark`, although PMFT injection is available on both SimX and physical ASICs.
- Require an inserted vModule with an operationally up target port and `mlxreg` available.
- TC-1 additionally requires a gNMI server configured with mTLS.
- Allocate a fresh, unused vModule per test; affected SimX builds only raise an interrupt for the first injection into each vModule.
- Clear `xcvr_fault` on the ports being checked and verify it is absent before injection. The field is append-only and does not clear automatically.
- Allow up to **120 seconds** for fault processing.

## 2. Fault Injection

Use PMFT with the ELS index and an eight-bit laser mask:

```bash
mlxreg -d <mst_device> --reg_name PMFT \
  -i module_index=<els>,sub_module=0,lane_mask=<mask> \
  -s num_of_faults_to_trigger=1,fault_type=<type>,time_interval_between_faults=1,set_laser_source_fault=<selector> -y
```

- `module_index` is the ELS index, not the SDK module index.
- For zero-based laser `k`, use `mask = 1 << k`; zero selects no laser. Tokens use one-based `lane{k+1}` numbering.

| Injection | Type | Selector | Expected token for laser 0 |
| --- | --- | --- | --- |
| APC failure warning | `1` | `1` | `xcvr_cpo_els_warning_code_lane1` |
| Laser high-power alarm | `0` | `3` | `xcvr_cpo_els_high_power_alarm_lane1` |

## 3. Test Cases

### TC-1: Single Fault — Syslog, STATE_DB, and gNMI

1. Select a fresh operationally up vModule and clear the target port's baseline.
2. Start an on_change subscription to `STATE_DB/TRANSCEIVER_STATUS_SW/<port>` and wait for the connection before injecting.
3. Inject an APC failure warning on laser 0.
4. Verify a WARNING entry from `pmon#xcvrd` containing `CPO fault: <port>` and the exact token `xcvr_cpo_els_warning_code_lane1`.
5. Verify the same token in `xcvr_fault` and in the gNMI notification.

**gNMI note**: On canonical setups without PTF, run `gnmi_cli` inside the DUT's gnmi container. Use a row-level subscription because field-level on_change currently returns an empty value; the field-level contract remains unverified.

### TC-2: Multiple Fault Tokens

1. Clear the target port's baseline.
2. Inject an APC warning on laser 0 (`lane_mask=1`), wait for processing, then inject it on laser 1 (`lane_mask=2`) of the same ELS.
3. Verify `xcvr_fault` contains both `xcvr_cpo_els_warning_code_lane1` and `xcvr_cpo_els_warning_code_lane2`, separated by `|`, without duplicates.
4. Verify a WARNING syslog entry for each token.

**Status**: Conditionally skipped on affected SimX builds because the second injection raises no interrupt. The source plan identifies the fix in SimX **26.7-1148**; run this case only with the fix available.

### TC-3: Preserve the xcvrd-Owned `error` Field

1. Clear `xcvr_fault` and snapshot the `error` field on every port of the target vModule.
2. Inject a laser high-power alarm on laser 0.
3. Verify the target port's `xcvr_fault` contains `xcvr_cpo_els_high_power_alarm_lane1`.
4. Verify every port's `error` field is byte-for-byte unchanged and contains no injected CPO token. Confirm the token remains in `xcvr_fault`.

### TC-4: Fault Fan-Out to All vModule Ports

1. Discover all logical ports sharing the target ELS. On SN6810_LD, derive `els_index = (PORT.index - 1) // 4` from the one-based CONFIG_DB index.
2. Clear `xcvr_fault` on every port in the group.
3. Inject a laser high-power alarm on laser 0.
4. Wait for `xcvr_cpo_els_high_power_alarm_lane1` on the first port, then check the remaining ports without separate waits. Every port must contain the token.

For the described SN6810_LD split configuration, one vModule spans four banks and eight logical ports. Group by ELS, not by a single bank index.

## 4. Teardown and Coverage Limits

After each test:

1. Clear the PMFT selector (`set_laser_source_fault=0`) for every injected laser mask.
2. Run `sfputil reset <port>` for the affected vModule to clear hardware fault latches and restore link operation.
3. Delete `xcvr_fault` from all affected STATE_DB port records. Restore any gNMI configuration changed by the test.

PMFT on this platform injects ELS laser faults, not module-level thermal faults. DOM/platform cross-path agreement is therefore outside this plan. Fault injection can disrupt links; clearing STATE_DB alone does not recover the hardware.
