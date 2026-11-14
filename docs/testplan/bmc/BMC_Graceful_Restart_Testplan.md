# 1. Feature Overview

On a chassis where SONiC runs on both the BMC and the switch-host, the BMC owns switch-host power. Today it removes that power without telling the host, so the host cannot flush its state, cannot run any platform ordering it needs, and cannot record why it went down.

This feature adds a handshake before the power off:

- A **graceful leg** is added to the existing `GRACEFUL_SHUT` command — ask the host to prepare, then remove power.

`GRACEFUL_RESTART` is deferred by the HLD and is not covered by this test plan. In this release a restart is `config chassis modules shutdown` followed by `startup`.

The handshake reuses the existing `System.RebootStatus`: the BMC asks, the host runs its normal reboot teardown without rebooting, and reports the result.

# 2. Operation Flow

## 2.1. Graceful shutdown

The power state sequence is `GRACEFUL_SHUTTING_DOWN` -> `POWERING_OFF` -> `POWERED_OFF`.

The outcome is recorded in `HOST_STATE|switch-host` and in the BMC event log.

**The reporting path survives the teardown.** `database`, `gnmi`, `sysmgr` and `sonic-hostservice` keep running, which is what lets the host answer the BMC's poll after its own teardown is done.

**The host never removes its own power.** `reboot -p` asks the watchdog to arm before it exits, so a host left powered is meant to reboot itself back into service.

# 3. Related Command and Configuration

No new command is added. The existing chassis-module commands are the entry point.

```
bmc$ config chassis modules shutdown SWITCH-HOST
bmc$ config chassis modules startup  SWITCH-HOST
bmc$ config chassis modules shutdown-timeout SWITCH-HOST <seconds>
```

`config chassis modules shutdown-timeout` accepts any non-negative integer, with **no upper limit**. The default is 120 s, and `0` means forced. Whether a value is safe on a platform is settled by measurement during platform qualification, which this test plan does not cover.

`show chassis modules status` on the BMC adds a `Result` column. The existing columns and their order do not change.

```
bmc$ show chassis modules status
  Name         Description  Oper-Status  Admin-Status  Serial   Power-On-Delay (sec)  Shutdown-Timeout (sec)  Result
  SWITCH-HOST  Switch Host  Online       down          SN12345  0                     120                     -
  SWITCH-HOST  Switch Host  Offline      down          SN12345  0                     120                     SUCCESS_GRACEFUL

host (next boot)$ show reboot-cause
  graceful shutdown from BMC
```

# 4. Test Cases

## 4.1. Summary

**Power is always removed; the handshake only decides how the operation is recorded** — graceful when the host confirmed it finished, forced otherwise. The cases are organised around that: group A covers the operations that end up recorded graceful, group B covers every way an operation ends up recorded forced, group C covers the two results that are neither, and group D covers the configuration and the operator-visible record.

| Category | # | Test case | Focus |
| --- | --- | --- | --- |
| **A. Normal flow** | 1 | Graceful Shutdown via CLI and Rack Manager | Both entry points run the same flow; recorded `SUCCESS_GRACEFUL`; the host reports the graceful reboot cause |
| | 2 | Graceful Restart | **Deferred** — `GRACEFUL_RESTART` is deferred by the HLD |
| **B. Degraded to forced**<br>*(one case per `op_reason`)* | 3 | Preconditions Not Met — No Request Is Sent | `not_qualified` / `timeout_zero` / `already_off` — proved by the host's pre-check never being entered |
| | 4 | BMC to Host Communication Failure | `rpc_failure` — the gNMI service stops while the BMC is waiting on the host |
| | 5 | No Answer Before the Deadline | `deadline` — and that the wait is not ended early |
| | 6 | Host Pre-Shutdown Failure | `check_failed` — the host reports it did not complete |
| **C. Critical leak** | 7 | Critical Leak Interrupts an Operation in Flight | `PREEMPTED`, injected into the graceful wait |
| | 8 | An Existing Critical Leak Blocks Every Power Raise | `POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE` — every power raise is refused while the leak stands |
| **D. Configuration and observability** | 9 | Configuration Boundaries | `shutdown-timeout` accepts any non-negative integer and rejects the rest |
| | 10 | Logging, State and Forensics | The recorded fields, the new column, the Rack Manager receipt, the reboot-cause history |

## 4.2. Conventions

| Term | What it means |
| --- | --- |
| *Pre-check stand-in* | A test-owned `platform_reboot_pre_check` in `/usr/share/sonic/device/<platform>/`. `reboot -p` runs it before the teardown and fails when it exits non-zero. `pre_reboot_hook` is not used, because `reboot -p` skips it on the switch-host. The stand-in counts its invocations, can be held or made to fail on demand, and always exits by itself after a fixed limit. A platform file of the same name is backed up first. |
| *Hold the pre-check* | Create the stand-in's hold flag before triggering. Its limit has to exceed `graceful_shutdown_timeout`, so the BMC deadline is reached while the host is still held. |
| *Fail the pre-check* | Create the stand-in's fail flag before triggering, so it exits non-zero. |
| *Pre-check entered* | The stand-in's invocation count went up by one during the operation. Every case that holds or fails the pre-check verifies this before it checks the result. |
| *Host never asked* | The stand-in's invocation count did not go up during the operation. `reboot -p` runs the pre-check for every request that reaches the host, so an unchanged count shows that none did. The count survives the power cut and is read once the host is back. |
| *Power state* | STATE_DB `HOST_STATE\|switch-host`, field `device_power_state`, on the BMC. |
| *Power removed* | Confirmed: the BMC reads the switch-host `OFFLINE`, the power state is `POWERED_OFF`, and the host is unreachable. A power-off call in the BMC event log only shows that removal was attempted. |

## 4.3. Restoration

Every case restores what it changed on every exit, failures included. Only test-owned state is removed, and a genuine alarm is never cleared or overridden.

| State changed | Restored to |
| --- | --- |
| Host `GNMI\|certs`, `GNMI\|gnmi`, `GNMI_CLIENT_CERT` | The rows saved before the change |
| BMC `GNMI_CLIENT\|certs` (Test Case 3) | The original row, or no row if there was none |
| `graceful_shutdown_timeout` | The original value |
| Pre-check stand-in | Removed, and the platform file put back if there was one |
| Host `gnmi.service` (Test Case 4) | Started |
| `thermalctld` (Test Cases 7, 8) | Resumed |
| `LEAK_CONTROL_POLICY` (Test Cases 7, 8) | The original values |
| Synthetic CRITICAL leak state (Test Cases 7, 8) | Removed. A case does not start while a genuine leak is present |
| Switch-host power | Powered on, then verified online and healthy. A genuine leak leaves the host off |

---

## Test Case 1: Graceful Shutdown via CLI and Rack Manager

**Objective**: Validate the complete graceful shutdown flow, that the chassis CLI and the Rack Manager `GRACEFUL_SHUT` command run the same flow, and that a completed operation is positively attributed.

This is the case an operator would run by hand, so it is kept to what an operator can see.

**Test Steps**

1. **Pass 1 (CLI)** — run `config chassis modules shutdown SWITCH-HOST` on the BMC.
2. Verify the switch-host is really down — the BMC reports it `OFFLINE` and the host is physically unreachable.
3. Verify `show chassis modules status` reports `Result = SUCCESS_GRACEFUL`, and record `op_request_id` from `HOST_STATE|switch-host`.
4. Power the switch-host back on, and verify `show reboot-cause` reports the **graceful** cause rather than the BMC power-down cause.
5. Verify the BMC event log's `OP_DONE` record for that request id is the same as the CLI output.
6. **Pass 2 (Rack Manager)** — Trigger graceful shutdown by Rack Manager and repeat the test.

---

## Test Case 2: Graceful Restart

**Deferred.** The HLD defers `GRACEFUL_RESTART`, and a Rack Manager row that carries it is closed `FAILED` with `UNKNOWN_COMMAND`. This case will be written with the change that adds the command.

---

## Test Case 3: Preconditions Not Met — No Request Is Sent

**Objective**: Validate that when the graceful leg cannot run, the BMC falls back to today's forced behaviour without touching the host.

**Expected outcome for every sub-scenario**: the host is never asked, power removed (confirmed), result `SUCCESS_FORCED` with the reason below.

| # | Precondition to establish | Expected `op_reason` | Additional check |
| --- | --- | --- | --- |
| 1 | Point `client_crt` in the BMC's `GNMI_CLIENT\|certs` at a file that does not exist | `not_qualified` | — |
| 2 | Set `graceful_shutdown_timeout = 0` | `timeout_zero` | — |
| 3 | Power the switch-host off first, and wait until it reads `OFFLINE` and the power state is `POWERED_OFF` | `already_off` | The request completes **without a second power call** being issued |

**Test Steps** (repeat for each sub-scenario)

1. Establish the precondition from the table.
2. Trigger `GRACEFUL_SHUT`.
3. Verify the result is `SUCCESS_FORCED` with the expected `op_reason`.
4. Perform the sub-scenario's additional check from the table.
5. Recover the switch-host and **verify the host was never asked**. This is what separates these from Test Case 4, where the request reaches the host and the transport fails afterwards.

---

## Test Case 4: BMC to Host Communication Failure

**Objective**: Validate that a transport-level failure between the BMC and the host degrades to forced, and is recorded `rpc_failure`.

**Test Steps**

1. Hold the pre-check.
2. Trigger `GRACEFUL_SHUT`, wait until the operation enters `GRACEFUL_SHUTTING_DOWN`, and verify the pre-check was entered.
3. Stop `gnmi.service` on the host.
4. Verify the result is `SUCCESS_FORCED` with `op_reason = rpc_failure`, that `graceful_shutdown_timeout` was not exceeded, and that power was removed.

---

## Test Case 5: No Answer Before the Deadline

**Objective**: Validate the timeout path at the production timeout value, and that the wait runs to the full deadline.

**Test Steps**

1. Set `graceful_shutdown_timeout` to the production value.
2. Hold the pre-check.
3. Trigger `GRACEFUL_SHUT`, verify the pre-check was entered, and let the wait run out.
4. Verify the operation ran to the **full deadline** before forcing, and is recorded `SUCCESS_FORCED` with `op_reason = deadline`.

---

## Test Case 6: Host Pre-Shutdown Failure

**Objective**: Validate that when the host reports its pre-shutdown did not complete, the operation is recorded forced with `op_reason = check_failed`.

**Test Steps**

1. Fail the pre-check.
2. Trigger `GRACEFUL_SHUT`.
3. Verify the pre-check was entered, and the result is `SUCCESS_FORCED` with `op_reason = check_failed`.

---

## Test Case 7: Critical Leak Interrupts an Operation in Flight

**Objective**: Validate that a critical leak interrupts an operation that is in its graceful wait.

**Test Steps**

1. Enter a controlled critical state: pause `thermalctld` and configure the critical leak action as a power off.
2. Hold the pre-check, submit `GRACEFUL_SHUT`, wait until the operation enters `GRACEFUL_SHUTTING_DOWN`, and verify the pre-check was entered.
3. Publish the CRITICAL leak state.
4. Verify the original operation is recorded `PREEMPTED`.

---

## Test Case 8: An Existing Critical Leak Blocks Every Power Raise

**Objective**: Validate that while a critical leak stands, every request that would raise power is refused.

**Test Steps**

1. Enter a controlled critical state and publish the CRITICAL leak state. Wait until the resulting `power_off` has finished and the switch-host is off.
2. Submit `POWER_ON`. Verify it is refused with `status = FAILED` and `result = POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE`, and that the host stays off.
3. Run `config chassis modules shutdown SWITCH-HOST` then `config chassis modules startup SWITCH-HOST`. Verify the BMC event log records the startup blocked with `POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE` and that the host stays off.

---

## Test Case 9: Configuration Boundaries

**Objective**: Validate that `shutdown-timeout` accepts any non-negative integer and rejects everything else.

**Test Steps**

1. Configure `config chassis modules shutdown-timeout SWITCH-HOST <value>` with `0`, `1`, `120` and a value far above the default such as `3600`, and verify each is accepted and read back from CONFIG_DB.
2. Configure a negative value, a non-numeric value and a fractional value, and verify each is rejected with a CLI error and CONFIG_DB keeps the previous value.

---

## Test Case 10: Logging, State and Forensics

**Objective**: Validate everything an operator can see after an operation has finished.

**Test Steps**

1. Submit `GRACEFUL_SHUT` from the Rack Manager and run it to completion.
2. Verify `HOST_STATE|switch-host` stores `op_request_id`, `op_trigger`, `op_result` and `op_reason`, and that the BMC log's `OP_DONE` record for that request id carries the same values. These two record the request id and the detailed outcome.
3. Verify `show chassis modules status` shows the new `Result` column with **the existing columns and their order unchanged**, and that the Rack Manager receipt row reports `status = DONE` and `result = SUCCESS`. The receipt carries no request id or detailed outcome.
4. Recover the switch-host, then verify the latest `show reboot-cause history` entry shows the BMC power-down hardware cause in its comment.
