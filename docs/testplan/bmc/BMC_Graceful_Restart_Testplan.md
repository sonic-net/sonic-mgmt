# 1. Feature Overview

On a chassis where SONiC runs on both the BMC and the switch-host, the BMC owns switch-host power. Today it removes that power without telling the host, so the host cannot flush its state, cannot run any platform ordering it needs, and cannot record why it went down.

This feature adds a handshake before the power off:

- A **graceful leg** is added to the existing `GRACEFUL_SHUT` command — ask the host to prepare, then remove power.
- A new **`GRACEFUL_RESTART`** command is added — the same shutdown, a short pause, then power on.

The handshake reuses the existing `System.RebootStatus`: the BMC asks, the host runs its normal reboot teardown without rebooting, and reports the result.

# 2. Operation Flow

## 2.1. Graceful shutdown

The power state sequence is `GRACEFUL_SHUTTING_DOWN` -> `POWERING_OFF` -> `POWERED_OFF`.

The outcome is recorded in `HOST_STATE|switch-host` and in the BMC event log.

**The reporting path survives the teardown.** `database`, `gnmi`, `sysmgr` and `sonic-hostservice` keep running, which is what lets the host answer the BMC's poll after its own teardown is done.

**The host never removes its own power.** `reboot -p` asks the watchdog to arm before it exits, so a host left powered is meant to reboot itself back into service.

## 2.2. Graceful restart

`GRACEFUL_RESTART` is the shutdown above, followed by a cancelable pause, then power on.

The power state sequence is `GRACEFUL_SHUTTING_DOWN` -> `POWERING_OFF` -> `POWERED_OFF` -> `POWERING_ON` -> `POWERED_ON`.

# 3. Related Command and Configuration

No new command is added. The existing chassis-module commands are the entry point.

```
bmc$ config chassis modules shutdown SWITCH-HOST
bmc$ config chassis modules startup  SWITCH-HOST
bmc$ config chassis modules shutdown-timeout SWITCH-HOST <seconds>
```

`config chassis modules shutdown-timeout` updates the **upper limit**. Previously any non-negative value was accepted, so nothing stopped a timeout longer than the platform's watchdog.

`show chassis modules status` on the BMC adds `RESULT` and `REQUEST-ID` columns.

```
bmc$ show chassis modules status
  Name         Description  Oper-Status  Admin-Status  Serial   Power-On-Delay (sec)  Shutdown-Timeout (sec)  Result            Request-Id
  SWITCH-HOST  Switch Host  Online       down          SN12345  0                     120                     -                 3f2b1c8a-...-9d41
  SWITCH-HOST  Switch Host  Offline      down          SN12345  0                     120                     SUCCESS_GRACEFUL  3f2b1c8a-...-9d41

host (next boot)$ show reboot-cause
  graceful shutdown from BMC
```

# 4. Test Cases

## 4.1. Summary

**Power is always removed; the handshake only decides how the operation is recorded** — graceful when the host confirmed it finished, forced otherwise. The cases are organised around that: group A covers the operations that end up recorded graceful, group B covers every way an operation ends up recorded forced, group C covers the two results that are neither, and group D covers the configuration and the operator-visible record.

| Category | # | Test case | Focus |
| --- | --- | --- | --- |
| **A. Normal flow** | 1 | Graceful Shutdown via CLI and Rack Manager | Both entry points run the same flow; recorded `SUCCESS_GRACEFUL`; the host reports the graceful reboot cause |
| | 2 | Graceful Restart | Down and back up under one request id; `admin_status` untouched; graceful reboot cause |
| **B. Degraded to forced**<br>*(one case per `op_reason`)* | 3 | Preconditions Not Met — No Request Is Sent | `not_qualified` / `timeout_zero` / `already_off` — proved by zero packets on the wire |
| | 4 | BMC to Host Communication Failure | `rpc_failure` — the gNMI service is gone when the BMC dials |
| | 5 | No Answer Before the Deadline | `deadline` — and that the wait is not ended early |
| | 6 | Host Pre-Shutdown Failure | `check_failed` — the host reports it did not complete |
| **C. Critical leak** | 7 | Critical Leak Interrupts an Operation in Flight | `PREEMPTED`, injected into both the graceful wait and the restart pause |
| | 8 | An Existing Critical Leak Blocks Every Power Raise | `CRITICAL_LEAK_PRESENT` — every power raise is refused while the leak stands |
| **D. Configuration and observability** | 9 | Configuration Boundaries | The new `shutdown-timeout` upper limit and its rejected values |
| | 10 | Logging, State and Forensics | The recorded fields, the new columns, the support bundle |

## 4.2. Conventions

| Term | What it means |
| --- | --- |
| *Pre-shutdown hook* | `pre_reboot_hook` in the host's platform directory, a product file SONiC runs before it tears the host down. The fixture replaces it with a wrapper that counts invocations, can block the host inside its pre-shutdown, and can exit non-zero on demand. The original is restored on teardown. |
| *Hold the pre-shutdown hook* | Create the wrapper's hold flag before triggering, remove it to release. Its timeout has to exceed `graceful_shutdown_timeout`, or Test Case 5 records `check_failed` instead of `deadline`. |
| *Power state* | STATE_DB `HOST_STATE\|switch-host`, field `device_power_state`, on the BMC. |
| *gNMI wire check* | A packet capture on the BMC filtered to the host's gNMI port, used **only to count packets** — gNOI runs over mTLS, so a capture can prove a request was never sent but not what a sent one contained. |

---

## Test Case 1: Graceful Shutdown via CLI and Rack Manager

**Objective**: Validate the complete graceful shutdown flow, that the chassis CLI and the Rack Manager `GRACEFUL_SHUT` command run the same flow, and that a completed operation is positively attributed.

This is the case an operator would run by hand, so it is kept to what an operator can see.

**Test Steps**

1. **Pass 1 (CLI)** — run `config chassis modules shutdown SWITCH-HOST` on the BMC.
2. Verify the switch-host is really down — the BMC reports it `OFFLINE` and the host is physically unreachable.
3. Verify `show chassis modules status` reports `RESULT = SUCCESS_GRACEFUL` with a `REQUEST-ID`.
4. Power the switch-host back on, and verify `show reboot-cause` reports the **graceful** cause rather than the BMC power-down cause.
5. Verify the BMC event log's `OP_DONE` record for that request id is the same as the CLI output.
6. **Pass 2 (Rack Manager)** — Trigger graceful shutdown by Rack Manager and repeat the test.

---

## Test Case 2: Graceful Restart

**Objective**: Validate that `GRACEFUL_RESTART` takes the switch-host down and brings it back under a single operation, without disturbing `admin_status`.

**Entry point**: Rack Manager only. There is no CLI for restart in this release.

**Test Steps**

1. Record `admin_status` from both CONFIG_DB and the STATE_DB runtime mirror, then submit `GRACEFUL_RESTART` through `RACK_MANAGER_COMMAND`.
2. Verify the switch-host went down and came **back up by itself** — the boot id changed, the image is as expected, and the host health checks pass. No operator action is needed in between, which is what separates a restart from a shutdown followed by a startup.
3. Verify `show reboot-cause` reports the **graceful** cause.
4. Verify `admin_status` is unchanged for the whole operation, in both the persisted configuration and the runtime mirror. A restart must not leave the module administratively down.
5. Verify the whole restart used **exactly one request id** across both power legs. A second id appearing on the power-on leg would mean the two legs were not run as one operation.

---

## Test Case 3: Preconditions Not Met — No Request Is Sent

**Objective**: Validate that when the graceful leg cannot run, the BMC falls back to today's forced behaviour without touching the host.

**Expected outcome for every sub-scenario**: zero packets to the host gNMI port, power removed, result `SUCCESS_FORCED` with the reason below.

| # | Precondition to establish | Expected `op_reason` | Additional check |
| --- | --- | --- | --- |
| 1 | Move the BMC client certificate to another location | `not_qualified` | — |
| 2 | Set `graceful_shutdown_timeout = 0` | `timeout_zero` | — |
| 3 | Power the switch-host off first, so it already reads `OFFLINE` | `already_off` | The request completes **without a second power call** being issued |

**Test Steps** (repeat for each sub-scenario)

1. Start the gNMI wire check, then establish the precondition from the table.
2. Trigger `GRACEFUL_SHUT`.
3. **Verify the capture recorded zero packets** to the host gNMI port. This is what separates it from Test Case 4, where packets are sent and the transport fails.
4. Verify the result is `SUCCESS_FORCED` with the expected `op_reason`.
5. Perform the sub-scenario's additional check from the table.

---

## Test Case 4: BMC to Host Communication Failure

**Objective**: Validate that a transport-level failure between the BMC and the host degrades to forced, and is recorded `rpc_failure`.

**Test Steps**

1. Hold the host's pre-shutdown hook.
2. Trigger `GRACEFUL_SHUT`, wait until the operation enters `GRACEFUL_SHUTTING_DOWN`, and confirm the hook is really being held.
3. Stop `gnmi.service` on the host.
4. Verify the result is `SUCCESS_FORCED` with `op_reason = rpc_failure`, that `graceful_shutdown_timeout` was not exceeded, and that the failure did **not** block the forced power-off.
5. Restart `gnmi.service`.

---

## Test Case 5: No Answer Before the Deadline

**Objective**: Validate the timeout path at the production timeout value, and that the wait runs to the full deadline.

**Test Steps**

1. Set `graceful_shutdown_timeout` to the production value.
2. Hold the host's pre-shutdown hook.
3. Trigger `GRACEFUL_SHUT` and let the wait run out.
4. Verify the operation ran to the **full deadline** before forcing, and is recorded `SUCCESS_FORCED` with `op_reason = deadline`.

---

## Test Case 6: Host Pre-Shutdown Failure

**Objective**: Validate that when the host reports its pre-shutdown did not complete, the operation is recorded forced with `op_reason = check_failed`.

**Test Steps**

1. Touch the pre-shutdown hook's fail flag so it exits non-zero.
2. Trigger `GRACEFUL_SHUT`.
3. Verify the result is `SUCCESS_FORCED` with `op_reason = check_failed`.

---

## Test Case 7: Critical Leak Interrupts an Operation in Flight

**Objective**: Validate that a critical leak interrupts an operation that is waiting, in both of the waits an operation can be sitting in.

**Two injection points are required** — the graceful wait is the RPC polling loop, the restart pause is a separate wait, and only the second is where a transient power raise would be visible.

**Test Steps** (injection point 1 — during the graceful wait)

1. Enter a controlled critical state: pause `thermalctld` and configure the critical leak action as a power off.
2. Hold the host's pre-shutdown hook, submit `GRACEFUL_RESTART`, and wait until the operation enters `GRACEFUL_SHUTTING_DOWN`.
3. Publish the CRITICAL leak state.
4. Verify the original operation is recorded `PREEMPTED`.

**Test Steps** (injection point 2 — during the restart's powered-off pause)

1. Repeat steps 1 and 2 **without** holding the hook, waiting until the power state reaches `POWERED_OFF`.
2. Publish the CRITICAL leak state.
3. Verify the original operation is recorded `PREEMPTED`, and that the host does not power back on.

---

## Test Case 8: An Existing Critical Leak Blocks Every Power Raise

**Objective**: Validate that while a critical leak stands, every request that would raise power is refused.

**Test Steps**

1. Enter a controlled critical state and publish the CRITICAL leak state. Wait until the resulting `power_off` has finished and the switch-host is off.
2. Submit `POWER_ON`. Verify it is refused with `result = CRITICAL_LEAK_PRESENT`.
3. Run `config chassis modules shutdown SWITCH-HOST` then `config chassis modules startup SWITCH-HOST`. Verify the BMC event log records the startup blocked with `CRITICAL_LEAK_PRESENT` and that the host stays off.
4. Submit `GRACEFUL_RESTART`. Verify it is refused with `CRITICAL_LEAK_PRESENT`.

---

## Test Case 9: Configuration Boundaries

**Objective**: Validate the configuration this feature changes — the new `shutdown-timeout` upper limit.

**Test Steps**

1. Configure `config chassis modules shutdown-timeout SWITCH-HOST <value>` with a set of valid values, including the boundary values on both ends, and verify each is accepted and read back correctly from CONFIG_DB.
2. Configure a value above the **new upper limit**, a negative value and a non-numeric value, and verify each is rejected with an appropriate error in the syslog.

---

## Test Case 10: Logging, State and Forensics

**Objective**: Validate everything an operator can see after an operation has finished.

**Test Steps**

1. Run one graceful shutdown to completion and recover the switch-host.
2. Verify `HOST_STATE|switch-host` stores `op_request_id`, `op_trigger`, `op_result` and `op_reason`, and that the BMC log's `OP_DONE` record carries the same values.
3. Verify `show chassis modules status` shows the new `RESULT` and `REQUEST-ID` columns with **the existing columns and their order unchanged**, and that the Rack Manager receipt row carries the matching `request_id` and `result`.
4. Verify the latest `show reboot-cause history` entry shows the BMC power-down hardware cause in its comment.
5. Collect a support bundle from the BMC and verify it contains `HOST_STATE` and the BMC event log (`/host/bmc/event.log`).

