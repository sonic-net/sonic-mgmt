# PFC Watchdog Hardware Recovery Test Plan

- [Overview](#overview)
- [Scope](#scope)
- [Related work](#related-work)
- [Background](#background)
- [Test setup](#test-setup)
- [Running the existing tests in both mechanisms](#running-the-existing-tests-in-both-mechanisms)
- [New test cases](#new-test-cases)
- [Dependencies](#dependencies)

## Overview

On Broadcom, orchagent picks one of three PFC watchdog modes from the SAI capabilities (`selectPfcWdRecoveryMode()` in `pfcwdhworch.cpp`):

- **Hardware:** the SAI supports both `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` and `SAI_QUEUE_ATTR_PFC_DLR_INIT`. The ASIC detects the deadlock and applies the action. orchagent (`PfcWdHwOrch`) programs it and reports its state.
- **Hybrid DLR:** the SAI supports `SAI_QUEUE_ATTR_PFC_DLR_INIT` only. The software watchdog detects the storm and starts the ASIC's recovery through the DLR handler.
- **Software:** any other case (neither attribute, or `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` only). The software watchdog detects the storm and mitigates it with the ACL handler.

Other platforms always run the software watchdog with a fixed handler, and no capability check: a zero-buffer handler on Mellanox, VS, Marvell, Clounix and Nephos, the ACL handler on Barefoot, and the DLR handler on Cisco-8000.

In the software and hybrid modes, detection runs in syncd, in the Lua plugin of the `PFC_WD` flex counter group, and orchagent receives the result as a notification. The design of the hardware mode is in the [PFC Watchdog Hardware-Based Detection and Recovery HLD](https://github.com/sonic-net/SONiC/blob/master/doc/pfcwd/pfc_watchdog_hardware_detection_recovery.md).

This plan covers two things:

1. Running every test in `tests/pfcwd/` under each mechanism the DUT supports, and checking the result that mechanism should give.
2. New cases for behaviour the existing tests do not reach: timer limits, the switch-wide action, changes made to a running watchdog, changes made during a storm, restarts and warm reboot, the counters the watchdog reports, and the hardware-mode CLI output.

[PFCWD_BASIC.md](PFCWD_BASIC.md) describes the software watchdog's detection, mitigation and restoration. This plan does not repeat it.

## Scope

- Single-ASIC DUTs on t0 and t1 topologies with a fanout that can send PFC frames.
- The hardware expectations apply to Broadcom platforms where `STATE_DB SWITCH_CAPABILITY|switch` has both `PFC_DLDR_CAPABLE` and `PFC_DLR_INIT_CAPABLE` set to `true`. `PfcWdHwOrch` is created only there.
- The software expectations are written for the ACL handler. On a platform with another handler, a case keeps the per-platform rules the existing tests already apply (for example `set_traffic_action()` in `test_pfcwd_function.py`, which expects arriving traffic to be forwarded on Mellanox, Cisco-8000 and Innovium, and with tunnel QoS remap), and skips a check that needs ACL drop rules. In hybrid DLR mode, which exists only on Broadcom, the action is switch-wide, as in hardware mode (case 5).

Out of scope: multi-ASIC DUTs (the checks read one DB namespace), the gNMI telemetry cases in section 12 of the HLD, and `snappi_tests/pfcwd`, which uses a traffic generator instead of a fanout.

## Related work

| Item | What it provides | State |
|---|---|---|
| [SONiC HLD](https://github.com/sonic-net/SONiC/blob/master/doc/pfcwd/pfc_watchdog_hardware_detection_recovery.md) | Hardware watchdog design. Section 12 lists test requirements | Merged |
| [sonic-swss#4412](https://github.com/sonic-net/sonic-swss/pull/4412) | `PfcWdHwOrch`, selected from the SAI capability | Merged |
| [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) | Storm counters and `PFC_WD_STATUS` for the hardware watchdog. Makes `restoration_time` optional in hardware mode | Open |
| [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090) | Clear stale hardware watchdog state at startup | Open |
| [sonic-swss#5091](https://github.com/sonic-net/sonic-swss/pull/5091) | Retry a start with a new action while the stop is still tearing down | Open |
| [sonic-swss#5092](https://github.com/sonic-net/sonic-swss/pull/5092) | Stop rewriting a deferred port's state on every retry | Open |
| [sonic-swss#5100](https://github.com/sonic-net/sonic-swss/pull/5100) | Storm history in STATE_DB (`PFC_WD_STATE`, `PFC_WD_STORM_HISTORY`). Builds on [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) | Open |
| [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) | Hardware mode in `show pfcwd config` and `show pfcwd config --json`, range checks in `pfcwd start`, refuses `pfcwd interval` and `pfcwd big_red_switch` in hardware mode | Open |
| [sonic-utilities#5002](https://github.com/sonic-net/sonic-utilities/pull/5002) | `show pfcwd stats --history` | Open |
| [sonic-mgmt#29060](https://github.com/sonic-net/sonic-mgmt/pull/29060) | Runs `tests/pfcwd/` in software mode on a hardware platform, when `--pfcwd-recovery-modes` asks for it | Open |
| [sonic-mgmt#23430](https://github.com/sonic-net/sonic-mgmt/pull/23430) | Hardware mode in the existing modules. Needs [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) at run time | Merged |
| [sonic-utilities#4898](https://github.com/sonic-net/sonic-utilities/pull/4898) | `pfcwd start` refuses a detection or restoration time below the configured `POLL_INTERVAL` | Merged |
| [sonic-mgmt#27982](https://github.com/sonic-net/sonic-mgmt/pull/27982) | PFC watchdog timer validation tests | Open |

## Background

### How the mechanisms differ

| | Software watchdog (ACL handler) | Hardware watchdog |
|---|---|---|
| Detection | The `PFC_WD` group's Lua plugin finds the queue paused for `detection_time` | The ASIC detects the deadlock and raises `SAI_SWITCH_NOTIFICATION_NAME_QUEUE_PFC_DEADLOCK` |
| Drop action | ACL rules drop traffic leaving the queue and traffic arriving on its priority | The ASIC drops traffic leaving the queue. Traffic arriving on the port is not dropped |
| Action per port | Each port can have its own action. In hybrid DLR mode the action is switch-wide | One action for the whole switch, `SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION` |
| Timers | The CLI and GCU check them against sonic-pfcwd.yang. orchagent checks the same ranges, and drops a row outside them with two ERROR logs. Only the YANG rule that ties the timers to `POLL_INTERVAL` has no orchagent check | The CLI and GCU check YANG. orchagent checks them against the range the SAI reports, if it reports one. The ASIC may round them |
| `PFC_WD\|GLOBAL` (`POLL_INTERVAL`, `BIG_RED_SWITCH`), `pfcwd interval`, `pfcwd big_red_switch` | Used | Not used. orchagent drops a `GLOBAL` row. The CLI refuses the two commands, and `pfcwd start_default` removes `POLL_INTERVAL` ([sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384)) |
| `pfc_stat_history` | Recorded by the Lua plugin | Accepted and ignored, with a WARN |
| `--action alert` | Supported | orchagent rejects it |

### State the tests read

| Location | Fields |
|---|---|
| `STATE_DB SWITCH_CAPABILITY\|switch` | `PFC_DLDR_CAPABLE`, `PFC_DLR_INIT_CAPABLE` |
| `STATE_DB PFC_WD_STATE_TABLE\|PFC_WD` | `RECOVERY_MECHANISM`, `DETECTION_TIME_MIN/MAX`, `RESTORATION_TIME_MIN/MAX`, `DLR_PACKET_ACTION` |
| `STATE_DB PFC_WD_HW_STATE\|<port>` | `recovery_type`, `status` (`configured` or `failed`), `configured_detection_time`, `configured_restoration_time`, `hw_detection_time`, `hw_restoration_time`, `action`. `hw_*` is the SAI read-back, or the configured value when the read-back fails |
| `STATE_DB PFC_WD_SW_STATE_TABLE\|<port>:<queue>` | `status`, written by the software watchdog |
| `STATE_DB PFC_WD_STATE\|<port>\|<queue>`, `PFC_WD_STORM_HISTORY\|<port>\|<queue>` | Storm state and history ([sonic-swss#5100](https://github.com/sonic-net/sonic-swss/pull/5100)) |
| `COUNTERS_DB COUNTERS:<queue oid>` | `PFC_WD_STATUS` and the `PFC_WD_QUEUE_STATS_*` storm counters |
| `ASIC_DB` queue object | `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` |
| `ASIC_DB` port object | `SAI_PORT_ATTR_PFC_TC_DLD_INTERVAL`, `SAI_PORT_ATTR_PFC_TC_DLR_INTERVAL` |
| `ASIC_DB` switch object | `SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION` |

The HLD is not consistent about the capability table: section 5.1 names `PFC_WD_HW_CAPABILITIES|GLOBAL`, and section 7.1 names `PFC_WD_GLOBAL|GLOBAL` and a per-queue `PFC_WD_STATE`. [sonic-swss#4412](https://github.com/sonic-net/sonic-swss/pull/4412) writes `PFC_WD_STATE_TABLE|PFC_WD`, and this plan follows the code.

### Hardware recovery: the expected events

The SAI defines the recovery timer this way (`SAI_PORT_ATTR_PFC_TC_DLR_INTERVAL` in `saiport.h`): recovery runs for `restoration_time` R, then normal state resumes, and if the queue is still deadlocked, detection and recovery start again after `detection_time` D. So a storm longer than D + R gives a DETECTED and RECOVERED pair every D + R or so, and a RECOVERED marks the end of R, not the end of the pause.

A SAI can instead end recovery when the pause stops, and not use R. The Broadcom SDK's PFC-state recovery mode does this, when the SAI configuration selects it. Then a storm gives one pair, and the RECOVERED comes after the pause stops, at the next scan of the recovery process.

Which model applies depends on the SAI and its configuration, not only on the ASIC. No SAI attribute tells the two apart, so the suite keeps a per-platform table (see [Platform values](#platform-values)). Every case that counts events, or waits for a RECOVERED, uses the model the table gives.

## Test setup

### Running each module in both mechanisms

By default each module runs once, in the DUT's own mechanism, read from `RECOVERY_MECHANISM`. [sonic-mgmt#29060](https://github.com/sonic-net/sonic-mgmt/pull/29060) adds a software phase on a hardware platform, run only when `--pfcwd-recovery-modes` lists it (the default is `native`). It works this way:

- It forces software mode on Broadcom only, on a SAI library that has the `sai_pfc_dldr_capability` property. Otherwise the phase skips.
- It sets `sai_pfc_dldr_capability=0` in the platform's SAI configuration files, and changes `sai_stats_support_mask` to the software value in the YAML files that have it. Then it restarts swss.
- It switches once per session, and switches back when the software phase ends.
- Before every test of the phase, it reads back `RECOVERY_MECHANISM` = `software`, and `PFC_DLDR_CAPABLE` and `PFC_DLR_INIT_CAPABLE` = `false`. An absent field fails the read-back.
- It deletes no STATE_DB key, and it does not read the mechanism back after the switch back.

On current master the read-back fails:

- Only `PfcWdHwOrch` writes `RECOVERY_MECHANISM`. `PFC_WD_RECOVERY_SOFTWARE` is defined in `pfcwdorch.h` but no code writes it.
- A swss cold start does not clear `PFC_WD_STATE_TABLE*`, `PFC_WD_HW_STATE*` or `PFC_WD_SW_STATE_TABLE*` (`swss.sh`), and [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090) clears `PFC_WD_HW_STATE` only in the `PfcWdHwOrch` constructor.

So after a restart into software mode, `RECOVERY_MECHANISM` is still `HARDWARE`, and the software phase fails at its first test. [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) also reads `RECOVERY_MECHANISM`, and without the deletions below would apply the hardware rules in the software phase.

The suite can still prove software mode on master. switchorch writes `PFC_DLDR_CAPABLE` and `PFC_DLR_INIT_CAPABLE` at every start, orchagent picks the mode from those two values alone, and only the `PfcWdHwOrch` constructor writes `RECOVERY_MECHANISM`. So:

- After swss stops and before it starts in software mode, the suite deletes `PFC_WD_STATE_TABLE|PFC_WD` and every `PFC_WD_HW_STATE|*` key, which its own mode switch makes stale.
- After the restart, it requires both capabilities to be `false`, `RECOVERY_MECHANISM` to be absent or `SOFTWARE`, and no `PFC_WD_HW_STATE|*` key. The capabilities rule out hybrid DLR mode, which orchagent picks when only `SAI_QUEUE_ATTR_PFC_DLR_INIT` is supported. After the deletion, an absent `RECOVERY_MECHANISM` shows that no `PfcWdHwOrch` was built.
- When the phase ends and swss restarts into hardware mode, it requires `RECOVERY_MECHANISM` to be `HARDWARE`, and deletes every `PFC_WD_SW_STATE_TABLE|*` key the software phase left.

These are changes to [sonic-mgmt#29060](https://github.com/sonic-net/sonic-mgmt/pull/29060) (see [Dependencies](#dependencies)).

A stale `HARDWARE` value also misleads the CLI after any swss restart that changes the mode. So the plan also lists an orchagent change: the software watchdog writes `RECOVERY_MECHANISM=SOFTWARE` and clears the other watchdog's rows when it starts. Once that is in the image, the read-back requires `SOFTWARE`, through a conditional mark by image version (see [Dependencies](#dependencies)).

A platform that cannot change mechanism runs only its own phase. No platform can be forced from software to hardware.

### Platform values

Some expectations depend on platform behaviour that neither the SAI nor STATE_DB reports. The suite keeps them in one file in the repository, under `tests/pfcwd/files/`, keyed by platform and, where it matters, by SAI configuration. Nothing is probed at run time, because nothing on the DUT reports these values. A case that needs a value the file does not have for the DUT skips, and the skip message names the missing entry.

| Value | Used by |
|---|---|
| Detection window: for a configured detection time, the earliest and latest time detection may fire after the pause starts. Given as a rule, because ASICs round differently: to a fixed step, or to the nearest power of two of a clock count, which can be well above or below the configured value. `hw_detection_time` does not always show the rounding | Cases 1 and 11, and the timer accuracy module |
| Recovery model: timer-based (SAI definition) or ends when the pause stops | Cases 2, 6, 8, 12, 13 |
| Recovery tolerance: how late a RECOVERED may come after its expected time. Under the pause-ends model this is the scan interval of the recovery process, which can be coarser than the detection step | Case 2 |
| Port groups that share one detection timer | Case 11 |

### Rules for every case

- Each case checks the result for the mechanism it runs in. A case that has no meaning in one mechanism skips there, with the reason in the skip message.
- Each storm is checked on the DUT: the port's PFC RX counter for the stormed priority (`SAI_PORT_STAT_PFC_<n>_RX_PKTS`) rises before the test expects a detection.
- A case restores the configuration it found, including whether the watchdog was running on each port, and leaves no storm running.
- A case that changes `PFC_WD|GLOBAL` records its fields first. In software mode, removing a field does not undo it in orchagent: the poll interval and `BIG_RED_SWITCH` stay until orchagent restarts. So the case runs `pfcwd big_red_switch disable` if it enabled it, and `pfcwd interval` with the recorded value, or with orchagent's default of 100 ms (`PFC_WD_POLL_MSECS`) when the field was absent. Then it removes only the fields it added. `pfcwd start_default` writes `POLL_INTERVAL` in software mode, so the field can exist before the case.
- Timers are chosen inside the usable range: the intersection of the STATE_DB range and the sonic-pfcwd.yang range (detection 100–5000 ms, restoration 100–60000 ms). When the SAI reports no range, orchagent writes no range fields and checks nothing, and the usable range is the YANG range.

## Running the existing tests in both mechanisms

These modules already exist. Each runs in the DUT's own mechanism, and in the software phase when [sonic-mgmt#29060](https://github.com/sonic-net/sonic-mgmt/pull/29060) is asked for it (see [Running each module in both mechanisms](#running-each-module-in-both-mechanisms)). The hardware-mode changes below are on master from [sonic-mgmt#23430](https://github.com/sonic-net/sonic-mgmt/pull/23430), except where a row says no PR has them yet.

[sonic-mgmt#23430](https://github.com/sonic-net/sonic-mgmt/pull/23430) needs [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) at run time, and has no probe for it: it picks the hardware path from `RECOVERY_MECHANISM` alone. On a hardware-mode image without [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854), `show pfcwd stats` has no rows and the queues have no `PFC_WD_*` counters, so these tests fail rather than skip:

- `test_pfcwd_function.py`: `test_pfcwd_storm_during_traffic` ("PFC storm was not detected"), and the tests that read the TX counters from COUNTERS_DB (`test_pfcwd_actions`, `test_pfcwd_multi_port`, `test_pfcwd_mmu_change`, `test_pfcwd_port_toggle`).
- `test_pfcwd_cli.py::test_pfcwd_show_stat`.
- `test_pfcwd_all_port_storm.py::test_all_port_storm_restore`.

A follow-up PR adds the [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) probe from [Dependencies](#dependencies) to these tests. No PR has it yet.

| Module | Change for hardware mode |
|---|---|
| `test_pfcwd_function.py` | Skip the RX checks, since the hardware acts on the egress queue only. Keep the timers inside the hardware range. Use `drop` in place of `dontcare` |
| `test_pfcwd_cli.py` | The same changes as `test_pfcwd_function.py` |
| `test_pfcwd_all_port_storm.py` | Do not run `pfcwd interval 200`, which [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) refuses in hardware mode. In software mode, also check that the `PFC_WD` poll finishes within its interval with every port stormed; no PR has this check yet |
| `test_pfcwd_timer_accuracy.py` | Keep the timers inside the hardware range. Judging detection against the platform's detection window is in no PR yet |
| `test_pfcwd_warm_reboot.py` | Turn off the fake storm (`DEBUG_STORM`) in hardware mode, through the `fake_storm` fixture. The hardware watchdog does not read it |
| `test_pfcwd_stat_history.py` | Skip in hardware mode; no PR has this yet. The module starts the watchdog with `action="alert"`, which the hardware watchdog rejects, and tests `pfc_stat_history`, which only the software Lua plugin computes. The skip conditions on master cover other ASICs, older releases and some topologies, not hardware mode |
| `test_pfc_config.py` | In hardware mode, clamp the template timers to the hardware range, push only the timer under test outside it, and expect the "is outside the supported range" log. In software mode, expect the "Failed to parse PFC Watchdog" log |

`test_xon_not_counted.py` does not start the watchdog and runs on `lt2` and `ft2`, so it is outside this plan.

## New test cases

Each case lists what it does, then what to expect in each mechanism. "Needs" names an open upstream PR, or a change no PR proposes yet, that the expectation depends on. "Software" means the ACL handler (see [Scope](#scope)).

### 1. Detection window

Storm a lossless queue for slightly less than the detection time, then for slightly more.

- **Software:** no detection for the shorter storm. The longer storm is detected at the first poll after `detection_time`.
- **Hardware:**
  - Detection fires inside the platform's detection window for the value programmed. The window is computed from `hw_detection_time`, since the ASIC may round the configured value down, and the rule has to cover the rounding when `hw_detection_time` shows the configured value (the SAI read-back returns it, or the read-back fails and orchagent keeps it).
  - After the start, ASIC_DB shows what orchagent programmed. `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` is `true` on each watched queue (the TCs in the port's `pfcwd_sw_enable`), and absent or `false` on the port's other queues. In `SAI_PORT_ATTR_PFC_TC_DLD_INTERVAL` and `SAI_PORT_ATTR_PFC_TC_DLR_INTERVAL`, each watched TC maps to `configured_detection_time` and `configured_restoration_time`. The `hw_*` fields are not compared here, since they can differ.

### 2. One continuous storm

Hold one storm for several times D + R, then stop it.

- **Software:** one detection. The queue restores `restoration_time` after the pause stops, for both actions. With the forward action, traffic keeps flowing during the storm.
- **Hardware, timer-based recovery:** a DETECTED and RECOVERED pair about every D + R while the storm lasts. Each RECOVERED comes R after its DETECTED, within the recovery tolerance. After the storm stops, the last RECOVERED arrives and no further DETECTED does. The detect count equals the restore count.
- **Hardware, recovery that ends with the pause:** one DETECTED and one RECOVERED. The RECOVERED comes after the pause stops, within the recovery tolerance.

### 3. Drop action, in both directions

With the drop action and a stormed queue, send traffic that leaves through the stormed queue, and traffic that arrives on the stormed port at that priority.

- **Software:** both directions are dropped. The TX drops in `show pfcwd stats` include the egress ACL drops.
- **Hardware:** egress traffic is dropped and arriving traffic is forwarded. The queue's dropped packets and the TX drops in `show pfcwd stats` agree, and so does the port's `IF_OUT_DISCARDS` where the platform counts these drops there. This includes packets dropped just before detection and just after restore. Needs [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854).

### 4. Timer limits at each entry point

Try timers just inside and just outside each range through `pfcwd start`, a `PFC_WD` row written to CONFIG_DB, a GCU patch, and the configuration loaded at boot. Include a value inside the hardware range and outside the YANG range, and the reverse.

- **Software:**
  - The CLI and GCU check sonic-pfcwd.yang. orchagent checks the same ranges: it drops a row outside them and logs two ERROR messages ("Failed to parse PFC Watchdog ..." and "Failed to process PFC watchdog SET task, invalid entry"). Only the YANG rule that ties the timers to `POLL_INTERVAL` has no orchagent check, so a CONFIG_DB row with a timer below `POLL_INTERVAL` is programmed.
  - A row without `restoration_time` is accepted. Once its queue storms, it is never restored: orchagent writes an empty restoration time, and the restore plugin skips the queue. With the drop or forward action, the queue stays stormed, with its handler in place, until the row is removed, Big Red Switch is enabled, or orchagent restarts. The case uses the drop action and checks this, since it is what master does. With the alert action the detect plugin restores the queue. Whether software mode should refuse such a row, as hardware mode does without [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854), is open; no PR proposes a change.
- **Hardware:**

  | Entry point | Checks | Expected for a value outside |
  |---|---|---|
  | `pfcwd start` | The YANG range (`click.IntRange`), then the usable range ([sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384)). It should not apply the `POLL_INTERVAL` check, which has no meaning in hardware mode | Refused, nothing written. Both bounds of the usable range are accepted |
  | GCU | YANG, including the `POLL_INTERVAL` rule when `PFC_WD\|GLOBAL` exists | Refused, nothing written |
  | CONFIG_DB row, or the configuration at boot | orchagent checks the SAI range only | Outside the SAI range: logged and dropped, nothing programmed, no `PFC_WD_HW_STATE` row. Inside the SAI range but outside YANG (for example 15 ms): accepted and programmed |

  - When the SAI reports no range: the CLI checks only YANG, and orchagent programs the value it is given.
  - Since [sonic-utilities#4898](https://github.com/sonic-net/sonic-utilities/pull/4898), `pfcwd start` refuses a detection or restoration time below the configured `POLL_INTERVAL`, in either mode, and GCU refuses the same through the YANG `must` rules. So in both modes the case runs its bound steps with no `POLL_INTERVAL`, or one at or below the lower bound of 100 ms, and restores the recorded value afterwards (see [Rules for every case](#rules-for-every-case)). In hardware mode the CLI cannot set `POLL_INTERVAL`, so a value left from software mode would block the start; the table above expects hardware-mode `pfcwd start` to skip the check. That needs [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) to keep it so when it is rebased on [sonic-utilities#4898](https://github.com/sonic-net/sonic-utilities/pull/4898).
  - When the SAI refuses a value inside its advertised range: the port's `PFC_WD_HW_STATE` row shows `failed`, orchagent retries, and the port shows `configured` once the row is changed to a value the SAI accepts. The suite writes the row to CONFIG_DB directly for this check.
  - A SAI that advertises a range it does not accept is a DUT defect. One SAI is known to advertise 1–1500 ms and accept only up to 15 ms, so no value the CLI or GCU allows (100 ms and up) can be programmed. Every hardware case that starts the watchdog through the CLI or GCU is affected, not only this one. So the suite checks once per module, before the first case, that the SAI accepts both bounds of the usable range, and fails the module with that reason when it does not.
  - `pfcwd start` without `--restoration-time` uses twice the detection time, capped at the hardware maximum ([sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384)). A CONFIG_DB row without `restoration_time` is accepted and keeps the restoration timer the hardware holds ([sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854)). On master without that PR, the row is logged and dropped.
  - Needs [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384). Related: [sonic-mgmt#27982](https://github.com/sonic-net/sonic-mgmt/pull/27982).

### 5. One action for the whole switch

Start the watchdog on two ports with different actions. Then stop it and start it again with another action.

- **Software:** each port keeps its own action.
- **Hardware:**
  - The CLI refuses a start that would leave two ports on different actions, with a message ([sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384)).
  - A CONFIG_DB row that would do the same is dropped: orchagent logs "PFC DLR packet action mismatch on port ..." at ERROR, and nothing changes in ASIC_DB. A row without an `action` is compared as `drop`.
  - `pfcwd stop` followed by `pfcwd start --action <other>` leaves the new action in `SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION`, and every port `configured`. Needs [sonic-swss#5091](https://github.com/sonic-net/sonic-swss/pull/5091).
- **Software in hybrid DLR mode:**
  - The CLI writes the row: [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) applies its checks only when `RECOVERY_MECHANISM` is `HARDWARE`, and in hybrid DLR mode nothing writes that field.
  - orchagent drops the row, and logs "Invalid PFC Watchdog action ... as switch level action ... is set" at ERROR. Nothing changes in ASIC_DB.
  - `pfcwd stop` followed by `pfcwd start --action <other>` leaves the new action in `SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION`.

### 6. Removing the watchdog leaves nothing behind

Storm a queue and remove the watchdog from the port, in three ways:

- a GCU patch that removes the port's `PFC_WD` row;
- `config reload` of a file built from the running configuration without that row. The saved configuration is not changed;
- after the storm stops and the RECOVERED arrives, `pfcwd stop`.

Separately, add a stale `PFC_WD_HW_STATE` row for an unwatched port and restart swss.

The GCU patch and `pfcwd stop` reach orchagent as a delete of the row. `config reload` does not: it stops the services, replaces CONFIG_DB and starts them again, so the new orchagent never sees the row and never calls `deleteEntry` for it. Only what orchagent clears at startup goes away. COUNTERS_DB and APPL_DB are flushed on the restart, so `PFC_WD_STATUS` is gone either way.

- **Software:**
  - GCU and `pfcwd stop`: the queue status, the `PFC_WD_SW_STATE_TABLE` rows and the ACL drop rules are removed, even when the queue is stormed at the time.
  - `config reload`: the ACL rules and the queue status are gone, and no `PFC_WD_SW_STATE_TABLE` row is left for the port. On master the rows stay, since only unregistering a port deletes them and nothing clears the table at startup. Needs an orchagent change that clears the table when the watchdog starts; no PR yet.
- **Hardware:**
  - GCU: a removal while the queue is stormed is deferred until the queue's next RECOVERED (case 8). Once it applies, no `PFC_WD_HW_STATE` row is left, and `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` is `false` on the queues that were watched.
  - `config reload`: nothing is deferred. After the restart, no `PFC_WD_HW_STATE` row is left for the port, and its queues have no `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` in ASIC_DB, which the restart flushed. Needs [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090) for the row.
  - No `PFC_WD_STATUS` is left in COUNTERS_DB. The hardware watchdog writes no COUNTERS_DB fields until [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854), so this check applies from then.
  - After the restart, `PFC_WD_HW_STATE` holds only the ports orchagent programmed. Needs [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090).

### 7. Changing the watched TCs

Change the port's `pfcwd_sw_enable` in PORT_QOS_MAP: drop one TC, clear it, and add a TC back. QosOrch only stores the new mask; the watchdog reads it when it starts on the port. So after each change the case restarts the watchdog on the port with `pfcwd stop` and `pfcwd start`.

- **Both:**
  - After the restart, a dropped TC is no longer watched, and an added TC is watched.
  - A port with no watched TC starts once a TC comes back.
- **Software:** the dropped TC's ACL rules are removed. A port with no watched TC logs "No lossless TC found on port" and "Failed to start PFC Watchdog on port" on every retry, at least once a second. The expectation is that it waits quietly, as in hardware mode. Needs a software watchdog change; no PR proposes it yet.
- **Hardware:** a released TC also has DLDR off. A port with no watched TC makes no SAI call while it waits. Its `PFC_WD_HW_STATE` row is written `failed` once and "No lossless TC found on port" is logged once, then nothing more while it waits (checked over 60 s). Needs [sonic-swss#5092](https://github.com/sonic-net/sonic-swss/pull/5092) for the single write and log.
- **Without a restart:** a mask change applies while the watchdog runs, for added and dropped TCs alike. Needs an orchagent change that passes the new mask to the watchdog; no PR proposes it yet.

### 8. Changes made during a storm

While a queue is stormed, run `pfcwd stop <port>`, and apply GCU patches that change `detection_time` or remove the port's row. Separately, drop the stormed TC from `pfcwd_sw_enable` and then remove the port's row.

- **Software:** each change applies at once.
- **Hardware:**
  - `pfcwd stop` is refused with a message and changes nothing. [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) finds the stormed queues from `PFC_WD_STATUS` in COUNTERS_DB, which the hardware watchdog writes only with [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854). Needs both.
  - A GCU change or removal is deferred until the queue's next RECOVERED, then applies: the new timer is programmed, or the watchdog is removed as in case 6. With timer-based recovery that RECOVERED can come while pause frames still arrive.
  - The removal after the stormed TC was dropped from the mask is still deferred. Today `isPortInStormedState()` reads the current mask, so the delete is not deferred and DLDR is turned off during the storm. Needs an orchagent change; no PR proposes it yet.

### 9. Settings that only the software watchdog uses

Write `PFC_WD|GLOBAL`, run `pfcwd interval`, `pfcwd big_red_switch enable`, and `pfcwd counter_poll disable` before a storm. Start a port with `--pfc-stat-history`. Separately, with no other port configured, start a port with `--action alert`. Afterwards, undo the `GLOBAL` settings as [Rules for every case](#rules-for-every-case) describes.

- **Software:**
  - `pfcwd interval`: the `PFC_WD` group's `POLL_INTERVAL` in FLEX_COUNTER_DB takes the new value.
  - `pfcwd big_red_switch enable`: every watched queue shows `BIG_RED_SWITCH_MODE` `enable` in COUNTERS_DB and drops its traffic, with no storm. `disable` clears both.
  - `pfcwd counter_poll disable`: the `PFC_WD` group is disabled in FLEX_COUNTER_DB, and a storm is not detected until the poll is enabled again.
  - `--pfc-stat-history`: the port's COUNTERS_DB entry gets, for the watched priority, the recent-pause fields that `show pfc counters --history` reads. A port that has not had the flag since swss last started has none.
  - `--action alert`: the storm is detected and the queue shows `stormed`, and its traffic is not dropped.
- **Hardware:**
  - orchagent drops the `GLOBAL` row and every port stays configured. Its INFO log does not reach syslog at the default NOTICE level, and `doTask` logs "Failed to process PFC watchdog SET task, invalid entry" at ERROR. The case expects that ERROR, and the log analyzer ignores it.
  - `pfcwd interval` and `pfcwd big_red_switch` return an error and write nothing ([sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384)).
  - With the counter poll disabled, detection and restore still happen.
  - `pfc_stat_history` is accepted and ignored with a WARN.
  - `--action alert` is refused by the CLI with a message. The case starts it on a port that is the only one configured. Today the CLI accepts it there, and orchagent drops the row with an ERROR, so the start fails silently. With another port on another action, [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) refuses it as an action mismatch. Needs a sonic-utilities change; no PR proposes it yet.

### 10. Warm reboot and PFC storms

Two parts.

- **Refusal:** with a queue stormed, `warm-reboot`, `fast-reboot` and `express-reboot` each refuse to start. The three run one script, and its `check_pfc_storm_active` runs `pfcwd show stats --check-storm`, which reads `PFC_WD_STATUS`. Each type is run, since a refused reboot costs no reboot time.
  - **Both:** the reboot is refused and the DUT keeps running. Needs [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) in hardware mode: before it, the hardware watchdog writes no `PFC_WD_STATUS`, `show pfcwd stats` lists no queue, and the reboot goes ahead during the storm.
- **Storm during the reboot:** send traffic through a lossless queue, start a warm reboot, and have the fanout start a storm after the old orchagent has stopped. A storm that starts before that is refused by the first part.
  - **Both:**
    - The new orchagent detects and reports the storm.
    - The storm is charged the traffic the queue counts from detection on, not the traffic sent before the reboot. In hardware mode the counters are read from SAI on detection and recovery ([sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854)), not through FlexCounter, so the 60 s FlexCounter delay on warm start does not apply. In software mode the `PFC_WD` group is created enabled.
    - The storm closes on restore: the restore count equals the detect count.
    - The next storm is counted as a new storm.
  - **Hardware:** a queue that enters recovery while syncd is down raises no DETECTED after the reboot, so orchagent has to read the queue's recovery state when it starts the watchdog. SAI has no attribute for that today. The nearest, `SAI_QUEUE_ATTR_PFC_CONTINUOUS_DEADLOCK_STATE`, reports the queue's pause state for software detection, not whether recovery is active. Needs [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) and a SAI attribute. Applies to platforms that support warm reboot.

### 11. Ports that share a detection timer

Take two ports that share a detection timer, from the platform table. Configure different detection times, then stop the watchdog on one port.

- **Hardware:** each port detects inside the platform's detection window for its own detection time (see [Platform values](#platform-values)). The remaining port still detects after the other port stops.
- **Software:** each port detects at its own time.

### 12. A second storm during recovery, and LAG members

Storm a second port while the first port's queue is between its DETECTED and RECOVERED. Separately, storm member ports of a PortChannel.

- **Both:** the second port is detected while the first recovers, and the PortChannel members detect and recover.

### 13. Storm history

Read `show pfcwd stats --history` after a storm, restore and repeat on one queue. Then run `sonic-clear pfccounters` and `sonic-clear queuecounters`, and read it again. Then run `pfcwd stop` and `pfcwd start` on the port, and read it again.

- **Both:**
  - The history lists each storm with its start, end and counters. With timer-based recovery a long storm gives several DETECTED and RECOVERED pairs, and the history has one entry per pair.
  - The two clear commands leave the history unchanged. No command clears it; removing the watchdog from the port does.
  - After `pfcwd stop` and `pfcwd start`, the port's history is empty.
  - Needs [sonic-swss#5100](https://github.com/sonic-net/sonic-swss/pull/5100) and [sonic-utilities#5002](https://github.com/sonic-net/sonic-utilities/pull/5002).

### 14. PFC RX counter stays monotonic during a storm

On platforms where the PFC RX counter can be read through two paths (the port counter group, and the `PFC_WD` group's own read), one path can return an older value than the other, and the counter steps backwards. The software watchdog's poll then sees no new PFC frames, and can restore the queue during the storm or miss the detection.

Read `SAI_PORT_STAT_PFC_<n>_RX_PKTS` for the stormed port and priority at every `PFC_WD` poll through a long storm. The case runs in software and hybrid DLR modes. In hardware mode the `PFC_WD` group has no members or plugin, so there is no second read path, and the case skips.

- **Software and hybrid DLR:** the value never decreases between two reads, and the queue stays stormed until the storm ends.

### 15. Hardware-mode CLI output

Read `show pfcwd config` and `show pfcwd config --json` with the watchdog running on two ports, one of them `failed`. In hardware mode, the case makes the second port `failed` by clearing its `pfcwd_sw_enable` in PORT_QOS_MAP before the start: orchagent then writes `status` `failed` for it (case 7). This is the "New CLI Command Testing" item in section 12.1 of the HLD.

`--json` is new in [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384), in both modes.

- **Software:**
  - `show pfcwd config` is unchanged from master.
  - The JSON has the keys `mode` (`software`), `ports`, `poll_interval` and `big_red_switch`. Each port has `action`, `detection_time`, `restoration_time` and `pfc_stat_history`, matching its `PFC_WD` row. `poll_interval` and `big_red_switch` match `PFC_WD|GLOBAL`, or are `null` when the field is absent.
- **Hardware:**
  - `show pfcwd config` prints `Recovery mode: hardware` above the table, and no poll interval or BIG_RED_SWITCH lines. The table shows the configured values.
  - The JSON has the software keys, with `mode` `hardware`, and two more: `hw_detection_time_ms` and `hw_restoration_time_ms`. Each is an object with `min` and `max`: the STATE_DB range clamped to the YANG range (detection 100–5000 ms, restoration 100–60000 ms). When the SAI reports no range for a timer, its object is `{"min": null, "max": null}`.
  - Each port also has `hw_detection_time`, `hw_restoration_time` and `hw_status`, matching `PFC_WD_HW_STATE`.
  - `poll_interval` and `big_red_switch` match `PFC_WD|GLOBAL`, or are `null` when the field is absent, as in software mode.
  - Needs [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384).

## Dependencies

| Case | Needs |
|---|---|
| Every module in hardware mode | [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854). [sonic-mgmt#23430](https://github.com/sonic-net/sonic-mgmt/pull/23430) is merged without a probe for it, so on an image without [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) the modules listed in [Running the existing tests in both mechanisms](#running-the-existing-tests-in-both-mechanisms) fail rather than skip |
| The [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) probe in the existing modules | A sonic-mgmt follow-up to [sonic-mgmt#23430](https://github.com/sonic-net/sonic-mgmt/pull/23430). No PR yet |
| Every case in software mode on a hardware platform | [sonic-mgmt#29060](https://github.com/sonic-net/sonic-mgmt/pull/29060), with the key deletions and read-backs in [Running each module in both mechanisms](#running-each-module-in-both-mechanisms) |
| Requiring `SOFTWARE` in the software phase | An orchagent change: the software watchdog writes `RECOVERY_MECHANISM=SOFTWARE` and clears the other watchdog's rows when it starts. No PR yet |
| 3 (hardware), 6 (`PFC_WD_STATUS`), 8 (CLI stop), 10 (hardware, and the refusal), 13 | [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) |
| 4 (CLI), 5 (CLI refusal), 8 (CLI stop), 9 (`pfcwd interval`, `big_red_switch`), 15 | [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) |
| 4 (hardware `pfcwd start` without the `POLL_INTERVAL` check) | [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384), rebased on [sonic-utilities#4898](https://github.com/sonic-net/sonic-utilities/pull/4898) |
| 4 (row without `restoration_time`) | [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) |
| 5 (stop then start with another action) | [sonic-swss#5091](https://github.com/sonic-net/sonic-swss/pull/5091) |
| 6 (`config reload`, hardware row), 6 (stale state after a restart) | [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090) |
| 6 (`config reload`, software rows) | An orchagent change: the software watchdog clears `PFC_WD_SW_STATE_TABLE` when it starts. No PR yet |
| 7 (waiting port, hardware) | [sonic-swss#5092](https://github.com/sonic-net/sonic-swss/pull/5092) |
| 7 (waiting port, software) | A software watchdog change. No PR yet |
| 7 (mask change without a restart) | An orchagent change. No PR yet |
| 8 (removal after the stormed TC is dropped from the mask) | An orchagent change. No PR yet |
| 9 (`--action alert` refused) | A sonic-utilities change. No PR yet |
| 10 (hardware, storm during the reboot) | A SAI attribute that reports a queue's recovery state |
| 13 | [sonic-swss#5100](https://github.com/sonic-net/sonic-swss/pull/5100) and [sonic-utilities#5002](https://github.com/sonic-net/sonic-utilities/pull/5002) |

A case whose dependency is missing must not fail the nightly run on one branch while passing on another. So each such case checks for the feature at run time, and skips with a message naming the PR when the feature is absent. Once the feature is in the image, the case runs and must pass.

The probe must not turn a regression into a skip. So it reads something the feature writes unconditionally, at watchdog start or from the CLI's own interface, never the output the case asserts:

| Dependency | Probe |
|---|---|
| [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) | After the watchdog starts on the port, every watched queue has `PFC_WD_STATUS` set to `operational` in COUNTERS_DB. Cases 6, 8 and 10 assert what happens to that field during and after a storm, not at start |
| [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) | `show pfcwd config` accepts `--json`. This is also the probe for case 15, which then asserts the content of the output |
| [sonic-utilities#5002](https://github.com/sonic-net/sonic-utilities/pull/5002) | `show pfcwd stats` accepts `--history` |

The other dependencies change behaviour and write nothing new at start, so they cannot be probed without reading the output the case asserts:

- [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090), [sonic-swss#5091](https://github.com/sonic-net/sonic-swss/pull/5091) and [sonic-swss#5092](https://github.com/sonic-net/sonic-swss/pull/5092) fix how the hardware watchdog handles a restart, a change of action and a waiting port.
- [sonic-swss#5100](https://github.com/sonic-net/sonic-swss/pull/5100) writes STATE_DB only when a storm is detected or restored.
- The orchagent change that writes `SOFTWARE`. A probe would read the value the phase's read-back asserts, so the requirement for `SOFTWARE` is gated by image version. Until the change has a PR and an image version, the read-back accepts an absent value, and no case is marked.
- The changes with no PR yet.

These use a conditional mark, limited by branch or image version, that names the PR or the missing change. A mark for a change with no PR yet is a strict expected failure: when the change lands, the case passes, the run reports it, and the mark is removed.
