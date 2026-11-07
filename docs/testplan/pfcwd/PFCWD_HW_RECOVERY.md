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

SONiC can run the PFC watchdog in two ways. The software watchdog polls each lossless queue from orchagent and mitigates a storm with ACL rules. The hardware watchdog lets the ASIC detect the deadlock and apply the action, and orchagent only programs it and reports its state. The design is in the [PFC Watchdog Hardware-Based Detection and Recovery HLD](https://github.com/sonic-net/SONiC/blob/master/doc/pfcwd/pfc_watchdog_hardware_detection_recovery.md).

This plan covers two things:

1. Running every test in `tests/pfcwd/` under each mechanism the DUT supports, and checking the result that mechanism should give.
2. New cases for behaviour the existing tests do not reach: timer limits, the switch-wide action, changes made to a running watchdog, changes made during a storm, restarts and warm reboot, and the counters the watchdog reports.

[PFCWD_BASIC.md](PFCWD_BASIC.md) describes the software watchdog's detection, mitigation and restoration. This plan does not repeat it.

## Scope

- Single-ASIC DUTs on t0 and t1 topologies with a fanout that can send PFC frames.
- Any platform whose SAI advertises `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR`. Orchagent then runs the hardware watchdog.
- Platforms without that capability run the software phase only. Every case below still applies to them, with the software expectation.

Out of scope: multi-ASIC DUTs (the checks read one DB namespace), and the gNMI telemetry cases in section 12 of the HLD.

## Related work

| Item | What it provides | State |
|---|---|---|
| [SONiC HLD](https://github.com/sonic-net/SONiC/blob/master/doc/pfcwd/pfc_watchdog_hardware_detection_recovery.md) | Hardware watchdog design. Section 12 lists test requirements | Merged |
| [sonic-swss#4412](https://github.com/sonic-net/sonic-swss/pull/4412) | `PfcWdHwOrch`, selected from the SAI capability | Merged |
| [sonic-swss#4854](https://github.com/sonic-net/sonic-swss/pull/4854) | Storm counters for the hardware watchdog | Open |
| [sonic-swss#5090](https://github.com/sonic-net/sonic-swss/pull/5090) | Clear stale hardware watchdog state at startup | Open |
| [sonic-swss#5091](https://github.com/sonic-net/sonic-swss/pull/5091) | Retry a start with a new action while the stop is still tearing down | Open |
| [sonic-swss#5092](https://github.com/sonic-net/sonic-swss/pull/5092) | Stop rewriting a deferred port's state on every retry | Open |
| [sonic-swss#5100](https://github.com/sonic-net/sonic-swss/pull/5100) | Record PFC storm history in STATE_DB. Builds on #4854 | Open |
| [sonic-utilities#4384](https://github.com/sonic-net/sonic-utilities/pull/4384) | Hardware watchdog CLI: `show pfcwd status` and range checks | Open |
| [sonic-utilities#5002](https://github.com/sonic-net/sonic-utilities/pull/5002) | `show pfcwd stats --history` | Open |
| [sonic-mgmt#29060](https://github.com/sonic-net/sonic-mgmt/pull/29060) | Run `tests/pfcwd/` under both mechanisms | Open |
| [sonic-mgmt#27982](https://github.com/sonic-net/sonic-mgmt/pull/27982) | PFC watchdog timer validation tests | Open |

## Background

### How the two mechanisms differ

| | Software watchdog | Hardware watchdog |
|---|---|---|
| Detection | A Lua plugin in the `PFC_WD` flex counter group finds the queue paused for `detection_time` | The ASIC detects the deadlock and raises `SAI_SWITCH_NOTIFICATION_NAME_QUEUE_PFC_DEADLOCK` |
| Drop action | ACL rules drop traffic leaving the queue and traffic arriving on its priority | The ASIC drops traffic leaving the queue. Traffic arriving on the port is not dropped |
| Action per port | Each port can have its own action | One action for the whole switch, `SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION` |
| Timers | Checked against sonic-pfcwd.yang | Must also be inside the range the SAI reports. The ASIC may round them |
| `PFC_WD\|GLOBAL` and `pfcwd interval` | Set the poll interval | Not used, and refused |

### State the tests read

| Location | Fields |
|---|---|
| `STATE_DB SWITCH_CAPABILITY\|switch` | `PFC_DLDR_CAPABLE`, `PFC_DLR_INIT_CAPABLE` |
| `STATE_DB PFC_WD_STATE_TABLE\|PFC_WD` | `RECOVERY_MECHANISM`, `DETECTION_TIME_MIN/MAX`, `RESTORATION_TIME_MIN/MAX`, `DLR_PACKET_ACTION` |
| `STATE_DB PFC_WD_HW_STATE\|<port>` | `recovery_type`, `status` (`configured` or `failed`), `configured_detection_time`, `configured_restoration_time`, `hw_detection_time`, `hw_restoration_time`, `action` |
| `COUNTERS_DB COUNTERS:<queue oid>` | `PFC_WD_STATUS` and the `PFC_WD_QUEUE_STATS_*` storm counters |
| `ASIC_DB` queue object | `SAI_QUEUE_ATTR_ENABLE_PFC_DLDR` |

The HLD describes a `PFC_WD_HW_CAPABILITIES|GLOBAL` table. sonic-swss#4412 implemented `PFC_WD_STATE_TABLE|PFC_WD` instead, and this plan follows the code.

## Test setup

### Running each module in both mechanisms

At module start, the suite reads `RECOVERY_MECHANISM` and runs the module in that mechanism. A platform that can turn off its hardware capability then runs the module a second time, in software mode. On Broadcom this is done by setting `sai_pfc_dldr_capability: 0` in the SAI configuration and restarting swss. The suite checks that `RECOVERY_MECHANISM` changed before running the phase. It restores the configuration afterwards, and checks that the DUT is back in its own mechanism. sonic-mgmt#29060 implements this.

A platform that cannot change mechanism runs only its own phase. No platform can be forced from software to hardware.

### Rules for every case

- Each case checks the result for the mechanism it runs in. A case that has no meaning in one mechanism skips there, with the reason in the skip message.
- Each storm is checked on the DUT: its PFC RX counter rises before the test expects a detection.
- A case that changes configuration restores it, and leaves the watchdog stopped and no storm running.
- Timers come from the hardware range in STATE_DB when the hardware watchdog runs, so no case depends on one platform's values.

## Running the existing tests in both mechanisms

These modules already exist. Each runs in both phases. sonic-mgmt#29060 makes the changes below. This table only summarises them.

| Module | Change for hardware mode |
|---|---|
| `test_pfcwd_function.py` | Skip the RX checks, since the hardware acts on the egress queue only. Read per-queue TX drops instead of a port-level fallback. Use a restoration time inside the hardware range |
| `test_pfcwd_cli.py` | The same counter changes as `test_pfcwd_function.py` |
| `test_pfcwd_all_port_storm.py` | No change. In software mode, also check that the `PFC_WD` poll finishes within its interval with every port stormed |
| `test_pfcwd_timer_accuracy.py` | Judge detection against `hw_detection_time` and the platform's detection granularity, not the software poll interval |
| `test_pfcwd_warm_reboot.py` | Use a real storm in hardware mode instead of the `DEBUG_STORM` field. The hardware watchdog does not read it |
| `test_pfcwd_stat_history.py` | No change. The history must keep counting under each action in both mechanisms |
| `test_xon_not_counted.py` | No change. XON frames must not count as a storm in either mechanism |
| `test_pfc_config.py` | After `load_minigraph`, the default timers are inside the hardware range and there is no `PFC_WD\|GLOBAL` row |
| `snappi_tests/pfcwd` | Do not require `PFC_WD\|GLOBAL POLL_INTERVAL` or run `pfcwd interval`. Use a restoration time inside the hardware range |

## New test cases

Each case lists what it does, then what to expect in each mechanism. "Needs" names an open upstream PR that the expectation depends on.

### 1. Detection window

Storm a lossless queue for slightly less than `detection_time` D, then for slightly more.

- **Software:** no detection for the shorter storm. The longer storm is detected at the first poll after D.
- **Hardware:** no detection before D, and detection by `hw_detection_time` plus the platform's detection granularity. The granularity shows as the rounding in `hw_detection_time`.

### 2. One continuous storm

Hold one storm for several detection times, then stop it.

- **Software:** one detection. The queue restores `restoration_time` after the pause stops, for both actions. With the forward action, traffic keeps flowing during the storm.
- **Hardware:** exactly one detection and one restore per storm. The restore comes after the pause stops, and no later than `restoration_time` plus the platform's detection granularity.

### 3. Drop action, in both directions

With the drop action and a stormed queue, send traffic that leaves through the stormed queue, and traffic that arrives on the stormed port at that priority.

- **Software:** both directions are dropped. The TX drops in `show pfcwd stats` include the egress ACL drops.
- **Hardware:** egress traffic is dropped and arriving traffic is forwarded. The queue's dropped packets and the TX drops in `show pfcwd stats` agree, and so does the port's `IF_OUT_DISCARDS` where the platform counts these drops there. This includes packets dropped just before detection and just after restore. Needs sonic-swss#4854.

### 4. Timer limits at each entry point

Try timers just inside and just outside the allowed range through `pfcwd start`, through a `PFC_WD` row written to CONFIG_DB (and through GCU), and from first boot.

- **Software:** the sonic-pfcwd.yang ranges are enforced: detection 100–5000 ms, restoration 100–60000 ms.
- **Hardware:**
  - The CLI refuses a value outside the STATE_DB range, writes nothing, and accepts each bound.
  - `pfcwd start` without `--restoration-time` uses twice the detection time, capped at the hardware maximum.
  - A row written to CONFIG_DB that is out of range, or has no `restoration_time`, is logged and dropped. Nothing is programmed, and no `PFC_WD_HW_STATE` row appears.
  - Needs sonic-utilities#4384. Related: sonic-mgmt#27982.

### 5. One action for the whole switch

Start the watchdog on two ports with different actions. Then stop it and start it again with another action.

- **Software:** each port keeps its own action.
- **Hardware:**
  - A row that would leave two ports on different actions is logged as an error and dropped, and nothing changes in ASIC_DB. The CLI refuses such a start with a message (sonic-utilities#4384).
  - `pfcwd stop` followed by `pfcwd start --action <other>` leaves every port `configured` with the new action. Needs sonic-swss#5091.

### 6. Removing the watchdog leaves nothing behind

Storm a queue, then remove the watchdog from the port with `pfcwd stop`, with a GCU patch, and with `config reload`. Separately, add a stale `PFC_WD_HW_STATE` row for an unwatched port and restart swss.

- **Software:** the queue status and the ACL drop rules are removed, even when the queue is stormed at the time.
- **Hardware:**
  - No `PFC_WD_HW_STATE` row is left, and DLDR is off on every queue.
  - No `PFC_WD_STATUS` is left in COUNTERS_DB. The hardware watchdog writes no COUNTERS_DB fields until sonic-swss#4854, so this check applies from then.
  - After the restart, `PFC_WD_HW_STATE` holds only the ports orchagent programmed. Needs sonic-swss#5090.

### 7. Changing the watched TCs while running

While the watchdog runs, change the port's `pfcwd_sw_enable` in PORT_QOS_MAP: drop one TC, clear it, and add a TC back.

- **Both:**
  - A dropped TC is released when the watchdog stops.
  - A port with no watched TC waits without SAI calls or repeated log lines for 60 s, and starts once a TC comes back. Needs sonic-swss#5092 in hardware mode.
  - An added TC is watched without restarting the watchdog. Today the watchdog reads the TCs only when it starts on the port, so this needs an orchagent change. No upstream PR proposes it yet.
- **Hardware:** a released TC also has DLDR off, and the waiting port shows `failed` once (sonic-swss#5092).

### 8. Changes made during a storm

While a queue is stormed, run `pfcwd stop <port>`, and apply GCU patches that change `detection_time` or remove the port's row.

- **Software:** each change applies at once.
- **Hardware:**
  - `pfcwd stop` is refused with a message and changes nothing. Needs sonic-utilities#4384.
  - The old configuration keeps running until the storm ends, and then the change applies: the new timer is programmed, or the watchdog is removed.

### 9. Settings that only the software watchdog uses

Write `PFC_WD|GLOBAL`, run `pfcwd interval`, and run `pfcwd counter_poll disable` before a storm.

- **Software:** each setting works. With the counter poll disabled, a storm is not detected until the poll is enabled again.
- **Hardware:** the `GLOBAL` row is ignored with an INFO log, and every port stays configured. `pfcwd interval` returns an error and writes nothing (sonic-utilities#4384). With the counter poll disabled, detection and restore still happen.

### 10. Storm during a warm reboot

Send traffic through a lossless queue. Start a warm reboot, and have the fanout start a storm partway through it. `warm-reboot` refuses to start while a queue is stormed. After a warm start, the flex counters publish only after 60 s. So the new orchagent sees the storm before the queue has counters.

- **Both:**
  - The new orchagent detects and reports the storm.
  - The storm is charged only what the queue counts after its counters publish, not the traffic sent before the reboot.
  - The storm closes on restore: the restore count equals the detect count.
  - The next storm is counted.
- **Hardware:** needs sonic-swss#4854. Applies to platforms that support warm reboot.

### 11. Ports with different detection times

On two ports where the ASIC shares a detection timer between ports, configure different detection times, then stop the watchdog on one port.

- **Hardware:** each port detects at its own time. The remaining port still detects after the other port stops.
- **Software:** each port detects at its own time.

### 12. A second storm during recovery, and LAG members

Storm a second port while the first is recovering. Separately, storm member ports of a PortChannel.

- **Both:** the second port is detected while the first recovers, and the PortChannel members detect and recover.

### 13. Storm history

Run the cases from `show pfcwd stats --history`: a storm, restore and repeat on one queue, and the history after counters are cleared.

- **Both:** the history lists each storm with its start, end and counters. Needs sonic-swss#5100 and sonic-utilities#5002.

### 14. PFC RX counter during a storm

Read the queue's PFC RX counter throughout a long storm.

- **Both:** the counter never decreases, and detection happens on time.

## Dependencies

| Case | Needs |
|---|---|
| 3 (hardware), 6 (`PFC_WD_STATUS`), 10 (hardware) | sonic-swss#4854 |
| 4 (hardware CLI), 5 (CLI refusal), 8 (CLI stop), 9 (`pfcwd interval`) | sonic-utilities#4384 |
| 5 (stop then start with another action) | sonic-swss#5091 |
| 6 (stale state after a restart) | sonic-swss#5090 |
| 7 (waiting port, hardware) | sonic-swss#5092 |
| 7 (added TC) | An orchagent change. No upstream PR proposes it yet |
| 13 | sonic-swss#5100 and sonic-utilities#5002 |
| All cases in software mode on a hardware platform | sonic-mgmt#29060 |

Until each dependency merges, the case that needs it is marked `xfail` with `strict: True` in the conditional mark file, citing the PR. When the PR merges, the case starts to pass and strict mode flags the mark for removal.
