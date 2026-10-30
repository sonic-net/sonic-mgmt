# BMC Serial Console Auto-Switch Test Plan

- [Definitions/Abbreviation](#definitionsabbreviation)
- [Overview](#overview)
  - [HLD](#hld)
  - [Testbed](#testbed)
- [Test Architecture](#test-architecture)
- [Test Cases](#test-cases)
  - [Console Routing Core](#console-routing-core)
  - [BMC Boot Behavior](#bmc-boot-behavior)
  - [Boundaries and Configuration](#boundaries-and-configuration)
  - [SwitchHost Platform API](#switchhost-platform-api)

---



## Definitions/Abbreviation


| **Term**               | **Description**                                                                                          |
| ---------------------- | -------------------------------------------------------------------------------------------------------- |
| BMC                    | Baseboard Management Controller running SONiC BMC                                                        |
| SWITCH-HOST            | Module representing the switch host CPU in a BMC-managed system                                          |
| Shared console         | Single chassis UART muxed between BMC and host CPU                                                       |
| Explicit switch        | Vendor hook to put the console on CPU; only path that moves the mux toward the host CPU                  |
| Host power-off         | `set_admin_state(False)`; host is powered off and the console must land on BMC                           |
| Host power-on          | `set_admin_state(True)`; console side is unchanged                                                       |
| Host power cycle / reset | `do_power_cycle()`; same console result as host `reboot()`. Console side is unchanged                  |
| Host-initiated restart | Host `reboot` / kernel panic / watchdog; console side is unchanged                                       |
| Host-initiated warm reboot | Host `warm-reboot`; console side is unchanged; skip if unsupported                                      |
| Host-initiated fast reboot | Host `fast-reboot`; console side is unchanged; skip if unsupported                                      |
| Board power cycle      | PDU / AC cycle of the chassis (BMC + host); hardware default returns console to BMC                      |
| Physical console       | Lab console-server session on the single shared UART                                                     |


---



## Overview

This test plan covers automatic routing of the shared chassis console UART between the BMC and the SWITCH-HOST CPU on SONiC BMC systems.

Routing is a hardware mux, not software multiplexing:

1. Host power-off puts the console on BMC
2. BMC reset / board power cycle puts the console on BMC before software runs
3. Host power APIs do not move the console toward CPU
4. Moving the console **toward the host CPU** requires an explicit set-console-on-CPU (vendor hook)

How a vendor sets or reads the mux is an implementation override. This plan does not name a vendor command.

This feature changes only host power-off (from CPU). BMC reboot/reset and board/PDU cycle already land on BMC via CPLD before software; those rows are unchanged.

| Action | Start | Before this feature | After this feature | Changed |
| --- | --- | --- | --- | --- |
| **Host power off (`set_admin_state(False)`)** | **CPU** | **CPU** | **BMC** | **Yes** |
| Host power off (`set_admin_state(False)`) | BMC | BMC | BMC | No |
| Host power on (`set_admin_state(True)`) | BMC or CPU | Unchanged | Unchanged | No |
| Host power cycle (`do_power_cycle()`) / `reboot()` / reset / panic / reload | BMC or CPU | Unchanged | Unchanged | No |
| BMC `reboot` | CPU | BMC | BMC | No |
| BMC `reboot` | BMC | BMC | BMC | No |
| Board / PDU power cycle | CPU | BMC | BMC | No |
| Board / PDU power cycle | BMC | BMC | BMC | No |

Out of scope:

- Console attach/detach / session management (BMC Core)
- BMC image upgrade while console remains usable
- Mux logging, BMC dump of mux state, and “one UART per system”
- Mux values other than BMC and CPU
- Vendor-only power commands that are not reachable as host power-off / power-on / reset / board cycle



### HLD

- **BMC Design Document**: https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md
- **BMC High-Level Test Plan**: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/bmc/BMC-high-level-test-plan.md



### Testbed

Any SONiC BMC testbed with:

- BMC running SONiC
- SWITCH-HOST module support
- Physical console access to the shared UART
- A vendor hook to set console on BMC or CPU, and to observe which side is selected
- Optional: PDU control for board power cycle tests

---

## Test Architecture

### 1. Gap

`tests/console/` and `tests/common/helpers/console_helper.py` attach to a **c0 reverse-SSH console switch**. They do not open the BMC front-panel shared UART. These cases need that UART: the mux register is not on the wire; several cases require seeing BMC vs host output on the physical console.

### 2. Inventory wiring

Reuse BMC high-level testbed modeling. The session under test is the **physical** link (`lab-con → BMC`), not `switch01-bmc-con → switch01` (BMC as console server to the host).

`duthost` is the BMC. SWITCH-HOST is `duthost.get_bmc_host()` / `tbinfo['bmc_host']`. Tests mark `@pytest.mark.topology('bmc')`.

### 3. New fixture: shared UART session

Add a pytest fixture (name TBD, e.g. `bmc_shared_uart`) that:

- Resolves the lab console-server host and line for `duthost` from conn-graph / `*_console_links.csv`
- Opens a `pexpect` session (same pattern as `create_ssh_client` in `console_helper.py`, different target)
- Yields a client tests can `send` / `expect`
- Disconnects on teardown (escape sequence; do not leave the line busy)

Helpers on that session (or small wrappers next to the fixture):

| Helper | Role |
| --- | --- |
| `expect_bmc_boot_log()` | Capture contains `U-Boot` (and/or `Hit any key to stop autoboot`); must **not** contain `GNU GRUB` or `AMI` |
| `expect_host_boot_log()` | Capture contains `GNU GRUB` or `AMI`; must **not** contain `U-Boot` |
| optional unique tokens | After the DUT is up: BMC SSH writes one token to the UART tty, host SSH another; UART must show only the expected one |

Do **not** search the capture for mux-register names. Those never appear on the wire.

Do **not** hard-code chip strings or DUT hostnames. Classify boot by BMC vs host fingerprints (`U-Boot` vs `GNU GRUB` / `AMI`).

BMC `reboot` and chassis PDU cycle are **equivalent** for the “early UART is BMC boot” observation (hardware default). Automated tests use BMC `reboot`. PDU is the same assert if BMC SSH is unavailable.

Cases **set** or **observe** console on BMC or CPU through a vendor-overridable hook. Observing boot output uses the UART fixture, not SSH.

### 4. Feature gate

Skip (or fail clearly) if conn-graph has no console link for the BMC DUT. Do not fall back to c0 console-switch fixtures.

---



## Test Cases

Cases **set** or **observe** console on BMC or CPU. They do not name a vendor mux API.


### Console Routing Core



#### Test Case #1: test_host_power_off_routes_console_to_bmc

**Test Objective**:
Host power-off puts the console on BMC, and the following power-on leaves it there. Call `set_admin_state(False)`, observe console on BMC, then call `set_admin_state(True)` and observe console still on BMC.

**Test Steps**:

1. Host powered on; set console on CPU; observe console on CPU
2. `set_admin_state(False)`
3. When power-off returns: observe console on BMC; host is unpowered (not silence on a dead CPU)
4. `set_admin_state(True)`; wait until the host is up
5. Observe console still on BMC

**Expected Result**:

- Console is on BMC as soon as power-off returns
- Host is unpowered; console is not left on the unpowered CPU
- After power-on, the host is up and the console is still on BMC

---



#### Test Case #2: test_host_initiated_restart_leaves_console_unchanged

**Test Objective**:
Host software restart does not move the console. From console on CPU run `reboot` / panic / watchdog (skip watchdog if unsupported); from console on BMC run `reboot`; observe console unchanged. For panic, also capture that a panic occurred.

**Test Steps**:

1. Host powered on; set console on CPU; observe console on CPU
2. On SWITCH-HOST run `reboot`. Keep UART capture through the reboot. Observe host boot on the console (`GNU GRUB` or `AMI`; no `U-Boot`). After host is up, observe console still on CPU
3. Set console on CPU. On SWITCH-HOST trigger kernel panic. Capture the panic output. After host is up, observe console still on CPU
4. Set console on CPU. On SWITCH-HOST expire watchdog. After host is up, observe console still on CPU
5. Set console on BMC, run host `reboot` — observe console still on BMC

**Expected Result**:

- Console side is unchanged after each event
- Operator on CPU is not switched to BMC
- Panic output is captured; console still on CPU after host is up

---



#### Test Case #3: test_host_initiated_warm_reboot_leaves_console_unchanged

**Test Objective**:
Warm reboot does not move the console. Skip if `warm-reboot` is absent, or if the platform does not support it.

**Test Steps**:

1. Host powered on; set console on CPU; observe console on CPU
2. If `warm-reboot` is not available, skip
3. On SWITCH-HOST run `warm-reboot`
4. After host is up, observe console still on CPU

**Expected Result**:

- Console side is unchanged
- Operator on CPU is not switched to BMC
- Skip, not fail, when warm reboot is unsupported

---



#### Test Case #4: test_host_initiated_fast_reboot_leaves_console_unchanged

**Test Objective**:
Fast reboot does not move the console. Skip if `fast-reboot` is absent, or if the platform does not support it.

**Test Steps**:

1. Host powered on; set console on CPU; observe console on CPU
2. If `fast-reboot` is not available, skip
3. On SWITCH-HOST run `fast-reboot`
4. After host is up, observe console still on CPU

**Expected Result**:

- Console side is unchanged
- Operator on CPU is not switched to BMC
- Skip, not fail, when fast reboot is unsupported

---



#### Test Case #5: test_bmc_power_cycle_routes_console_to_bmc

**Test Objective**:
Board/PDU cycle returns the console to BMC (hardware default), not a restored CPU setting. Cycle from console on CPU and from console on BMC; observe BMC boot on the console. Skip if the testbed has no PDU.

**Test Steps**:

1. If the testbed has no PDU, skip. Set console on CPU; observe console on CPU
2. Confirm console routing is not persisted in software (no DB restore)
3. Start physical console capture
4. Board power cycle via PDU
5. When BMC is reachable, observe console on BMC (not restored to CPU)
6. Observe BMC boot on the capture (`U-Boot`; no `GNU GRUB` / `AMI`); console is BMC and usable
7. Repeat from console on BMC — observe still BMC after cycle (BMC boot, not host GRUB)

**Expected Result**:

- No PDU: skipped, not failed
- After board power cycle, console is on BMC; pre-cycle CPU setting is not restored
- Capture is BMC boot, not host BIOS/GRUB

---



#### Test Case #6: test_bmc_reboot_uart_shows_bmc_boot

**Test Objective**:
BMC reboot shows BMC boot on the console with no software console switch. Set console on CPU, open capture, reboot BMC; observe BMC boot.

**Test Steps**:

1. Set console on CPU; observe console on CPU
2. Start UART capture and keep it open
3. Run `reboot` on the BMC. Do not set console during boot. A board/PDU power cycle is an equivalent trigger for this observation if BMC `reboot` is unavailable.
4. When capture is complete, observe BMC boot: **has** `U-Boot`; **has not** `GNU GRUB` or `AMI`
5. After BMC is up, observe console on BMC

**Expected Result**:

- Capture is BMC boot, not host BIOS/GRUB
- Console is on BMC after BMC is up
- No manual set-console-on-BMC was required for BMC output to appear

---



### BMC Boot Behavior



#### Test Case #7: test_bmc_boot_host_power_and_console_default

**Test Objective**:
BMC reboot never auto-switches the console to CPU, whether the host stays off or powers on. Reboot BMC with host powered off, then with host allowed to power on; observe console on BMC both times.

**Test Steps**:

1. Set console on BMC; observe console on BMC
2. `set_admin_state(False)`
3. Run `reboot` on the BMC; wait until BMC is up
4. Observe console on BMC
5. Observe host is unpowered; console is BMC
6. `set_admin_state(True)`, wait for host power-on, then run `reboot` on the BMC again
7. After BMC is up, observe console still on BMC even if the host is powered

**Expected Result**:

- Host off, then BMC reboot: host unpowered, console on BMC
- Host on, then BMC reboot: host may power on, console still on BMC

---



### Boundaries and Configuration



#### Test Case #8: test_set_console_same_side_is_noop

**Test Objective**:
Setting console to the side it is already on is a no-op. Set BMC then BMC again, CPU then CPU again; observe no switch.

**Test Steps**:

1. Set console on BMC; observe console on BMC
2. Set console on BMC again; observe console still on BMC (no flip)
3. Set console on CPU; observe console on CPU
4. Set console on CPU again; observe console still on CPU

**Expected Result**:

- Same-side set leaves console unchanged
- No interruption on the physical console

---



#### Test Case #9: test_power_action_while_console_already_on_bmc

**Test Objective**:
From console on BMC, `set_admin_state(False)`, `set_admin_state(True)`, and `do_power_cycle()` leave the console on BMC. Power-on does not move it toward CPU.

**Test Steps**:

1. Set console on BMC; observe console on BMC
2. `set_admin_state(False)` — observe console still on BMC
3. `set_admin_state(True)` — observe host is powered on; console still on BMC
4. `do_power_cycle()` — observe console still on BMC

**Expected Result**:

- Power actions succeed
- Console remains on BMC; power-on does not auto-switch to CPU

---



### SwitchHost Platform API



#### Test Case #10: test_host_reset_leaves_console_unchanged

**Test Objective**:
`do_power_cycle()` does not move the console off CPU. Set console on CPU, call it once; observe console still on CPU.

**Test Steps**:

1. Host powered on; set console on CPU; observe console on CPU
2. `do_power_cycle()`
3. During/after the power cycle, observe console still on CPU; after host is up, observe console still on CPU

**Expected Result**:

- Console stays on CPU
- Operator on host UART is not switched to BMC

