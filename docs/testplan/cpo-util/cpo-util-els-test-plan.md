# CPO Util ELS firmware management test plan

HLD: https://github.com/nvidia-sonic/SONiC/blob/cpo-util-hld-v2/doc/cpo-util/cpo-util-hld.md

## Table of contents

- [Overview](#overview)
- [Scope](#scope)
- [Testbed and topology](#testbed-and-topology)
- [Test fixtures](#test-fixtures)
- [Test cases](#test-cases)
  - [TC-01 — ELS firmware upgrade and reboot persistence](#tc-01--els-firmware-upgrade-and-reboot-persistence)
  - [TC-02 — ELS stepwise firmware lifecycle using all](#tc-02--els-stepwise-firmware-lifecycle-using-all)
  - [TC-03 — Invalid inputs and corrupted firmware rejected](#tc-03--invalid-inputs-and-corrupted-firmware-rejected)
  - [TC-04 — Firmware lock](#tc-04--firmware-lock)
  - [TC-05 — Interrupted download recovery](#tc-05--interrupted-download-recovery)
  - [TC-06 — Traffic recovery after firmware run](#tc-06--traffic-recovery-after-firmware-run)
- [Known limitations](#known-limitations)
- [Open items](#open-items)

## Overview

This plan validates the Phase 1 `cpoutil` firmware command group on a CPO-capable SONiC DUT: `firmware {upgrade|download|run|commit}` and `show {oe|els} fwversion`, with `--raw` binaries only.

**ELS is the primary test target.** All firmware operations (download, run, commit, upgrade) are tested on ELS only. OE is out of scope for firmware operations; only `cpoutil show oe fwversion` is verified for correct output format in TC-01.

## Scope

### In scope

- ELS firmware commands: `upgrade`, `download`, `run`, `commit` with `--raw`, selected by index or `all`
- `cpoutil show els fwversion` (text and `--json`)
- `cpoutil show oe fwversion` (output format verification only)
- Firmware lock: lock held during an operation, busy rejection on the same ELS, lock released after the operation
- Interrupted download recovery (Ctrl-C)
- Negative inputs: invalid index, missing/corrupted firmware, missing arguments
- Post-commit cold reboot persistence
- Syslog logging (NOTICE on start/complete, ERROR on failure)
- Port and traffic recovery after `run` (reset + admin toggle), verified with a PTF packet

### Out of scope

- OE firmware operations (download/run/commit/upgrade)
- OIF Firmware Update Package parsing/matching (HLD Appendix A)
- `--component mcu` placeholder (HLD §14)
- SAI, SDK, orchagent, Config DB changes (none in this feature)
- `TRANSCEIVER_FIRMWARE_INFO` in STATE_DB (HLD §12)
- Firmware operations during warm/fast reboot (HLD §10)

### CLI reference

```
cpoutil firmware upgrade  els <index>|all --raw <fw.bin>
cpoutil firmware download els <index>|all --raw <fw.bin>
cpoutil firmware run      els <index>|all
cpoutil firmware commit   els <index>|all
cpoutil show oe  fwversion [<index>] [--json]
cpoutil show els fwversion [<index>] [--json]
cpoutil config interface reset <port>
```

`show ... fwversion` takes no selector to show all targets, or an index to show one. The `firmware` commands keep `all` as the selector for all targets. `config interface reset <port>` resets the CPO module serving the port; the ports it serves must then be admin toggled.

## Testbed and topology

- Topology: any CPO-capable DUT
- DUT must have at least 1 ELS index
- TC-06 needs a PTF container and a topology with routed neighbors (e.g. t0), so that a packet can be sent from a PTF port into the DUT and received on the PTF port of a CPO port
- Port mapping: ELS `<N>` serves `Ethernet<32*N>` .. `Ethernet<32*N+31>`

## Test fixtures

All fixtures run on the DUT shell. Source of truth for firmware state is `cpoutil show els fwversion`, not `TRANSCEIVER_FIRMWARE_INFO` in STATE_DB.

### `cpo_supported` — scope: session

Skip the entire test module if the DUT does not support CPO.

**Setup:**

1. Check if `cpo.json` exists under the DUT device directory (e.g. `/usr/share/sonic/device/<platform>/cpo.json`).
2. If `cpo.json` does not exist, `pytest.skip`.

### `els_indices` — scope: module

Return a sorted list of ELS index integers available on the DUT.

**Setup:**
1. Run `cpoutil show els fwversion` and parse the output.
2. Extract ELS indices from target names (e.g. `els0` -> `0`, `els1` -> `1`).
3. Return sorted list of indices.

### `els_firmware_binaries` — scope: function

Stage the ELS firmware images listed in `firmware.json` on the DUT. Images are downloaded to the test host (ngts) with `localhost.get_url` and copied to the DUT with `duthost.copy` (about 240 KB each), so the DUT needs no DNS or route to the firmware server.

- `[0]` = **default / gold** image (used by `restore_els_firmware`)
- `[1]` = **target** image (used by tests for upgrade / download operations)

**Setup:**
1. Read the ELS entries from `firmware.json` under the chassis matching `fwutil show status` output.
2. Download both images to a temporary directory on the test host, copy them to the DUT staging directory `/home/admin/cpoutil_firmware`, then remove the local temporary directory. The staging directory is on persistent storage, so it survives the reboot in TC-01.
3. Create a corrupted binary (zero-filled) for TC-03 negative tests.

**Returns:**
```python
{"default": "<dut_path>", "target": "<dut_path>", "corrupted": "<dut_path>",
 "default_version": "<version>", "target_version": "<version>"}
```

No teardown: the staging directory is removed at the end of `restore_els_firmware`.

### `dom_polling_disabled` — scope: function

Stop xcvrd in the pmon container before each firmware operation test to prevent I2C contention, and restart after. This avoids modifying CONFIG_DB (unlike per-port `config interface transceiver dom` commands).

**Setup:**
1. `docker exec pmon supervisorctl stop xcvrd`
2. Wait for xcvrd to fully stop (~5 s).

**Teardown:**
1. Check if xcvrd is already running (e.g. after a reboot in TC-01, xcvrd auto-starts with pmon).
2. If not running, `docker exec pmon supervisorctl start xcvrd`.

xcvrd provisions the ports, so tests that must bring ports back up during the test (TC-06) reset the ELS first and then start xcvrd themselves before the admin toggle.

### `restore_els_firmware` — scope: function

After each test case, check which ELS are not running the default firmware, restore them in parallel, verify, recover their ports, and clean up the DUT staging directory.

**Teardown logic:**

1. Run `cpoutil show els fwversion` and identify ELS where Active Firmware != default version (`firmware.json[0]["version"]`).
2. If none, remove the staging directory and return.
3. For each ELS that needs restore, start `cpoutil firmware upgrade els <index> --raw <default_fw.bin>` in background (parallel), and wait for all to complete.
4. Verify all ELS are running the default version; fail the test otherwise (staging directory and background logs are kept for debugging).
5. The upgrade runs the new image, which takes the ports of each restored ELS down. With xcvrd stopped, reset each restored ELS through its first port (`cpoutil config interface reset Ethernet<32*N>`); then start xcvrd and admin toggle the ports. Wait until all those ports are oper up; fail otherwise. The reset is done with xcvrd stopped so that xcvrd does not access the modules while they are reset (otherwise the kernel logs `Fails to access module eeprom`).
6. Remove background logs and the DUT staging directory `/home/admin/cpoutil_firmware`.

### `ignore_expected_cpoutil_errors` — scope: function (autouse)

Negative tests (corrupted image, busy lock, interrupted download) make cpoutil log errors on purpose, e.g. `ERR cpoutil: ELS firmware download failed on ELS0: ...`. The test module defines a module-level `CPOUTIL_IGNORE_REGEX` list and this fixture adds it to `loganalyzer[duthost.hostname].ignore_regex` so the framework loganalyzer does not fail these tests:

```python
CPOUTIL_IGNORE_REGEX = [
    r".*ERR cpoutil: ELS firmware \w+ (failed|aborted) on ELS\d+.*",
    r".*ERR CdbFirmware: .*",
]
```

### Command timeouts

cpoutil processes the targets of `all` sequentially (for example, `run` waits about 5 s per ELS for the device reset). The per-ELS timeout of each firmware command (download, run, commit, upgrade) is multiplied by the number of ELS when the selector is `all`.

### Fixture dependency and execution order

```
cpo_supported (session, skip gate)
+-- els_indices (module, list available ELS indices)
|
|   Per test function:
|   +-- els_firmware_binaries (function, download via test host, copy default + target to DUT, create corrupted image)
|   +-- ignore_expected_cpoutil_errors (function, autouse, loganalyzer ignore list)
|   +-- dom_polling_disabled (function, stop/start xcvrd)
|   +-- restore_els_firmware (function, restore ELS to default and remove DUT staging dir on teardown)
```

## Test cases

All test cases are **P1**. Execution order: TC-01 -> TC-02 -> TC-03 -> TC-04 -> TC-05 -> TC-06.

### TC-01 — ELS firmware upgrade and reboot persistence

**Goal:** Verify `upgrade` performs download+run+commit in one command, firmware persists after cold reboot, and `show fwversion` output is correct in both text and JSON format. Also verify `cpoutil show oe fwversion` outputs correct format.

**Steps:**
1. Record initial ELS firmware state via `cpoutil show els fwversion 0`.
2. Pick the image from `firmware.json` whose version differs from the current Active Firmware (target `[1]` by default, or default `[0]` if the ELS already runs the target version), and run `cpoutil firmware upgrade els 0 --raw <picked_fw.bin>`.
3. Verify stdout shows progress bar and `Upgrading ELS0 firmware ... OK (<n> bytes)`.
4. Verify syslog contains `NOTICE cpoutil: ELS firmware upgrade started on ELS0` and `... completed on ELS0`, and no errors, using a LogAnalyzer limited to the upgrade (before the reboot). The autouse loganalyzer is disabled for TC-01 (`@pytest.mark.disable_loganalyzer`), because the cold reboot logs boot-time errors unrelated to cpoutil.
5. Run `cpoutil show els fwversion 0` (text) — verify:
   - Active Firmware equals the version of the picked image.
   - Running Image is the other bank letter from the initial state.
   - Committed Image equals Running Image.
6. Run `cpoutil show els fwversion 0 --json` — verify:
   - Output is valid JSON.
   - Keyed by `els0`.
   - Field values match the text output.
7. Cold reboot the DUT.
8. After reboot, run `cpoutil show els fwversion 0` — verify Active Firmware, Running Image, and Committed Image match pre-reboot values.
9. Run `cpoutil show oe fwversion` — verify the command succeeds and output lists OE entries with firmware version fields (format validation only, no version assertion).

**Covers:** core upgrade functionality, fwversion text and JSON output, reboot persistence, syslog logging, OE show fwversion format.

### TC-02 — ELS stepwise firmware lifecycle using `all`

**Goal:** Verify the stepwise download -> run -> commit lifecycle on all ELS targets, with bank state validated after each step.

**Steps:**
1. Record initial state via `cpoutil show els fwversion`.
2. `cpoutil firmware download els all --raw <target_fw.bin>` — verify progress and `OK (<n> bytes)` per target.
3. `cpoutil show els fwversion` — verify for each ELS:
   - Inactive Firmware equals the downloaded (target) version.
   - Active Firmware and Running Image unchanged.
4. `cpoutil firmware run els all`.
5. `cpoutil show els fwversion` — verify for each ELS:
   - Running Image switched to the other bank letter.
   - Active Firmware equals the post-download Inactive Firmware.
6. `cpoutil firmware commit els all`.
7. `cpoutil show els fwversion` — verify for each ELS:
   - Committed Image equals Running Image.

**Covers:** download, run, commit as separate operations, `all` keyword batch processing, per-step bank state verification.

### TC-03 — Invalid inputs and corrupted firmware rejected

**Goal:** Verify that bad arguments and corrupted firmware are rejected with clear errors, and the active firmware is not affected.

**Steps:**
1. Record initial state via `cpoutil show els fwversion 0`.
2. Test each invalid input and verify the command fails with a clear error message:

| Input | Command | Expected |
|-------|---------|----------|
| Invalid index | `cpoutil firmware download els 999 --raw <target_fw.bin>` | Fatal error before any firmware operation |
| Missing `--raw` | `cpoutil firmware download els 0` | Argument parsing error |
| Non-existent file | `cpoutil firmware download els 0 --raw /nonexistent` | Fatal error |
| Corrupted binary | `cpoutil firmware download els 0 --raw <corrupted.bin>` | Download fails, non-zero exit |

3. After each invalid input, run `cpoutil show els fwversion 0` and verify Active Firmware and Running Image are unchanged from initial state.
4. For the corrupted binary case, the autouse loganalyzer verifies at teardown that syslog contains `ERR cpoutil: ELS firmware download failed on ELS0` (added to its `expect_regex`).

**Covers:** input validation, corrupted firmware rejection, error logging, active firmware unaffected by failures.

### TC-04 — Firmware lock

**Goal:** Verify the ELS firmware lock is held during a firmware operation, a second operation on the same ELS is rejected as busy, and the lock is released afterwards.

The lock file `/var/lock/nvidia-cpo/els<N>.lock` is created on first use and never removed, so its existence proves nothing. Lock state is checked with a non-blocking exclusive flock: `flock -n -x /var/lock/nvidia-cpo/els<N>.lock true` fails (non-zero) while another process holds the lock.

**Steps:**

**Step 1 — Lock held during download:**
1. Start `cpoutil firmware download els 0 --raw <target_fw.bin>` in background.
2. While the download is in progress, verify `flock -n -x /var/lock/nvidia-cpo/els0.lock true` fails (lock held).

**Step 2 — Same ELS concurrent download returns busy:**
1. While the download from Step 1 is still running, start another `cpoutil firmware download els 0 --raw <target_fw.bin>`.
2. Verify the second process fails with `Another firmware operation is in progress`.

**Step 3 — Lock released after download:**
1. Wait for the first download to finish.
2. Verify `flock -n -x /var/lock/nvidia-cpo/els0.lock true` succeeds (lock released).

**Covers:** lock held during operation, mutual exclusion on same device, lock release after operation.

### TC-05 — Interrupted download recovery

**Goal:** Verify that Ctrl-C during a download exits cleanly and the next download on the same ELS succeeds.

**Steps:**
1. Start `cpoutil firmware download els 0 --raw <target_fw.bin>`.
2. Send SIGINT (Ctrl-C) before download completes.
3. Verify the command exits.
4. Run `cpoutil show els fwversion 0` — verify Running Image is unchanged.
5. Start `cpoutil firmware download els 0 --raw <target_fw.bin>` again.
6. Verify the retry completes with `OK (<n> bytes)`.

**Covers:** interrupt handling, download abort, lock release on interrupt, recovery.

### TC-06 — Traffic recovery after firmware run

**Goal:** Verify that `cpoutil firmware run` takes the ports of the ELS down, and that resetting the ELS and admin toggling its ports brings the ports and traffic back.

**Traffic path:** PTF sends one IPv4 packet on the PTF port of a DUT port outside the ELS (`src_port`, e.g. Ethernet32). The destination MAC is the DUT router MAC and the destination IP is the neighbor behind the first port of the ELS (`dst_port`, e.g. Ethernet0 -> 10.0.0.1). The DUT routes the packet out of `dst_port`, and PTF verifies it arrives on the PTF port of `dst_port` with TTL decremented by 1 (Ethernet MAC and IP checksum are not compared). PTF port indices come from `minigraph_ptf_indices`.

```
PTF port(src_port) -> DUT src_port -> route to neighbor -> DUT dst_port -> PTF port(dst_port)
```

**Steps:**
1. Verify all ports of ELS0 are oper up, pick `src_port` (an oper up port outside ELS0) and `dst_port` (first port of ELS0), and verify the packet is received (baseline).
2. Pick the image whose version differs from the current Active Firmware, then run `cpoutil firmware download els 0 --raw <picked_fw.bin>` and `cpoutil firmware run els 0`.
3. Verify all ports of ELS0 go oper down.
4. `cpoutil firmware commit els 0`, then `cpoutil config interface reset Ethernet0` while xcvrd is still stopped, then start xcvrd and admin toggle (`config interface shutdown` / `startup`) all ports of ELS0.
5. Verify:
   - All ports of ELS0 are oper up again.
   - Active Firmware equals the picked version and Committed Image equals Running Image.
   - The packet is received again (retried for up to 120 s while the LAG and the neighbor come back).

**Covers:** port down after `run`, port recovery via reset + admin toggle, data-plane traffic recovery, firmware state after recovery.

## Known limitations

- Raw binary only; no host-side image validation (HLD §12)
- `run` takes the ports served by the ELS down; they stay down until the ELS is reset and its ports are admin toggled. TC-06 verifies this recovery with a single packet on one port of one ELS in one direction (into the CPO port); the other ports are verified by oper status only (HLD §12)
- Firmware lock covers only firmware hooks; other CDB clients (e.g. xcvrd) must be stopped — this plan stops xcvrd via `supervisorctl stop xcvrd` (HLD §7.8)
- Some devices reject download while the running image is not committed, or clear the inactive bank on failed download (HLD §12). If a test leaves an ELS running an uncommitted image, `restore_els_firmware` cannot restore it
- TC-04 requires the platform to set `FIRMWARE_LOCK_DIR` (`/var/lock/nvidia-cpo` on NVIDIA CPO platforms)
- Expected cpoutil errors are ignored module-wide by loganalyzer, so loganalyzer does not catch unexpected cpoutil errors in TC-01/TC-02; those tests rely on command return codes and version checks

## Open items

- OE firmware operation testing (future, when OE is in scope)
