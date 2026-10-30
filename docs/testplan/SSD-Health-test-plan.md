# SSD Health Test Plan

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
  - [Related issue](#related-issue)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [test_ssd_smart_health_baseline](#test-case-test_ssd_smart_health_baseline)
  - [test_ssd_write_stress_endurance](#test-case-test_ssd_write_stress_endurance)
  - [test_ssd_mixed_io_stress](#test-case-test_ssd_mixed_io_stress)

## Revision


| Rev | Date       | Author          | Change Description |
| --- | ---------- | --------------- | ------------------ |
| 0.1 | 2026-10-11 | Noa Ferber       | Initial version    |




## Overview

This follows the request in
[sonic-net/sonic-mgmt#23149](https://github.com/sonic-net/sonic-mgmt/issues/23149): sonic-mgmt
needs tests for SSD health, for all Spectrum platforms.

Right now sonic-mgmt has no test that:

- Reads and checks SSD/NVMe SMART health data (media errors, reallocated sectors, wear
level, temperature, power-on hours).
- Puts write/read load on the disk and checks the SMART counters and kernel logs still look
healthy afterwards.
- Checks that read/write I/O works under load (no fio errors, non-zero throughput), and logs the
I/O stats.
- Tracks the SSD's endurance signal (wear level / media errors trend) across runs.

This test plan adds that as new test cases under `tests/platform_tests/ssd/.`

## Scope

These tests provide regression coverage for SSD/NVMe health and behavior under I/O load on a
physical SONiC DUT. The stress workloads use a large file under `/host`, on the existing SSD
filesystem, and do not access the raw disk device.

What each test covers from the original gap description:

1. Disk health getting worse after back-to-back huge writes → `test_ssd_write_stress_endurance`.
2. Read/write stats look ok vs. limits → `test_ssd_mixed_io_stress`.
3. Extra I/O pressure to check disk health → `test_ssd_write_stress_endurance` /
  `test_ssd_mixed_io_stress`.
4. SSD endurance signal (wear level / media errors trend) → `test_ssd_smart_health_baseline`
  (single snapshot) plus `test_ssd_write_stress_endurance` / `test_ssd_mixed_io_stress`
   (baseline/delta comparison around the I/O load).



## Testbed

Any topology (`topology('any')`), physical DUT (`device_type('physical')`) — SMART/NVMe data
needs a real disk, so it doesn't make sense on a virtual switch (`vsonic`).

## Related issue

[SSD health check · Issue #23149 · sonic-net/sonic-mgmt](https://github.com/sonic-net/sonic-mgmt/issues/23149)

## Setup configuration

**Disk-detection fixture**
A module-scoped fixture identifies the disk that backs `/host` using `findmnt` and `lsblk`, and
reads its transport type and model from `lsblk`. SATA and NVMe disks are supported; other disk
types are skipped.

**Utility-install fixture**
A fixture installs the utilities needed on the DUT if they're missing (`smartctl` from
`smartmontools`, `nvme-cli`, `fio`), and removes them again in teardown (`finally`/fixture
finalizer), no matter how the test ends, so the DUT is left as it was found.

**Skip instead of fail**
Tests skip (not fail) on platforms/DUTs where SMART/NVMe tools can't be installed or the disk
doesn't expose the expected health data.

**Shared health parsing**
`test_ssd_health.py` has a health class per disk type, `SataHealth` (`smartctl -a -j`, with the
wear level from `show platform ssdhealth`) and `NvmeHealth` (`nvme smart-log -o json`). Both return
a health dict with the same fields, so all test cases reuse the same threshold checks.

## Test Cases



### Test case: test_ssd_smart_health_baseline

Covers gap item 4 (endurance signal), as a single health snapshot with no load involved. This
test is fast (no I/O load), and it also checks that the disk is healthy before the stress tests run.

#### Test steps

1. Find the DUT's disk device and make sure SMART/NVMe tools are available (install if
  missing).
2. Read current health data via `smartctl -a` / `nvme smart-log`.
3. Parse: media/error count, reallocated sectors (SATA) or media errors (NVMe), percentage
  used / wear level count, temperature, power-on hours, critical warning flags.

#### Verify

- No critical warning flags are set.
- Media/reallocated errors are `0`.
- Temperature is within the platform's safe range.
- Percentage used / wear level is below a configurable failure threshold (default e.g. 90%).



### Test case: test_ssd_write_stress_endurance

Covers gap item 1 (deterioration on back-to-back huge writes), item 3 (extra I/O pressure), and
item 4 (endurance signal).

#### Test steps

1. Capture baseline SMART/NVMe health data (reuses baseline logic from
  `test_ssd_smart_health_baseline`).
2. Run a bounded sequential-write `fio` job against a large file on an existing, already
  mounted filesystem (not a raw device), with a parametrized runtime.
3. Record the start time before the load, then inspect the kernel messages reported by `dmesg`
  since that time for disk-related I/O errors.
4. Capture SMART/NVMe health data again after the run.
5. Clean up the test file.

#### Verify

- fio job finishes with no I/O errors and reports write bandwidth/IOPS greater than zero
(this is a sanity check, not a performance target).
- No new media errors / reallocated sectors compared to baseline.
- No NVMe/disk-related errors in `dmesg` during the run. The SSD does not write to the kernel
  log itself; the errors come from the kernel drivers when an I/O to the disk fails. Example from a
  real case, where the link between the SATA controller and the SSD failed
  ([NVIDIA KB](https://docs.nvidia.com/networking-ethernet-software/knowledge-base/Configuration-and-Usage/Hardware-and-Platform-Issues/SSD-is-Read-only-on-Switches-with-Intel-7-Series-SATA-Controllers/)):

  ```text
  kernel: [3238274.795264] ata1.00: exception Emask 0x10 SAct 0x40 SErr 0x4050000 action 0xe frozen
  kernel: [3238274.815419] ata1.00: failed command: WRITE FPDMA QUEUED
  kernel: [3238274.841065] ata1: hard resetting link
  ```
- Temperature is within the configured safe range before and after the load.


### Test case: test_ssd_mixed_io_stress

Covers gap item 2 (read/write stats sanity), item 3 (extra I/O pressure), and item 4
(endurance signal).

#### Test steps

1. Capture baseline SMART/NVMe health data.
2. Run a bounded mixed random read/write `fio` job (70% read, 4K blocks, iodepth 32,
  parametrized runtime) against the same test file used in `test_ssd_write_stress_endurance`.
3. Sample `iostat -xm` during the run (or a fixed number of samples) to record utilization,
  average queue size and latency.
4. Capture SMART/NVMe health data again after the run.

#### Verify

- fio finishes with no I/O errors, and both read and write report bandwidth/IOPS greater than
  zero (a sanity check, not a performance target).
- `iostat -xm` samples (IOPS, MB/s, latency, queue size, utilization) are logged during the run
  for debugging.
- No new media errors / reallocated sectors compared to baseline.
- No NVMe/disk-related errors in `dmesg` during the run.
