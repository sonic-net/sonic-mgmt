# QoS Test Tools

End-to-end tooling for running spytest QoS tests on SONiC testbeds:
upgrade DUTs, run tests in containers, publish results to the dashboard.

## Quick Reference

```bash
# Full automated run (upgrade + test + transfer logs + publish)
./spytest_run.py --yaml /path/to/gamut_2x2_qos.yaml --url <image_url> --publish

# Run tests only (skip upgrade, use whatever image is on the DUTs)
./spytest_run.py --yaml /path/to/gamut_2x2_qos.yaml --skip-upgrade

# Run a single test inside container
./run_test.sh --yaml /path/to/gamut_2x2_qos.yaml pfc/test_v4_pfc_2to1_congestion_2x2.py

# Quick local results summary
python3 spytest_summary.py run_logs_gamut_20260512_120500/
python3 spytest_summary.py run_logs_gamut_20260512_120500/ -f   # failures only

# Publish results standalone (after tests already ran)
python3 spytest_publish.py run_logs_gamut_20260512_120500/ --yaml gamut_2x2_qos.yaml
```

## Tools Overview

| File | Purpose |
|------|---------|
| `spytest_run.py` | **Orchestrator** — upgrade → config → test → transfer logs → publish |
| `run_test.sh` | **Test runner** — container setup + spytest invocation |
| `spytest_publish.py` | **Publisher** — parse results → XML → upload → dashboard |
| `spytest_summary.py` | **Quick summary** — local results viewer (no network) |
| `spytest_lib.py` | Shared parsing library (used by publish + summary) |
| `testbed_config.py` | Central config registry (testbed → docker image, NPU, profile, etc.) |
| `testbed.py` | Testbed reservation tool (prevents stepping on each other) |
| `to_dut.py` | Push config\_db.json to DUTs |
| `from_dut.py` | Pull config\_db.json from DUTs |
| `upgrade_on_dut.sh` | On-DUT image upgrade helper |

## Testbed Configuration

All tools look up testbed-specific settings from `testbed_config.py` using the YAML filename.
To add a new testbed, add an entry to `TESTBED_CONFIGS`.

| Testbed YAML | Platform | NPU | Profile | Fabric |
|---|---|---|---|---|
| `tortuga_2x2_G200_testbed.yaml` | Tortuga | G200 | Tortuga | IPv4, VXLAN |
| `tortuga_2x2_Q200_testbed.yaml` | Tortuga | Q200 | Tortuga | IPv4, VXLAN |
| `gamut_2x2_qos.yaml` | Gamut | SPECTRUM4 | Gamut | IPv4, VXLAN |
| `rocev2_testbed.yaml` | OCI | G200 | OCI | IPv6 |

Container tar files are hosted on `sonic-ucs-m6-51:/home/sonic/containers/` and
fetched automatically to the dev machine on first use (cached in `<spytest_dir>/.containers/`).

---

## spytest_run.py — Full Pipeline

Runs the complete workflow: upgrade DUTs → push base configs → run tests → transfer logs → publish to dashboard.

Publishing is **opt-in** — pass `--publish` to enable Phase 4 (dashboard upload).

```bash
# Full run (upgrade + test + publish)
./spytest_run.py --yaml /path/to/gamut_2x2_qos.yaml --url <image_url> --publish

# Skip upgrade, run tests on current image
./spytest_run.py --yaml /path/to/gamut_2x2_qos.yaml --skip-upgrade

# Run specific tests only
./spytest_run.py --yaml /path/to/gamut_2x2_qos.yaml --skip-upgrade --test pfc/test_v4_pfc_2to1_congestion_2x2.py

# Schedule a run 2 hours from now
./spytest_run.py --yaml /path/to/gamut_2x2_qos.yaml --url <image_url> --schedule 2
```

| Option | Description |
|--------|-------------|
| `--yaml` | Testbed YAML file path (required) |
| `--url` | Image URL for DUT upgrade |
| `--spine-url` | Separate image URL for spines |
| `--branch` | Git branch to checkout before running |
| `--test` | Test file(s) to run (default: `full`) |
| `--skip-upgrade` | Skip DUT upgrade phase |
| `--skip-config` | Skip pushing base configs |
| `--publish` | Publish results to dashboard (Phase 4) |
| `--schedule N` | Schedule run N hours from now via crontab |

**Pipeline phases:**
1. **Phase 0** — Git pull / checkout branch
2. **Phase 1** — Upgrade DUTs (parallel SSH, reboot, wait for containers)
3. **Phase 1.5** — Push base configs via `to_dut.py`
4. **Phase 2** — Run tests via `run_test.sh`
5. **Phase 3** — Transfer logs to server via SCP
6. **Phase 4** — Publish results via `spytest_publish.py` (only with `--publish`)

---

## run_test.sh — Container Test Runner

Sets up the Docker container and runs spytest inside it. Called by `spytest_run.py` or directly.

```bash
# Run all QoS tests
./run_test.sh --yaml /path/to/gamut_2x2_qos.yaml full

# Run a specific test
./run_test.sh --yaml /path/to/gamut_2x2_qos.yaml pfc/test_v4_pfc_2to1_congestion_2x2.py

# Pass env vars to spytest
./run_test.sh --yaml /path/to/gamut_2x2_qos.yaml --env SPYTEST_TOPOLOGY=2x2 full
```

**Container auto-setup:** If the container isn't running, the script:
1. Fetches the docker tar from `sonic-ucs-m6-51` (if not cached locally)
2. Loads the docker image
3. Creates and starts the container with `$PWD` mounted at `/data`

Container naming: `<prefix>_$USER` (e.g. `keysight_11.00_shbhatna`).

---

## spytest_publish.py — Results Publisher

Parses spytest results, generates JUnit XML, uploads logs, and imports to the dashboard.
Profile, NPU, and fabric are derived from the testbed YAML — no manual `--profile`/`--platform` needed.

```bash
# Full publish (parse → XML → upload → dashboard)
python3 spytest_publish.py run_logs_gamut_20260512_120500/ --yaml gamut_2x2_qos.yaml

# Override auto-detected branch/build
python3 spytest_publish.py run_logs_gamut_20260512_120500/ --yaml gamut_2x2_qos.yaml \
    --branch 202505c --build 41146

# Dry run (preview only)
python3 spytest_publish.py run_logs_gamut_20260512_120500/ --yaml gamut_2x2_qos.yaml --dry-run

# Generate XML only (no upload)
python3 spytest_publish.py run_logs_gamut_20260512_120500/ --yaml gamut_2x2_qos.yaml --xml-only -o results.xml

# Skip upload (just generate XML + import)
python3 spytest_publish.py run_logs_gamut_20260512_120500/ --yaml gamut_2x2_qos.yaml --skip-upload
```

| Option | Description |
|--------|-------------|
| `--yaml` | Testbed YAML filename (required) |
| `--branch` | Override auto-detected branch (e.g. `202505c`) |
| `--build` | Override auto-detected build ID |
| `--fabric` | Force fabric: `IPv4`, `VXLAN`, or `IPv6` |
| `--topo` | Topology: `2x2`, `B2B`, `3-tier`, `standalone` |
| `--dry-run` | Preview all steps without executing |
| `--xml-only` | Generate XML locally only |
| `--skip-upload` | Skip SCP upload to server |
| `--skip-import` | Skip dashboard import |
| `-o` | Output XML file path |
| `-v` | Verbose output |

**Auto-detection:** Branch and build ID are detected from (in order):
1. `version_info.txt` (written by `spytest_run.py`)
2. Directory name patterns (e.g. `202505c_gamut_image_41146`)
3. `build.txt` or `*_summary.txt` (written by spytest framework)

---

## spytest_summary.py — Quick Summary

View results locally without uploading anything.

```bash
python3 spytest_summary.py run_logs_gamut_20260512_120500/
python3 spytest_summary.py run_logs_gamut_20260512_120500/ -f   # failures only
```

---

## Testbed Reservation

Prevents multiple engineers from running tests on the same testbed simultaneously.
Before running tests, you must reserve the testbed. The run scripts (`run_test.sh`,
`spytest_run.py`) verify you hold a valid reservation before proceeding.

```bash
# Show all testbed status
./testbed.py

# Reserve a testbed (hours + note required)
./testbed.py --testbed 10002 --reserve 4 --note "qos regression"

# Release when done
./testbed.py --testbed 10002 --release
```

**Workflow:**
1. Reserve: `./testbed.py --testbed <ID> --reserve <hours> --note "<purpose>"`
2. Run tests: `./run_test.sh --testbed <ID> ...` or `./spytest_run.py --testbed <ID> ...`
3. Release: `./testbed.py --testbed <ID> --release`

Reservations auto-expire after the specified hours (safety net for crashes).
If you don't release manually, the reservation will expire and free up.

---

## DUT Utilities

**Push configs to DUTs:**
```bash
python3 to_dut.py --yaml /path/to/testbed.yaml --config-dir dut_configs/gamut_2x2_configs
python3 to_dut.py --yaml /path/to/testbed.yaml --config-dir dut_configs/gamut_2x2_configs --yes
```

**Pull configs from DUTs:**
```bash
python3 from_dut.py ./saved_configs/
```

**Upgrade a DUT directly (run ON the DUT):**
```bash
./upgrade_on_dut.sh --url http://server/sonic-image.tar.gz
./upgrade_on_dut.sh --url http://server/sonic-image.tar.gz --no-reboot
```

---

## Infrastructure

| Component | Details |
|-----------|---------|
| **Dashboard** | http://sonic-ucs-m6-51:5005 |
| **Log server** | `sonic-ucs-m6-51:/home/sonic/test_logs_central/spytest_logs/` |
| **Container server** | `sonic-ucs-m6-51:/home/sonic/containers/` |
| **User** | `sonic` |

## Troubleshooting

**Container tar not found:** Tars are fetched from `sonic-ucs-m6-51:/home/sonic/containers/` via SCP.
Make sure the tar file exists on the server and `sshpass` is available.

**Build ID not detected:** Auto-detected from dir name, `version_info.txt`, or `build.txt`.
Use `--build <id>` to override.

**Branch not detected:** Auto-detected from `version_info.txt`, dir name, or `build.txt`.
Use `--branch 202505c` to override.

**DNS/proxy issues with dashboard:** The publish script SSHes to the server and runs curl
against `localhost:5005` to bypass DNS/proxy issues.
