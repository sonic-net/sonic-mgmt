# Snappi GCU (Generic Configuration Updater) Tests

This document describes how GCU-based Reduced-Set-Base (RSB) configuration works for
Snappi tests, how to run those tests, and how to troubleshoot common issues.

## Overview

When `--test_gcu_snappi` is enabled, the test harness:

1. Modifies a copy of `minigraph.xml` to remove front-panel ports (RSB minigraph).
2. Loads that minigraph on the DUT and saves the resulting **RSB** `config_db` snapshot
   (`rsb_configs/`).
3. **Builds** JSON patch files under `gcu_patches/` using `jsondiff` and `jq` (this step
   does **not** run `config apply-patch`). Patches capture the difference between
   `rsb_configs` (reduced) and `full_configs` (original).
4. Restores the **original** `minigraph.xml` on the DUT disk from `full_configs/`
   (`copy_minigraph_back`). The running `config_db` at this point is still the RSB
   snapshot from step 2 until patches are applied.
5. At the **start of each test module**, runs `sudo config apply-patch` on the generated
   patch file(s) to bring the DUT to the **test runtime configuration** (original baseline
   plus the changes encoded in the patch).
6. At **session teardown** (after all modules finish), runs `config_reload` from the
   restored original minigraph and `config save` to return the DUT to its original
   configuration.

Primary implementation files:

| File | Role |
|------|------|
| `snappi_tests/conftest.py` | GCU fixtures, patch prepare/apply/archive |
| `common/helpers/xml_utils.py` | Minigraph XML modification (`modify_minigraph`) |

---

## Prerequisites

**Run `test_pretest.py` before GCU Snappi tests** on a testbed (especially after testbed
changes, failed runs, or cache issues). Pretest helps ensure:

- Local test cache is cleaned (`test_cleanup_cache`)
- DUT feature/service state is valid
- Testbed metadata and golden configs are refreshed

Without pretest, the DUT may retain stale portchannel/LAG state and RSB conversion may
not remove `PORTCHANNEL` / `PORTCHANNEL_MEMBER` from `rsb_configs` as expected.

Example:

```bash
pytest test_pretest.py \
  --inventory ../ansible/<inventory> \
  --host-pattern <dut-hostname> \
  --testbed <testbed-name> \
  --testbed_file ../ansible/testbed.csv \
  --topology util
```

Then run Snappi GCU tests (see [Running tests](#running-tests)).

---

## GCU modes: `--test_gcu_snappi`

| Value | Description |
|-------|-------------|
| *(empty, default)* | GCU disabled; fixtures are no-ops |
| `no_front_panel_ports` | Remove **all** front-panel ports from the RSB minigraph |
| `one_front_panel_port` | Keep **one** front-panel port; remove the rest |

### How ports are selected

In `modify_minigraph()` (`common/helpers/xml_utils.py`):

- Front-panel ports = keys in `minigraph_ports` whose names do not contain `-BP`.
- `no_front_panel_ports`: all front-panel ports are removed.
- `one_front_panel_port`: the first front-panel port (per ASIC minigraph facts pass)
  is kept; all others are removed. If only one front-panel port exists, minigraph
  modification is a no-op for that ASIC.

On multi-ASIC DUTs, `modify_minigraph()` is called **once per ASIC** using that ASIC's
`duts_minigraph_facts` entry, but always edits the **same** fetched minigraph file.

---

## Session flow (high level)

```
test_pretest.py (recommended)
        │
        ▼
pytest snappi_tests/... --test_gcu_snappi=<mode>
        │
        ├─► convert_to_rsb (session, autouse) — setup
        │     • fetch /etc/sonic/minigraph.xml
        │     • modify_minigraph() per ASIC
        │     • backup full_configs (original config + minigraph)
        │     • load modified minigraph → config_reload → config save  [RSB on DUT]
        │     • backup rsb_configs (RSB config snapshot)
        │     • prepare_gcu_patches() — jsondiff/jq only → gcu_patches/
        │     • copy_minigraph_back() — restore original minigraph.xml on disk
        │
        ├─► load_gcu_config (module, autouse) — per test module
        │     • setup: sudo config apply-patch  [test runtime config on DUT]
        │     • teardown: archive patch JSON to gcu_patches_archive/
        │
        └─► convert_to_rsb finally (session teardown)
              • config_reload from original minigraph  [restore original config]
              • config save
```

---

## Minigraph modification

### Fetch and edit

1. Minigraph is fetched from the DUT to the test host (`/tmp/...`).
2. `modify_minigraph(minigraph_file, minigraph_data, rsb_mode, platform_asic=...)`
   edits that file in place using `remove_xml_entries()`.

### Non–Broadcom-DNX platforms

Removes interface names, aliases, neighbors, portchannel members (when
`minigraph_portchannels` is populated in facts), and related XML entries using a
broad minigraph scrubbing path.

### Broadcom-DNX platforms (`platform_asic == "broadcom-dnx"`)

Uses a targeted path:

1. **Portchannels** — For each portchannel whose member is in `interfaces_to_remove`,
   remove the portchannel name from the minigraph (when `minigraph_portchannels` is
   available in minigraph facts).
2. **BGP neighbors** — Remove neighbor names tied to removed interfaces.
3. **BGP addresses** — Remove `addr` / `peer_addr` only for BGP peers associated with
   removed neighbors (not all BGP entries).

Platform detection uses `node.facts.get("platform_asic")` passed from
`convert_to_rsb`; it is not hardcoded in the helper.

### Load RSB minigraph

If any XML was modified, the edited file is copied to `/etc/sonic/minigraph.xml` on
the DUT and `config_reload(config_source="minigraph")` is run, followed by
`config save`.

### Minigraph handling

After RSB backup and patch generation, **`copy_minigraph_back()` restores the original
minigraph file** from `full_configs/minigraph.xml` onto the DUT (`/etc/sonic/minigraph.xml`).
This does **not** by itself change the running `config_db`; it prepares the DUT so that
**session teardown** can reload the original configuration from minigraph.

**During the test:** runtime configuration comes from **`config apply-patch`** (module
setup), not from the on-disk minigraph file.

**After all tests:** session `finally` runs `config_reload(config_source="minigraph")` using
the restored original minigraph, returning the DUT to its pre-test configuration.

---

## GCU patch generation (`prepare_gcu_patches`)

Patch **generation** uses `jsondiff` and `jq` on the DUT. It does **not** invoke
`config apply-patch`. Application happens later in `load_gcu_config`.

For each ASIC ID from `duthost.get_asic_ids()`:

1. `jsondiff` between `rsb_configs/config_db{asic}.json` and
   `full_configs/config_db{asic}.json`.
2. Filter out `remove`, `move`, and `BUFFER_*` operations.
3. Prefix paths with `/asic{N}` for multi-ASIC.
4. Split `INTERFACE` operations into `INTERFACES_{asic}.json`.
5. Change remaining operations to `"add"`.

### Per-ASIC patch files (non-DNX apply path)

| File | Contents |
|------|----------|
| `patch{asic}.json` | Main patch (non-INTERFACE ops), e.g. `patch0.json`, `patchNone.json` |
| `INTERFACES_{asic}.json` | INTERFACE-related ops only |

On a pizza-box (single ASIC), `asic` may be `None` → filenames like `patchNone.json`.

---

## Broadcom-DNX variant

### Combined patch

On `platform_asic == "broadcom-dnx"`, after individual per-ASIC files are generated,
`combine_gcu_patches()`:

1. Collects `patch{asic}.json` and `INTERFACES_{asic}.json` that **exist and are
   non-empty** (in deterministic order: all `patch*` first, then all `INTERFACES_*`).
2. Merges them with `jq -s 'add'` into **`gcu_patches/combined_patch.json`**.

### Applying patches on DNX

In `load_gcu_config`:

- **DNX:** Apply `gcu_patches/combined_patch.json` once.
  - If combined patch is missing or empty, fall back to applying each `*.json` file
    individually (same as non-DNX).
- **Non-DNX:** Apply each `*.json` file under `gcu_patches/` via `dut.find()`.

Supervisor nodes are skipped for both apply and archive.

---

## Patch apply (`load_gcu_config`)

- **Scope:** `module` (setup applies patches; teardown archives them).
- **Command:** `sudo config apply-patch <patch-file>`
- **When:** Start of each test module, after session setup has built patches and
  restored the original minigraph on disk.
- **Purpose:** Apply the generated JSON patch to bring the DUT to the **test runtime
  configuration** for that module.
- **Success check:** Last line of stdout must be `Patch applied successfully.`
- **Empty files:** Skipped (`size == 0`).

After the module finishes, applied patch JSON files are moved to a timestamped archive
under `gcu_patches_archive/` so the next module does not re-apply stale patches.

**Session teardown** (not module teardown) restores the original DUT configuration via
`config_reload` from the original minigraph — see [Session flow](#session-flow-high-level).

---

## Directories on the DUT

All paths are relative to the DUT user home directory (typically `admin@<dut>:~`).

| Directory / path | When created | Contents |
|------------------|--------------|----------|
| `full_configs/` | Session setup (`convert_to_rsb`) | Snapshot **before** RSB minigraph load: `config_db*.json`, `minigraph.xml` (original full config) |
| `rsb_configs/` | Session setup, after RSB load | Snapshot **after** RSB minigraph load: RSB `config_db*.json`, modified minigraph |
| `gcu_patches/` | `prepare_gcu_patches` | JSON patches for `config apply-patch`; cleared and regenerated each session prepare |
| `gcu_patches_archive/<UTC-timestamp>/` | Module teardown after successful apply | Archived `*.json` from `gcu_patches/` (debug/history) |

### Example `gcu_patches/` layout (multi-ASIC, non-DNX)

```
gcu_patches/
  patch0.json
  patch1.json
  INTERFACES_0.json
  INTERFACES_1.json
```

### Example with Broadcom-DNX

```
gcu_patches/
  patch0.json
  patch1.json
  INTERFACES_0.json
  INTERFACES_1.json
  combined_patch.json          # used for apply on DNX
```

After module teardown:

```
gcu_patches/                   # empty
gcu_patches_archive/
  20260721_221530/
    combined_patch.json
    patch0.json
    ...
```

---

## Running tests

### Enable GCU

Add `--test_gcu_snappi` to your pytest command:

```bash
pytest snappi_tests/pfc/test_m2o_oversubscribe_lossless.py \
  --inventory ../ansible/<inventory> \
  --host-pattern <dut-hostname> \
  --testbed <testbed-name> \
  --testbed_file ../ansible/testbed.csv \
  --topology multidut-tgen \
  --test_gcu_snappi=no_front_panel_ports
```

Or keep one front-panel port:

```bash
  --test_gcu_snappi=one_front_panel_port
```

### Recommended full workflow

```bash
# 1. Pretest (once per testbed session / after issues)
pytest test_pretest.py --inventory ... --host-pattern ... --testbed ... --topology util

# 2. Snappi test with GCU
pytest snappi_tests/<suite>/test_<name>.py \
  --inventory ... \
  --host-pattern ... \
  --testbed ... \
  --topology multidut-tgen \
  --test_gcu_snappi=no_front_panel_ports \
  ...
```

---

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `PORTCHANNEL` in both `full_configs` and `rsb_configs` | Pretest not run; stale DUT/cache state | Run `test_pretest.py`; re-run GCU session |
| Portchannels still in `show interface` before patch apply | RSB minigraph reload did not strip LAGs | Re-run pretest; inspect modified minigraph on test host during debug |
| GCU apply fails / `Patch applied successfully` missing | Invalid patch, timeout, or YANG validation | Inspect patch file in `gcu_patches/` or `gcu_patches_archive/`; check `config apply-patch` manually |
| Patches applied twice / stale behavior | Old JSON left in `gcu_patches/` | Archive logic should move files after each module; check `gcu_patches_archive/` and ensure module teardown ran |
| DNX apply issues with many patch files | Ordering / multiple applies | DNX uses `combined_patch.json`; confirm `platform_asic` is `broadcom-dnx` and combined file exists |
| Supervisor node errors | GCU skipped on supervisor by design | Expected; only linecard/front-end nodes are converted |
| Empty `minigraph_portchannels` on T2 chassis | Per-ASIC minigraph facts may not populate portchannels | RSB still works via minigraph reload + config_db diff when pretest was run; portchannel removal in XML may rely on BGP path on DNX |

### Inspect patches on DUT

```bash
ls -la gcu_patches/
ls -la gcu_patches_archive/*/
grep -i portchannel gcu_patches/*.json
```

### Compare config backups

```bash
diff <(jq -S '.PORTCHANNEL' full_configs/config_db0.json) \
     <(jq -S '.PORTCHANNEL' rsb_configs/config_db0.json)
```

### Session cleanup

Session `finally` in `convert_to_rsb` runs `config_reload` from minigraph and
`config save` to restore a consistent state after all tests complete.

---

## Related pytest options

| Option | Purpose |
|--------|---------|
| `--test_gcu_snappi` | Enable GCU RSB mode (`no_front_panel_ports`, `one_front_panel_port`, or empty) |
| `--topology multidut-tgen` | Typical topology for Snappi/Ixia tests |

---

## Summary

- **Pretest first** — required for reliable RSB/portchannel behavior on chassis testbeds.
- **RSB snapshot** — created temporarily by loading a modified minigraph; saved as
  `rsb_configs/` and used with `full_configs/` to **build** patch files (`jsondiff`/`jq`).
- **Patch build ≠ patch apply** — `prepare_gcu_patches` only writes JSON files;
  `load_gcu_config` runs `sudo config apply-patch` at module start.
- **During tests** — DUT runtime config comes from applied GCU patches.
- **After all tests** — session teardown reloads the **original minigraph** to restore
  the DUT to its original configuration.
- **Broadcom-DNX** merges patches into `combined_patch.json` and applies it once.
- **On-DUT folders:** `full_configs`, `rsb_configs`, `gcu_patches`, `gcu_patches_archive`.
