# PrefixListMgr Refactor & `SUPPRESS_PREFIX` Test Plan

Reference PR: [sonic-net/sonic-buildimage#26937](https://github.com/sonic-net/sonic-buildimage/pull/26937)
Target test directory: `tests/bgp/`
Existing baseline test: [tests/bgp/test_prefix_list.py](../../tests/bgp/test_prefix_list.py)

- [Overview](#overview)
  - [Scope](#scope)
  - [Summary of PR Changes](#summary-of-pr-changes)
  - [Risk Areas](#risk-areas)
  - [Testbed](#testbed)
- [Setup Configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [Regression — ANCHOR_PREFIX](#regression--anchor_prefix)
    - [TC-A1: `prefix_list add/remove/status` CLI on UpstreamLC / UpperSpineRouter](#tc-a1-prefix_list-addremovestatus-cli-on-upstreamlc--upperspinerouter)
    - [TC-A2: ANCHOR_PREFIX end-to-end (re-run existing `test_prefix_list.py`)](#tc-a2-anchor_prefix-end-to-end-re-run-existing-test_prefix_listpy)
    - [TC-A3: ANCHOR_PREFIX rejected on non-spine device](#tc-a3-anchor_prefix-rejected-on-non-spine-device)
    - [TC-A4: ANCHOR_PREFIX survives `config reload` and `bgp` container restart](#tc-a4-anchor_prefix-survives-config-reload-and-bgp-container-restart)
    - [TC-A5: PrefixListMgr is registered on every device](#tc-a5-prefixlistmgr-is-registered-on-every-device)
  - [New — SUPPRESS_PREFIX](#new--suppress_prefix)
    - [TC-S1: SUPPRESS_PREFIX CLI add/remove/status (IPv4 + IPv6)](#tc-s1-suppress_prefix-cli-addremovestatus-ipv4--ipv6)
    - [TC-S2: SUPPRESS_PREFIX FRR `prefix-list` rendered correctly](#tc-s2-suppress_prefix-frr-prefix-list-rendered-correctly)
    - [TC-S3: SUPPRESS_PREFIX works on any device type](#tc-s3-suppress_prefix-works-on-any-device-type)
    - [TC-S4: SUPPRESS_PREFIX `constants.yml` name override](#tc-s4-suppress_prefix-constantsyml-name-override)
    - [TC-S5: SUPPRESS_PREFIX `constants.yml` fallback (no override)](#tc-s5-suppress_prefix-constantsyml-fallback-no-override)
    - [TC-S6: SUPPRESS_PREFIX persists across `config reload` and bgp container restart](#tc-s6-suppress_prefix-persists-across-config-reload-and-bgp-container-restart)
  - [Negative / Validation](#negative--validation)
    - [TC-N1: Unsupported prefix type rejected by CLI](#tc-n1-unsupported-prefix-type-rejected-by-cli)
    - [TC-N2: Unsupported prefix type written directly to CONFIG_DB](#tc-n2-unsupported-prefix-type-written-directly-to-config_db)
    - [TC-N3: Malformed prefix rejected](#tc-n3-malformed-prefix-rejected)
    - [TC-N4: `status` allowed on every device (read-only)](#tc-n4-status-allowed-on-every-device-read-only)
    - [TC-N5: `chassis_supervisor` skip behavior unchanged](#tc-n5-chassis_supervisor-skip-behavior-unchanged)
- [Implementation](#implementation)
- [Pass / Fail Criteria Summary](#pass--fail-criteria-summary)

---

## Overview

### Scope
This plan verifies the refactor of `PrefixListMgr` in `sonic-bgpcfgd` and the
companion `prefix_list` CLI in the FRR docker, plus the newly introduced
`SUPPRESS_PREFIX` type. The goals are:

1. **No regression** for the existing `ANCHOR_PREFIX` flow on
   `UpstreamLC` / `UpperSpineRouter` devices.
2. **Correct behavior** of the new `SUPPRESS_PREFIX` type on every device.
3. **Registry / per-type device-gating** works end-to-end (Python manager and
   shell CLI agree).
4. **`constants.yml`-driven prefix-list name resolution** works and
   degrades gracefully when no overrides exist.
5. PrefixListMgr is now registered **unconditionally** in `bgpcfgd`
   startup — validate this does not introduce side effects on non-spine
   devices.

### Summary of PR Changes
| File | What changed |
|------|--------------|
| `src/sonic-bgpcfgd/bgpcfgd/managers_prefix_list.py` | Introduced `PREFIX_TYPE_CONFIG` registry; per-type device allow-list via `_is_device_allowed()`; templates and prefix-list names looked up via registry / `constants.yml`. |
| `src/sonic-bgpcfgd/bgpcfgd/main.py` | `PrefixListMgr` now appended unconditionally (was gated on UpstreamLC/UpperSpineRouter). `AsPathMgr` gating unchanged. |
| `dockers/docker-fpm-frr/base_image_files/prefix_list` | Replaced global `check_spine_router` with per-type `validate_device_for_type`; metadata is cached. `supported_prefix_types` now includes `SUPPRESS_PREFIX`. `status` no longer device-gated. |
| `dockers/docker-fpm-frr/frr/bgpd/suppress_prefix/add_suppress_prefix.conf.j2` | New template: `<ipv> prefix-list <name> permit <prefix>`. |
| `dockers/docker-fpm-frr/frr/bgpd/suppress_prefix/del_suppress_prefix.conf.j2` | New template: `no <ipv> prefix-list <name> permit <prefix>`. |
| `files/image_config/constants/constants.yml` | New `bgp.prefix_list.SUPPRESS_PREFIX.{ipv4_name,ipv6_name}` keys (`SUPPRESS_IPV4_PREFIX` / `SUPPRESS_IPV6_PREFIX`). |
| `src/sonic-bgpcfgd/tests/test_prefix_list.py` | New unit tests for unsupported types, wrong device, suppress add/del v4/v6, constants override and fallback. |

### Risk Areas
1. **PrefixListMgr unconditional registration** — could cause new warnings,
   subscription, or log spam on non-spine devices; needs validation.
2. **CLI `validate_device_for_type` parsing** — array literal
   `"SpineRouter:UpstreamLC UpperSpineRouter"` is parsed by shell word
   splitting; verify behaviour on chassis supervisors (skipped) and
   linecards.
3. **`status` now allowed on any device** — backward compatible but must
   never make config changes.
4. **`constants.yml` override path** — used only for `SUPPRESS_PREFIX`;
   make sure `ANCHOR_PREFIX` continues to use `ANCHOR_CONTRIBUTING_ROUTES`.
5. **Schema** — the table is still `PREFIX_LIST|<TYPE>|<prefix>`; do not
   require YANG model changes.

### Testbed
| Testbed | Coverage |
|---------|----------|
| `t2` (multi-asic, chassis with UpstreamLC) | Full ANCHOR_PREFIX regression + SUPPRESS_PREFIX on UpstreamLC. Recommended for end-to-end verification because it is the only topology where ANCHOR_PREFIX is functional. |
| `t1` / `t1-lag` | SUPPRESS_PREFIX on a non-spine device (must succeed) + ANCHOR_PREFIX rejected (must fail with the new error message). |
| `t0` | Same as `t1`: SUPPRESS_PREFIX functional + PrefixListMgr-running-but-no-anchor verification. |
| `vs` (kvm t0 / t1) | Smoke-test all CLI plumbing and `bgpcfgd` startup behavior. |

> Use `pytest.mark.topology(...)` to gate each test. ANCHOR_PREFIX end-to-end
> (TC-A2) keeps the existing `t2` mark from
> [tests/bgp/test_prefix_list.py](../../tests/bgp/test_prefix_list.py). All
> other new cases should be marked `t0`, `t1`, `t2` or
> `any` as noted per case.

---

## Setup Configuration

No persistent ansible/minigraph changes are required. Each test:
- Reads `/etc/sonic/constants.yml` for prefix-list names where applicable.
- Pushes config via the `prefix_list` CLI or directly to CONFIG_DB
  (`PREFIX_LIST|<type>|<prefix>`).
- Cleans up its writes in a fixture `finalizer` or `yield`-teardown.
- Snapshots and restores `running-config` of FRR for IPv4 / IPv6 prefix-lists
  it touches.

Helpers (added to `tests/bgp/test_prefix_list_suppress.py` or reused from
`test_prefix_list.py`):

| Helper | Purpose |
|--------|---------|
| `op_prefix_with_cmd(duthost, prefix_type, prefix, action)` | Wrapper around `sudo prefix_list <action> <type> <prefix>`. |
| `verify_prefix_list_in_db(duthost, prefix_type, prefix)` | Greps `prefix_list status` for `('<type>', '<prefix>')` per asic. |
| `verify_frr_prefix_list_entry(asichost, name, prefix, ipv, present=True)` | Runs `vtysh -c 'show running-config'` (or `show ip prefix-list <name>`) and asserts presence/absence. |
| `get_device_metadata(duthost)` | Reads `DEVICE_METADATA.localhost.{type,subtype}`. |
| `get_suppress_pl_names(duthost)` | Reads `constants.yml` and returns `(ipv4_name, ipv6_name)`. |

---

## Test Cases

### Regression — ANCHOR_PREFIX
> Goal: prove that nothing has changed for the existing flow.

#### TC-A1: `prefix_list add/remove/status` CLI on UpstreamLC / UpperSpineRouter
**Topology:** `t2` (Upstream LC line card) — reuse `rand_one_uplink_duthost`
fixture from existing test.

**Steps**
1. On the selected UpstreamLC duthost:
   1. `sudo prefix_list add ANCHOR_PREFIX 205.168.0.0/24`
   2. `sudo prefix_list add ANCHOR_PREFIX 50c0::/48`
2. Run `prefix_list status` and parse output.
3. Run `sonic-db-cli CONFIG_DB keys "PREFIX_LIST|ANCHOR_PREFIX|*"` on the
   asic instance(s).
4. From `vtysh`, run
   `show ip prefix-list ANCHOR_CONTRIBUTING_ROUTES`
   and
   `show ipv6 prefix-list ANCHOR_CONTRIBUTING_ROUTES`.
5. Remove both prefixes with `sudo prefix_list remove ANCHOR_PREFIX <prefix>`
   and re-verify they are gone.

**Pass criteria**
- `status` lists exactly one `('ANCHOR_PREFIX', '<prefix>')` tuple per
  frontend asic.
- CONFIG_DB has the key, vtysh shows the prefix in
  `ANCHOR_CONTRIBUTING_ROUTES`.
- After `remove`, both views are empty for those prefixes.
- All commands exit 0.

#### TC-A2: ANCHOR_PREFIX end-to-end (re-run existing `test_prefix_list.py`)
**Topology:** `t2`.

**Steps**
1. Build the candidate image containing this PR.
2. Re-run the existing tests **as-is**:
   - `tests/bgp/test_prefix_list.py::test_prefix_list_tsa`
   - `tests/bgp/test_prefix_list.py::test_prefix_list_specific_routes`
3. Compare runtime and pass/fail with the same tests on the baseline image.

**Pass criteria**
- Both tests pass with no flakes.
- No new WARN/ERROR lines from `bgpcfgd` related to `PrefixListMgr`
  (verify via `loganalyzer`).

#### TC-A3: ANCHOR_PREFIX rejected on non-spine device
**Topology:** `t0` or `t1`.

**Steps**
1. On any non-spine duthost, attempt:
   `sudo prefix_list add ANCHOR_PREFIX 205.168.0.0/24`
2. Capture exit code, stderr.
3. Examine `bgpcfgd` logs for warning lines:
   `PrefixListMgr:: Device type <type>/<subtype> not supported for
   ANCHOR_PREFIX`
4. As a second sub-step, **write directly** to CONFIG_DB with
   `sonic-db-cli CONFIG_DB hset "PREFIX_LIST|ANCHOR_PREFIX|205.168.0.0/24"`
   to bypass CLI gating and confirm that PrefixListMgr logs the warning
   and `vtysh` does NOT pick up the prefix.
5. Clean up CONFIG_DB key.

**Pass criteria**
- CLI exits non-zero with stderr containing
  `Prefix type 'ANCHOR_PREFIX' is not supported on device type`.
- Direct CONFIG_DB write produces a `log_warn` (`Device type ... not
  supported for ANCHOR_PREFIX`) and produces no FRR config change.
- No crash of bgpcfgd (`docker exec bgp supervisorctl status` shows
  `bgpcfgd` RUNNING).

#### TC-A4: ANCHOR_PREFIX survives `config reload` and `bgp` container restart
**Topology:** `t2`.

**Steps**
1. Add an ANCHOR_PREFIX prefix via CLI (TC-A1 setup).
2. `sudo config save -y`.
3. `sudo config reload -y -f` (wait for converge with `wait_until`).
4. Re-verify CONFIG_DB and FRR state (same as TC-A1 step 3-4).
5. `docker restart bgp` and wait for `bgpcfgd` ready.
6. Re-verify CONFIG_DB and FRR.
7. Clean up.

**Pass criteria**
- Prefix is restored to ANCHOR_CONTRIBUTING_ROUTES after both reload and
  container restart.

#### TC-A5: PrefixListMgr is registered on every device
**Topology:** any (`t0`, `t1`, `t2`, vs).

**Steps**
1. `docker exec bgp ps -ef | grep bgpcfgd`.
2. `docker exec bgp cat /var/log/swss/swss.rec | head` — confirm clean
   startup.
3. Search `/var/log/syslog` for the new log line:
   `AsPath Manager is enabled for <DEVICE_TYPE>` on spine devices, and
   ensure the **old** line
   `Prefix List Manager and AsPath Manager are enabled for
   UpperSpineRouter/UpstreamLC` is gone.
4. From within bgp container, check the manager objects are subscribed:
   `redis-cli -n 4 PSUBSCRIBE __keyspace@4__:PREFIX_LIST*` for a short
   window (≤ 5 s) — should not error out.

**Pass criteria**
- `bgpcfgd` healthy on every device.
- New log line present on spine, no leftover old message.
- No crash, no traceback in `/var/log/syslog`.

### New — SUPPRESS_PREFIX
> Goal: validate the new SUPPRESS_PREFIX feature end-to-end on a physical
> device.

#### TC-S1: SUPPRESS_PREFIX CLI add/remove/status (IPv4 + IPv6)
**Topology:** `t0`, `t1`, `t2` (one device of each is enough).

**Steps**
1. Pick a frontend duthost.
2. `sudo prefix_list add SUPPRESS_PREFIX 192.168.100.0/24`
3. `sudo prefix_list add SUPPRESS_PREFIX 2001:db8:abcd::/48`
4. `sudo prefix_list status` — assert both tuples appear N_asic times.
5. Verify CONFIG_DB:
   - `sonic-db-cli CONFIG_DB keys "PREFIX_LIST|SUPPRESS_PREFIX|*"`
6. Remove both prefixes with `prefix_list remove`.
7. Re-run `status` to confirm both are gone.

**Pass criteria**
- All commands exit 0.
- CONFIG_DB keys appear and disappear as expected.
- `status` output matches expected count per frontend asic.

#### TC-S2: SUPPRESS_PREFIX FRR `prefix-list` rendered correctly
**Topology:** `t0`, `t1`, `t2`.

**Steps**
1. Read `constants.yml`:
   ```
   constants:
     bgp:
       prefix_list:
         SUPPRESS_PREFIX:
           ipv4_name: SUPPRESS_IPV4_PREFIX
           ipv6_name: SUPPRESS_IPV6_PREFIX
   ```
2. Add an IPv4 and IPv6 prefix as in TC-S1.
3. On every frontend asic, run:
   - `vtysh -n <asic> -c "show ip prefix-list SUPPRESS_IPV4_PREFIX"`
   - `vtysh -n <asic> -c "show ipv6 prefix-list SUPPRESS_IPV6_PREFIX"`
4. Parse FRR `running-config` and verify the exact line:
   - `ip prefix-list SUPPRESS_IPV4_PREFIX seq <n> permit 192.168.100.0/24`
   - `ipv6 prefix-list SUPPRESS_IPV6_PREFIX seq <n> permit 2001:db8:abcd::/48`
5. Remove prefixes and verify lines are gone.

**Pass criteria**
- FRR `show <ip|ipv6> prefix-list` returns the configured prefix while
  set; returns empty after removal.

#### TC-S3: SUPPRESS_PREFIX works on any device type
**Topology:** parametrize over `(t0, t1, t2)`.

**Steps**
1. On each non-spine duthost (ToRRouter, LeafRouter, BackEnd, etc.),
   add a SUPPRESS_PREFIX entry via CLI (IPv4 only is enough).
2. Confirm CONFIG_DB and FRR state.
3. Remove and confirm cleanup.
4. Repeat directly via CONFIG_DB write to confirm PrefixListMgr in-process
   does not gate on device type for SUPPRESS_PREFIX.

**Pass criteria**
- SUPPRESS_PREFIX accepted on every tested device type.
- No warning in `bgpcfgd` log saying
  "Device type ... not supported for SUPPRESS_PREFIX".

#### TC-S4: SUPPRESS_PREFIX `constants.yml` name override
**Topology:** `t0` or `t1`.

> This case verifies the `bgp.prefix_list.<type>.ipv4_name` override path.
> Done with a transient edit of `constants.yml`; restore on teardown.

**Steps**
1. Back up `/etc/sonic/constants.yml`.
2. Edit `constants.yml` so that
   `bgp.prefix_list.SUPPRESS_PREFIX.ipv4_name = CUSTOM_IPV4_PREFIX` and
   `ipv6_name = CUSTOM_IPV6_PREFIX`.
3. `docker restart bgp` to reload constants.
4. Wait for `bgpcfgd` ready.
5. Add SUPPRESS_PREFIX entries for both v4 and v6.
6. Confirm FRR shows `ip prefix-list CUSTOM_IPV4_PREFIX ...` and
   `ipv6 prefix-list CUSTOM_IPV6_PREFIX ...`.
7. Confirm **no** `SUPPRESS_IPV4_PREFIX`/`SUPPRESS_IPV6_PREFIX` lines exist.
8. Teardown: remove prefixes, restore `constants.yml`, restart bgp.

**Pass criteria**
- Override applied: custom names visible in FRR config.
- Default names absent.

#### TC-S5: SUPPRESS_PREFIX `constants.yml` fallback (no override)
**Topology:** `t0` / `t1` / `t2` (default image).

**Steps**
1. Confirm `constants.yml` already has the default
   `SUPPRESS_IPV4_PREFIX` / `SUPPRESS_IPV6_PREFIX`.
2. Add SUPPRESS_PREFIX prefixes.
3. Confirm FRR uses defaults.
4. Now **delete** the `bgp.prefix_list` section from `constants.yml`
   temporarily, restart bgp, re-add a prefix.
5. Confirm FRR still uses the registry-default names
   (`SUPPRESS_IPV4_PREFIX` / `SUPPRESS_IPV6_PREFIX`) — these come from
   the registry lambda fallback.
6. Restore `constants.yml`.

**Pass criteria**
- Both with and without the `bgp.prefix_list` constants block, the
  default names are used.

#### TC-S6: SUPPRESS_PREFIX persists across `config reload` and bgp container restart
**Topology:** `t0` / `t1`.

**Steps**
1. Add a SUPPRESS_PREFIX v4 and v6 prefix.
2. `sudo config save -y`.
3. `sudo config reload -y -f` then wait for converge.
4. Verify FRR still has the configured prefix-list entries.
5. `docker restart bgp`, wait for ready, re-verify.
6. Clean up.

**Pass criteria**
- Persistence holds across `config reload` and `docker restart bgp`.

### Negative / Validation
#### TC-N1: Unsupported prefix type rejected by CLI
**Topology:** any.

**Steps**
1. `sudo prefix_list add UNKNOWN_TYPE 10.0.0.0/24`.
2. Capture exit code and stderr.

**Pass criteria**
- Exit code non-zero.
- stderr contains the validate-operation message from the CLI
  (`prefix_type ... not in supported_prefix_types`).
- CONFIG_DB has no key for `UNKNOWN_TYPE`.

#### TC-N2: Unsupported prefix type written directly to CONFIG_DB
**Topology:** any.

**Steps**
1. `sonic-db-cli CONFIG_DB hset "PREFIX_LIST|FOO_TYPE|10.0.0.0/24" NULL NULL`.
2. Wait a few seconds.
3. Tail `/var/log/syslog` for line:
   `PrefixListMgr:: Prefix type 'FOO_TYPE' is not supported`.
4. Verify FRR has no entry related to FOO_TYPE.
5. Clean up CONFIG_DB key.

**Pass criteria**
- Warning is logged.
- `bgpcfgd` does not crash.
- No FRR config change.

#### TC-N3: Malformed prefix rejected
**Topology:** any.

**Steps**
1. Try via CLI:
   `sudo prefix_list add SUPPRESS_PREFIX 999.999.0.0/24` — expect CLI
   regex / sonic CLI validation to reject.
2. Try via CONFIG_DB direct:
   `sonic-db-cli CONFIG_DB hset "PREFIX_LIST|SUPPRESS_PREFIX|not-a-prefix"
    NULL NULL`.
3. Inspect log: `PrefixListMgr:: Prefix '...' format is wrong for prefix
   list 'SUPPRESS_PREFIX'`.
4. Clean up CONFIG_DB key.

**Pass criteria**
- CLI form rejected at parse time.
- Direct DB write produces only a warning, no crash, no FRR change.

#### TC-N4: `status` allowed on every device (read-only)
**Topology:** any (especially non-spine).

**Steps**
1. On a non-spine device, run `sudo prefix_list status` (no `add`/`remove`).
2. Verify exit 0 and output prints the (possibly empty) list of installed
   prefix-list entries from CONFIG_DB.
3. Also verify it succeeds on `chassis_supervisor` if applicable — recall
   the CLI still calls `skip_chassis_supervisor`, so it should exit
   cleanly with a skip message but **not** error.

**Pass criteria**
- `status` returns exit 0 on every device.
- No config changes are made.

#### TC-N5: `chassis_supervisor` skip behavior unchanged
**Topology:** `t2` (chassis with supervisor).

**Steps**
1. On the supervisor card, run:
   - `sudo prefix_list add SUPPRESS_PREFIX 10.0.0.0/24` — expect the
     existing supervisor skip path to short-circuit.
   - `sudo prefix_list status` — should also short-circuit per
     `skip_chassis_supervisor`.
2. Capture exit code / stdout.
3. Verify CONFIG_DB on supervisor was not touched.

**Pass criteria**
- Behavior matches pre-PR baseline (no crash, supervisor is skipped).

---

## Implementation

The test cases above will be implemented in
[tests/bgp/test_prefix_list_suppress.py](../../tests/bgp/test_prefix_list_suppress.py).

TC-A2 has no new code — it is covered by re-running the existing
[tests/bgp/test_prefix_list.py](../../tests/bgp/test_prefix_list.py) on the
candidate image. All other TCs map 1:1 to a `test_*` function in
`test_prefix_list_suppress.py`.

---

## Pass / Fail Criteria Summary

| TC | Required result |
|----|-----------------|
| TC-A1 | CLI add/remove/status round-trip works on UpstreamLC; FRR shows / hides entries in `ANCHOR_CONTRIBUTING_ROUTES`. |
| TC-A2 | Existing `test_prefix_list.py` passes unchanged. No new bgpcfgd warnings. |
| TC-A3 | ANCHOR_PREFIX rejected on non-spine (both CLI and direct DB). Warning is logged. No FRR change. No bgpcfgd crash. |
| TC-A4 | ANCHOR_PREFIX persists through config reload + bgp container restart. |
| TC-A5 | PrefixListMgr now runs on every device; old "Prefix List Manager … enabled for UpperSpineRouter/UpstreamLC" log line is gone. No crash anywhere. |
| TC-S1 | SUPPRESS_PREFIX add/remove via CLI succeeds, status reflects state, CONFIG_DB keys appear/disappear. |
| TC-S2 | FRR shows `<ip|ipv6> prefix-list <name> permit <prefix>` while set; nothing after removal. |
| TC-S3 | SUPPRESS_PREFIX works on ToRRouter / LeafRouter / SpineRouter / UpstreamLC alike. |
| TC-S4 | Custom names from `constants.yml` are honored end-to-end. |
| TC-S5 | Default names from registry are used when no override is present. |
| TC-S6 | SUPPRESS_PREFIX persists through config reload + bgp container restart. |
| TC-N1 | CLI rejects unknown prefix type with non-zero exit and clear stderr. |
| TC-N2 | Direct DB write of unknown type is logged-warned by bgpcfgd, no FRR change, no crash. |
| TC-N3 | Malformed prefix is rejected (CLI) or logged (DB), no crash. |
| TC-N4 | `status` works on every device including non-spine without making changes. |
| TC-N5 | Chassis supervisor still skipped by `skip_chassis_supervisor`, no errors. |

**Overall pass requires:** every TC above is green on the candidate image
**and** `bgpcfgd` shows zero new errors/tracebacks across all tested
topologies for the duration of the run.
