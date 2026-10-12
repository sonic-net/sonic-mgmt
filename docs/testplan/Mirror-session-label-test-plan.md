# SONiC Mirror Session Label test plan

## Table of Contents

- [Revision history](#revision-history)
- [Abbreviations](#abbreviations)
- [How to read this plan](#how-to-read-this-plan)
- [The core idea (mental model)](#the-core-idea-mental-model)
- [Test case summary & coverage](#test-case-summary--coverage)
- [Overview](#overview)
- [Scope](#scope)
  - [In scope](#in-scope)
  - [Out of scope](#out-of-scope)
- [References](#references)
- [Testbed and topology](#testbed-and-topology)
- [Counter semantics](#counter-semantics)
- [Conventions](#conventions)
- [Test cases](#test-cases)
  - [Fixture](#fixture)
  - [Area 1 — Functionality](#area-1--functionality)
  - [Area 2 — Interoperability](#area-2--interoperability)
  - [Area 3 — Reliability](#area-3--reliability)
  - [Area 5 — Scale](#area-5--scale)
  - [Area 6 — Installation, Setup, Upgrade](#area-6--installation-setup-upgrade)
  - [Areas without a dedicated test](#areas-without-a-dedicated-test)



## Revision history


| Rev | Date       | Author          | Description                                                 |
| --- | ---------- | --------------- | ----------------------------------------------------------- |
| 0.1 | 2026-10-11 | Anton Hryshchuk | Initial draft generated from HLD Rev 1.0 (hld-to-test-plan) |




## Abbreviations


| Term       | Expansion                                                                          |
| ---------- | ---------------------------------------------------------------------------------- |
| ACL        | Access Control List                                                                |
| ASIC       | Application-Specific Integrated Circuit                                            |
| ASIC_DB    | Redis database holding the SAI objects programmed by orchagent (DB 1)              |
| CLI        | Command-Line Interface                                                             |
| CONFIG_DB  | Redis database holding operator configuration (DB 4)                               |
| DUT        | Device Under Test                                                                  |
| ERSPAN     | Encapsulated Remote SPAN                                                           |
| GCU        | Generic Config Updater                                                             |
| gNMI       | gRPC Network Management Interface                                                  |
| HLD        | High Level Design                                                                  |
| ISSU       | In-Service Software Upgrade                                                        |
| LAG        | Link Aggregation Group                                                             |
| MirrorOrch | Orchagent class that creates and removes mirror sessions                           |
| OID        | SAI object identifier                                                              |
| PTF        | Packet Test Framework                                                              |
| SAI        | Switch Abstraction Interface                                                       |
| SPAN       | Switched Port Analyzer (local mirror session)                                      |
| STATE_DB   | Redis database holding operational state published by orchagent (DB 6)             |
| swss       | Switch State Service container                                                     |
| TC         | Test case                                                                          |
| VLAN       | Virtual Local Area Network                                                         |
| WJH        | What Just Happened (NVIDIA telemetry feature that reserves a hardware mirror slot) |
| YANG       | Data modelling language used for the SONiC configuration schema                    |




## How to read this plan

- This plan says **what we verify and how to tell pass from fail**. For *how the feature works*, read the HLD.
- Read **The core idea** first, then the **Test case summary & coverage** table; the cards are reference.
- Size: 11 tests + 1 readiness fixture. P0 = 2 tests (<5 min), P0+P1 ≈ 30–35 min including one config reload, one warm reboot and the PTF traffic steps; the P2 rows (cold reboot, fast reboot, swss restart, multi-ASIC, churn) and ISSU (separate NVIDIA upgrade job) are extra.
- Log checks are not separate tests: the `loganalyzer` fixture runs automatically around every test, and each test lists the log lines it expects (see Conventions).
- Mirrored-traffic checks are steps inside existing tests (PTF), not separate tests: `test_label_create` (the label does not change the mirrored packet) and `test_label_persistence` (mirror traffic survives every restart type; zero loss across warm reboot).



## The core idea (mental model)

A mirror session may carry an optional, create-only `label` (`[A-Za-z0-9_-]{1,31}`, unique per ASIC). The label travels CONFIG_DB → MirrorOrch → SAI at **create** time only, is mirrored into STATE_DB, and is the only thing that lets a recreated session reclaim its old hardware slot after warm reboot / ISSU v1. Every TC checks one of: (a) valid labels are accepted and visible in all layers, (b) invalid/duplicate/in-place labels are rejected without side effects, (c) labels survive restarts and reboots.


| Input                                                 | Expected behaviour                                           |
| ----------------------------------------------------- | ------------------------------------------------------------ |
| no `label`                                            | session works as before; no label in STATE_DB / ASIC_DB      |
| valid unique `label`                                  | CONFIG_DB + STATE_DB + `show` (Label column) + ASIC_DB LABEL |
| invalid / empty / > 31 chars / duplicate in same ASIC | rejected, no SAI object, ERROR in syslog                     |
| `label` changed on live session                       | no SAI SET; only delete + recreate changes it                |




## Test case summary & coverage


| Test / fixture                      | What it proves                                                                                                                                                                                          | Pri                            | Area                                                         | HLD §                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------ | ------------------------------------------- |
| fixture `label_capability`          | DUT is label-capable on every ASIC and CLI exposes `--label` / `Label` column; else skip the suite (module-scope readiness gate, not a test)                                                            | gate                           | Preconditions                                                | §2.10.3, §5                                 |
| `test_label_create`                 | Session with and without a label (3 CLI forms): label visible in CONFIG_DB, STATE_DB, `show`, ASIC_DB only when set; removed with the session; NOTICE logs on create/remove; mirrored packet is the same with and without a label (PTF)                             | P0                             | 1 Functionality; 7 Logging                                   | §1.2, §2.8, §2.9, §2.11                     |
| `test_label_validation`             | Valid labels accepted verbatim; invalid labels (empty, 32, 65 chars, charset, non-ASCII) and duplicate labels on one ASIC rejected by CLI and by MirrorOrch without side effects; ERROR logs            | P0                             | 1 Functionality; 7 Logging                                   | §1.1.4, §2.8, §2.10.2, §3.2.2               |
| `test_label_change_on_live_session` | Label changed on a live session (direct HSET / GCU replace) never alters ASIC_DB; delete + recreate works                                                                                               | P1                             | 1 Functionality                                              | §1.1.5, §2.13                               |
| `test_label_capability_unsupported` | CLI rejects `--label` when capability is false/missing; unlabeled still works                                                                                                                           | P1                             | 1 Functionality                                              | §2.10.3, §2.14.2                            |
| `test_label_persistence`            | Labels, sessions and ACL mirror-action binding persist across config reload, warm reboot (P1), cold reboot, fast reboot, swss restart (P2 rows); warm row checks a create param differing between lives; mirror traffic delivered after every restart and without loss across warm reboot (PTF) | P1 (reload, warm); P2 (others) | 1 Functionality; 2 Interoperability; 6 Install/Setup/Upgrade | §0.5, §1.1.6, §1.5, §2.11.2, §3.2.3, §5.8.3 |
| `test_label_gcu`                    | GCU: valid labeled create applied, invalid label rejected by YANG                                                                                                                                       | P1                             | 2 Interoperability                                           | §2.10.4, §2.11.7                            |
| `test_label_recreate`               | ≥10 create/remove cycles with same label: no cores, no leak, label reusable                                                                                                                             | P2                             | 3 Reliability                                                | §2.12, §5.7                                 |
| `test_label_scale`                  | N labeled unique sessions at platform max active with distinct ASIC_DB objects                                                                                                                          | P1                             | 5 Scale                                                      | §1.3, §5.7                                  |
| `test_label_multi_asic`             | Multi-ASIC: label stored per namespace, same label on different ASICs OK, duplicate within one ASIC rejected, warm-reboot restore per ASIC — multi-ASIC DUT only                                        | P2                             | 5 Scale                                                      | §1.6, §3.2.4                                |
| `test_label_issu_v1`                | ISSU v1 (NVIDIA): labels retained, sessions active, mirror traffic uninterrupted; slot kept; row with internal slot consumers (trim/WJH) enabled                                                        | P1 (off); P2 (on)              | 6 Install/Setup/Upgrade                                      | §5.7, §5.8, §5.9                            |
| (area 4)                            | Performance — excluded: no datapath change (HLD §1.4)                                                                                                                                                   | —                              | 4 Performance                                                | §1.4                                        |
| (area 8)                            | Customer scenario "production monitoring + warm reboot" (HLD §0.5): covered by `test_label_persistence` (warm row: mirror traffic across warm reboot) and `test_label_issu_v1`             | —                              | 8 Customer Scenarios                                         | §0.5                                        |




## Overview

Test plan for the optional mirror-session `label` feature. Upstream design: **SONiC Mirror Session Label HLD, Rev 1.0 (2026-09-06)**, internal NVIDIA design document `mirror-label-design.md` — no public SONiC HLD link exists yet. The HLD defines behaviour; this plan defines verification.

## Scope



### In scope

- `--label` on `config mirror_session add | erspan add | span add`; `Label` column in `show mirror_session` (HLD §1.2).
- Label syntax, length, uniqueness-per-ASIC and create-only semantics at CLI/YANG and MirrorOrch (HLD §1.1, §2.8, §2.10.2).
- CONFIG_DB / STATE_DB / ASIC_DB representation and `SWITCH_CAPABILITY|switch MIRROR_SESSION_LABEL_CAPABLE` (HLD §2.11).
- GCU path (§2.11.7); reboot/restart persistence (§1.5); warm reboot and ISSU v1 label continuity (§1.1.6, §5.8, §5.9); multi-ASIC (§1.6); logging (§2.9).
- Support gating before functional tests (fixture `label_capability`).
- Mirrored-traffic delivery with PTF: the label does not change the mirrored packet (`test_label_create`); mirror traffic is delivered after every restart type and without loss across warm reboot (`test_label_persistence`, HLD §3.2.3, §0.5; ISSU: `test_label_issu_v1`, HLD §5.9).



### Out of scope

- Throughput, latency and line-rate behaviour of mirrored traffic (HLD §1.4, area 4): traffic steps are functional only (delivery, packet content, loss count).
- Performance (§1.4, area 4): no datapath change.
- Counters (§2.7: none introduced); platform / lower-layer API (§2.5, §2.6); security (§4: no new surface; backend validation covered by `test_label_validation`).
- ISSU v2 (§5.8.2); unit tests of sonic-swss / sonic-utilities / sonic-yang-models (§3.1); product policy of mandatory labels (§5.10); syncd label matching, new modify command, "label on every session" policy (§0.2).
- gNMI client tests (§2.10.4) — same YANG → CONFIG_DB path as `test_label_gcu`.
- Unsupported-platform negative TCs (gated once by fixture `label_capability`).




## References

- HLD: `mirror-label-design.md` Rev 1.0 (internal). Requirement spec cited in HLD §5.2: [https://nvidia.atlassian.net/wiki/spaces/NSWARCH/pages/3624771472/SONIC+SAI+Mirror+Session+Label](https://nvidia.atlassian.net/wiki/spaces/NSWARCH/pages/3624771472/SONIC+SAI+Mirror+Session+Label)



## Testbed and topology

Topology marker: `t0` (as `tests/span` and `tests/everflow`). Traffic is injected and captured with PTF. Multi-ASIC cases (`test_label_multi_asic`) need a multi-ASIC DUT. ISSU cases (`test_label_issu_v1`) are NVIDIA-only. No VS-only, snappi or TGEN cases.


## Counter semantics

Not applicable: the feature introduces no counters (HLD §2.7).

## Conventions

- **Session commands** (HLD §2.10.3.2):
  - ERSPAN: `config mirror_session erspan add <name> <src_ip> <dst_ip> <dscp> <ttl> <gre> <queue> [-l|--label <label>]`
  - SPAN: `config mirror_session span add <name> <dst_port> <src_port> <dir> <queue> [-l|--label <label>]`
  - Remove: `config mirror_session remove <name>`; legacy `config mirror_session add` also takes `--label`.
- **Layers** (source of truth for assertions):
  - CONFIG_DB: `redis-cli -n 4 HGETALL "MIRROR_SESSION|<name>"`
  - STATE_DB: `redis-cli -n 6 HGETALL "MIRROR_SESSION_TABLE|<name>"`
  - ASIC_DB: `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*"` then `HGETALL` on each key; label is `SAI_MIRROR_SESSION_ATTR_LABEL`
  - Capability: `redis-cli -n 6 HGETALL "SWITCH_CAPABILITY|switch"` (pattern in `tests/ipfwd/test_nhop_group.py`)
  - CLI: `show mirror_session` (ERSPAN and SPAN tables, `Label` column)
- **Waiting**: after reboot/restart wait for `tests/common/platform/processes_utils.py::wait_critical_processes`, then poll `show mirror_session` until every session is `active`, cap 300 s; timeout = failure.
- **Standard rollback**: `config mirror_session remove <name>` for every session created by the TC, then assert CONFIG_DB, STATE_DB and ASIC_DB have no residue.
- **Direct HSET injection** (backend-path rows): bypasses the CLI frontend check (HLD §4.5: backend must not trust the CLI). To create a session write **one multi-field** `redis-cli -n 4 HSET "MIRROR_SESSION|<name>" type SPAN <other required fields> label <value>` — never fields first and `label` afterwards, which creates an unlabeled object and turns the label write into an in-place change. To change a label on a live session use the single-field `HSET ... label <value>`.
- **Rejection rows** (expected error + no state change): capture CONFIG_DB/STATE_DB/ASIC_DB before; assert the CLI error matches the pattern, and the three layers are unchanged after.
- **Log checks (LogAnalyzer, automatic)**: the `loganalyzer` fixture (`tests/common/plugins/loganalyzer/__init__.py`, `autouse=True`) runs around every test and fails it on unexpected ERROR lines. Therefore no TC starts or stops it by hand. A TC that provokes a log line sets `loganalyzer[<dut>].expect_regex` before the trigger (pattern as in `tests/acl/test_acl.py:878`), and the fixture validates at the end of the test that every expected line appeared. Expected lines (HLD §2.9): ERROR with session name and label for an invalid label (CLI and MirrorOrch) and for a duplicate label (CLI and MirrorOrch); NOTICE for session created/removed. Exact message texts are `[TBD — Open item 1]`; where a negative row provokes further ERROR lines (e.g. the in-place change), they are added to `ignore_regex` / `expect_regex` once observed.
- **SPAN create** is already used in `tests/span/conftest.py:168` (`config mirror_session span add ...`); `--label` itself has no repo usage yet.
- **Reboot**: `tests/common/reboot.py::reboot(duthost, localhost, reboot_type=...)`; config reload via `config reload -y`.



## Test cases

Tests are named like the future pytest functions; priority is in each heading. The one readiness gate is a fixture, not a test.

### Fixture

**fixture** `label_capability` **(module scope, autouse) — capability and CLI present → suite runs, else skip**
**Goal:** HLD §2.10.3 prerequisites before functional tests.
**Steps:**

1. For every ASIC read `SWITCH_CAPABILITY|switch` from STATE_DB.
2. Assert `MIRROR_SESSION_LABEL_CAPABLE` is `true` on every ASIC.
3. Run `config mirror_session span add --help`; assert `-l`/`--label` is listed.
4. Run `show mirror_session`; assert the `Label` column header exists.

**Pass:** all checks pass; otherwise skip the whole suite for this DUT (not a failure).

---



### Area 1 — Functionality

`test_label_create` **— create session with / without label → label visible only when set · P0**
**Goal:** a valid label is accepted and reported consistently; a missing label changes nothing; the label does not affect mirrored traffic (HLD §2.8, §2.11.5, §1.4).
Parameters: `label` ∈ {set (equal to the session name), absent}; `(type, CLI form)` ∈ {ERSPAN `erspan add`, ERSPAN legacy `add`, SPAN `span add`}.
**Expected log:** NOTICE for session created and removed (via `expect_regex`).
**Steps:**

1. Create the session with `--label <L>` (use `-l` for one variant) or without a label (legacy syntax).
2. Labeled: assert CONFIG_DB `label == L`; STATE_DB `MIRROR_SESSION_TABLE|<name>` `label == L`; `show mirror_session` row has `Label == L`; exactly one ASIC_DB mirror-session object has `SAI_MIRROR_SESSION_ATTR_LABEL == L`.
3. Unlabeled: assert no `label` in CONFIG_DB/STATE_DB, no `SAI_MIRROR_SESSION_ATTR_LABEL` in its ASIC_DB object, and the `Label` column is present and empty in both the ERSPAN and SPAN tables.
4. Assert the session is `active`; labeled and unlabeled sessions coexist (leave the unlabeled one from the previous parameter in place while creating the labeled one).
5. Traffic (PTF): SPAN rows — send a packet to source port `S1` and verify exactly one copy at the monitor port, identical to the sent packet; ERSPAN rows — bind an ACL rule with `MIRROR_INGRESS_ACTION` to the session, send a matching packet and verify exactly one ERSPAN-encapsulated copy at the destination equal to the expected packet from `get_expected_mirror_packet` (computed without any label input). The expectation is the same in the labeled and the unlabeled parameter.
6. Remove the ACL rule and the sessions; assert the STATE_DB key and ASIC_DB object are gone.

**Pass:** only labeled sessions carry the label in all layers while they exist; none after removal; all sessions `active`; the mirrored packet is the same with and without a label (label has no effect on mirror traffic).

---

`test_label_validation` **— valid label accepted; invalid or duplicate label rejected, nothing changed · P0**
**Goal:** frontend and backend validation and per-ASIC uniqueness (HLD §1.1.4, §2.8 Tables 2–3, §2.10.2, §3.2.2, §4.5).
**Expected log:** ERROR with session name and label for every rejected row (CLI rows from the frontend, direct-HSET rows from MirrorOrch).
Parameters, group **syntax** (one row at a time — create, assert, remove; SPAN session unless stated):


| Variant       | Label                                                 | Expected |
| ------------- | ----------------------------------------------------- | -------- |
| valid-min     | `a`                                                   | accepted |
| valid-max     | 31-char string                                        | accepted |
| valid-charset | `A1_-z`, 31-char with `_` and `-`                     | accepted |
| valid-name32  | 32-char session name with a 31-char label (HLD §2.13) | accepted |
| invalid-empty | `""`                                                  | rejected |
| invalid-32    | 32 chars                                              | rejected |
| invalid-65    | 65 chars                                              | rejected |
| invalid-chars | with space, with `.`, with `/`, non-ASCII             | rejected |


**Steps — group syntax:**

1. Capture CONFIG_DB/STATE_DB/ASIC_DB state.
2. Valid rows: create the session with that label; assert CONFIG_DB, STATE_DB and ASIC_DB carry the exact label (no truncation) and the session is `active`; remove it (Standard rollback).
3. Invalid rows: run `config mirror_session span add ... --label <bad>`; assert non-zero exit and an error text about label length / allowed characters 
4. Repeat step 3 once each for `erspan add` and legacy `add` with one invalid label.
5. Backend path: for `label ""` and a 32-char label, direct HSET the session into CONFIG_DB (Conventions); assert no ASIC_DB object for it, no 31-char truncated label in STATE_DB/ASIC_DB, and the session is not `active`. Remove the injected key.

**Steps — group uniqueness** (session names `M1`..`M4`):

1. Create ERSPAN `M1` (monitor port `R`) with label `DUP` (long form `--label`).
2. Via CLI create SPAN `M2` (`D1`/`S1`) with label `DUP` (short form `-l`); assert rejection and no `MIRROR_SESSION|M2` in CONFIG_DB.
3. Via direct multi-field HSET create `MIRROR_SESSION|M2` as SPAN on `D1`/`S1` with `label DUP`.
4. Assert ASIC_DB still holds one object with label `DUP`, and `M2` is not `active` / has no ASIC_DB object. Then `redis-cli -n 4 DEL "MIRROR_SESSION|M2"` and assert it is gone.
5. Race: direct multi-field HSET two new ERSPAN sessions `M3`, `M4` (distinct `dst_ip`, same route/port `R`, same label `RACE`) back-to-back; assert exactly one ASIC_DB object carries `RACE` (the label is the only conflict between them).
6. Standard rollback (remove `M1`; `redis-cli -n 4 DEL "MIRROR_SESSION|M3" "MIRROR_SESSION|M4"`).

**Pass:** every valid label is stored verbatim; every invalid label is rejected before any DB write; the second same-label session never produces an ASIC_DB object and `M1` stays active; the backend never creates a SAI object nor truncates; the expected ERROR lines appear. At most one SPAN session exists at any time in this test.

---

`test_label_change_on_live_session` **— label changed on live session → no SAI SET · P1**
**Goal:** create-only semantics (HLD §1.1.5, §2.13, §2.10.4, §2.11.7).
Parameters: `change path` ∈ {direct HSET, GCU `replace` of `/MIRROR_SESSION/<name>/label` via `config apply-patch`}.
**Expected log:** none asserted for the in-place change `[TBD — log emission unverified; HLD gives task_duplicated only as a return status]`; any resulting ERROR line is added to `ignore_regex` once observed.
**Steps:**

1. Create a labeled ERSPAN session `M1` with label `L1`; record the ASIC_DB object key and label.
2. Change the label to `L2` through the parameter's path.
3. Assert the ASIC_DB object (same key) still has `L1` and STATE_DB `label` is still `L1` (effective label, HLD §2.11.2); record any divergence observed in CONFIG_DB.
4. Rollback: remove `M1`, recreate with `L1`; assert CONFIG_DB = STATE_DB = ASIC_DB = `L1`.
5. Change the label the supported way: remove `M1`, recreate with `L2`; assert all layers `L2`.

**Pass:** the live ASIC_DB label never changes in place, on either path; only delete + recreate changes it; no residue.

---

`test_label_capability_unsupported` **— capability false/missing →** `--label` **rejected · P1**
**Goal:** CLI honours `MIRROR_SESSION_LABEL_CAPABLE` (HLD §2.10.3).
**Steps:**

1. Make the capability false: `redis-cli -n 6 HSET "SWITCH_CAPABILITY|switch" MIRROR_SESSION_LABEL_CAPABLE false` (MirrorOrch writes it once at init, HLD §2.11.5, so it should persist until swss restarts); repeat with `HDEL` for the missing case `[confirm on DUT]`.
2. Run `config mirror_session span add ... --label X`; assert rejection and no state change.
3. Create the same session without `--label`; assert it succeeds.
4. Restore with `HSET ... true` (or restart swss); assert `true` again (Standard rollback).

**Pass:** labeled create rejected only while the capability is not `true`; unlabeled create always works. On multi-ASIC, rejection occurs if any target ASIC is not capable (HLD §2.14.2).

---

`test_label_persistence` **— reload / reboot / restart → labels, sessions and ACL binding preserved · P1 (config reload, warm), P2 (cold, fast, swss restart)**
**Goal:** CONFIG_DB is authoritative; STATE_DB/ASIC_DB rebuilt; the label ties a session across lives; ACL ↔ session binding is by session name and unaffected by the label (HLD §0.5, §1.1.6, §1.5, §2.11.2, §5.8.3). Mirrored traffic is checked with PTF.
Parameters: `restart_type` ∈ {`config reload` (P1, ≈1 min), `warm` (P1, ≈2 min), `cold` (P2, ≈5 min), `fast` (P2, ≈3 min), `swss restart` (P2, ≈1 min)}.
**Steps:**

1. Create labeled ERSPAN `A`, labeled SPAN `B` (`D1`/`S1`) and unlabeled ERSPAN `C` (distinct `dst_ip`); create an ACL table of type mirror with a rule `MIRROR_INGRESS_ACTION: A` (pattern: `tests/everflow/everflow_test_utilities.py`).
2. Before any restart assert the rule is active in `show acl rule`, references `A`, and `A`, `B`, `C` keep their labels (`C` none) and `active` status; send traffic (PTF) matching the rule and traffic on `S1`, and assert the mirrored copy of `A` and of `B` arrives at its own destination and nowhere else (baseline).
3. Warm row only: make CONFIG_DB differ from the running life (HLD §2.13, §5.8.3): direct HSET a changed create parameter on `A` (e.g. `redis-cli -n 4 HSET "MIRROR_SESSION|A" ttl <new>`); assert ASIC_DB for `A` is unchanged (no online modify).
4. `config save -y`; record labels, ASIC_DB keys and the ACL rule.
5. Perform the restart type (`sudo systemctl restart swss` for the swss row, pattern `tests/common/dualtor/dual_tor_mock.py`; `reboot_type` of `tests/common/reboot.py::reboot` for the others); wait per Conventions. Warm row: keep continuous PTF traffic (fixed rate, ≥ 1000 packets for the `A` rule and for `S1`/`B`) running across the whole reboot, from before the reboot until sessions are `active` again `[TBD — helper and loss counting at the monitor ports; pattern: start_warm_reboot_traffic in tests/packet_trimming]`.
6. Assert CONFIG_DB labels are unchanged; STATE_DB and ASIC_DB carry the same labels for **every** labeled session (ASIC_DB keys may change); `C` still has none; all sessions `active`; orchagent running and no new core files.
7. Assert the ACL rule still references `A`, and `A` and `B` keep their own labels (no label swap or cross-session binding). Repeat the baseline traffic of step 2 and assert the same mirrored copies arrive (all rows). Warm row: assert the continuous traffic lost zero mirrored packets (HLD §3.2.3 `[TBD — loss tolerance to confirm on DUT]`) and each stream reached only its own session.
8. Warm row only: assert `A` in ASIC_DB now shows the new TTL **and** the same label (the new life replays the changed CONFIG_DB).
9. swss row only: direct HSET a new label on `B`, restart swss again, assert `B` is recreated with the new CONFIG_DB label (HLD §2.13).
10. Rollback: remove the ACL rule and the sessions (Standard rollback) and `config save -y`.



**Pass:** same labels, same ACL binding and all sessions active after each restart type; the warm row also shows the differing parameter applied under the same label. Mirrored traffic is delivered after every restart type and, in the warm row, without loss.

---



### Area 2 — Interoperability

`test_label_gcu` **— GCU with label → valid create applied, invalid rejected · P1**
**Goal:** GCU carries the field (HLD §2.10.4, §2.11.7); the in-place change path is covered by `test_label_change_on_live_session`.
**Expected log:** none beyond the GCU rejection of the invalid patch `[TBD]`.
**Steps:**

1. `config apply-patch` an `add` of `/MIRROR_SESSION/<M1>` with a valid label; assert CONFIG_DB/STATE_DB/ASIC_DB carry it.
2. Apply a patch with an invalid label (e.g. 32 chars); assert it is rejected by the YANG validation and nothing changes.
3. Rollback: remove the session through a GCU `remove` patch; assert no residue.

**Pass:** valid create applied with the label in all layers, invalid label rejected, no residue.

---



### Area 3 — Reliability

`test_label_recreate` **— create/remove cycles → no leak, label reusable · P2**
**Goal:** repeated churn leaves nothing behind (HLD §2.12, §5.7).
**Steps:**

1. Record ASIC_DB mirror-session object count and core files.
2. Repeat 10 times: create labeled session `M1` with label `L`, assert `active`, remove it.
3. Assert object count equals baseline, no new core files, and `L` can be created again.

**Pass:** 10/10 cycles succeed; no leak, no cores; functional after the last cycle.

---



### Area 5 — Scale

`test_label_scale` **— max labeled sessions → all active and distinct · P1**
**Goal:** the label does not change the limit; unique labels at the maximum (HLD §1.3, §5.7).
**Steps:**

1. Determine N = platform max minus reserved internal slots `[TBD — max-session source unverified; requires DUT confirmation]`.
2. Create N sessions with unique labels (at most two SPAN, the rest ERSPAN with distinct `dst_ip`).
3. Assert all are `active` with N distinct ASIC_DB objects, each with its own label.
4. Create one more session `[TBD — over-limit behaviour not specified by the HLD]`.
5. Standard rollback.

**Pass:** all N sessions active, labels intact, no label cross-binding.

---

`test_label_multi_asic` **— multi-ASIC namespaces → per-ASIC uniqueness and restore · P2** *(multi-ASIC DUT only)*
**Goal:** HLD §1.6, §3.2.4.
**Setup:** repeat the port plan and the ERSPAN routing per namespace (`-n asicN` / `ip netns exec asicN` forms of the same commands): route and PTF-facing port in every ASIC that hosts ERSPAN `E`, free destination/source ports in the ASIC that hosts SPAN `P`. In a namespace without ERSPAN routing only CONFIG_DB/STATE_DB labels are asserted, not `active`/ASIC_DB.
**Steps:**

1. Create ERSPAN `E` with label `X` via the CLI; the CLI writes it in every namespace where it creates the session (HLD §1.6). Assert `sonic-db-cli -n asicN CONFIG_DB HGET "MIRROR_SESSION|E" label` is `X` for each of those namespaces.
2. Create SPAN `P` with a **different** label `Y` on one ASIC; assert accepted and present only in that namespace.
3. Duplicate check per namespace: create a session with label `X` that lands on an ASIC where `E` holds `X`
4. Assert `show mirror_session` merges sessions from all namespaces with their labels.
5. Warm reboot; assert every ASIC independently has its labeled sessions restored (STATE_DB/ASIC_DB per namespace).
6. Standard rollback in every namespace.

**Pass:** no cross-ASIC uniqueness rejection; every ASIC restores its own labeled sessions.

---



### Area 6 — Installation, Setup, Upgrade

`test_label_issu_v1` **— ISSU v1 → labels retained, slots kept · P1 (consumers off), P2 (consumers on)** *(NVIDIA, separate upgrade job)*
**Goal:** each label keeps the hardware slot it held; internal slot consumers keep theirs (HLD §5.7, §5.8, §5.9).
Parameters: `internal consumers (packet trim, WJH)` ∈ {off (P1), on (P2, platforms with reserved slots)}.
**Steps:**

1. Consumers-on row only: enable the internal consumers and read the reserved slots from the platform SAI profile.
2. Create labeled sessions and one unlabeled; record labels and slot per label. Make one create parameter differ via direct HSET + `config save -y` (as `test_label_persistence` warm row, step 3).
3. Perform ISSU v1 with the continuous PTF traffic running.
4. Assert (fallback, no slot visibility needed) labels retained in CONFIG_DB/STATE_DB/ASIC_DB and all sessions `active`; the changed parameter took the new value; mirror traffic (PTF, as in the warm row of `test_label_persistence`) kept flowing through the upgrade without loss (HLD §5.9 `[TBD — loss tolerance]`).
5. Assert each label keeps its slot; consumers-on row: operator sessions never occupy a reserved slot and each labeled session restores only its own slot.

**Pass:** labels retained and sessions active; slot equality (and untouched reserved slots) once observable.

---



### Areas without a dedicated test

- **Area 4 Performance:** excluded (HLD §1.4: no per-packet work).
- **Area 7 Logging and Debugability:** covered inside the tests above, not by a separate test: the `loganalyzer` fixture runs automatically and each test declares its expected log lines (`test_label_create`, `test_label_validation`; Conventions).
- **Area 8 Customer Scenarios:** HLD §0.5 (production monitoring session + warm reboot) is covered by `test_label_persistence` (warm row: mirror traffic across warm reboot) and `test_label_issu_v1`.

