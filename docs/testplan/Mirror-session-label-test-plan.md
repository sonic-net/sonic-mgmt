# SONiC Mirror Session Label test plan

## Table of Contents

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
- [Conventions](#conventions)
- [Test cases](#test-cases)
  - [Fixtures](#fixtures)
  - [Area 1 — Functionality](#area-1--functionality)
  - [Area 2 — Interoperability](#area-2--interoperability)
  - [Area 3 — Reliability](#area-3--reliability)
  - [Area 5 — Scale](#area-5--scale)
  - [Areas without a dedicated test](#areas-without-a-dedicated-test)
- [Known limitations](#known-limitations)
- [Open items](#open-items)



## Abbreviations


| Term       | Expansion                                                                        |
| ---------- | -------------------------------------------------------------------------------- |
| ACL        | Access Control List                                                              |
| ASIC       | Application-Specific Integrated Circuit                                          |
| ASIC_DB    | Redis database holding the SAI objects programmed by orchagent (DB 1)            |
| CLI        | Command-Line Interface                                                           |
| CONFIG_DB  | Redis database holding operator configuration (DB 4)                             |
| DUT        | Device Under Test                                                                |
| ERSPAN     | Encapsulated Remote SPAN                                                         |
| GCU        | Generic Config Updater                                                           |
| GRE        | Generic Routing Encapsulation (ERSPAN transport)                                 |
| HLD        | High Level Design                                                                |
| MirrorOrch | Orchagent class that creates and removes mirror sessions                         |
| OID        | SAI object identifier                                                            |
| PTF        | Packet Test Framework                                                            |
| SAI        | Switch Abstraction Interface                                                     |
| SPAN       | Switched Port Analyzer (local mirror session)                                    |
| STATE_DB   | Redis database holding operational state published by orchagent (DB 6)           |
| swss       | Switch State Service container                                                   |
| VLAN       | Virtual Local Area Network                                                       |
| YANG       | Data modelling language used for the SONiC configuration schema                  |




## How to read this plan

- This plan says **what we verify and how to tell pass from fail**. For *how the feature works*, read the HLD.
- Read **The core idea** first, then the **Test case summary & coverage** table; the cards are reference.
- Size: 10 tests and one readiness gate (fixture), 25 parametrized rows. P0 = 3 tests (13 rows, ≈ 10–15 min), P0 + P1 without the long restarts ≈ 20 min; the reload / cold / fast / swss restart rows of `test_label_persistence` (≈ 25–30 min), the warm reboot test (≈ 7 min) and the P2 churn test make the complete run take about one hour.
- Log checks are not separate tests: the `loganalyzer` fixture runs around every test that does not restart the DUT (see Conventions).
- Mirrored-traffic checks are steps inside existing tests (PTF), not separate tests: `test_label_create` (the label does not change the mirrored packet), `test_label_persistence` (mirror traffic is delivered again after every restart type) and `test_label_warm_reboot` (no mirrored packet is lost across a warm reboot).



## The core idea (mental model)

A mirror session may carry an optional, create-only `label` (`[A-Za-z0-9_-]{1,31}`, unique per ASIC). The label travels CONFIG_DB → MirrorOrch → SAI at **create** time only, is mirrored into STATE_DB, and is the only thing that lets a recreated session reclaim its old hardware slot after a warm reboot. Every test checks one of: (a) valid labels are accepted and visible in all layers, (b) invalid / duplicate / in-place labels are rejected without side effects, (c) labels survive restarts and reboots.


| Input                                                 | Expected behaviour                                           |
| ----------------------------------------------------- | ------------------------------------------------------------ |
| no `label`                                            | session works as before; no label in STATE_DB / ASIC_DB      |
| valid unique `label`                                  | CONFIG_DB + STATE_DB + `show` (Label column) + ASIC_DB LABEL |
| invalid / empty / > 31 chars / duplicate in same ASIC | rejected, no SAI object                                      |
| `label` changed on live session                       | no SAI SET; only delete + recreate changes it                |




## Test case summary & coverage


| Test / fixture                      | What it proves                                                                                                                                                                                                            | Pri                            | Area                  | HLD §                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | --------------------- | ------------------------------ |
| fixture `label_capability`          | DUT is label-capable on every ASIC and the CLI exposes `--label`; else skip the module (readiness gate, not a test)                                                                                                       | gate                           | Preconditions         | §2.10.3, §2.14.2                    |
| `test_label_create`                 | Session with and without a label (3 CLI forms): label visible in CONFIG_DB, STATE_DB, `show` and ASIC_DB only when set; gone with the session; mirrored packet is the same with and without a label (PTF)                 | P0                             | 1 Functionality       | §1.2, §2.8, §2.11              |
| `test_label_validation_syntax`      | Valid labels (length 1 and 31, full charset, 32-char session name) accepted verbatim; one randomly chosen invalid label (empty, 32, 65 chars, space, `.`, `/`, non-ASCII) rejected by the CLI and by MirrorOrch (direct CONFIG_DB injection) | P0                             | 1 Functionality       | §1.1 (2), §2.8, §2.10.2, §3.2.2  |
| `test_label_validation_duplicate`   | A second session with an already used label on one ASIC is rejected by the CLI and by MirrorOrch; two same-label sessions written back to back produce one SAI object                                                      | P0                             | 1 Functionality       | §1.1 (4), §2.8, §4.5             |
| `test_label_change_on_live_session` | Label changed on a live session (direct HSET / GCU replace) never alters an existing ASIC_DB object; delete + recreate works                                                                                              | P1                             | 1 Functionality       | §1.1 (5), §2.13                  |
| `test_label_capability_unsupported` | CLI rejects `--label` (with the capability message) when the capability is false or missing; unlabeled creation still works                                                                                               | P1                             | 1 Functionality       | §2.10.3, §2.14.2               |
| `test_label_gcu`                    | GCU: valid labeled create applied, invalid label rejected by YANG                                                                                                                                                         | P1                             | 2 Interoperability    | §2.10.4, §2.11.7               |
| `test_label_persistence`            | Labels, sessions and ACL ↔ session binding persist across config reload (P1), cold reboot, fast reboot, swss restart (P2); mirrored traffic is delivered again afterwards                                                 | P1 (reload); P2 (others)       | 3 Reliability         | §1.1 (6), §1.5, §2.11.2          |
| `test_label_warm_reboot`            | Same three-session scenario across a warm reboot with continuous mirrored traffic: no mirrored packet is lost, labels and bindings are restored                                                                           | P1                             | 3 Reliability         | §0.5, §1.1 (6), §3.2.3           |
| `test_label_recreate`               | 10 create / remove cycles with the same label: no leak, label reusable                                                                                                                                                    | P2                             | 3 Reliability         | §2.12                          |
| `test_label_scale`                  | N labeled unique sessions at the platform maximum are all active with distinct ASIC_DB objects                                                                                                                            | P1                             | 5 Scale               | §1.3                           |
| (area 4)                            | Performance — excluded: no datapath change (HLD §1.4)                                                                                                                                                                     | —                              | 4 Performance         | §1.4                           |
| (area 8)                            | Customer scenario "production monitoring + warm reboot" (HLD §0.5): covered by `test_label_warm_reboot`                                                                                                                   | —                              | 8 Customer Scenarios  | §0.5                           |




## Overview

Test plan for the optional mirror-session `label` feature. Design: **SONiC Mirror Session Label HLD** ([PR #2599](https://github.com/sonic-net/SONiC/pull/2599), `doc/mirror_label/mirror-label-design.md`). The HLD defines behaviour; this plan defines verification. `§N` refers to the section numbers of that document; `§1.1 (n)` is the n-th functional requirement of §1.1.

## Scope



### In scope

- `--label` on `config mirror_session add | erspan add | span add`; `Label` column in `show mirror_session` (HLD §1.2).
- Label syntax, length, uniqueness per ASIC and create-only semantics at CLI/YANG and MirrorOrch (HLD §1.1, §2.8, §2.10.2).
- CONFIG_DB / STATE_DB / ASIC_DB representation and `SWITCH_CAPABILITY|switch MIRROR_SESSION_LABEL_CAPABLE` (HLD §2.11).
- GCU path (§2.11.7); reboot / restart persistence (§1.5); warm reboot label continuity (§1.1 (6)).
- Support gating before the functional tests (fixture `label_capability`).
- Mirrored-traffic delivery with PTF: the label does not change the mirrored packet (`test_label_create`); mirror traffic is delivered after every restart type and not lost across a warm reboot (`test_label_persistence`, `test_label_warm_reboot`; HLD §3.2.3, §0.5).

### Out of scope

- Throughput, latency and line-rate behaviour of mirrored traffic (HLD §1.4, area 4): traffic steps are functional only (delivery, packet content, loss count).
- Counters (§2.7: none introduced); platform / lower-layer API (§2.5, §2.6); security (§4: no new surface; backend validation is covered by `test_label_validation_syntax` and `test_label_validation_duplicate`).
- Multi-ASIC namespaces (HLD §1.6): the tests use the first ASIC only; multi-ASIC is not implemented for now (see Open items).
- gNMI client tests (§2.10.4): same YANG → CONFIG_DB path as `test_label_gcu`.
- Unit tests of sonic-swss / sonic-utilities / sonic-yang-models (§3.1).
- Unsupported-platform negative tests (the capability is `false`, HLD §2.14.3): a functional test cannot provoke them; they need a dedicated SAI implementation that returns the capability and the error message, so they belong to unit tests. The module is skipped by the fixture `label_capability` on such a platform.
- Out of scope in the HLD itself (§0.2): a policy requiring a label on every mirror session, a new mirror-session modify command, syncd label matching.




## References

- HLD: SONiC Mirror Session Label HLD, [sonic-net/SONiC PR #2599](https://github.com/sonic-net/SONiC/pull/2599) (`doc/mirror_label/mirror-label-design.md`).



## Testbed and topology

Topology marker: `t0` (as `tests/span` and `tests/everflow`). The tests live in `tests/span/mirror_label/`; the ports come from the `ports_for_test` fixture of `tests/span/conftest.py`: three VLAN members of the first VLAN with at least three ports.

| Role     | Port                | Use                                                                                                    |
| -------- | ------------------- | ------------------------------------------------------------------------------------------------------ |
| `src`    | first VLAN member   | PTF injects packets here; source port of port-mirror sessions                                          |
| `routed` | second VLAN member  | removed from the VLAN and turned into an L3 port towards the PTF host: ERSPAN destination               |
| `dst`    | last VLAN member    | removed from the VLAN: monitor (destination) port of SPAN sessions                                     |

Traffic is injected and captured with PTF. No VS-only, snappi or TGEN cases.



## Conventions

- **Session commands** (HLD §2.10.3.2):
  - ERSPAN: `config mirror_session erspan add <name> <src_ip> <dst_ip> <dscp> <ttl> <gre> <queue> [<src_port> <direction>] [-l|--label <label>]`
  - SPAN: `config mirror_session span add <name> <dst_port> <src_port> <direction> <queue> [-l|--label <label>]`
  - Legacy ERSPAN: `config mirror_session add <name> <src_ip> <dst_ip> <dscp> <ttl> <gre> <queue> [-l|--label <label>]` (no source port, so no mirrored traffic)
  - Remove: `config mirror_session remove <name>`.
- **Direction of SPAN sessions**: the `span_direction` fixture reads `PORT_INGRESS_MIRROR_CAPABLE` and `PORT_EGRESS_MIRROR_CAPABLE` from STATE_DB (`SWITCH_CAPABILITY|switch`). Both `true` → `both`; only ingress `true` → `rx`; ingress not supported → the test is skipped. An absent key counts as supported, as in the CLI. ERSPAN sessions with a source port use `rx`.
- **Layers** (source of truth for assertions):
  - CONFIG_DB: `redis-cli -n 4 HGETALL "MIRROR_SESSION|<name>"`
  - STATE_DB: `redis-cli -n 6 HGETALL "MIRROR_SESSION_TABLE|<name>"`
  - ASIC_DB: `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*"` then `HGETALL` on each key; the label is `SAI_MIRROR_SESSION_ATTR_LABEL` (an escaped value such as `\x5F` for `_` is unescaped before comparing)
  - Capability: `redis-cli -n 6 HGETALL "SWITCH_CAPABILITY|switch"`
  - CLI: `show mirror_session` (ERSPAN and SPAN tables, `Label` column)
- **Waiting**: after a reboot / restart wait for `wait_critical_processes`, then poll STATE_DB until every session is `active`, cap 300 s; timeout = failure.
- **Cleanup**: the autouse fixture `label_session_cleanup` removes every test session (`lbl_*`, created through the CLI or injected into CONFIG_DB) before and after each test, so a failed test leaves nothing behind. Tests that save the configuration back up `/etc/sonic/config_db.json` first and restore it at the end (`label_config_backup`).
- **ERSPAN control plane**: the fixture `label_erspan_route` writes into CONFIG_DB the IP `192.168.200.1/30` on the `routed` port, the static route `10.20.0.0/24` via `192.168.200.2` and a static `NEIGH` entry for the PTF host. ERSPAN destinations are `10.20.0.33` + index, so one route covers all of them, and everything survives reload and reboot.
- **Mirrored packet identification**: a port-mirror session copies everything that enters the source port, including background packets of the PTF host (and, with direction `both`, the packets that leave it). A test counts only the frames that carry the test packet's source IP: the ERSPAN frames by their inner packet, the SPAN frames on the `dst` port directly.
- **Direct HSET injection** (backend-path rows): bypasses the CLI frontend check (HLD §4.5: the backend must not trust the CLI). To create a session write **one multi-field** `redis-cli -n 4 HSET "MIRROR_SESSION|<name>" type ... label <value>` — never the other fields first and `label` afterwards, which creates an unlabeled object and turns the label write into an in-place change. To change a label on a live session use the single-field `HSET ... label <value>`.
- **Rejection rows** (expected error + no state change): capture CONFIG_DB / STATE_DB / ASIC_DB before; assert a non-zero exit of the CLI and that the three layers are unchanged after.
- **Log checks (LogAnalyzer)**: the `loganalyzer` fixture runs around every test that does not restart the DUT. Backend rejection rows (direct CONFIG_DB injection) first wait, with a time limit, for the MirrorOrch line that proves the rejection (HLD §2.9 Table 5), registered through `loganalyzer.expect_regex`, and only then assert the absence of the STATE_DB key and of the ASIC_DB object: `Invalid label for mirror session <name>`, `Failed to create mirror session <name>: label <label> is already used by session <other>`, and `Failed to create session <name>: object already exists` (single-field HSET on a live session). A bare "sleep, then check nothing happened" is not used: it also passes when orchagent has not processed the write or rejected it for another reason. The ERROR that orchagent writes when the key of a rejected session is removed (`Failed to remove non-existent mirror session`) is ignored where a test injects such a session. `test_label_persistence` and `test_label_warm_reboot` disable `loganalyzer`: reloads and reboots produce expected errors.
- **Reboot**: `tests/common/reboot.py::reboot(duthost, localhost, reboot_type=...)`; config reload through `config_reload(..., safe_reload=True)`.
- **Hardware only**: the plan is written for hardware DUTs in the t0 topology; the virtual switch (vs, KVM) is not supported.



## Test cases

Tests are named like the pytest functions; the priority is in each heading. The readiness gate is a fixture, not a test.

### Fixtures

**fixture** `label_capability` **(module scope, autouse) — capability and CLI present → module runs, else skip**
**Goal:** HLD §2.10.3 prerequisites before the functional tests.
**Steps:**

1. For every ASIC read `SWITCH_CAPABILITY|switch` from STATE_DB; assert `MIRROR_SESSION_LABEL_CAPABLE` is `true`.
2. Run `config mirror_session span add --help`; assert `--label` is listed.

**Pass:** both checks pass; otherwise the whole module is skipped (not a failure).

Other fixtures (see Conventions): `label_session_cleanup` (autouse), `label_ports`, `label_erspan_route`, `span_direction`, `label_config_backup`, `label_max_sessions`.

---



### Area 1 — Functionality

`test_label_create` **— create session with / without label → label visible only when set · P0**
**Goal:** a valid label is accepted and reported consistently; a missing label changes nothing; the label does not affect mirrored traffic (HLD §2.8, §2.11.5, §1.4).
Parameters (6 rows): CLI form ∈ {`erspan` (`erspan add` with a source port), `erspan_legacy` (`add`, no source port), `span` (`span add`)} × `labeled` ∈ {labeled, unlabeled}. The label of a labeled row is `L_<form>`; labeled ERSPAN rows use the short `-l` option, the labeled SPAN row uses `--label`.
**Steps:**

1. Record the ASIC_DB mirror-session object count. Create the session with or without a label.
2. Wait until it is `active`.
3. Labeled: assert CONFIG_DB `label`, STATE_DB `label`, the `show mirror_session` `Label` column and exactly one ASIC_DB object with `SAI_MIRROR_SESSION_ATTR_LABEL` equal to the label. For ERSPAN forms also create an unlabeled ERSPAN session next to it, assert it has no label and remove it.
4. Unlabeled: assert no label in CONFIG_DB / STATE_DB / ASIC_DB and exactly one new ASIC_DB object.
5. Traffic (PTF): `span` — send an IP packet with a test source IP to the `src` port, count for a fixed time the frames that carry this source IP on the `dst` port and verify exactly one, identical to the packet sent (other frames on `dst` are not counted: the port also receives copies of other traffic, and PTF in relax mode would not report an extra frame anyway); `erspan` — send an IP packet with a test source IP to the `src` port and verify exactly one ERSPAN frame towards the session destination on the `routed` PTF port (only frames carrying the test source IP are counted); the frames are logged with their IP id. `erspan_legacy` has no source port, so no traffic is sent. The expectation is the same for labeled and unlabeled rows.
6. Remove the session; assert the STATE_DB key and the ASIC_DB object are gone and the object count equals the baseline.

**Pass:** only labeled sessions carry the label in every layer while they exist; none after removal; the mirrored packet is the same with and without a label.

---

`test_label_validation_syntax` **— valid label accepted; invalid label rejected, nothing changed · P0**
**Goal:** frontend and backend validation (HLD §1.1 (2), §2.8 Tables 2–3, §2.10.2, §3.2.2, §4.5).
Parameters (6 rows, one row at a time):

| Row id                                   | Label / name                                 | Expected |
| ---------------------------------------- | -------------------------------------------- | -------- |
| `valid-label-len1`                       | 1 character                                  | accepted |
| `valid-label-len31`                      | 31 characters                                | accepted |
| `valid-label-charset`                    | letters, digits, `_` and `-`                 | accepted |
| `valid-label-charset-len31`              | 31 characters mixing all allowed characters  | accepted |
| `valid-name-len32-label-len31`           | 32-character session name, 31-char label (HLD §2.13) | accepted |
| `invalid-label-random`                   | one label chosen at random from: empty, 32 characters, 65 characters, a space, `.`, `/`, a non-ASCII character | rejected |

**Steps:**

1. Valid rows: create a SPAN session with that label (direction from `span_direction`); wait for `active`; assert CONFIG_DB, STATE_DB and ASIC_DB carry the exact label (no truncation).
2. Invalid row: capture the three layers; run the session creation for SPAN, ERSPAN (`erspan add`) and legacy ERSPAN (`add`) with the label; each must exit non-zero and leave the three layers unchanged.
3. Backend path (the invalid row): inject the session into CONFIG_DB with a direct multi-field HSET (Conventions); wait for the MirrorOrch ERROR `Invalid label for mirror session <name>`, then assert there is no `MIRROR_SESSION_TABLE|<name>` key in STATE_DB, no new ASIC_DB object, and no 31-character truncated label in ASIC_DB.

The invalid label is chosen at random on every run (the test log prints it); the rejection of every invalid form is covered by unit tests.

**Pass:** every valid label is stored verbatim; the invalid label is rejected by the CLI before any DB write and by MirrorOrch on the direct path; MirrorOrch never creates a SAI object for an invalid label and never truncates it.

---

`test_label_validation_duplicate` **— duplicate label on one ASIC rejected · P0**
**Goal:** per-ASIC uniqueness (HLD §1.1 (4), §2.8, §4.5). Only ERSPAN sessions are used (names `m1`..`m4`).
**Steps:**

1. Create ERSPAN `m1` with label `DUP`; assert exactly one ASIC_DB object carries `DUP`.
2. Via the CLI create ERSPAN `m2` (different destination) with label `DUP` (short `-l` form); assert a non-zero exit and no `MIRROR_SESSION|m2` in CONFIG_DB.
3. Inject `m2` with a direct multi-field HSET and label `DUP`; wait for the ERROR `Failed to create mirror session m2: label DUP is already used by session m1`, then assert ASIC_DB still holds one `DUP` object and STATE_DB has no key for `m2`; delete the injected key.
4. Race: inject `m3` and `m4` (distinct destinations, same label `RACE`) back to back; wait for the same ERROR for whichever of the two loses; assert exactly one ASIC_DB object carries `RACE` and `m1` is still `active`.

**Pass:** the second same-label session never produces an ASIC_DB object and `m1` stays active; exactly one of the racing sessions gets the label.

---

`test_label_change_on_live_session` **— label changed on a live session → no in-place SAI change · P1**
**Goal:** a label cannot be changed on a live session; the only way to change it is remove + create (HLD §1.1 (5), §2.13). Neither path below is a supported way to change a label: the test checks that they do not alter the SAI object in place.
Parameters: `path` ∈ {direct single-field HSET of `label`, GCU `replace` of `/MIRROR_SESSION/<name>/label` through `config apply-patch`}.
**Steps:**

1. Create ERSPAN `live` with label `L1`; record its ASIC_DB object.
2. Change the label to `L2` through the parameter's path.
3. HSET: wait for the NOTICE `Failed to create session <name>: object already exists`, then assert the object is untouched and STATE_DB and ASIC_DB still say `L1`, while CONFIG_DB and the `Label` column of `show mirror_session` (it reads the label from CONFIG_DB) say `L2`: this is the divergence between CONFIG_DB and the runtime state that HLD §2.13 describes. GCU: there is no GCU operation that renames the label; poll until the session is `active` again. GCU treats every field of `MIRROR_SESSION` as create-only (`CreateOnlyFilter` contains `["MIRROR_SESSION", "*", "*"]` in `generic_config_updater/patch_sorter.py`, and `CreateOnlyMoveValidator` does not allow a replace), so it applies the replace as delete + add, i.e. the same remove + create flow: the session is recreated as a new SAI object carrying `L2` and every layer follows with `L2`. A recreation after a plain HSET is a failure.
4. Rollback: remove the session, recreate it with `L1`; assert all layers say `L1`.
5. Change the label the supported way: remove, recreate with `L2`; assert all layers say `L2`.

**Pass:** an existing ASIC_DB object never changes its label in place, on either path; the label changes only through delete + recreate.

---

`test_label_capability_unsupported` **— capability false / missing → `--label` rejected · P1**
**Goal:** the CLI honours `MIRROR_SESSION_LABEL_CAPABLE` (HLD §2.10.3).
Parameters: `mode` ∈ {`false` (`HSET ... false`), `missing` (`HDEL`)}.
**Steps:**

1. Set STATE_DB `MIRROR_SESSION_LABEL_CAPABLE` as the mode says; capture the three layers.
2. Create a SPAN session with `--label X`; assert a non-zero exit, that the CLI message is `Mirror session label is not supported` (a rejection for another reason does not count), and that the layers are unchanged.
3. Create the same session without a label; assert it succeeds, is `active` and has no label.
4. Restore the capability (`HSET ... true`).

**Pass:** the labeled create is rejected only because of the capability; the unlabeled create always works.

---



### Area 2 — Interoperability

`test_label_gcu` **— GCU with a label → valid create applied, invalid rejected · P1**
**Goal:** GCU carries the field (HLD §2.10.4, §2.11.7); the in-place change path is covered by `test_label_change_on_live_session`.
**Steps:**

1. `config apply-patch` an `add` of `/MIRROR_SESSION/<name>` with a valid label; assert the label in CONFIG_DB, STATE_DB and ASIC_DB.
2. Remove the session; apply a patch with a 32-character label; assert it is rejected by YANG validation and the three layers are unchanged.

**Pass:** the valid create is applied with the label in every layer; the invalid label is rejected and nothing changes.

---



### Area 3 — Reliability

**Scenario shared by `test_label_persistence` and `test_label_warm_reboot`.** Three ERSPAN sessions `lbl_persist_01`..`03`, created from the highest number to the lowest (orchagent replays them in the opposite, alphabetical order, so a label cannot be restored by luck through the order of re-creation), each with its own destination `10.20.0.33`..`35`:

| Session          | Label | Role                                                                  |
| ---------------- | ----- | --------------------------------------------------------------------- |
| `lbl_persist_01` | `P01` | port mirror: mirrors the ingress of the `src` port                    |
| `lbl_persist_02` | none  | mirrors nothing                                                       |
| `lbl_persist_03` | `P03` | bound by an ACL rule (mirror table `EVERFLOW`, source IP `20.0.0.10`) |

The state check (before and after a restart): every session is `active`; labels in CONFIG_DB, STATE_DB and ASIC_DB are as created (session 02 has none); the ASIC_DB label ↔ destination pairs are right; the ACL rule still points to session 03; one test packet (source IP `20.0.0.10`) sent to the `src` port yields exactly one copy to the destination of session 01 and one to the destination of session 03 and none to session 02 (only frames with the test source IP are counted). Only ERSPAN sessions are used.

`test_label_persistence` **— reload / reboot / restart → labels, sessions and ACL binding preserved · P1 (config reload), P2 (cold, fast, swss restart)**
**Goal:** CONFIG_DB is authoritative; STATE_DB and ASIC_DB are rebuilt; the ACL ↔ session binding is by session name and unaffected by the label (HLD §1.1 (6), §1.5, §2.11.2).
Parameters: `restart_type` ∈ {`config_reload`, `cold`, `fast`, `swss_restart`}.
**Steps:**

1. Create the three sessions and the ACL rule; assert the state check (baseline).
2. `config save -y`; perform the restart (`systemctl restart swss` for the swss row, `config_reload` or `reboot` for the others); wait for the critical processes and re-initialize PTF.
3. Assert the state check again.
4. `swss_restart` row only: write the label `P01_NEW` straight into CONFIG_DB of session 01 (single-field HSET), restart swss again and assert that session 01 now carries `P01_NEW` in every layer (CONFIG_DB is the source of truth) while the other sessions are unchanged.
5. Remove the ACL rule (cleanup removes the sessions) and restore the saved configuration.

**Pass:** same labels, same ACL binding, all sessions active and the same mirrored copies after every restart type.

---

`test_label_warm_reboot` **— warm reboot with continuous mirrored traffic → no loss, labels restored · P1**
**Goal:** the customer scenario of HLD §0.5 and the zero-loss requirement of §3.2.3.
**Steps:**

1. Create the three sessions and the ACL rule; assert the state check; `config save -y`.
2. Start a PTF thread that sends one test packet (source IP `20.0.0.10`) every 10 ms to the `src` port and counts the ERSPAN frames per destination.
3. Warm reboot the DUT and wait for the warmboot finalizer and the critical processes; stop the traffic.
4. Assert the traffic sent more than zero packets, that each of the two mirrored streams (session 01 and session 03) received as many frames as were sent (allowed loss 0), and that session 02 received none. The longest pause between two mirrored frames is logged per stream.
5. Re-initialize PTF; assert the state check again.

**Pass:** zero loss on both streams, nothing on session 02, labels and the ACL binding restored.

---

`test_label_recreate` **— create / remove cycles → no leak, label reusable · P2**
**Goal:** repeated churn leaves nothing behind (HLD §2.12).
**Steps:**

1. Record the ASIC_DB mirror-session object count.
2. Repeat 10 times: create ERSPAN `rec` with label `REC`, wait for `active`, remove it, assert it is gone.
3. Assert the object count equals the baseline; create it once more and assert the label in every layer.

**Pass:** 10 of 10 cycles succeed; no leak; the label is reusable.

---



### Area 5 — Scale

`test_label_scale` **— max labeled sessions → all active and distinct · P1**
**Goal:** the label does not change the limit; unique labels at the maximum (HLD §1.3).
**Steps:**

1. N is the number of mirror sessions the platform supports and is passed as a parameter (`--label_max_sessions`, no default); the test is skipped when it is not passed. If the SAI profile in the syncd container (`/tmp/sai.profile`) contains `SAI_MIRROR_SESSION_HW_ID_RESERVATION`, one slot is reserved and N − 1 sessions are created.
2. Create the sessions as ERSPAN with unique labels `S<index>` and distinct destinations.
3. Assert all are `active`, with as many new distinct ASIC_DB objects as sessions, each carrying its own label, and no duplicate label in ASIC_DB.

**Pass:** all sessions are active, labels are intact, no label cross-binding.

---



### Areas without a dedicated test

- **Area 4 Performance:** excluded (HLD §1.4: no per-packet work).
- **Area 6 Installation, Setup, Upgrade:** the warm reboot is covered by `test_label_warm_reboot`; no other upgrade flow is part of this plan.
- **Area 7 Logging and Debugability:** not covered by a separate test; see the log handling in Conventions.
- **Area 8 Customer Scenarios:** HLD §0.5 (production monitoring session + warm reboot) is covered by `test_label_warm_reboot`.




## Known limitations

- The platform maximum of mirror sessions is not detected: it is passed as `--label_max_sessions` (one slot is subtracted when the SAI profile reserves one). Behaviour of one session over the limit is not tested.
- SPAN sessions use `both` only where the ASIC mirrors ingress and egress; elsewhere `rx` is used. The label tests do not check the direction itself.
- Multi-ASIC DUTs are exercised through their first ASIC only.
- A port-mirror session also copies background packets of the PTF host, so traffic checks identify the test packet by its source IP.



## Open items

1. The `inactive` → `active` cycle of a labeled ERSPAN session (MirrorOrch removes the SAI object when the next hop is lost and creates it again with the label, HLD §2.12) is not covered: the plan is written for the t0 topology, where the BGP default route always resolves the collector, so the session cannot become inactive.
2. HLD §2.11.7 says that a GCU patch of the label path "is already accepted by the sorter", and §2.13 says that "a field-only GCU patch can make CONFIG_DB diverge from runtime state". In sonic-utilities master the GCU sorter treats every `MIRROR_SESSION` field as create-only, so a field-only patch is applied as delete + add and CONFIG_DB does not diverge. The plan follows the sorter. HLD fix requested in SONiC PR 2599.
3. Multi-ASIC DUTs are out of scope for now (HLD §1.6, §3.2.4): the tests exercise the first ASIC only, there is no multi-ASIC setup. A follow-up has to add the per-ASIC label scope checks.
