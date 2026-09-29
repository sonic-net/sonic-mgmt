# SAI Fidelity Scoring (libsaivs / SONiC VS)

Opt-in pytest plugin that scores each test from **observed** SAI operations in
`/var/log/swss/sairedis.rec` (multi-ASIC: `sairedis.asic{N}.rec`). This is not
a static per-testfile lookup table.

## Why three tiers?

On Virtual Switch (`libsaivs`), orchagent/syncd still issue SAI calls, but
fidelity varies:

| Tier | Meaning | Examples |
|------|---------|----------|
| **1** | Fully faithful — behaves like hardware on VS | routes, next hops, neighbors, hostifs, VR, VLANs, LAGs |
| **2** | Stored in ASIC_DB, not enforced in a forwarding pipeline | ACL tables/entries, QoS maps, schedulers, WRED, buffers, policers, mirrors |
| **3** | Stubbed / missing / canned responses | hardware counters/stats, ECN/PFC watermarks, PFC deadlock, vendor attrs |

Mappings live in declarative [`tier.yml`](tier.yml). Unknown object types
default to **tier 3** (`default:unknown`) and are logged so they can be audited
later.

## Score formula

```
score = (1.0*n1 + 0.5*n2 + 0.0*n3) / (n1 + n2 + n3)
```

Weights are configurable under `weights:` in `tier.yml`.

**Zero SAI calls → `score = None` ("no SAI activity").** Do not treat absence
of calls as perfect fidelity (never report `1.0` for an empty delta).

Example log line:

```
47 SAI calls — 32 tier 1, 12 tier 2, 3 tier 3 (score 0.83)
```

## Unit tests (no DUT, no scapy)

`tests/common/__init__.py` imports scapy, so normal `pytest tests/...` collection
fails in a bare environment. These unit tests import by path:

```bash
python3 tests/common/plugins/fidelity/unit_test/unit_test_tier_engine.py -v
python3 tests/common/plugins/fidelity/unit_test/unit_test_sairedis_window.py -v
```

## Logrotate / swss restart (inode windowing)

The plugin does **not** rely on line count alone. Before each test it snapshots
`(inode, size, line_count)` for each `sairedis.rec` path. After the test:

| Window status | Meaning | Score |
|---------------|---------|-------|
| `OK` | Same inode; read new lines only | Normal |
| `STITCHED` | File was renamed (e.g. to `.1`); residual + new file combined | Normal (summary shows `[stitched]`) |
| `HISTORY_LOST` / `RECORDER_RESET` / `TRUNCATED` / … | Cannot rebuild the window | **`score=None`** + error reason — never a fake “no SAI activity” |

True empty delta with `OK` still means “no SAI activity” (`score=None`).

## Run against a VS / KNE testbed

Plugin is **off by default**. Enable with `--sai-fidelity` (only scores when
`duthost.facts["asic_type"] == "vs"`):

```bash
./run_tests.sh -n <testbed> -d <dut> -f vtestbed.yaml -i ../ansible/veos_vtb -u \
  -e "--sai-fidelity --sai-fidelity-report logs/sai_fidelity.json"
```

Optional:

- `--sai-fidelity-tier-file PATH` — override `tier.yml`
- `@pytest.mark.sai_fidelity(enabled=False)` — opt a single test out

Per-test values are also attached as JUnit `user_properties`:
`sai_calls`, `sai_tier1`, `sai_tier2`, `sai_tier3`, `sai_fidelity_score`,
`sai_fidelity_window`.

## Reading the JSON report

Default path: `logs/sai_fidelity.json`. Each test record includes:

- `nodeid`, `outcome`, `total`, `n1`, `n2`, `n3`, `score`, `window_status`
- `breakdown` — top object types (what dragged the score down)
- `error` — set when the window could not be trusted

**Warning:** A **PASSED** test with a **low** fidelity score means the test
passed on VS but exercised stubbed or unenforced SAI paths. Treat that as
"**verify on hardware**" — do not assume VS PASS ≡ ASIC PASS for those ops.

## Layout

| File | Role |
|------|------|
| `tier.yml` | Declarative tier mapping + weights |
| `tier_engine.py` | Pure classify / score (no pytest, no DUT) |
| `sairedis_window.py` | Inode snapshot + rotate stitch |
| `__init__.py` | Pytest plugin hooks |
| `unit_test/` | Standalone unit tests + sample `.rec` |
