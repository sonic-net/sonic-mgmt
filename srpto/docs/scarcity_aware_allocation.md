# Scarcity-Aware DUT Allocation

## The problem

`DUTPool._find_duts_matching_topology()` picks a DUT combination for a
script that declares `link_requirements` (e.g. `min_topology: ["D1D2:2"]`).
Before this change, it returned the **first** combination it found, in
`itertools.combinations()` order over the free DUT list — which follows the
order DUTs appear in the testbed YAML's `devices:` section.

That's fine when only one script in a run has a topology constraint. It
breaks down when several scripts could each be satisfied by *multiple*
DUT pairings, and one of those pairings is the *only* option for some
other, stricter script:

**Worked example.** Testbed links: `D1-D2: 2`, `D2-D3: 1`, `D3-D4: 1`.
Four scripts in one run:

| Script | Needs |
|---|---|
| A | 1 DUT, no link constraint |
| B | 2 DUTs, ≥1 link between them |
| C | 1 DUT, no link constraint |
| D | 2 DUTs, ≥2 links between them |

D can **only** ever be satisfied by `(D1, D2)` — it's the one pair in the
whole testbed with 2 links. B could be satisfied by `(D1,D2)`, `(D2,D3)`,
or `(D3,D4)` — any of the three work equally well for B.

With "first match wins," if B's worker thread happens to call
`_try_allocate` before D's, it grabs `(D1, D2)` — because that's simply the
first pair `itertools.combinations(['D1','D2','D3','D4'], 2)` produces —
even though B had two other options that would have worked just as well.
D is then stuck waiting for B to finish (B holds one of the two DUTs D
needs), for no reason: B never needed D1 or D2 specifically, it just got
them because they sorted first.

## The fix

Score every DUT by how "precious" it is across the **whole known batch**
of scripts in the run, then have `_find_duts_matching_topology` prefer the
valid combination with the lowest total score, instead of the first one
found.

**Scoring** (`engine._compute_dut_scarcity`): for every script with a
link/tgen requirement, enumerate every physical DUT combination (against
the *full* testbed, not just currently-free DUTs) that could ever satisfy
it (`engine._enumerate_valid_combos`). A script with only one valid
combination contributes a full `1.0` to each DUT in it. A script with `N`
equally-valid combinations spreads `1.0` across them — `1/N` to each DUT
in each combination — so having *an* option doesn't make a DUT look
artificially scarce; only having *few* options does.

Continuing the worked example, this produces:

```
D1: 1.333   (1/3 from B's (D1,D2) option, + 1.0 from D's only option)
D2: 1.667   (1/3 from B's (D1,D2) + 1/3 from B's (D2,D3), + 1.0 from D)
D3: 0.667   (1/3 from B's (D2,D3) + 1/3 from B's (D3,D4))
D4: 0.333   (1/3 from B's (D3,D4))
```

**Selection** (`DUTPool._find_duts_matching_topology`): among the
combinations that satisfy the *current* requirement, pick the one whose
DUTs sum to the lowest score, tie-breaking on original `combinations()`
order for determinism. For B, that means comparing `(D1,D2)=3.0`,
`(D2,D3)=2.334`, `(D3,D4)=1.0` — B is steered to `(D3, D4)`, leaving `D1`
and `D2` completely free for D.

Verified against exactly this scenario (`DUTPool` used directly, no CLI):

```
DUT scarcity scores: {'D1': 1.333, 'D2': 1.667, 'D3': 0.667, 'D4': 0.333}
B allocated: ['D3', 'D4']
D allocated: ['D1', 'D2']   # immediately, no wait
```

## How it's wired in

1. `ParallelScheduler.run()` computes `requirements` for every runnable
   script (after the pre-flight topology-feasibility filter, so a script
   that got `skipped` doesn't distort scarcity scores for the ones that
   will actually run).
2. It calls `_compute_dut_scarcity(...)` once, over that whole batch, and
   hands the result to `self._pool.set_scarcity_scores(...)` — **before**
   any worker thread starts acquiring.
3. `DUTPool` stores it in `self._dut_scarcity` and consults it purely as a
   tiebreaker inside `_find_duts_matching_topology` — every other guard
   (topology-exclusive, PTF, shared-resource, anti-starvation, DUT-count)
   is unchanged.

Backward compatible by construction: if `set_scarcity_scores` is never
called, `self._dut_scarcity` stays `{}`, every candidate combination scores
`0.0`, and the tiebreak (original `combinations()` order) reproduces the
exact old first-match behavior.

## v2: live retirement + scarcity-aware FIFO

Two gaps from v1 are closed:

- **Scores are no longer purely static.** `_compute_dut_scarcity` now
  returns `(scores, per_script_contribution)` — the second dict is each
  script's own `{dut: weight}` breakdown. `DUTPool.set_scarcity_scores`
  stores both; `_try_allocate`'s commit step **retires** (subtracts) a
  script's contribution from the live `_dut_scarcity` the instant that
  script is allocated — not when it finishes and releases. Once a script
  has committed to a specific combo it will never reconsider, so there's
  no reason for its weight to keep steering scripts that are still
  waiting. This gets the practical benefit of "live" scoring (the picture
  shrinks as the batch's demand gets settled) without ever having to
  redo the combinatorial search mid-run — retiring is an O(1) subtraction
  per allocation, keyed by script name.
- **The plain FIFO path is scarcity-aware too.** A script with no
  `link_requirements`/`tgen_link_requirements` (plain "give me N DUTs")
  still contributes nothing to `_dut_scarcity` — it has no narrow need of
  its own — but it now CONSULTS the live scores when choosing which free
  DUTs to take: `_try_allocate`'s FIFO branch sorts free DUTs by
  `(scarcity_score, original_index)` instead of taking `free[:dut_count]`
  verbatim. So a fully flexible script no longer blindly grabs a DUT some
  other, stricter script in the batch can only get from a narrow set of
  combinations — verified directly against `DUTPool`: a flexible 2-DUT
  request and a strict "only D1-D2 has 2 links" request, FIFO request
  going first, correctly lands on `(D3, D4)` and leaves `(D1, D2)` free.
  With no scores set (every candidate ties at 0.0), this reproduces the
  exact old `free[:dut_count]` order — fully backward-compatible.

## Known limitations (still open)

- **No `dut_names`-aware scoring.** A script that pins explicit DUT names
  (`req.dut_names`) bypasses this matching function entirely, same as
  before — there's no choice being made there to steer.
- **Contributions are keyed by script basename**
  (`os.path.basename(script_path)`), matching the identifier
  `_run_one_script` already uses for `pool.acquire()`/`held_by`/etc. Two
  scripts with the same filename in different directories in one batch
  would collide here — a pre-existing identifier choice this feature
  didn't introduce, not fixed as part of this change.
