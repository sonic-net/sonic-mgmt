# Adjacency-Aware DUT Allocation

## The problem

SRPTO's lock only ever tracked **DUT ownership** — which script holds which
DUT *name*. It had no concept of the **physical links between DUTs held by
two different, concurrently-running scripts**.

**Worked example**, using the real `master_testbed.yaml` topology
(`D1-D2:1, D1-D3:1, D2-D3:2, D2-D4:1, D2-D5:1, D3-D4:1, D3-D5:1, D4-D5:2`):
suppose script A holds `D1`, running a test that triggers a heavy BGP route
update or interface flap. If a second, unrelated script B then asks for
"any 1 free DUT" and the old FIFO path hands it `D2` — real cable, real
link, `D1-D2:1` — then B's test now shares a physical link with a DUT it
has no idea is mid-churn. A timing-sensitive assertion in B (a keepalive
timer, a convergence-time check) can get thrown off by traffic it never
asked for and has no visibility into. SRPTO's per-DUT lock prevented two
scripts from touching the *same* DUT, but did nothing about the fact that
`D1` and `D2` are the same physical neighborhood.

This is not a shared-process issue — each SONiC device runs its own
independent Redis/Orchagent/BGP daemon. It's a real-network-topology issue:
control-plane *traffic* (BGP UPDATEs, LLDP, STP BPDUs) crosses real cables
between DUTs that are nominally "isolated" by SRPTO's subset-testbed
mechanism, because that mechanism isolates *DUT ownership*, not *network
adjacency*.

## The fix

Score every **candidate** DUT, at the moment of allocation, by how many
real links it has into a DUT **currently held by a different script**, and
prefer the lowest-scoring valid option — same tiebreaker philosophy as
`scarcity_aware_allocation.md`, applied to a different, *live* signal.

**Scoring** (`DUTPool._live_adjacency_penalty`): for a candidate DUT, walk
its physical neighbors (`self._adjacency`, built once from
`topology_connections` at pool init) and count how many are `busy` and
`held_by` some other script name. A DUT touching two currently-busy
foreign neighbors scores worse than one touching only one.

Unlike scarcity — which is static, computed once per run from the whole
known batch, and explicitly retired per script on allocation — adjacency
is **fully live**: it's recomputed fresh on every single allocation
attempt directly from `self._slots`' current busy state. There is nothing
to retire or go stale; the moment a script releases a DUT, the very next
allocation attempt naturally sees a lower penalty for that DUT's
neighbors, with no bookkeeping required.

**Selection**: both `DUTPool._find_duts_matching_topology` (the topology-
aware combo path) and the plain FIFO branch in `_try_allocate` now sort
candidates by `scarcity_score + adjacency_penalty` instead of scarcity
alone. Verified against the worked example above (`DUTPool` used directly,
no CLI):

```
Script A holds: ['D1']
Script B (flexible, FIFO path) allocated: ['D4']     # not D2 or D3 — both touch busy D1
Script C (needs 2 DUTs, >=1 link) allocated: ['D4', 'D5']  # not D2/D3 — zero adjacency to D1
```

## Why this is a tiebreaker, never a hard block

A hard "never allocate a DUT adjacent to something busy" rule would make
most parallelism impossible on a densely-meshed small lab: in
`master_testbed.yaml`, `D2` alone is physically linked to *all four* other
DUTs. If `D2` happens to be the one busy DUT, **every** remaining free DUT
is adjacent to it — there is no non-adjacent option, and a hard block would
simply stall the whole pool for no benefit. Confirmed directly: with `D2`
busy instead of `D1` in the same worked example, every free candidate ties
at penalty `1` and the FIFO tiebreak (original list order) decides — there
is no better choice available, by construction of the topology, not a bug
in the scoring.

So adjacency, like scarcity, only ever chooses **among already-valid**
combos. It never turns a valid allocation into a wait, and it never blocks
an allocation that would otherwise succeed.

## Known limitations (v1 of this feature)

- **Only link adjacency, not shared compute.** If two DUTs are actually VMs
  on the same hypervisor host (common for `testbed_vs_*` virtual-SONiC
  labs), a CPU-heavy test on one can still starve a timing-sensitive test
  on the other, with zero physical link between them to detect. spytest's
  testbed YAML format has no "backing host" field to key off — this would
  need a format extension, not a scheduler change.
- **Limited headroom on dense, small meshes.** As shown above, a hub-like
  DUT (connected to everyone) leaves no non-adjacent alternative to steer
  toward. The benefit scales with how *sparse* the real topology is — a
  larger lab with more DUTs and a less saturated mesh has more room for
  this to actually change an outcome than our 5-DUT validation testbed
  does.
- **Doesn't model link *direction* of risk.** A link contributes the same
  penalty regardless of whether the busy neighbor's test is actually doing
  anything disruptive (a quiet `test_snmp.py` and a route-flooding
  `test_bgp_scale.py` are scored identically). Weighting by what the
  neighboring script actually *does* would need the scheduler to know more
  about each script's behavior than its topology requirement — not
  attempted here.
