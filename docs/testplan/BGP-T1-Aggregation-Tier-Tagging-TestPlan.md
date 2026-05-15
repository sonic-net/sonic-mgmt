# BGP T1 Aggregation Tier-Based Community Tagging Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Background: T1 Aggregation Strategy](#background-t1-aggregation-strategy)
- [Topology and Setup Configuration](#topology-and-setup-configuration)
  - [Testbed Topology](#testbed-topology)
  - [Prerequisites](#prerequisites)
  - [Community Tag Reference](#community-tag-reference)
  - [Route-Map / Prefix-List Reference](#route-map--prefix-list-reference)
- [Route Validation Approach](#route-validation-approach)
- [Test Cases](#test-cases)
  - [Test Group 1: T1→T2 Upstream — TO_TIER2 Aggregate Tagging and Contributing Suppression](#test-group-1-t1t2-upstream--to_tier2-aggregate-tagging-and-contributing-suppression)
  - [Test Group 2: T1→T0 Downstream — Aggregate Leak Prevention](#test-group-2-t1t0-downstream--aggregate-leak-prevention)
  - [Test Group 3: BGP Sentinel and Monitor Route-Maps](#test-group-3-bgp-sentinel-and-monitor-route-maps)
  - [Test Group 4: Lifecycle Operations with Community Verification](#test-group-4-lifecycle-operations-with-community-verification)

> **Note**: This plan only covers the T1 (`LeafRouter`) DUT side. The producer side of the suppression contract — `TO_TIER1_V4/V6` seq 100 on a `ToRRouter` / `BackEndToRRouter` DUT — is out of scope.

---

## Overview

This test plan covers test scenarios for the **T1 aggregation tier-based community tagging** feature delivered by the FRR template changes in `dockers/docker-fpm-frr/frr/bgpd/templates/msft.general/{v4,v6}.{leaf.spine,leaf.tor.all,tor}/policy.conf.j2` and the new `sentinels` / `msft.monitors` route-maps. These tests validate the route-map and community behavior as observed on T1's neighbors.

### Scope

In this T1 deployment, instead of using `summary-only` aggregation (which would suppress contributing routes), the T1 (`LeafRouter`) advertises **both** the aggregate route and contributing routes upward to T2 (`SpineRouter`/`UpperSpineRouter`/`RegionalHub`/`AZNGHub`), each handled by distinct community-driven route-map rules. Downstream neighbors (T0 / `ToRRouter`) must NEVER see the synthetic aggregate, only the original contributing prefixes. Sentinel and IPv6 BGP-monitor sessions receive the aggregate with the same upstream tag.

This tagging is implemented natively in the FRR template (no `vtysh` hot-patch required). The `aggregate-address-prefix-list` and `contributing-address-prefix-list` populated by `AggregateAddressMgr` (in `bgpcfgd`) drive the route-map matching at runtime; the template's placeholder prefix-lists (`127.0.0.1/32` / `::1/128`) keep the policy a no-op until the prefix-lists are populated.

### Background: T1 Aggregation Strategy

This design does NOT use `summary-only=true` on T1. Instead:

1. **Both aggregate and contributing routes are advertised upstream** to T2 / RH / AZNG / RWA neighbors.
2. **Aggregate routes are tagged** with `COMM_AGG_T1 = 65525:21` so that T2/RH can identify and prefer them.
3. **Contributing routes can be selectively suppressed** at T1 if and only if T0 has tagged them upstream with `COMM_SUPPRESS_ON_T1 = 65525:110`. T0 performs this tagging itself: its `TO_TIER1_V4/V6` route-map has a seq 100 entry that matches prefixes in `SUPPRESS_ON_T1_IPV{4,6}_PREFIX` and applies `set community 65525:110 additive`.
4. **Aggregate routes are denied toward T0** by an explicit deny on `AGGREGATE_ROUTES_V4/V6`, preventing aggregation leakage downstream.

| Scenario | Direction | Aggregate Community | Contributing Behavior |
|----------|-----------|---------------------|-----------------------|
| **T1 → T2 (upstream)** | out | `65525:21` (`COMM_AGG_T1`) | Permitted by catch-all unless tagged `65525:110` (`COMM_SUPPRESS_ON_T1`); seq 300 deny then drops it |
| **T1 → T0 (downstream)** | out | denied | Permitted by catch-all (T1 doesn't withhold contributing from T0) |
| **T0 → T1 (upstream)** | out | n/a (T0 doesn't aggregate) | Prefixes in `SUPPRESS_ON_T1_IPV{4,6}_PREFIX` are tagged `65525:110` (`COMM_SUPPRESS_ON_T1`); others go via catch-all untagged |
| **T1 → BGP Sentinel** | out | `65525:21` (`COMM_AGG_T1`) | Permitted by catch-all |
| **T1 → IPv6 BGPMon** | out | `65525:21` (`COMM_AGG_T1`) | Permitted by catch-all |
| **T1 ← Sentinel / BGPMon** | in | `FROM_BGP_SENTINEL` / `FROM_BGPMON_V6` (**unchanged by this feature**) | Conditional on `constants.bgp.sentinel_community`: `FROM_BGP_SENTINEL` has `permit 100 match community sentinel_community` only when the constant is defined, otherwise only the final deny remains; `FROM_BGPMON_V6` always applies `set ipv6 next-hop prefer-global / on-match next`, and has `permit 200 match community bgpmon_v6_community` only when the same constant is defined |

---

## Topology and Setup Configuration

### Testbed Topology

Tests run on a **t1** topology. The DUT is the T1 (`LeafRouter`) device peering with T0 (`ToRRouter`) downstream and T2 (`SpineRouter`/`UpperSpineRouter`/`LowerSpineRouter`) upstream neighbors. Test Group 3 (Sentinel/Monitor) requires additional `BGP_SENTINELS` / `BGP_MONITORS` peer entries; on standard t1 testbeds these are simulated via ExaBGP.

```
        [T2 - SpineRouter]            [T2 - SpineRouter]
        (upstream:                    (upstream:
         validates 65525:21            validates 65525:21
         on aggregate;                 on aggregate;
         injects 65525:110 from T0     validates contributing
         to test seq 300 deny)         visibility for catch-all)
              |                              |
         eBGP session                   eBGP session
         (route-map: TO_TIER2_V4/V6)
              |                              |
   +----------+------------------------------+----------+
   |               DUT (T1 - LeafRouter)                |
   |  Internal FRR template with                         |
   |  tier-based community tagging route-maps:           |
   |    TO_TIER2_V4/V6  (out → T2)                       |
   |    TO_TIER0_V4/V6  (out → T0)                       |
   |    TO_BGP_SENTINEL (out → Sentinel)                 |
   |    TO_BGPMON_V6    (out → IPv6 BGPMon)              |
   |  Placeholder prefix-lists populated at runtime by   |
   |    AggregateAddressMgr from CONFIG_DB.              |
   +----------+------------------------------+----------+
              |                              |
         eBGP session                   eBGP session
         (route-map: TO_TIER0_V4/V6)
              |                              |
        [T0 - ToRRouter]              [T0 - ToRRouter]
        (downstream: originates       (downstream: originates
         contributing routes;          contributing routes;
         can tag 65525:110 to test     verifies aggregate
         suppression)                  is NOT received)

        [Sentinel / BGPMon (ExaBGP, optional)]
        (upstream-style: receives aggregate with 65525:21;
         FROM_BGP_SENTINEL / FROM_BGPMON_V6 are NOT changed by
         this feature — inbound behavior remains as before)
```

### Prerequisites

1. **Image baseline**: DUT MUST be running a SONiC image built from the **MSFT-internal `Networking-acs-buildimage` repo** (the corporate fork of `sonic-buildimage`). All FRR templates referenced by this plan (`msft.general/{v4,v6}.{leaf.spine,leaf.tor.all,tor}/policy.conf.j2`, `sentinels/policies.conf.j2`, `msft.monitors/policies.conf.j2`) and the placeholder prefix-lists / community-lists / route-maps they render exist **only** in that fork; standard public-image SONiC builds (e.g. `sonic-vs` from the upstream `sonic-buildimage`) render the plain `general/*` templates and will not satisfy any case in this plan — the entire suite MUST be skipped on those images. The production testbeds targeted by this plan are already provisioned with the internal image, so no extra image-swap is required; tests SHOULD detect the image flavor at session-startup (for example, by checking whether `vtysh -c "show route-map TO_TIER2_V4"` returns a non-empty result and whether `bgp community-list COMM_AGG_T1` exists) and `pytest.skip(...)` the module cleanly otherwise.
2. FRR template must include:
   - Placeholder prefix-lists `AGGREGATE_ROUTES_V4/V6` (`127.0.0.1/32` / `::1/128`)
   - Placeholder prefix-lists `AGGREGATE_CONTRIBUTING_ROUTES_V4/V6`
   - Placeholder prefix-lists `SUPPRESS_ON_T1_IPV4_PREFIX` / `SUPPRESS_ON_T1_IPV6_PREFIX` (T0 templates only)
   - `community-list standard COMM_AGG_T1 permit 65525:21`
   - `community-list standard COMM_SUPPRESS_ON_T1 permit 65525:110`
   - Route-map `TO_TIER2_V4/V6` with seq 100 / 200 / 300 / 10000
  - Route-map `TO_TIER0_V4/V6` with seq 400 deny aggregate
  - Route-map `TO_BGP_SENTINEL`, `TO_BGPMON_V6` with seq 100 / 200 / 1000 on `LeafRouter` DUTs; non-`LeafRouter` DUTs render only the pre-existing simple catch-all `permit 100`
  - Route-maps `FROM_BGP_SENTINEL` and `FROM_BGPMON_V6` are **NOT** modified by this feature — they retain pre-feature behavior: for sentinel, conditional community-based permit when `constants.bgp.sentinel_community` is defined plus final deny; for bgpmon_v6, unconditional `set ipv6 next-hop prefer-global / on-match next`, conditional community-based permit when the same constant is defined, plus final deny.
3. BGP sessions must be established with all T0 and T2 neighbors.
4. `AggregateAddressMgr` must be running and subscribing to `CONFIG_DB:BGP_AGGREGATE_ADDRESS`.
5. The `aggregate-address-prefix-list` / `contributing-address-prefix-list` field values used in CONFIG_DB MUST match the prefix-list names embedded in the FRR template (`AGGREGATE_ROUTES_V4/V6`, `AGGREGATE_CONTRIBUTING_ROUTES_V4/V6` on T1; `SUPPRESS_ON_T1_IPV4_PREFIX`, `SUPPRESS_ON_T1_IPV6_PREFIX` on T0). Mismatched names create orphan prefix-lists with no route-map effect.
6. Test Cases 1.8–1.10 (T1→T2 suppression) and Test Group 3 require ExaBGP (or a cooperating cEOS neighbor) capable of injecting routes with arbitrary BGP communities. Test Case 4.3 (rapid churn) reuses the TC 1.8 inject pattern and therefore inherits the same requirement. Test Group 3 additionally requires ExaBGP as a *receiver* on ptfhost to act as the BGPSentinel / BGPMonitor peer (see the TG 3 Setup Recipe).

### DUT Role Detection

Multiple test cases in this plan gate on DUT device type (`LeafRouter`, `ToRRouter` / `BackEndToRRouter`). Use the following runtime probes — these match the fact-gathering style already in use across `sonic-mgmt-int` ([tests/copp/test_copp.py:371](../../tests/copp/test_copp.py#L371), [tests/common/helpers/drop_counters/drop_counters.py:138](../../tests/common/helpers/drop_counters/drop_counters.py#L138)):

```python
cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
dut_type    = cfg_facts["DEVICE_METADATA"]["localhost"]["type"]       # 'LeafRouter' / 'ToRRouter' / 'BackEndToRRouter' / 'SpineRouter' ...
dut_subtype = cfg_facts["DEVICE_METADATA"]["localhost"].get("subtype", "")  # 'DualToR' / 'UpstreamLC' / '' ...
```

| Gate | Probe | Action when probe fails |
|------|-------|--------------------------|
| `LeafRouter` (Test Group 3 outbound aggregate tagging) | `dut_type == "LeafRouter"` | Skip the `LeafRouter`-only assertions; still allowed to run the simpler catch-all `permit 100` sanity (see TG 3 applicability notes). |
| `ToRRouter` / `BackEndToRRouter` (any T0-as-DUT scenario) | `dut_type in ("ToRRouter", "BackEndToRRouter")` | Out of scope for this plan; skip cleanly. |

Implementation note: a single session-scoped fixture (e.g. `dut_role`) returning a `namedtuple(type, subtype)` keeps each case free of repeated probing.

### Community Tag Reference

| Tag | Value | Set By | Matched By |
|-----|-------|--------|------------|
| `COMM_AGG_T1` | `65525:21` | T1 (`TO_TIER2_V4/V6` seq 200, `TO_BGP_SENTINEL` seq 100/200, `TO_BGPMON_V6` seq 100/200) | T2 / RH / AZNG / Sentinel / BGPMon — to identify aggregate origin |
| `COMM_SUPPRESS_ON_T1` | `65525:110` | T0 (`TO_TIER1_V4/V6` seq 100, on prefixes in `SUPPRESS_ON_T1_IPV{4,6}_PREFIX`) or any upstream operator | T1 (`TO_TIER2_V4/V6` seq 300 deny, with prefix-list AND community match) |

### Route-Map / Prefix-List Reference

| Object | Template | Direction | Purpose |
|--------|----------|-----------|---------|
| `TO_TIER2_V4` / `TO_TIER2_V6` | `msft.general/{v4,v6}.leaf.spine/policy.conf.j2` | out (T1→T2) | seq 100 deny `UPSTREAM_PREFIX`; seq 200 permit aggregate, set `65525:21`; seq 300 deny suppressed contributing; seq 10000 catch-all permit |
| `TO_TIER0_V4` / `TO_TIER0_V6` | `msft.general/{v4,v6}.leaf.tor.all/policy.conf.j2` | out (T1→T0) | seq 400 deny aggregate |
| `TO_TIER1_V4` / `TO_TIER1_V6` | `msft.general/{v4,v6}.tor/policy.conf.j2` | out (T0→T1) | seq 100 permit `SUPPRESS_ON_T1_IPV{4,6}_PREFIX`, set `65525:110` additive (i.e. T0 marks the contributing prefixes T1 should later suppress); seq 1000 catch-all permit |
| `TO_BGP_SENTINEL` | `sentinels/policies.conf.j2` | out (T1→Sentinel) | `LeafRouter` only: seq 100 V4 aggregate, seq 200 V6 aggregate, seq 1000 catch-all; non-`LeafRouter`: simple catch-all `permit 100` |
| `FROM_BGP_SENTINEL` | `sentinels/policies.conf.j2` | in | **NOT changed by this feature** — `permit 100 match community sentinel_community` (when `sentinel_community` defined) + `deny 200` |
| `TO_BGPMON_V6` | `msft.monitors/policies.conf.j2` | out (T1→BGPMon) | `LeafRouter` only: seq 100 V4 aggregate, seq 200 V6 aggregate, seq 1000 catch-all; non-`LeafRouter`: simple catch-all `permit 100` |
| `FROM_BGPMON_V6` | `msft.monitors/policies.conf.j2` | in | **NOT changed by this feature** — `permit 100 set ipv6 next-hop prefer-global / on-match next` + (optional) `permit 200 match community bgpmon_v6_community` + `deny 300` |
| `AGGREGATE_ROUTES_V4` / `AGGREGATE_ROUTES_V6` | T1 templates | n/a | placeholder + runtime-populated; matched in seq 200 of `TO_TIER2_*` and seq 100/200 of sentinel/bgpmon route-maps |
| `AGGREGATE_CONTRIBUTING_ROUTES_V4/V6` | T1 templates | n/a | placeholder + runtime-populated; matched in seq 300 of `TO_TIER2_*` (with `COMM_SUPPRESS_ON_T1`) |
| `SUPPRESS_ON_T1_IPV4_PREFIX` / `SUPPRESS_ON_T1_IPV6_PREFIX` | T0 templates | n/a | placeholder + runtime-populated; matched in seq 100 of `TO_TIER1_*` to apply `set community 65525:110` |

---

## Route Validation Approach

All test cases validate behavior by checking **routes and their community attributes as received by the DUT's neighbors** combined with **route-map static state on the DUT**. The feature is treated as a black box at the data path; route-map content is checked at the configuration plane to catch template/name regressions early.

### Neighbor Classification Convention

Tests in this plan classify `nbrhosts` entries in two layers, following the pattern established by [test_prefix_list_internal_only.py](../../tests/bgp/test_prefix_list_internal_only.py):

- **Layer 1 — VM-name suffix** for layered neighbors:
  - `*T0` → downstream (`ToRRouter` / `BackEndToRRouter`)
  - `*T2` → upstream spine-tier (`SpineRouter` / `UpperSpineRouter` / `LowerSpineRouter`)
  - Example: `t0_neighbors = [n for n in nbrhosts.keys() if n.endswith('T0')]`
- **Layer 2 — `DEVICE_NEIGHBOR_METADATA[*]['type']`** for role-named neighbors that don't follow the suffix convention (`RegionalHub`, `AZNGHub`, peers from `BGP_SENTINELS` / `BGP_MONITORS`, etc.):
  ```python
  cfg = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
  meta = cfg["DEVICE_NEIGHBOR_METADATA"]
  rh_names = [k for k, v in meta.items() if v["type"] == "RegionalHub"]
  rh_neighbors = [host for name, host in nbrhosts.items() if name in rh_names]
  ```
- Whenever a test below says **"on T2"**, it means **the union of**:
  - Layer-1 `*T2` `nbrhosts` entries, AND
  - Layer-2 entries whose `DEVICE_NEIGHBOR_METADATA` `type` is `SpineRouter` / `UpperSpineRouter` / `LowerSpineRouter` / `RegionalHub` / `AZNGHub`.
- Whenever a test says **"on T0"**, it means **Layer-1 `*T0` `nbrhosts` entries**, optionally augmented by Layer-2 `ToRRouter` / `BackEndToRRouter` if any such role-named entries exist.
- Whenever a test says **"on Sentinel / BGPMon"**, it means **Layer-2 entries whose `DEVICE_NEIGHBOR_METADATA` `type` indicates `BGPSentinel` / `BGPMonitor`** (or the ExaBGP mock playing that role in the testbed).

### On T2 (Upstream) Neighbors — Verify Route Communities

1. **Aggregate route**: prefix received with community `65525:21`, NOT `65525:110`.
2. **Contributing routes**: received without DUT-added tags unless tagged at injection time.
3. **Suppressed contributing routes**: when injected with `65525:110` from T0, MUST NOT be received on T2.
4. **`UPSTREAM_PREFIX` loop check**: routes carrying community `8075:54000` must be denied (existing behavior, must remain intact).

### On T0 (Downstream) Neighbors — Verify Aggregate is Hidden

1. Aggregate route MUST NOT be received on T0 (`TO_TIER0_*` seq 400 deny).
2. All other routes the DUT advertises to T0 follow existing policy unchanged.

### On Sentinel / BGPMon (Upstream) Neighbors — Verify Aggregate Tagging

1. Aggregate routes received with `65525:21`.
2. The Sentinel/BGPMon inbound behavior (`FROM_BGP_SENTINEL` / `FROM_BGPMON_V6`) is **NOT** part of this feature and is out of scope; existing sentinel/bgpmon regression suites (`test_bgpmon.py`, `test_bgpmon_v6.py`, `test_bgp_sentinel.py`) own that coverage.

### Reading Communities on Neighbors

For every test case below that asserts "on T2 / Sentinel / BGPMon: prefix received with community X", reuse the existing dual-NOS helper [`get_route_communities(host, prefix)`](../../tests/bgp/test_bgp_aggregate_address_community_tagging_msft_internal.py) and its polling wrapper [`check_communities_on_neighbors(nbrhosts, neighbor_list, prefix, expected, unexpected)`](../../tests/bgp/test_bgp_aggregate_address_community_tagging_msft_internal.py) (defined in the same file, lines 328–400). They already cover:

| Neighbor kind | Underlying command | JSON path |
|---|---|---|
| **cEOS** (Arista vEOS / `EosHost`) | `EosHost.get_route(prefix)` → `show ip bgp <prefix>` (or `show ipv6 bgp <prefix>`) with `output=json` — see [tests/common/devices/eos.py::EosHost.get_route](../../tests/common/devices/eos.py#L325) | `vrfs.default.bgpRouteEntries.<prefix>.bgpRoutePaths[*].routeDetail.communityList` |
| **SONiC** (FRR / `SonicHost`) | `vtysh -c "show ip bgp <prefix> json"` | `paths[*].community.list[*].string` |
| **ExaBGP receiver** (BGPSentinel / BGPMonitor peer) | reads `/tmp/bgp_monitor_dump.log` populated by a **new** dump script `tests/bgp/bgp_monitor_dump_with_attrs.py` (see Test Group 3 Setup Recipe — the existing `tests/bgp/bgp_monitor_dump.py` only records NLRI prefixes and discards path attributes, so it is **not** reusable for community verification) | each JSON line contains `{peer, prefix, communities, ...}` — readers MUST filter by `(peer, prefix)` since all four TG-3 receivers append to the same shared file |

Usage pattern proven by [test_bgp_aggregate_address_community_tagging_msft_internal.py:2547–2590](../../tests/bgp/test_bgp_aggregate_address_community_tagging_msft_internal.py#L2547-L2590):

```python
from tests.bgp.test_bgp_aggregate_address_community_tagging_msft_internal import (
    get_route_communities,
    check_communities_on_neighbors,
)

# Single-host single-shot read
actual = get_route_communities(nbrhosts[t2_name]["host"], AGGR_V4)
pytest_assert("65525:21" in actual,
              "Aggregate missing 65525:21 — got {}".format(actual))

# Multi-host polling assertion — preferred for any case with convergence latency
pytest_assert(
    wait_until(60, 2, 0, check_communities_on_neighbors,
               nbrhosts, t2_names, AGGR_V4,
               expected={"65525:21"}, unexpected={"65525:110"}),
    "Aggregate community state did not converge on T2 within 60s",
)
```

**Action item**: when this feature lands, lift `get_route_communities` / `check_communities_on_neighbors` from the MA/OOB test file into [tests/common/helpers/bgp_routing.py](../../tests/common/helpers/bgp_routing.py) (next to the already-shared `verify_route_on_neighbors`). This plan and the MA/OOB plan will both import the canonical version. **Do not copy the helper bodies into this plan's test files.**

For ExaBGP receiver peers (Sentinel / BGPMon), parse each JSON line written by the **new** `tests/bgp/bgp_monitor_dump_with_attrs.py` (see Test Group 3 Setup Recipe step 4 for the script body) into `/tmp/bgp_monitor_dump.log` — **not** `get_route_communities`, since the receiver is not an `EosHost` or `SonicHost`. **Do not** reuse the existing `tests/bgp/bgp_monitor_dump.py` as-is: it iterates `obj['neighbor']['message']['update']['announce']` and writes only the NLRI (see [bgp_monitor_dump.py:24-37](../../tests/bgp/bgp_monitor_dump.py#L24-L37)), throwing away `obj['neighbor']['message']['update']['attribute']['community']`. The new script reads the same exabgp JSON event and writes the peer, the prefix, and the community list — the per-peer key is mandatory because all four TG-3 receivers (V4/V6 BGPMon + V4/V6 Sentinel) share `/tmp/bgp_monitor_dump.log`, so a community-only filter would let one peer's `65525:21` shadow another peer's missing tag and produce a false pass.

### On the DUT — Static Configuration Checks

1. `vtysh -c "show running-config"` contains the expected placeholder `ip prefix-list` entries.
2. `vtysh -c "show route-map <name>"` returns the expected sequence of `permit` / `deny` clauses with the documented `match` and `set` actions.
3. `vtysh -c "show bgp community-list <name>"` returns the expected community values.

### Route-Map / Prefix-List Inspection Strategy

FRR's `show route-map X json` output is **not reliable across the FRR versions shipped in SONiC** (no in-repo test currently consumes it — the one docstring mention in [test_route_map_check.py](../../tests/route/test_route_map_check.py) explicitly falls back to text). This plan adopts the two patterns already proven in-repo, depending on the assertion granularity needed:

#### Pattern A — Token-presence grep (lightweight)

Use when a test only needs to know *whether a token is present anywhere in a named route-map* (e.g. "`AGGREGATE_ROUTES_V4` is referenced", "`65525:21` appears somewhere"). This is the style already in [test_bgp_aggregate_address_community_tagging_msft_internal.py](../../tests/bgp/test_bgp_aggregate_address_community_tagging_msft_internal.py) lines 226 and 607–608:

```python
# Single-token check (returns True / False via rc)
duthost.shell(
    "vtysh -c 'show route-map TO_TIER2_V4' 2>/dev/null | grep -q '65525:21 additive'",
    module_ignore_errors=False,  # rc != 0 fails the assertion
)
# Or capture and assert in Python — works equally well on multi-asic via `vtysh -n <asic>`
output = duthost.shell("vtysh -c 'show route-map TO_TIER2_V4'")["stdout"]
assert "AGGREGATE_ROUTES_V4" in output
assert "65525:21" in output
```

Applicable test cases: TG 1 runtime behavior verification (tagging + suppression).

#### Pattern B — Structured `show run` block walker (precise)

Use when a test must distinguish between sequence numbers, permit vs deny, or assert that a `match` / `set` lives in a *specific* clause. This is the pattern already used by [test_route_map_check.py::verify_v6_next_hop_from_run](../../tests/route/test_route_map_check.py) (lines 38–75). Reuse / refactor that helper into [tests/bgp/bgp_helpers.py](../../tests/bgp/bgp_helpers.py) with the following signatures:

```python
def get_frr_running_configs(duthost) -> list[tuple[str, str]]:
    """Return [(asic_label, running_config_text), ...].
    Multi-asic safe: uses `vtysh -n <asic_id> -c \"show run\"`.
    Lifted verbatim from tests/route/test_route_map_check.py::get_run_configs."""

def find_route_map_clause(
    cfg_text: str, name: str, seq: int, mode: str = "permit"
) -> list[str] | None:
    """Return the body lines inside the `route-map NAME MODE SEQ` block.
    Returns None if no such block exists. State-machine pattern from
    verify_v6_next_hop_from_run: split lines, match
    `^route-map (\\S+) (permit|deny) (\\d+)`, accumulate body until `exit`."""

def assert_route_map_clause(
    cfg_text: str, name: str, seq: int, mode: str,
    *, must_contain: tuple[str, ...] = (), must_not_contain: tuple[str, ...] = (),
) -> None:
    """High-level assertion wrapper. Fails with a contextual message including
    the matched block body when expectations are not met."""
```

Applicable test cases: any future structural assertion that needs to distinguish a specific clause; runtime tagging / suppression cases in TG 1 and TG 2 use Pattern A.

#### Multi-ASIC handling

T1 LeafRouters in production are frequently multi-ASIC. Every `vtysh` call in this plan MUST go through the helper above (or follow the same `is_multi_asic` / `vtysh -n <asic_id>` pattern). Each assertion runs once per ASIC and aggregates failures, matching the style of `test_route_map_check.test_route_map_check`.

#### CONFIG_DB Write Strategy (GCU vs `sonic-db-cli`)

All `BGP_AGGREGATE_ADDRESS` mutations in this plan use the canonical 2-segment key `BGP_AGGREGATE_ADDRESS|<prefix>` — the YANG model [sonic-bgp-aggregate-address.yang](../../../Networking-acs-buildimage/src/sonic-yang-models/yang-models/sonic-bgp-aggregate-address.yang) declares `key "aggregate-address"` as the sole list key, and bgpcfgd's [`key2prefix(key)`](../../../Networking-acs-buildimage/src/sonic-bgpcfgd/bgpcfgd/managers_aggregate_address.py#L198-L200) parses the prefix as `key.split("|")[-1]`. There is no `default` VRF segment. Two write paths are used in this plan, by design:

| Path | When to use | Rationale |
|------|------------|-----------|
| **GCU** — [`gcu_add_community_aggregate`](../../tests/bgp/test_bgp_aggregate_address_community_tagging_msft_internal.py) (JSON patch `op=add path=/BGP_AGGREGATE_ADDRESS/<prefix-encoded>`) | TG 1, TG 3, TG 4 functional cases; any test that needs YANG validation, checkpoint/rollback, or coordinated multi-row writes | Same audit trail as production config pushes; rolls back cleanly via `rollback_or_reload(duthost)`; catches schema regressions early. |
| **Direct CONFIG_DB** — `sonic-db-cli CONFIG_DB HSET '<key>' ...` / `DEL '<key>'` | TC 4.4 churn loop **only** | GCU adds ~6s of overhead per write (config-engine + YANG validation + checkpoint rewrite); `sonic-db-cli HSET` is ~0.02s, which is the only way to actually stress the bgpcfgd → FRR write path. The pattern is the one already proven by [test_7_3_rapid_add_remove_cycling](../../tests/bgp/test_bgp_aggregate_address_scale_stress.py#L862-L867). Bypassing GCU intentionally trades audit / rollback safety for the ability to exercise the convergence behavior the test is targeting. |

Do NOT mix paths within the same test case (e.g. GCU-add then `sonic-db-cli DEL`); the GCU checkpoint state will not reflect the deletion and `rollback_or_reload` will undo the wrong thing.

---

## Test Cases

### Test Group 1: T1→T2 Upstream — TO_TIER2 Aggregate Tagging and Contributing Suppression

**Objective**: Validate both halves of the T1→T2 outbound `TO_TIER2_V4/V6` policy:
- **Tagging (TC 1.1–1.7)**: `BGP_AGGREGATE_ADDRESS` writes via `AggregateAddressMgr` populate the runtime prefix-lists, which cause the aggregate route advertised to T2 to be tagged with `COMM_AGG_T1` (`65525:21`).
- **Suppression (TC 1.8–1.10)**: contributing routes that T0 marked with `COMM_SUPPRESS_ON_T1` (`65525:110`) are withheld from T2, while all other contributing traffic passes through unchanged via the catch-all.

#### Test Case 1.1: Aggregate route tagged with 65525:21 toward T2 (IPv4)
- **Config**: `summary-only=false`, `aggregate-address-prefix-list=AGGREGATE_ROUTES_V4`, `contributing-address-prefix-list=AGGREGATE_CONTRIBUTING_ROUTES_V4`, `bbr-required=false`
- **Steps**:
  1. On DUT: write `BGP_AGGREGATE_ADDRESS|10.100.0.0/16` to CONFIG_DB with above fields
  2. Announce contributing routes `10.100.1.0/24`, `10.100.2.0/24` from T0 (or ExaBGP at T0 position)
  3. Wait for aggregate convergence
  4. On T2: verify aggregate route `10.100.0.0/16` is received
  5. On T2: verify community `65525:21` is attached to the aggregate
  6. On T2: verify `65525:110` is NOT present on the aggregate
  7. On T2: verify the aggregate community attribute equals exactly `{65525:21}` plus whatever the route already carried; nothing else added by DUT

#### Test Case 1.2: Aggregate route tagged with 65525:21 toward T2 (IPv6)
- **Intent**: IPv6 dual of TC 1.1 — same assertions, symmetric coverage.
- **Config**: IPv6 aggregate `2001:db8:100::/48`, `aggregate-address-prefix-list=AGGREGATE_ROUTES_V6`, `contributing-address-prefix-list=AGGREGATE_CONTRIBUTING_ROUTES_V6`, `summary-only=false`, `bbr-required=false`
- **Steps**:
  1. On DUT: write `BGP_AGGREGATE_ADDRESS|2001:db8:100::/48` to CONFIG_DB with above fields
  2. Announce contributing IPv6 routes `2001:db8:100:1::/64`, `2001:db8:100:2::/64` from T0 (or ExaBGP at T0 position)
  3. Wait for aggregate convergence
  4. On T2: verify aggregate route `2001:db8:100::/48` is received
  5. On T2: verify community `65525:21` is attached to the aggregate
  6. On T2: verify `65525:110` is NOT present on the aggregate
  7. On T2: verify the aggregate community attribute equals exactly `{65525:21}` plus whatever the route already carried; nothing else added by DUT

#### Test Case 1.3: Contributing routes traverse to T2 by catch-all (IPv4)
- **Steps**:
  1. Setup same as TC 1.1
  2. On T2: verify each contributing route `10.100.1.0/24` / `10.100.2.0/24` IS received
  3. On T2: verify the contributing route does NOT carry `65525:21` (DUT only tags aggregate)
  4. On T2: verify the contributing route does NOT carry `65525:110` (no suppression injected)
  5. Confirm seq 10000 catch-all of `TO_TIER2_V4` is the path taken

#### Test Case 1.4: Contributing routes traverse to T2 by catch-all (IPv6)
- **Steps**:
  1. Setup same as TC 1.2
  2. On T2: verify each contributing route `2001:db8:100:1::/64` / `2001:db8:100:2::/64` IS received
  3. On T2: verify the contributing route does NOT carry `65525:21`
  4. On T2: verify the contributing route does NOT carry `65525:110`
  5. Confirm seq 10000 catch-all of `TO_TIER2_V6` is the path taken

#### Test Case 1.5: Aggregate prefix-list populated dynamically
- **Steps**:
  1. Before adding aggregate: `vtysh -c "show ip prefix-list AGGREGATE_ROUTES_V4"` returns only the placeholder `127.0.0.1/32`
  2. After adding aggregate (Test Case 1.1 config): same command returns placeholder PLUS `permit 10.100.0.0/16`
  3. After deleting the CONFIG_DB entry: returns only the placeholder again

#### Test Case 1.6: Multiple aggregates share the same prefix-list
- **Steps**:
  1. Add aggregate A `10.100.0.0/16` with `aggregate-address-prefix-list=AGGREGATE_ROUTES_V4`
  2. Add aggregate B `10.200.0.0/16` with the SAME prefix-list name
  3. On T2: verify both aggregates received with `65525:21`
  4. Remove aggregate A
  5. On T2: verify A withdrawn, B still tagged with `65525:21`
  6. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows placeholder + `10.200.0.0/16` only

#### Test Case 1.7: Shared prefix-list returns to placeholder after all aggregates are removed
- **Intent**: Full-drain variant of TC 1.5 / TC 1.6 — after **every** aggregate sharing a prefix-list is removed, no orphan dynamic entries remain.
- **Steps**:
  1. Add aggregate A `10.100.0.0/16` with `aggregate-address-prefix-list=AGGREGATE_ROUTES_V4`
  2. Add aggregate B `10.200.0.0/16` with the SAME prefix-list name
  3. On T2: verify both aggregates are received with community `65525:21`
  4. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows placeholder + `10.100.0.0/16` + `10.200.0.0/16`
  5. Remove aggregate A from CONFIG_DB
  6. Remove aggregate B from CONFIG_DB
  7. On T2: verify both aggregates are withdrawn (neither `10.100.0.0/16` nor `10.200.0.0/16` is received)
  8. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows ONLY the placeholder `127.0.0.1/32` — no leftover dynamic entries
  9. On DUT: `show ip prefix-list AGGREGATE_CONTRIBUTING_ROUTES_V4` likewise shows ONLY the placeholder (paired prefix-list MUST drain in lockstep)
  10. On DUT: `redis-cli -n 4 KEYS 'BGP_AGGREGATE_ADDRESS|*'` returns empty (no stale CONFIG_DB rows)

#### Test Case 1.8: Contributing tagged 65525:110 is suppressed toward T2 (IPv4)
- **Config**: Aggregate `10.100.0.0/16` with both prefix-lists configured so that `10.100.1.0/24` falls into `AGGREGATE_CONTRIBUTING_ROUTES_V4`
- **Steps**:
  1. From T0/ExaBGP, announce `10.100.1.0/24` carrying community `65525:110`
  2. On DUT: verify `vtysh -c "show ip bgp 10.100.1.0/24"` displays `Community: 65525:110`
  3. On T2: verify `10.100.1.0/24` is NOT received
  4. On DUT: verify `show ip bgp neighbor <T2> advertised-routes` does NOT contain `10.100.1.0/24`

#### Test Case 1.9: Contributing tagged 65525:110 is suppressed toward T2 (IPv6)
- **Config**: IPv6 aggregate `2001:db8:100::/48` with both prefix-lists configured so that `2001:db8:100:1::/64` falls into `AGGREGATE_CONTRIBUTING_ROUTES_V6`
- **Steps**:
  1. From T0/ExaBGP, announce `2001:db8:100:1::/64` carrying community `65525:110`
  2. On DUT: verify `vtysh -c "show bgp ipv6 2001:db8:100:1::/64"` displays `Community: 65525:110`
  3. On T2: verify `2001:db8:100:1::/64` is NOT received
  4. On DUT: verify `show bgp ipv6 neighbor <T2> advertised-routes` does NOT contain `2001:db8:100:1::/64`

#### Test Case 1.10: Suppression requires both "is a tracked contributing prefix" AND "carries 65525:110"
- **Intent**: T1 withholds a contributing route from T2 only when **both** A (prefix is in `AGGREGATE_CONTRIBUTING_ROUTES_V4`) AND B (route carries `65525:110`) hold. This case covers the two reverse cells (F,T) and (T,F); (T,T) is TC 1.8 and (F,F) is TC 1.3.
- **Config**: Aggregate `10.100.0.0/16` with both prefix-lists configured so that `10.100.1.0/24` falls into `AGGREGATE_CONTRIBUTING_ROUTES_V4`
- **Steps (A false, B true)**:
  1. From T0/ExaBGP, announce `10.100.99.0/24` (NOT a contributing prefix) carrying community `65525:110`
  2. On DUT: verify `vtysh -c "show ip bgp 10.100.99.0/24"` displays `Community: 65525:110`
  3. On T2: verify `10.100.99.0/24` IS received, with `65525:110` preserved and no DUT-added `65525:21`
  4. On DUT: verify `show ip bgp neighbor <T2> advertised-routes` DOES contain `10.100.99.0/24`
- **Steps (A true, B false)**:
  5. From T0/ExaBGP, announce `10.100.1.0/24` (IS a contributing prefix) without `65525:110` (no community, or any unrelated community such as `65000:100`)
  6. On DUT: verify `vtysh -c "show ip bgp 10.100.1.0/24"` does NOT display `65525:110`
  7. On T2: verify `10.100.1.0/24` IS received, with the announced community set preserved and no DUT-added `65525:21` / `65525:110`
  8. On DUT: verify `show ip bgp neighbor <T2> advertised-routes` DOES contain `10.100.1.0/24`

---

### Test Group 2: T1→T0 Downstream — Aggregate Leak Prevention

**Objective**: Validate that `TO_TIER0_V4/V6` seq 400 deny prevents the synthetic aggregate from being advertised downstream to T0. This is critical to avoid attracting traffic for prefixes that the T1 cannot actually reach beyond what its T0s already know.

#### Test Case 2.1: Aggregate not advertised to T0 (IPv4)
- **Config**: Aggregate `10.100.0.0/16` with prefix-lists
- **Steps**:
  1. Add aggregate, announce contributing routes from T0
  2. On T0: verify `10.100.0.0/16` is NOT received from DUT
  3. On T0: verify the contributing routes (which T0 itself originated) are unchanged
  4. On DUT: `show ip bgp neighbor <T0> advertised-routes` does NOT contain `10.100.0.0/16`

#### Test Case 2.2: Aggregate not advertised to T0 (IPv6)
- **Intent**: IPv6 dual of TC 2.1 — same assertions, symmetric coverage.
- **Config**: IPv6 aggregate `2001:db8:100::/48` with prefix-lists
- **Steps**:
  1. Add aggregate, announce contributing routes from T0
  2. On T0: verify `2001:db8:100::/48` is NOT received from DUT
  3. On T0: verify the contributing routes (which T0 itself originated) are unchanged
  4. On DUT: `show bgp ipv6 neighbor <T0> advertised-routes` does NOT contain `2001:db8:100::/48`

#### Test Case 2.3: Other DUT-originated routes are unaffected
- **Steps**:
  1. With aggregate in place, verify DUT continues to advertise default route / loopback / non-aggregate prefixes to T0 normally
  2. Verify no syslog errors regarding `TO_TIER0_V4` route-map evaluation

---

### Test Group 3: BGP Sentinel and Monitor Route-Maps

**Objective**: Validate the new `TO_BGP_SENTINEL` and `TO_BGPMON_V6` outbound aggregate tagging on `LeafRouter`.

- **Applicability**: Both test cases require a `LeafRouter` DUT because aggregate-tagging clauses in `TO_BGP_SENTINEL` / `TO_BGPMON_V6` are guarded by the `LeafRouter` device type. Skip cleanly on non-`LeafRouter` DUTs.

#### Setup Recipe (BGPMon + BGPSentinel ExaBGP peers on ptfhost)

A t1 testbed does NOT come pre-provisioned with `BGP_SENTINELS` / `BGP_MONITORS` peers. Each TG-3 test MUST add them at session-start and tear them down on exit. The recipe is **assembled entirely from existing sonic-mgmt-int assets** — no new ExaBGP/template code should be written.

| Step | Reuse from |
|------|------------|
| 1. GCU checkpoint before any mutation | `tests.common.gcu_utils.create_checkpoint(duthost)` (already used by [test_bgp_aggregate_address.py](../../tests/bgp/test_bgp_aggregate_address.py)) |
| 2. Render & write `BGP_MONITORS\|<peer>` to CONFIG_DB | Reuse the **existing `bgpmon_setup_teardown` fixture** verbatim — [tests/bgp/conftest.py::bgpmon_setup_teardown](../../tests/bgp/conftest.py) (renders `tests/bgp/templates/bgp_template.j2` with `db_table_name='BGP_MONITORS'`, then calls `asichost.write_to_config_db`) |
| 3. Push `BGP_SENTINELS\|BGPSentinelV4/V6` rows via GCU | Reuse the patch shape from [tests/generic_config_updater/test_bgp_sentinel.py::bgp_sentinel_tc1_add_config](../../tests/generic_config_updater/test_bgp_sentinel.py) — `apply_gcu_patch` with `op=add path=/BGP_SENTINELS value={V4: {ip_range,src_address,name}, V6: {...}}`. Constants for names (`BGP_SENTINEL_NAME_V4`, `BGP_SENTINEL_NAME_V6`) and ports (`BGP_SENTINEL_PORT_V4=7900`, `BGP_SENTINEL_PORT_V6=7901`) are already in [tests/bgp/bgp_helpers.py](../../tests/bgp/bgp_helpers.py). |
| 4. Start ExaBGP **receiver** on ptfhost (one per peer: V4/V6 BGPMon + V4/V6 Sentinel) | Same `ptfhost.exabgp(name=<peer>, state="started", ...)` call shape as `bgpmon_setup_teardown`, but pass `dump_script=/usr/share/exabgp/bgp_monitor_dump_with_attrs.py` (the new script — see contract below). |
| 5. Wait for BGP session up — **must cover both AFIs** | `vtysh -c "show ip bgp summary"` (≡ `show bgp ipv4 unicast summary`) only lists IPv4 peers; the IPv6 Sentinel / IPv6 BGPMon sessions activated only under `address-family ipv6 unicast` will not appear there. Use `vtysh -c "show bgp summary json"` once and walk both `ipv4Unicast.peers` and `ipv6Unicast.peers`, asserting `state == "Established"` for every expected peer IP (V4 BGPMon, V6 BGPMon, V4 Sentinel, V6 Sentinel). Reuse the 121s convergence budget from [test_bgpmon.py](../../tests/bgp/test_bgpmon.py): `wait_until(121, 5, 0, _all_tg3_peers_established)`. |
| 6. Read DUT-advertised aggregate's communities | `communities_for_prefix(ptfhost, peer=<receiver peer_ip>, prefix=<aggregate>)` — filters the shared dump by `(peer, prefix)` and returns a `set[str]` of community strings. Assert `"65525:21"` is in the returned set. |

**New dump script** `tests/bgp/bgp_monitor_dump_with_attrs.py` (additive — does not replace the shared `bgp_monitor_dump.py`, which discards path attributes):

- **Input**: exabgp JSON events on stdin (same source as `bgp_monitor_dump.py`).
- **Output**: one JSON line per advertised prefix, appended to `/tmp/bgp_monitor_dump.log` (`DUMP_FILE` in [tests/bgp/bgp_helpers.py:36](../../tests/bgp/bgp_helpers.py#L36)), shape `{peer, prefix, communities}`.
- **`peer` field is mandatory**: all four TG-3 receivers (V4/V6 BGPMon + V4/V6 Sentinel) append to the same file. Without per-peer tagging, a `65525:21` from one peer would mask a missing tag on another and the assertion would falsely pass. Extract from `neighbor.address.peer` (exabgp v4) or `neighbor.ip` (v3).
- **Communities**: extract `update.attribute.community`, normalize both v3 (`[[asn, value], ...]`) and v4 (`["asn:value", ...]`) emissions to `"asn:value"` strings.
- **AFIs**: handle both `update.announce["ipv4 unicast"]` and `update.announce["ipv6 unicast"]`.

**Verification helper** `communities_for_prefix(ptfhost, peer, prefix, dump_path=DUMP_FILE) -> set[str]`:

- Reads the dump file via `ptfhost.shell("cat ...")`, returns the union of `communities` from lines where both `peer` and `prefix` match.
- `peer` MUST equal the `peer_ip` passed to `ptfhost.exabgp(..., peer_ip=...)` (the DUT loopback the receiver session peers with).

**Per-test hygiene**: `ptfhost.shell("truncate -s 0 /tmp/bgp_monitor_dump.log")` at the start of every TG-3 case — the file is append-only and would otherwise carry cross-case state.

| 7. Teardown | `ptfhost.exabgp(name=<peer>, state="absent")` for each peer, then `rollback_or_reload(duthost)` and `delete_checkpoint(duthost)` — same teardown wrapper as TG 1. |

Implementation note: a single module-scoped fixture (e.g. `tg3_sentinel_bgpmon_setup`) that wraps steps 1–5 and yields a context object (`{peer_v4, peer_v6, sentinel_peer_v4, sentinel_peer_v6, dump_path}`) keeps every TG-3 test case to two screenfuls.

#### Test Case 3.1: Sentinel receives aggregate with 65525:21 (IPv4 + IPv6)
- **Config**: `BGP_SENTINELS` peer configured with one IPv4 and one IPv6 session
- **Steps**:
  1. Add IPv4 and IPv6 aggregates with prefix-lists
  2. On Sentinel: verify IPv4 aggregate `10.100.0.0/16` received with `65525:21`
  3. On Sentinel: verify IPv6 aggregate `2001:db8:100::/48` received with `65525:21`
  4. On Sentinel: verify catch-all clause permits other (non-aggregate) prefixes (loopback, etc.)

#### Test Case 3.2: BGPMon V6 receives aggregate with 65525:21 (dual-stack tagging)
- **Steps**:
  1. With aggregates in place, on IPv6 BGPMon peer: verify both V4 and V6 aggregates are received with `65525:21`

#### Test Case 3.3: Contributing tagged 65525:110 is NOT suppressed toward Sentinel / BGPMon
- **Config**: Aggregate `10.100.0.0/16` (V4) and `2001:db8:100::/48` (V6) with both prefix-lists configured so that `10.100.1.0/24` falls into `AGGREGATE_CONTRIBUTING_ROUTES_V4` and `2001:db8:100:1::/64` falls into `AGGREGATE_CONTRIBUTING_ROUTES_V6`. Setup otherwise identical to TC 3.1 / 3.2 (reuse `tg3_sentinel_bgpmon_setup`).
- **Steps**:
  1. From T0/ExaBGP, announce `10.100.1.0/24` and `2001:db8:100:1::/64` each carrying community `65525:110`
  2. On DUT: verify both prefixes display `Community: 65525:110` in `show ip bgp` / `show bgp ipv6`
  3. On Sentinel V4 receiver: verify `10.100.1.0/24` IS received with `65525:110` preserved and no DUT-added `65525:21`
  4. On Sentinel V6 receiver: verify `2001:db8:100:1::/64` IS received with `65525:110` preserved and no DUT-added `65525:21`
  5. On BGPMon V4 receiver: verify `10.100.1.0/24` IS received with `65525:110` preserved and no DUT-added `65525:21`
  6. On BGPMon V6 receiver: verify `2001:db8:100:1::/64` IS received with `65525:110` preserved and no DUT-added `65525:21`

---

### Test Group 4: Lifecycle Operations with Community Verification

**Objective**: Validate that aggregate lifecycle operations correctly preserve / restore the tier-based tagging, verified on T2 / T0 neighbors. (Basic add / remove behavior is already covered by TG 1 — TC 1.1 for tagging, TC 1.5 for prefix-list dynamic add/remove; this group focuses on operations that go beyond a single CONFIG_DB write.)

#### Test Case 4.1: BGP container restart preserves tagging
- **Steps**:
  1. Add aggregate, verify tagging on T2
  2. `systemctl restart bgp` on DUT
  3. Wait for BGP sessions to re-establish
  4. On T2: verify aggregate received with `65525:21`
  5. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` contains placeholder + dynamic entry

#### Test Case 4.2: Config reload preserves tagging
- **Steps**:
  1. Add aggregate, `config save -y`
  2. `config reload -y -f`
  3. After convergence, on T2: verify `65525:21` on aggregate
  4. On T0: verify aggregate still NOT received

#### Test Case 4.3: Rapid add/remove churn does not corrupt prefix-list state
- **Intent**: Stress the `BGP_AGGREGATE_ADDRESS` → `AggregateAddressMgr` → FRR write path under back-to-back add/remove, and prove that the new tier-tagging prefix-lists (`AGGREGATE_ROUTES_V4`, `AGGREGATE_CONTRIBUTING_ROUTES_V4`) return to baseline with no orphans. All pacing constants and helpers reuse those already proven by [tests/bgp/test_bgp_aggregate_address_scale_stress.py::test_7_3_rapid_add_remove_cycling](../../tests/bgp/test_bgp_aggregate_address_scale_stress.py) (lines 829–935). **Do not invent new throttle numbers or restart-detection helpers.**
- **Reused helpers / constants** (all defined in [tests/bgp/bgp_aggregate_helpers.py](../../tests/bgp/bgp_aggregate_helpers.py)):
  - `BGP_SETTLE_WAIT = 5` — used once between batches (NOT between iterations).
  - `verify_bgp_aggregate_cleanup(duthost, prefix)` — asserts the aggregate is fully removed from FRR running-config.
  - `wait_until` from `tests.common.utilities`.
  - `_wait_for_dut_ready(duthost)` / `_check_dut_health(duthost)` — copy the patterns from the stress-test class methods.
- **Iteration count**: **100** (`RAPID_CYCLE_ITERATIONS` in the stress test). The plan's original "50" is replaced to align with the existing reference implementation; if budget requires fewer iterations on a slow testbed, parametrize via a fixture rather than hard-coding a different number here.
- **Pacing pattern (per iteration — no `time.sleep` between iterations)**:

  ```python
  CYCLE_TIMEOUT = 30   # seconds, per-iteration wait_until budget
  CYCLE_INTERVAL = 2   # seconds, polling interval
  AGGR_V4 = "10.100.0.0/16"
  db_key = f"BGP_AGGREGATE_ADDRESS|{AGGR_V4}"
  db_add_cmd = (
      f"sonic-db-cli CONFIG_DB HSET '{db_key}' "
      f"'bbr-required' 'false' 'summary-only' 'false' 'as-set' 'false' "
      f"'aggregate-address-prefix-list' 'AGGREGATE_ROUTES_V4' "
      f"'contributing-address-prefix-list' 'AGGREGATE_CONTRIBUTING_ROUTES_V4'"
  )
  db_del_cmd = f"sonic-db-cli CONFIG_DB DEL '{db_key}'"

  for iteration in range(1, RAPID_CYCLE_ITERATIONS + 1):
      duthost.shell(db_add_cmd, module_ignore_errors=True)
      pytest_assert(
          wait_until(CYCLE_TIMEOUT, CYCLE_INTERVAL, 0, _aggregate_present_on_t2),
          f"Iteration {iteration}: aggregate not received on T2 with 65525:21",
      )
      duthost.shell(db_del_cmd, module_ignore_errors=True)
      pytest_assert(
          wait_until(CYCLE_TIMEOUT, CYCLE_INTERVAL, 0, _aggregate_absent_on_t2),
          f"Iteration {iteration}: aggregate not withdrawn from T2",
      )
  ```

  Notes on the chosen approach:
  - **Direct CONFIG_DB writes** (`sonic-db-cli HSET` / `DEL`) — measured at ~0.02s vs. ~6s for GCU; the GCU overhead would dominate and mask the convergence behavior being tested.
  - **No `time.sleep` between iterations** — pacing is provided by `wait_until` on a real convergence condition (route appears/disappears on T2). A blind sleep would either be too long (mask the bug) or too short (flaky on slow VS).
  - **One settling wait at the end only** — a single `time.sleep(BGP_SETTLE_WAIT)` after the final iteration before the post-checks, matching the stress-test pattern (lines 591 / 791 / 827).
- **Pre-test setup**:
  1. `_wait_for_dut_ready(duthost)`.
  2. Announce contributing routes from T0 (reuse the inject pattern from TC 1.8) so each `add` iteration actually has something to tag on T2 (this is what makes `_aggregate_present_on_t2` a real signal).
  3. Confirm starting state: `show ip prefix-list AGGREGATE_ROUTES_V4` returns ONLY the placeholder.
- **Post-test verification (after the loop + single `BGP_SETTLE_WAIT`)**:
  4. `verify_bgp_aggregate_cleanup(duthost, AGGR_V4)` — FRR has no leftover `aggregate-address` command.
  5. `show ip prefix-list AGGREGATE_ROUTES_V4` returns ONLY the placeholder `127.0.0.1/32` (no orphan dynamic entries).
  6. `show ip prefix-list AGGREGATE_CONTRIBUTING_ROUTES_V4` returns ONLY the placeholder.
  7. `redis-cli -n 4 KEYS 'BGP_AGGREGATE_ADDRESS|*'` returns empty.
  8. `_check_dut_health(duthost)` — no exited containers, CPU < 95%, memory < 95%.
  9. On the bgp container: `docker logs bgp --since=10m 2>&1 | grep -Ei 'error|traceback'` returns no `bgpcfgd` error/traceback messages. (Tolerate routine route-flap noise; use the existing log-analyzer ignore list if needed.)
  10. On T2: the aggregate prefix is fully withdrawn (no leftover from the last iteration).

---

## Out of Scope

- Performance / scale testing (covered by `test_bgp_aggregate_address_scale_stress.py`)
- MA / OOB community tagging (covered by [BGP-Aggregate-Address.md](BGP-Aggregate-Address.md))
- Public-image (non-MSFT) FRR template behavior — the route-maps and community values in this plan target the `msft.general` / `msft.monitors` template family **rendered only by `Networking-acs-buildimage` (the MSFT-internal fork of `sonic-buildimage`)**. Standard upstream-image testbeds (e.g. `sonic-vs` from the public `sonic-buildimage`) are explicitly out of scope and the suite MUST `pytest.skip(...)` on them.

## Cross-Reference

- FRR template source: `dockers/docker-fpm-frr/frr/bgpd/templates/msft.general/{v4,v6}.{leaf.spine,leaf.tor.all,tor}/policy.conf.j2`, `sentinels/policies.conf.j2`, `msft.monitors/policies.conf.j2`
- Runtime population: `src/sonic-bgpcfgd/bgpcfgd/managers_aggregate_address.py` (`AggregateAddressMgr`)
- Template-rendering unit tests: `src/sonic-bgpcfgd/tests/test_templates.py` + `tests/data/{msft.general,sentinels,msft.monitors}/policies.conf/`
- IPv6 next-hop policy regression: `src/sonic-bgpcfgd/tests/test_ipv6_nexthop_global.py` (the `DENY_ALL_ROUTE_MAPS` whitelist does not carve out `FROM_BGPMON_V6`)
- Sister test plan (MA / OOB upstream): [BGP-Aggregate-Address.md](BGP-Aggregate-Address.md)
