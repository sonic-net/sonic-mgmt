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
  - [Test Group 1: Static Template Regression](#test-group-1-static-template-regression)
  - [Test Group 2: T1→T2 Upstream — Aggregate Tagging with COMM_AGG_T1](#test-group-2-t1t2-upstream--aggregate-tagging-with-comm_agg_t1)
  - [Test Group 3: T1→T2 Upstream — Contributing Suppression with COMM_SUPPRESS_ON_T1](#test-group-3-t1t2-upstream--contributing-suppression-with-comm_suppress_on_t1)
  - [Test Group 4: T1→T0 Downstream — Aggregate Leak Prevention](#test-group-4-t1t0-downstream--aggregate-leak-prevention)
  - [Test Group 5: T0→T1 Upstream — Contributing Tagging](#test-group-5-t0t1-upstream--contributing-tagging)
  - [Test Group 6: BGP Sentinel and Monitor Route-Maps](#test-group-6-bgp-sentinel-and-monitor-route-maps)
  - [Test Group 7: Lifecycle Operations with Community Verification](#test-group-7-lifecycle-operations-with-community-verification)
  - [Test Group 8: Prefix-List Driven Tagging Mechanism](#test-group-8-prefix-list-driven-tagging-mechanism)

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

Tests run on a **t1 / t1-lag / t1-64-lag** topology. The DUT is the T1 (`LeafRouter`) device peering with T0 (`ToRRouter`) downstream and T2 (`SpineRouter`/`UpperSpineRouter`/`LowerSpineRouter`) upstream neighbors. Test Groups 6 (Sentinel/Monitor) require additional `BGP_SENTINELS` / `BGP_MONITORS` peer entries; on standard t1 testbeds these are simulated via ExaBGP.

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

1. DUT MUST be running a SONiC image with the updated `msft.general/{v4,v6}.{leaf.spine,leaf.tor.all,tor}` and `sentinels` / `msft.monitors` FRR templates.
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
6. Test Groups 6 / 7.3 require ExaBGP (or a cooperating cEOS neighbor) capable of injecting routes with arbitrary BGP communities.

### Community Tag Reference

| Tag | Value | Set By | Matched By |
|-----|-------|--------|------------|
| `COMM_AGG_T1` | `65525:21` | T1 (`TO_TIER2_V4/V6` seq 200, `TO_BGP_SENTINEL` seq 100/200, `TO_BGPMON_V6` seq 100/200) | T2 / RH / AZNG / Sentinel / BGPMon — to identify aggregate origin |
| `COMM_SUPPRESS_ON_T1` | `65525:110` | T0 (`TO_TIER1_V4/V6` seq 100, on prefixes in `SUPPRESS_ON_T1_IPV{4,6}_PREFIX`) or any upstream operator | T1 (`TO_TIER2_V4/V6` seq 300 deny, with prefix-list AND community match) |

### Route-Map / Prefix-List Reference

| Object | Template | Direction | Purpose |
|--------|----------|-----------|---------|
| `TO_TIER2_V4` / `TO_TIER2_V6` | `msft.general/{v4,v6}.leaf.spine/policy.conf.j2` | out (T1→T2) | seq 100 deny `UPSTREAM_PREFIX`; seq 200 permit aggregate, set `65525:21`; seq 300 deny suppressed contributing; seq 10000 catch-all permit |
| `TO_TIER0_V4` / `TO_TIER0_V6` | `msft.general/{v4,v6}.leaf.tor.all/policy.conf.j2` | out (T1→T0) | seq 400 deny aggregate (V6 must use `match ipv6 address` — bug-fix regression) |
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

### On T2 (Upstream) Neighbors — Verify Route Communities

1. **Aggregate route**: prefix received with community `65525:21`, NOT `65525:110`.
2. **Contributing routes**: received without DUT-added tags unless tagged at injection time.
3. **Suppressed contributing routes**: when injected with `65525:110` from T0, MUST NOT be received on T2.
4. **`UPSTREAM_PREFIX` loop check**: routes carrying community `8075:54000` must be denied (existing behavior, must remain intact).

### On T0 (Downstream) Neighbors — Verify Aggregate is Hidden

1. Aggregate route MUST NOT be received on T0 (`TO_TIER0_*` seq 400 deny).
2. All other routes the DUT advertises to T0 follow existing policy unchanged.
3. (T0-as-DUT scenario, Test Group 5) Contributing routes the T0-DUT advertises to its T1 upstream MUST carry `65525:110` when matching `SUPPRESS_ON_T1_IPV{4,6}_PREFIX`.

### On Sentinel / BGPMon (Upstream) Neighbors — Verify Aggregate Tagging

1. Aggregate routes received with `65525:21`.
2. The Sentinel/BGPMon inbound behavior (`FROM_BGP_SENTINEL` / `FROM_BGPMON_V6`) is **NOT** part of this feature; existing sentinel/bgpmon regression suites continue to own that coverage. This plan only checks that those route-maps are **not** accidentally altered (sanity check).

### On the DUT — Static Configuration Checks

1. `vtysh -c "show running-config"` contains the expected placeholder `ip prefix-list` entries.
2. `vtysh -c "show route-map <name>"` returns the expected sequence of `permit` / `deny` clauses with the documented `match` and `set` actions.
3. `vtysh -c "show bgp community-list <name>"` returns the expected community values.

---

## Test Cases

### Test Group 1: Static Template Regression

**Objective**: Confirm that the FRR template renders the expected placeholder prefix-lists, community-lists, and route-map structure on a freshly-booted DUT. These tests are fast (no traffic, no neighbor interaction) and serve as a fence against future template regressions (community-list value drift, route-map seq misordering, V6 `match ip` bug regression).

#### Test Case 1.1: Placeholder prefix-lists exist
- **Steps**:
  1. On DUT: `vtysh -c "show running-config"`
  2. Verify `ip prefix-list AGGREGATE_CONTRIBUTING_ROUTES_V4 seq 5 permit 127.0.0.1/32` is present
  3. Verify `ip prefix-list AGGREGATE_ROUTES_V4 seq 5 permit 127.0.0.1/32` is present
  4. Verify `ipv6 prefix-list AGGREGATE_CONTRIBUTING_ROUTES_V6 seq 5 permit ::1/128` is present
  5. Verify `ipv6 prefix-list AGGREGATE_ROUTES_V6 seq 5 permit ::1/128` is present

#### Test Case 1.2: Community-lists carry expected values
- **Steps**:
  1. On DUT: `vtysh -c "show bgp community-list COMM_AGG_T1"`
  2. Verify single entry `permit 65525:21`
  3. On DUT: `vtysh -c "show bgp community-list COMM_SUPPRESS_ON_T1"`
  4. Verify single entry `permit 65525:110`

#### Test Case 1.3: TO_TIER2_V4 sequence ordering and actions
- **Steps**:
  1. On DUT: `vtysh -c "show route-map TO_TIER2_V4"`
  2. Verify seq 100 is `deny` with `match community UPSTREAM_PREFIX`
  3. Verify seq 200 is `permit` with `match ip address prefix-list AGGREGATE_ROUTES_V4` and `set community 65525:21 additive`
  4. Verify seq 300 is `deny` with both `match ip address prefix-list AGGREGATE_CONTRIBUTING_ROUTES_V4` and `match community COMM_SUPPRESS_ON_T1`
  5. Verify seq 10000 is `permit` with no `match` (catch-all)

#### Test Case 1.4: TO_TIER2_V6 mirrors V4 with V6 prefix-lists
- **Note**: On Fairwater DUTs, `v6.leaf.spine/policy.conf.j2` conditionally renders an extra `TO_TIER2_V6 permit 110` clause for `LargeComputeAI_BE_Loopback_128` + `IPV6_128_ONLY`, setting `no-export` additive. Do not fail the test only because this Fairwater-specific clause appears between seq 100 and seq 200.
- **Steps**:
  1. Same as 1.3 but for `TO_TIER2_V6`
  2. Verify seq 200/300 use `match ipv6 address` (NOT `match ip`) — regression for the V6 template fix
  3. If the DUT is Fairwater, verify seq 110 is present with `match community LargeComputeAI_BE_Loopback_128`, `match ipv6 address prefix-list IPV6_128_ONLY`, and `set community no-export additive`; otherwise verify seq 110 is absent.

#### Test Case 1.5: TO_TIER0_V4/V6 deny aggregate at seq 400
- **Steps**:
  1. On DUT (T1): `vtysh -c "show route-map TO_TIER0_V4"` and `TO_TIER0_V6`
  2. Verify seq 400 is `deny` with `match ip[v6] address prefix-list AGGREGATE_ROUTES_V4/V6`
  3. Verify catch-all seq 10000 `permit` is preserved

#### Test Case 1.6: TO_TIER1_V4/V6 contributing tagging at seq 100
- **Applicability**: Only when DUT is `ToRRouter` / `BackEndToRRouter`. Skip otherwise.
- **Note**: This case validates only the outbound `TO_TIER1_V4/V6` route-maps added for contributing-prefix tagging. Do not assert the structure of the inbound `FROM_TIER1_V4/V6` route-maps, which are separate pre-existing policies and may contain unrelated clauses.
- **Steps**:
  1. On DUT (T0): `vtysh -c "show route-map TO_TIER1_V4"` and `TO_TIER1_V6`
  2. Verify seq 100 `permit` with `match ip[v6] address prefix-list SUPPRESS_ON_T1_IPV{4,6}_PREFIX` and `set community 65525:110 additive`
  3. Verify seq 1000 catch-all `permit` exists

#### Test Case 1.7: Sentinel / BGPMon route-maps present on LeafRouter
- **Applicability**: The aggregate-tagging shape of `TO_BGP_SENTINEL` / `TO_BGPMON_V6` applies only when DUT device type is `LeafRouter`. On non-`LeafRouter` DUTs, skip seq 100/200/1000 aggregate-tagging assertions and only expect the pre-existing simple catch-all `permit 100` for these outbound route-maps.
- **Steps**:
  1. `show route-map TO_BGP_SENTINEL` — verify seq 100 (V4 aggregate, set `65525:21`), seq 200 (V6 aggregate, set `65525:21`), seq 1000 catch-all
  2. `show route-map FROM_BGP_SENTINEL` — verify the **pre-feature** structure is preserved: when `constants.bgp.sentinel_community` is set, expect `permit 100 match community sentinel_community` followed by `deny 200`; no extra clauses introduced by this feature.
  3. `show route-map TO_BGPMON_V6` — same shape as `TO_BGP_SENTINEL`
  4. `show route-map FROM_BGPMON_V6` — verify the **pre-feature** structure is preserved: `permit 100 set ipv6 next-hop prefer-global / on-match next`, optional `permit 200 match community bgpmon_v6_community`, final `deny 300`; no extra clauses introduced by this feature.

---

### Test Group 2: T1→T2 Upstream — Aggregate Tagging with COMM_AGG_T1

**Objective**: Validate that `BGP_AGGREGATE_ADDRESS` configuration in CONFIG_DB drives `AggregateAddressMgr` to populate prefix-lists, which in turn cause `TO_TIER2_V4/V6` seq 200 to tag the aggregate route advertised to T2 with `65525:21`.

#### Test Case 2.1: Aggregate route tagged with 65525:21 toward T2 (IPv4)
- **Config**: `summary-only=false`, `aggregate-address-prefix-list=AGGREGATE_ROUTES_V4`, `contributing-address-prefix-list=AGGREGATE_CONTRIBUTING_ROUTES_V4`, `bbr-required=false`
- **Steps**:
  1. On DUT: write `BGP_AGGREGATE_ADDRESS|default|10.100.0.0/16` to CONFIG_DB with above fields
  2. Announce contributing routes `10.100.1.0/24`, `10.100.2.0/24` from T0 (or ExaBGP at T0 position)
  3. Wait for aggregate convergence
  4. On T2: verify aggregate route `10.100.0.0/16` is received
  5. On T2: verify community `65525:21` is attached to the aggregate
  6. On T2: verify `65525:110` is NOT present on the aggregate
  7. On T2: verify the aggregate community attribute equals exactly `{65525:21}` plus whatever the route already carried; nothing else added by DUT

#### Test Case 2.2: Aggregate route tagged with 65525:21 toward T2 (IPv6)
- **Config**: IPv6 aggregate `2001:db8:100::/48`, `aggregate-address-prefix-list=AGGREGATE_ROUTES_V6`, `contributing-address-prefix-list=AGGREGATE_CONTRIBUTING_ROUTES_V6`
- **Steps**:
  1. Add IPv6 aggregate via CONFIG_DB
  2. Announce contributing IPv6 routes from T0
  3. On T2: verify aggregate route has community `65525:21`
  4. On T2: verify routing is unaffected by an erroneous IPv4 match (regression for V6 `match ipv6 address` bug)

#### Test Case 2.3: Contributing routes traverse to T2 by catch-all (no DUT-added tag)
- **Steps**:
  1. Setup same as 2.1
  2. On T2: verify each contributing route `10.100.1.0/24` / `10.100.2.0/24` IS received
  3. On T2: verify the contributing route does NOT carry `65525:21` (DUT only tags aggregate)
  4. On T2: verify the contributing route does NOT carry `65525:110` (no suppression injected)
  5. Confirm seq 10000 catch-all is the path taken

#### Test Case 2.4: Aggregate prefix-list populated dynamically
- **Steps**:
  1. Before adding aggregate: `vtysh -c "show ip prefix-list AGGREGATE_ROUTES_V4"` returns only the placeholder `127.0.0.1/32`
  2. After adding aggregate (Test Case 2.1 config): same command returns placeholder PLUS `permit 10.100.0.0/16`
  3. After deleting the CONFIG_DB entry: returns only the placeholder again

#### Test Case 2.5: Multiple aggregates share the same prefix-list
- **Steps**:
  1. Add aggregate A `10.100.0.0/16` with `aggregate-address-prefix-list=AGGREGATE_ROUTES_V4`
  2. Add aggregate B `10.200.0.0/16` with the SAME prefix-list name
  3. On T2: verify both aggregates received with `65525:21`
  4. Remove aggregate A
  5. On T2: verify A withdrawn, B still tagged with `65525:21`
  6. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows placeholder + `10.200.0.0/16` only

---

### Test Group 3: T1→T2 Upstream — Contributing Suppression with COMM_SUPPRESS_ON_T1

**Objective**: Validate that `TO_TIER2_V4/V6` seq 300 deny correctly suppresses contributing routes that arrive carrying community `65525:110`, and that this suppression is conditional on both the prefix-list match AND the community match (AND semantics within a single seq).

#### Test Case 3.1: Contributing tagged 65525:110 is suppressed toward T2 (IPv4)
- **Config**: Aggregate `10.100.0.0/16` with both prefix-lists configured
- **Steps**:
  1. From T0/ExaBGP, announce `10.100.1.0/24` carrying community `65525:110`
  2. On DUT: verify `vtysh -c "show ip bgp 10.100.1.0/24"` displays `Community: 65525:110`
  3. On T2: verify `10.100.1.0/24` is NOT received
  4. On DUT: verify `show ip bgp neighbor <T2> advertised-routes` does NOT contain `10.100.1.0/24`

#### Test Case 3.2: Contributing tagged 65525:21 is NOT suppressed (seq 200 short-circuits)
- **Steps**:
  1. From T0/ExaBGP, announce `10.100.4.0/24` carrying community `65525:21`
  2. Note: `10.100.4.0/24` matches the placeholder-augmented `AGGREGATE_ROUTES_V4` only if it has been added; for this case, ensure it does NOT match either aggregate or contributing prefix-list
  3. On T2: verify `10.100.4.0/24` IS received via seq 10000 catch-all
  4. Re-run after adding `10.100.4.0/24` to `AGGREGATE_ROUTES_V4` (i.e. classify it as aggregate): seq 200 fires, `65525:21` is set additive

#### Test Case 3.3: Contributing without any community traverses normally (catch-all)
- **Steps**:
  1. Announce `10.100.2.0/24` from T0 with no communities
  2. On T2: verify `10.100.2.0/24` IS received with no DUT-added tags

#### Test Case 3.4: Suppression requires prefix-list AND community (AND semantics)
- **Steps**:
  1. Announce `10.100.1.0/24` from T0 with community `65525:110` — this prefix is in `AGGREGATE_CONTRIBUTING_ROUTES_V4`. **Expected**: T2 does NOT see it.
  2. Announce `10.100.99.0/24` from T0 with community `65525:110` — this prefix is NOT in `AGGREGATE_CONTRIBUTING_ROUTES_V4`. **Expected**: T2 DOES see it (seq 300 fails on the prefix-list match → falls through to seq 10000)
  3. Announce `10.100.1.0/24` from T0 without community `65525:110`. **Expected**: T2 DOES see it (seq 300 fails on the community match → falls through to seq 10000)

#### Test Case 3.5: IPv6 suppression
- **Steps**:
  1. Repeat 3.1 with IPv6 aggregate `2001:db8:100::/48`, contributing `2001:db8:100:1::/64`, community `65525:110`
  2. On T2: verify `2001:db8:100:1::/64` is NOT received

---

### Test Group 4: T1→T0 Downstream — Aggregate Leak Prevention

**Objective**: Validate that `TO_TIER0_V4/V6` seq 400 deny prevents the synthetic aggregate from being advertised downstream to T0. This is critical to avoid attracting traffic for prefixes that the T1 cannot actually reach beyond what its T0s already know.

#### Test Case 4.1: Aggregate not advertised to T0 (IPv4)
- **Config**: Aggregate `10.100.0.0/16` with prefix-lists
- **Steps**:
  1. Add aggregate, announce contributing routes from T0
  2. On T0: verify `10.100.0.0/16` is NOT received from DUT
  3. On T0: verify the contributing routes (which T0 itself originated) are unchanged
  4. On DUT: `show ip bgp neighbor <T0> advertised-routes` does NOT contain `10.100.0.0/16`

#### Test Case 4.2: Other DUT-originated routes are unaffected
- **Steps**:
  1. With aggregate in place, verify DUT continues to advertise default route / loopback / non-aggregate prefixes to T0 normally
  2. Verify no syslog errors regarding `TO_TIER0_V4` route-map evaluation

#### Test Case 4.3: IPv6 aggregate not advertised to T0 (V6 match regression)
- **Config**: IPv6 aggregate `2001:db8:100::/48`
- **Steps**:
  1. Add IPv6 aggregate, announce IPv6 contributing routes from T0
  2. On T0: verify `2001:db8:100::/48` is NOT received from DUT
  3. On DUT: `show running-config` confirms `TO_TIER0_V6` seq 400 uses `match ipv6 address` (NOT `match ip address` — bug regression check)

---

### Test Group 5: T0→T1 Upstream — Suppression Tagging at T0

**Objective**: Validate `TO_TIER1_V4/V6` seq 100 on a `ToRRouter` DUT: prefixes that match `SUPPRESS_ON_T1_IPV{4,6}_PREFIX` are tagged with `65525:110` (`COMM_SUPPRESS_ON_T1`) when advertised upstream to T1. This is the producer side of the suppression contract — T1 then consumes it via Test Group 3.

- **Applicability**: Only when DUT is `ToRRouter` / `BackEndToRRouter` (e.g., t0-only or dualtor topology). Skip on plain t1.

#### Test Case 5.1: Contributing matching SUPPRESS_ON_T1_IPV4_PREFIX is tagged 65525:110
- **Config (DUT = T0)**: `BGP_AGGREGATE_ADDRESS|default|10.100.1.0/24` with `contributing-address-prefix-list=SUPPRESS_ON_T1_IPV4_PREFIX`
- **Steps**:
  1. Add aggregate; verify `vtysh -c "show ip prefix-list SUPPRESS_ON_T1_IPV4_PREFIX"` contains `permit 10.100.1.0/24 le 32` in addition to the placeholder
  2. From the T0-DUT's downstream (e.g., a server-facing peer or local origination), make the prefix `10.100.1.0/24` an active route
  3. On T1 upstream of this T0: verify `10.100.1.0/24` is received with community `65525:110`
  4. On T1: verify `TO_TIER2_V4` seq 300 deny is hit (e.g., `vtysh -c "show ip bgp 10.100.1.0/24"` shows the route received but not advertised to T2)

#### Test Case 5.2: Prefix not in SUPPRESS_ON_T1_IPV{4,6}_PREFIX is NOT tagged
- **Steps**:
  1. Originate `10.100.99.0/24` from the T0 itself (not configured in any prefix-list)
  2. On T1: verify the route is received WITHOUT `65525:110` (catch-all `TO_TIER1_V4` seq 1000 path)
  3. On T2 (one hop further upstream of T1): verify the route IS received via T1's `TO_TIER2_V4` seq 10000 catch-all (no suppression triggered)

#### Test Case 5.3: IPv6 suppression tagging at T0
- **Steps**:
  1. Configure IPv6 aggregate with `contributing-address-prefix-list=SUPPRESS_ON_T1_IPV6_PREFIX`
  2. On T1: verify the IPv6 contributing route arrives carrying community `65525:110`
  3. On T2: verify the same IPv6 route is denied by T1's `TO_TIER2_V6` seq 300

---

### Test Group 6: BGP Sentinel and Monitor Route-Maps

**Objective**: Validate the new `TO_BGP_SENTINEL` and `TO_BGPMON_V6` outbound aggregate tagging on `LeafRouter`. The corresponding `FROM_BGP_SENTINEL` / `FROM_BGPMON_V6` route-maps are **not** changed by this feature; test cases here only sanity-check that those FROM_ route-maps remain at their pre-feature behavior. Requires Sentinel and IPv6 BGPMon peers (real or ExaBGP-simulated).

- **Applicability**: Test Cases 6.1 and 6.2 require a `LeafRouter` DUT because aggregate-tagging clauses in `TO_BGP_SENTINEL` / `TO_BGPMON_V6` are guarded by the `LeafRouter` device type. Skip those outbound aggregate-tagging cases on non-`LeafRouter` DUTs. Test Cases 6.3 and 6.4 may still sanity-check inbound `FROM_` behavior when the corresponding peers exist.

#### Test Case 6.1: Sentinel receives aggregate with 65525:21 (IPv4 + IPv6)
- **Config**: `BGP_SENTINELS` peer configured with one IPv4 and one IPv6 session
- **Steps**:
  1. Add IPv4 and IPv6 aggregates with prefix-lists
  2. On Sentinel: verify IPv4 aggregate `10.100.0.0/16` received with `65525:21`
  3. On Sentinel: verify IPv6 aggregate `2001:db8:100::/48` received with `65525:21`
  4. On Sentinel: verify catch-all clause permits other (non-aggregate) prefixes (loopback, etc.)

#### Test Case 6.2: BGPMon V6 receives aggregate with 65525:21 (dual-stack tagging)
- **Steps**:
  1. With aggregates in place, on IPv6 BGPMon peer: verify both V4 and V6 aggregates are received with `65525:21`

#### Test Case 6.3: FROM_BGP_SENTINEL is NOT modified by this feature
- **Steps**:
  1. Determine whether `constants.bgp.sentinel_community` is defined in this deployment (for example, by checking whether `sentinel_community` is rendered in the running FRR config).
  2. If `sentinel_community` is defined: from Sentinel/ExaBGP, announce a test prefix `10.250.0.0/24` toward DUT, **with** that community value (e.g., whatever `constants.bgp.sentinel_community` resolves to in the deployment). On DUT, `show ip bgp 10.250.0.0/24` MUST show the route in the main BGP table (i.e. it was permitted by `FROM_BGP_SENTINEL` `permit 100`).
  3. If `sentinel_community` is defined: repeat the announcement **without** that community; the route MUST be denied (`FROM_BGP_SENTINEL` `deny 200`).
  4. If `sentinel_community` is NOT defined: do not expect `permit 100`; `FROM_BGP_SENTINEL` should only contain the final `deny 200`, and any route from the Sentinel peer should be denied by that route-map.
  5. On DUT: `vtysh -c "show route-map FROM_BGP_SENTINEL"` confirms the expected **pre-feature** conditional structure for the deployment; fail the test if this feature introduces extra clauses.

#### Test Case 6.4: FROM_BGPMON_V6 is NOT modified by this feature
- **Steps**:
  1. Determine whether `constants.bgp.sentinel_community` is defined in this deployment (the `bgpmon_v6_community` list is rendered from the same constant).
  2. From IPv6 BGPMon ExaBGP peer, announce a test IPv6 prefix toward DUT. Verify `FROM_BGPMON_V6` always applies `set ipv6 next-hop prefer-global / on-match next` before continuing route-map evaluation.
  3. If `constants.bgp.sentinel_community` is defined: announce the test IPv6 prefix with community `bgpmon_v6_community`; verify the route enters the main BGP table via `permit 200`, and verify the next-hop is the global-preferred form.
  4. If `constants.bgp.sentinel_community` is defined: repeat without that community; verify the route is denied by final `deny 300` after seq 100 applies the next-hop action and continues.
  5. If `constants.bgp.sentinel_community` is NOT defined: do not expect `permit 200`; after seq 100 applies the next-hop action and continues, the route should hit final `deny 300`.
  6. Confirm `tests/test_ipv6_nexthop_global.py` (or its sonic-mgmt equivalent) **does NOT** treat `FROM_BGPMON_V6` as a deny-all whitelisted route-map.

---

### Test Group 7: Lifecycle Operations with Community Verification

**Objective**: Validate that aggregate lifecycle operations correctly preserve / restore the tier-based tagging, verified on T2 / T0 neighbors.

#### Test Case 7.1: Add aggregate — tagging starts
- **Steps**:
  1. Before adding aggregate: on T2, verify no `65525:21` on `10.100.0.0/16` (route does not exist)
  2. Add aggregate via CONFIG_DB
  3. On T2: verify aggregate appears with `65525:21`
  4. On T0: verify aggregate is NOT received

#### Test Case 7.2: Remove aggregate — tagging stops, prefix-list reverts
- **Steps**:
  1. Aggregate active with tag verified
  2. Delete `BGP_AGGREGATE_ADDRESS|default|10.100.0.0/16` from CONFIG_DB
  3. On T2: verify aggregate route withdrawn
  4. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows ONLY the `127.0.0.1/32` placeholder
  5. On T2: verify contributing routes still flow normally via catch-all

#### Test Case 7.3: BGP container restart preserves tagging
- **Steps**:
  1. Add aggregate, verify tagging on T2
  2. `systemctl restart bgp` on DUT
  3. Wait for BGP sessions to re-establish
  4. On T2: verify aggregate received with `65525:21`
  5. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` contains placeholder + dynamic entry

#### Test Case 7.4: Config reload preserves tagging
- **Steps**:
  1. Add aggregate, `config save -y`
  2. `config reload -y -f`
  3. After convergence, on T2: verify `65525:21` on aggregate
  4. On T0: verify aggregate still NOT received
  5. On DUT: route-map structure (Test Group 1) re-validated

#### Test Case 7.5: Warm-reboot preserves tagging within SLO
- **Steps**:
  1. Add aggregate, verify tagging
  2. Trigger warm-reboot
  3. Measure time from reboot completion to "T2 receives aggregate with `65525:21`"; SHOULD be within standard warm-reboot SLO
  4. Verify no traffic loss on dataplane probes during the window

#### Test Case 7.6: Rapid add/remove churn does not corrupt prefix-list state
- **Steps**:
  1. Add and remove `BGP_AGGREGATE_ADDRESS|default|10.100.0.0/16` 50 times in succession
  2. After settling, on DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows ONLY placeholder
  3. On DUT: no orphaned dynamic entries, no `bgpcfgd` error logs

---

### Test Group 8: Prefix-List Driven Tagging Mechanism

**Objective**: Validate that the contract between `AggregateAddressMgr` (CONFIG_DB-driven population) and the FRR template (placeholder name) is the sole mechanism activating tier tagging, mirroring Test Group 3 from the MA/OOB plan.

#### Test Case 8.1: Aggregate without prefix-lists — no tagging
- **Steps**:
  1. Add aggregate `10.100.0.0/16` with `aggregate-address-prefix-list=""` and `contributing-address-prefix-list=""` (empty)
  2. Announce contributing routes from T0
  3. On T2: verify aggregate route IS received (FRR `aggregate-address` still emits it)
  4. On T2: verify aggregate does NOT carry `65525:21` (seq 200 fails the prefix-list match)
  5. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` shows ONLY placeholder
  6. Confirms tagging is purely prefix-list driven and the empty-name path is safe (no orphan prefix-list)

#### Test Case 8.2: Mismatched prefix-list name — no tagging, no error
- **Steps**:
  1. Add aggregate with `aggregate-address-prefix-list=NON_EXISTENT_LIST` (a name not referenced by any route-map)
  2. On DUT: `show ip prefix-list NON_EXISTENT_LIST` returns the aggregate prefix (Mgr happily creates it)
  3. On T2: verify NO `65525:21` tagging (the new prefix-list is not referenced by `TO_TIER2_V4`)
  4. On DUT: bgpcfgd logs only informational messages, no errors
  5. This case documents that name-mismatch is silent — TG 1 (template regression) is what guards against drift

#### Test Case 8.3: Prefix-list name change at runtime
- **Steps**:
  1. Add aggregate with `aggregate-address-prefix-list=AGGREGATE_ROUTES_V4`, verify tagging on T2
  2. Update the same CONFIG_DB entry to `aggregate-address-prefix-list=ALT_NAME`
  3. On DUT: `show ip prefix-list AGGREGATE_ROUTES_V4` reverts to placeholder only
  4. On DUT: `show ip prefix-list ALT_NAME` contains the aggregate prefix
  5. On T2: verify aggregate is now received WITHOUT `65525:21` (matches the rationale of TC 8.2)

#### Test Case 8.4: BBR-required aggregate populates prefix-list only when BBR is enabled
- **Steps**:
  1. Disable BBR on DUT
  2. Add `BGP_AGGREGATE_ADDRESS|default|10.100.0.0/16` with `bbr-required=true` and prefix-lists
  3. On DUT: verify `show ip prefix-list AGGREGATE_ROUTES_V4` shows ONLY placeholder (`AggregateAddressMgr` defers via `set_address_state(..., ADDRESS_INACTIVE_STATE)`)
  4. On T2: verify no `65525:21` tagging
  5. Enable BBR
  6. On DUT: prefix-list now contains placeholder + `10.100.0.0/16`
  7. On T2: aggregate received with `65525:21`
  8. Disable BBR again — prefix-list returns to placeholder-only, T2 stops receiving aggregate

---

## Out of Scope

- Performance / scale testing (covered by `test_bgp_aggregate_address_scale_stress.py`)
- MA / OOB community tagging (covered by [BGP-Aggregate-Address.md](BGP-Aggregate-Address.md))
- Public-image (non-MSFT) FRR template behavior — the route-maps and community values in this plan target the `msft.general` / `msft.monitors` template family

## Cross-Reference

- FRR template source: `dockers/docker-fpm-frr/frr/bgpd/templates/msft.general/{v4,v6}.{leaf.spine,leaf.tor.all,tor}/policy.conf.j2`, `sentinels/policies.conf.j2`, `msft.monitors/policies.conf.j2`
- Runtime population: `src/sonic-bgpcfgd/bgpcfgd/managers_aggregate_address.py` (`AggregateAddressMgr`)
- Template-rendering unit tests: `src/sonic-bgpcfgd/tests/test_templates.py` + `tests/data/{msft.general,sentinels,msft.monitors}/policies.conf/`
- IPv6 next-hop policy regression: `src/sonic-bgpcfgd/tests/test_ipv6_nexthop_global.py` (the `DENY_ALL_ROUTE_MAPS` whitelist does not carve out `FROM_BGPMON_V6`)
- Sister test plan (MA / OOB upstream): [BGP-Aggregate-Address.md](BGP-Aggregate-Address.md)
