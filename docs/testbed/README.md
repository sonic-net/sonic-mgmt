# SONiC Testbed

- [Overview](README.testbed.Overview.md)
- Setup
  - [Physical Switch Testbed Setup](README.testbed.Setup.md)
  - [Virtual Switch Testbed Setup](README.testbed.VsSetup.md)
  - [Virtual Switch Multiple Devices Testbed Setup](README.testbed.WANSetup.md)
  - [Setup sonic-mgmt Docker](README.testbed.Docker.md)
  - [Server OS Upgrade](README.testbed.ServerOSUpgrade.md)
  - [cEOS](README.testbed.cEOS.md)
  - [Routing](README.testbed.Routing.md)
  - [Keysight](README.testbed.Keysight.md)
- [Configuration](README.new.testbed.Configuration.md)
- [Generic HwSKU and Topology](#generic-hwsku-and-topology)
- [Minigraph](README.testbed.Minigraph.md)
- [Command Line](README.testbed.Cli.md)
- [Example](README.testbed.Example.md)
  - [Manual check testbed info](/docs/testbed/README.testbed.Example.Config.md)
- [FAQ](README.testbed.FAQ.md)
- [Internal](README.testbed.Internal.md)
- [Kubernetes Setup](README.testbed.k8s.Setup.md)
- [SAI Test Setup](./sai_quality/README.md)
- [TACACS](README.testbed.TACACS.md)

## Generic HwSKU and Topology

**Status:** Draft prototype. Architecture, operating procedures, historical
validation evidence, and limitations are consolidated here. Generic deployment
and the legacy minigraph PORT-override path are separate workflows.

**Execution defaults:** Generic `add-topo`, `deploy-mg`, `remove-topo`, and
`recover-generic` execute changes by default. Use `--print-data` for a
credential-safe preview without provisioning, reload, or save; `--apply` is
removed. Fresh previews may still contact devices for preparation/rendering.
Reserve the lab before running commands without `--print-data`.
Only successful paired reload/save triggers disposable-artifact cleanup.

- [Overview and motivation](#overview-and-motivation)
- [Architecture](#architecture)
- [Operator and developer guide](#operator-and-developer-guide)
- [Validation strategy and current evidence](#validation-strategy-and-current-evidence)
- [Alternatives considered](#alternatives-considered)
- [Limitations and future work](#limitations-and-future-work)
- [Implementation map](#implementation-map)
- [References](#references)

### Overview and motivation

Static breakout-specific HwSKUs couple a physical port layout to a named
`port_config.ini` or default breakout definition. Qualifying another supported
mixture can consequently require another SKU variant and matching lab topology,
even when the platform already advertises the required capabilities.

The objective is to make a testbed scenario a generated, reviewable product of
platform capabilities, actual wiring, and explicit test intent:

```text
Base device assets + maximum-breakout wiring + topology recipe
                              |
                              v
                Compatible DUT and leaf layouts
                              |
                              v
          Realized ports + forwarding + installed QoS policy
                              |
                              v
          Isolated PTF connectivity + verified deployment
```

The workflow avoids creating a new static port definition for every test
mixture. It does not eliminate the need for correct vendor/platform assets,
lookup coverage, SDK initialization, or compatible installed templates.

Two concerns are deliberately separated:

- **Reusable foundation:** capability parsing, physical-channel matching,
  joint layout selection, per-link roles, artifact integrity, and ownership.
- **Current forwarding scenario:** individual routed uplinks with static routes,
  and downlinks in a shared access VLAN/SVI, transported to a PTF container.

The foundation is not intrinsically T0-specific. The implemented forwarding
recipe is T0-style; arbitrary T1/T2, LAG, and BGP scenarios are not implemented.
This is a controlled testbed-generation workflow, not a replacement for every
existing sonic-mgmt topology.

The [operator and developer guide](#operator-and-developer-guide) below
contains detailed procedures and a separate legacy PORT-override workflow.

### Relationship to existing designs

The document follows the requirements, components, data-contract, workflow, and
validation structure used by existing sonic-mgmt HLDs. The following designs
provide context, not a claim that their entire implementations are used here.

| Reference | Relevant idea | Boundary of this design |
| --- | --- | --- |
| [Testbed V2 HLD](README.testbed.Testbed_v2.hld.md) | Separate physical connection metadata from logical VLAN connectivity and testbed lifecycle. | This prototype consumes connection-graph files and explicit transport allocations. It does not implement Testbed V2's connection database, daemons, or dynamic allocation service. |
| [OCS integration HLD](README.testbed.OCS.HLD.md) | Separate architecture from setup instructions; validate configuration, operational state, and traffic independently. | No OCS control or optical-circuit orchestration is introduced. |
| [Dynamic Port Breakout HLD][dpb-hld] | Use platform-advertised modes, ordered lanes, and canonical child-port naming; consider dependent configuration. | This prototype renders complete configurations and reloads two devices. It does not promise DPB's nondisruptive runtime breakout behavior, and intentionally emits no `BREAKOUT_CFG`. |
| [Run Time Buffers Configuration Update design][buffer-design] | Select headroom from speed/cable lookup inputs and let the buffer manager own runtime profile generation. | Disabled PFC is not overridden. Rendering uses installed lookups; the active daemon/lookup contract is no longer probed. |
| [Configuration Database Manual][config-db-manual] | Distinguish traditional and dynamic buffer models and their configuration objects. | Only the inspected single-ASIC traditional backend is supported. A buffer pool's `mode: dynamic` is not the same as `buffer_model: dynamic`. |

Upstream documents describe general contracts. The installed device assets and
the inspected prototype determine compatibility for a particular deployment.
In particular, a shared template pathname is not evidence that an installed
template is identical to current upstream `master`.

### Requirements

| ID | Requirement | Enforcement or evidence |
| --- | --- | --- |
| R1 | Derive ports from advertised platform capabilities rather than maintaining a static file for every layout. | Platform parsing plus independent installed canonical-parser validation. |
| R2 | Select compatible DUT and SONiC-leaf layouts jointly over actual wiring. | Exact channel-set/speed matching on both endpoints. |
| R3 | Preserve resources outside the managed scope. | Whole-cage protection, dependent-configuration checks, baseline/asset drift checks. |
| R4 | Maximize mode/operating and lookup-case coverage within valid physical wiring. | CSV VLANs constrain traffic provisioning, not physical child selection; report both coverage scopes. |
| R5 | With an empty source uplink list, select the first eight realized physical DUT ports numerically. | Generated YAML records roles; no matching-mode/speed requirement by default. |
| R6 | Assign physical direction per realized child port, independently of logical forwarding. | Explicit selectors, default downlinks, truthful reciprocal neighbors. |
| R7 | Reuse installed QoS/buffer values and ownership rather than inventing hardware policy. | Reviewed template adapter, installed lookup rows, and per-port PFC decisions. Runtime buffer qualification remains external. |
| R8 | Prepare mappings in add-topo; render and deploy the same frozen layout in deploy-mg. | Immutable plan/prepared/rendered stages, stable ownership ID, and no silent replanning. |
| R9 | Make physical-port, DUT-index, transport-VLAN, and PTF-index mappings explicit. | Resolved facts, generated topology, and rendered transport report. |
| R10 | Make mutation versus preview explicit and reserve shared infrastructure before execution. | Commands execute by default; `--print-data` previews without applying. Collect/render/host/device phases remain separate. |
| R11 | Check both device reloads before persistence and retain recovery information. | Pairwise stage/apply/save orchestration and private backups. |
| R12 | Preserve traditional lifecycle behavior without topology-name heuristics. | Content-based add/remove routing; explicit generic deploy selector. |
| R13 | Keep complete configurations and inherited credentials private. | Private workspaces, restricted files, suppressed configuration-bearing output. |

Coverage, database convergence, link state, and packet correctness are separate
requirements. None is a substitute for the others.

### Scope

#### In scope

- One DUT and one connected SONiC transport leaf, each single-ASIC.
- Maximum-breakout wiring inventories and explicit protected cages.
- Advertised uniform modes and advertised ordered composite modes.
- Alternate operating speeds, per-child physical roles, and deterministic
  assignment of supported lookup cases.
- One forwarding address family per scenario, IPv4 or IPv6.
- Complete DUT/leaf CONFIG_DB inputs, installed QoS/buffer rendering, and
  controlled replacement of understood managed-port dependencies.
- Explicitly allocated leaf/root/host transport and scenario-owned PTF endpoints.
- Operator-driven deployment, verification, save, and configuration recovery.

#### Out of scope

- New platform, SDK, SAI, transceiver, or vendor headroom algorithms.
- Arbitrary unadvertised mixtures within a cage.
- Multi-ASIC/multi-DUT deployments, dynamic buffer calculation, and unknown
  QoS-template families.
- Generated PortChannels, LACP, BGP neighbors, or neighbor VMs.
- Hitless reconfiguration or an atomic transaction across devices and host.
- Automatic discovery/reservation of free IPs, VLANs, or shared lab resources.
- Automatic QoS reloads or repair of platform initialization problems.
- Automatic adaptation of the entire pytest/nightly and config-restore pipeline.
- Lossless/PFC, congestion, or line-rate qualification solely from deployment.

### Definitions and design invariants

| Object | Meaning |
| --- | --- |
| Cage | A physical resource with an ordered lane list and advertised breakout modes. |
| Maximum-breakout channel | An indivisible wiring connection represented by one source connection-graph row. It is not necessarily an entire physical cable. |
| Realized child port | An Ethernet endpoint created by selecting a mode and operating combination for a cage. |
| Operating combination | The mode plus selected speed, or ordered group-speed tuple for a composite mode. |
| Physical role | Uplink/downlink direction of a realized DUT connection relative to the scenario. |
| Forwarding role | Routed interface, access member, VLAN/SVI, or another logical use; not synonymous with physical direction. |
| Transport VLAN | An isolated channel carrying one selected DUT link through the leaf/root toward PTF. It is distinct from the DUT access VLAN. |
| DUT port index / PTF index | Different mapping identifiers. Neither is generally the numeric suffix of an Ethernet name. |

The following invariants are mandatory:

- A selected cage uses one advertised mode and all its realized children
  participate. Protected and unused cages retain their existing layouts.
- A child consumes complete wiring channels and matches exactly one complete
  peer child at the same speed. Peer mode names need not be identical.
- Protected cages are not reassigned to make a plan appear complete.
- Selecting `Ethernet0` assigns that realized child, not every sibling of a cage
  that happens to share its name.
- The realized `PORT` table is authoritative. Selected mode metadata lives in
  the manifest; the entire output `BREAKOUT_CFG` table is omitted.
- A rendered scenario is not a hardware qualification result.

### Architecture

```text
Controller: sonic-mgmt
  testbed.yaml + inventory         named topology recipe
             |                              |
             +--------------+---------------+
                            |
  snapshots or read-only collection + maximum-breakout wiring
                            |
                            v
                Inventory / protection analysis
                            |
                            v
                 Joint DUT/leaf layout solver
                            |
                 plan/ (sealed layout, roles, settings)
                            |
             read-only canonical PORT/transport preparation
                            |
                            v
                 prepared/ (fixed PTF mapping and ownership ID)
                            |
          +-----------------+-------------------+
          |                                     |
          v                                     v
  add-topo                           deploy-mg --generic
  scenario-owned PTF                 render full configs + YANG
  host VLAN endpoints                -> rendered/ (same ownership ID)
  existing transport untouched        verify host -> stage both
                                     -> apply both -> save both
                                                |
                                      failure: paired recovery
```

The leaf's selected ports are transport access endpoints. Its existing
root-facing trunk carries the separate channel VLANs:

```text
PTF ethA <-> host/root/leaf, channel VLAN A <-> DUT downlink
                                                    |
                                             DUT VLAN/SVI + L3
                                                    |
PTF ethB <-> host/root/leaf, channel VLAN B <-> DUT routed uplink
```

Both DUT roles may physically connect to the same leaf. PTF emulates hosts and
routed next hops; the transport leaf is not automatically their BGP peer.

### Operator and developer guide

#### Problem

Each HwSKU variant (e.g., `Arista-7060X6-64PE-O128S2`, `-C256S2`, `-C224O8`) traditionally
requires its own `port_config.ini` file in `sonic-buildimage`. Changing the breakout layout
means creating a new HwSKU name, a new directory, a new `port_config.ini`, and a new
`sonic-buildimage` PR. This doesn't scale.

#### Solution

Generate the PORT table dynamically at deploy time using the existing Ansible playbook
(`config_sonic_basedon_testbed.yml`) and the `generate_golden_config_db` module — no
`port_config.ini`, `hwsku.json`, or manual file copies needed.

The playbook uses two data sources already available in every testbed:

- **`links.csv`** — the lab topology file on the sonic-mgmt server. Provides port names
  and speeds (the "what").
- **`platform.json`** — the hardware description already present on the DUT at
  `/usr/share/sonic/device/<platform>/platform.json`. Provides physical lanes, aliases,
  indices, and valid breakout modes (the "how").

#### Architecture

```
 sonic-mgmt server                              DUT
 ┌──────────────────────────────────┐           ┌──────────────────────┐
 │  ansible/files/                  │           │  /usr/share/sonic/   │
 │    sonic_<lab>_links.csv         │           │  device/<platform>/  │
 │    sonic_<lab>_devices.csv       │           │    platform.json     │
 └───────────┬──────────────────────┘           └──────────┬───────────┘
             │                                             │
             ▼                                             │
 ┌───────────────────────────────────┐                     │
 │ config_sonic_basedon_testbed.yml  │                     │
 │                                   │                     │
 │  1. Extract port_speeds + hwsku   │                     │
 │     from links.csv & devices.csv  │                     │
 │     (delegated to localhost)      │                     │
 │                                   │                     │
 │  2. Call generate_golden_config_db│                     │
 │     on DUT with port_speeds       │─────────────────────┤
 └───────────┬───────────────────────┘                     │
             │                                             │
             ▼                                             ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  generate_golden_config_db (Ansible module, runs on DUT)        │
 │                                                                 │
 │  generate_port_table_from_platform(port_speeds, platform.json): │
 │    for each cage in platform.json:                              │
 │      • find ports from port_speeds in cage's address range      │
 │      • match port count + speed against breakout_modes          │
 │      • split lanes evenly among ports                           │
 │      • assign aliases from matched breakout mode                │
 │      • add FEC=rs for speeds ≥ 200G                             │
 │                                                                 │
 │  Output: golden_config_db.json with PORT table                  │
 └──────────────────────────────────┬──────────────────────────────┘
                                    │
                                    ▼
                 config load_minigraph --override_config -y
                   ├── minigraph → all tables (BGP, VLAN, etc.)
                   └── golden_config_db.json → PORT table override
```

#### How It Works

##### Step 1: Playbook extracts port speeds from links.csv

When `port_override_from_links=true` is passed to the playbook, a task
delegated to `localhost` reads `links.csv` and `devices.csv` to extract:

- **port_speeds** — `{port_name: speed}` for the target DUT hostname
- **hwsku** — the HwSKU string from `devices.csv`

These are passed to the `generate_golden_config_db` Ansible module as parameters.

##### Step 2: Module rebuilds PORT table from platform.json on the DUT

The `generate_golden_config_db` module (in `ansible/library/`) runs on the DUT.
For FT2/LT2 topologies, it calls `generate_port_table_from_platform()` which:

1. Opens `/usr/share/sonic/device/<platform>/platform.json` (already on the DUT)
2. For each physical cage defined in `platform.json`:
   - Collects which ports from `port_speeds` fall into this cage's lane range
   - Matches the port count + speed against the cage's `breakout_modes`
   - Splits the cage's SerDes lanes evenly among the matched ports
   - Assigns aliases from the matched breakout mode entry
   - Adds `fec: rs` for port speeds ≥ 200G
3. Writes the result as `golden_config_db.json`

If `port_speeds` is provided from `links.csv`, those speeds are used (they
reflect the desired breakout layout). Otherwise, the module falls back to the
minigraph PORT table speeds.

##### Step 3: Minigraph + golden config applied together

The playbook runs `config load_minigraph --override_config -y`, which:

- Loads all config_db tables from minigraph (BGP, VLAN, LOOPBACK, etc.)
- Overrides the PORT table with the one from `golden_config_db.json`

The result is a PORT table with correct lanes, aliases, indices, speeds, and
FEC — derived entirely from `links.csv` + `platform.json`, with no
`port_config.ini` involved.


##### Fallback Behavior

If `platform.json` is missing or has no `interfaces` section, the module falls
back to using the minigraph PORT table directly, adding `fec: rs` for ports
with speeds ≥ 200G. This preserves backward compatibility with DUTs that lack
`platform.json`.

#### Usage

##### Read-only maximum-breakout link inventory

`ansible/scripts/map_breakout_links.py` produces a JSON inventory without editing
the wiring CSV or configuring devices. Supply local snapshots of the DUT and peer
`platform.json` and the DUT platform's `pg_profile_lookup.ini`. No `port_config.ini`
is read or required. The platform file may live in the platform directory rather
than the HwSKU directory; supply its actual path.

For each parent, the tool finds the advertised mode(s) with the most children.
Following the existing SONiC PORT-generation convention, it splits the platform's
ordered lane list evenly and names child interfaces `Ethernet<parent + lane offset>`.
Aliases and supported speeds come from those maximum-breakout modes; the CSV
bandwidth must be supported at both endpoints. Hardware lane IDs need not be
contiguous or equal Ethernet numbers. Uneven lane splits, inconsistent alias
counts, conflicting maximum-mode aliases, and overlapping resources are rejected.
This adapter supports the `Ethernet<number>` parent naming convention; other
naming or channel-order conventions require an explicit adapter, not a fallback
to a port table.

For `example-generic`, after obtaining the snapshots:

```bash
python3 ansible/scripts/map_breakout_links.py \
    --hostname example-dut \
    --peer-hostname example-leaf \
    --links-csv ansible/files/sonic_example_links.csv \
    --platform-json /path/to/dut/platform.json \
    --pg-profile-lookup /path/to/dut/pg_profile_lookup.ini \
    --peer-platform-json /path/to/peer/platform.json
```

Output includes explicit DUT/peer cage and lane mappings, original CSV attributes,
raw supported modes, and unchanged lookup rows matched to supported DUT mode
speeds. Missing lookup speeds are reported, not synthesized. Only links to the
selected peer can be eligible. Whole cages containing other connections or ports
absent from the CSV are protected on both devices. Use repeated `--exclude-port`
arguments for additional reserved DUT ports; speeds alone do not identify reserved
or management ports.

Missing, null, or blank optional source-link `AutoNeg`, `LinkTraining`, and `FEC`
attributes mean unset; rendering does not invent a setting for them. Explicit
string values are trimmed, normalized, and checked for conflicts and supported
values. The FEC string `none` is an explicit setting, unlike JSON null.
Non-string, non-null attributes are rejected. Missing/null/blank `VlanID`
attributes likewise contribute no transport VLAN; IDs are never fabricated.

This is an inventory, **not a breakout plan or a claim of operational compatibility**.
It does not assign cable lengths, choose modes, aggregate links, generate topology,
check FEC/shared hardware resources, or apply configuration. Lookup cable lengths
are supported test inputs, not measurements of the physical cables. Advertised uniform
and mixed modes, including alternate speeds, are supported. Mixed groups require
explicit lane counts and must consume the cage's lanes exactly. These files are
required inputs, not optional fallbacks.

##### Offline joint DUT/leaf planning and generic forwarding

`ansible/scripts/plan_generic_topology.py` consumes the same read-only snapshots
(local files or collected through inventory), plus a generic-forwarding recipe.
It jointly selects a subset of eligible DUT/SONiC-leaf cages and one advertised
mode and operating-speed combination per selected cage. All children
of each selected mode participate. Whole-cage protection from the inventory is
preserved.

After maximizing attainable coverage and satisfying forwarding and any configured
uplink repetition, the solver minimizes the number of selected DUT cages.
It does not fill spare cages with repeated modes. Explicit role selectors retain
their eligible cages; unavailable child names remain ignored. Coupled leaf cages
must be selected together with their DUT connections, never left half-selected.
Unused cages are recorded in `manifest.json.unused_cages` and retain their existing
configuration; full-device reloads may still flap them. Required coverage is not
reduced merely because a cage is unused. Search exhaustion leaves a best-known
subset with `optimality_proven: false`, not a claim of a proven minimum.
This remains a single-layout plan: unavoidable gaps such as insufficient
simultaneous 10G/25G children remain explicitly incomplete, not scheduled as rounds.
Existing frozen scenarios keep their original selection; use a fresh workspace
to adopt the minimum-cage policy.

Newly rendered configurations set each selected DUT and leaf child's `speed`
and single-entry `adv_speeds` list to its planned operating speed, including
physical-only children. This replaces inherited advertised speeds such as `all`;
explicit CSV autonegotiation, FEC, and link-training settings still apply.
With autonegotiation enabled, only the selected speed is advertised rather than
all supported speeds. Protected ports remain unchanged. Cached rendered
configurations are reused unchanged; this policy does not update live devices
or prove their operational speed.

When moving from a larger deployed layout to a smaller selection, an existing
access VLAN/SVI can still serve ports on unused cages. Those consumers remain
preserved, so the renderer rejects reuse of their VLAN or subnet. Use approved
non-overlapping allocations or explicitly migrate the old members before
rendering; minimum-cage planning does not silently detach unused ports.

Low-speed cages participate on the same basis as higher-speed cages; there is
no minimum cage-bandwidth cutoff. This includes the lab's `Ethernet512` and
`Ethernet520`, each advertising `1x25G[10G]`, when their wiring is eligible.
No opt-in flag is needed. Explicit `--exclude-port`,
out-of-scope neighbors and incomplete wiring still apply,
with whole-cage protection propagated across connected devices.
Create a fresh workspace for this policy; older sealed scenarios retain their
original protected cages rather than expanding during rendering or deployment.

The supported offline model treats each maximum-breakout CSV connection as an
indivisible physical channel. A new child must be an exact union of those channels,
and must reach exactly one complete child on the opposite device at the same speed.
Channel order can be reversed between devices. Aggregations spanning opposite
parent cages, partial channels, and conflicting explicit CSV FEC/AN/link-training
settings are rejected. This proves compatibility in the supplied channel model,
**not electrical or operational compatibility**.

New CLI plans allow realized children without a CSV VLAN for physical/link
coverage. All selected children receive PORT, neighbor, and installed QoS/buffer
configuration; deployment does not check their link state. Only children with
named CSV-backed endpoints on both devices get traffic provisioning, using the
DUT endpoint's existing VLAN.
Other children have `transport_vlan_id: null`, `ptf_index: null` and
`interface_mode: physical_only`: no routed/access forwarding or PTF channel.
They remain in mode/speed/buffer coverage and are explicitly traffic-unqualified
in `coverage.json.traffic_coverage`. A fully wired cage with no VLANs is not
automatically protected; the original hard wiring/ownership exclusions remain.
No VLANs are invented and no shared trunks are expanded. Frozen older scenarios
retain their original scope; prepare a fresh workspace for this policy.

Coverage targets **one physical cage for every eligible advertised DUT mode
and lookup-backed operating combination**, regardless of current uplink/downlink
labels. For example, `1x200G[100G]` creates separate 200G and 100G targets.
Mixed modes retain their ordered groups: `4x100G(4)+1x400G(4)` creates four
single-lane 100G children followed by one four-lane 400G child.
Alternate speeds in mixed groups form distinct ordered combinations; every
component speed must have lookup rows. Missing lookup values are never invented. Lookup
speed/cable cases use distinct active children where capacity permits; additional
children reuse cases deterministically. Physical compatibility and protected
resources are hard requirements. Coverage is best-effort: mode/buffer shortfalls
remain `status: incomplete`, with uncovered cases explicitly reported, but do not
block rendering or deployment. Valid forwarding, physical consistency,
installed rendering/YANG, and ownership checks remain mandatory.

Buffer rows whose speed is advertised only by protected DUT cages are recorded
under `coverage.json.excluded_buffer_cases`, with their original values, supporting
cages, and an out-of-scope reason. They are neither required nor counted as covered.
If any eligible DUT cage advertises the speed, its cable cases remain required.
Lookup speeds not advertised anywhere also remain visible as requirements rather
than being silently dropped. Consequently `complete` describes the managed scope,
not qualification of protected ports. Frozen older plans are not reinterpreted:
replan to adopt this scope. Remaining in-scope cases still use the existing
best-effort search; coverage shortfalls and search exhaustion are reported, not
misrepresented as qualification or proven optimality.

Forwarding roles apply to individual realized interfaces/physical links, never
whole cages. `physical_links.uplinks` selects uplink **DUT child ports**.
Every other selected child defaults to downlink.
`physical_links.downlinks` may optionally list explicit downlink selectors; it may be
empty, `null`, or omitted. `uplinks: []` automatically selects the first eight
selected physical DUT ports in numeric Ethernet order. Planning
writes explicit uplink/downlink lists into generated `topology.yml`;
the editable source recipe remains empty. All other selected ports are downlinks.
The current T0 scenario still requires at least one downlink, so eight or fewer
selected ports cannot produce a deployable automatic-role plan.
An explicit nonempty uplink list remains supported. Use canonical
`Ethernet<number>` names, not aliases, physical cage selectors, CSV row numbers,
PTF indices, or PortChannel names. A parent and its first child may share the same
name: listing `Ethernet0` assigns only that resolved child, not every child of cage
`Ethernet0`. Explicit roles can span cages or differ between siblings within one
cage; automatic roles use realized-port order, not cage IDs or PTF indices.

There is **no matching-mode/speed uplink requirement by default**. The first eight
uplinks can use different advertised combinations. New default plans freeze
`uplink_repetition_scope: none` and `min_same_breakout_uplinks: 0`.
The optional legacy `--min-same-breakout-uplinks N` remains available only with
explicit nonempty uplink selectors; it requests N physical uplinks sharing one
full mode/operating combination. Omit it for automatic first-eight selection.
The requested repetition count remains a planning objective, not a second
render/deployment gate; replan to
adopt the new policy.

The solver checks joint DUT/leaf wiring, protected resources, advertised per-cage
modes, and mode/lookup coverage; role lists no longer require an exact child set
in each cage. Uniform and mixed modes are allowed only when advertised by
`platform.json`. Mixed group order, explicit lane widths, aliases, and each child's
speed are preserved; an unadvertised or underspecified mixture is never synthesized.
Different cages may use different advertised combinations.

Names that do not match the final selected children are ignored, including
children absent under the chosen breakout and names outside the managed scope.
They never cause protected ports to be reconfigured. The planner prints skipped
names and records them under `resolved_facts.json.role_resolution.ignored_ports`;
defaulted access links are recorded under `defaulted_downlinks`. Malformed or
duplicate selectors are still errors, as are conflicting explicit roles on an
existing selected child. An unmatched name appearing in both lists is ignored.
The current T0 forwarding scenario routes traffic-backed uplinks individually and puts traffic-backed downlinks
in one access VLAN/SVI. This is an explicit scenario policy, not the definition of
physical direction; arbitrary routed-downlink forwarding is not implemented.
It needs at least one traffic-backed uplink and downlink and sufficient approved pools.
Otherwise the physical plan remains review-only, with an allocation error.
Physical-only children retain their physical uplink/downlink role but receive no
forwarding address or membership. Eight physical uplinks need not mean eight PTF paths.

For new VLAN-scoped plans, the bounded solver prefers forwardable layouts,
then physical-cage combination diversity and covered cable cases. An explicitly
requested legacy N-uplink target is prioritized before coverage. Optimistic
per-cage bounds prune candidates without treating mutually exclusive choices as
simultaneously available. `coverage.json.uplink_repetition` includes every target,
including zero-count groups. Only the selected row is `required: true`; other rows
have no repetition shortfall and are not deployment blockers.
This changes only repetition: all required physical combinations and supplied
buffer speed/cable cases still need coverage for a complete plan.
`coverage.json.breakout_diversity` separately reports physical cage counts, including
combinations represented only by downlinks. New manifests use schema version 3.
Uniform `speed` fields remain integers; mixed layout and coverage `speed` fields
are ordered arrays, one value per mode component (for example `[100000, 400000]`).
Each child endpoint still has its own integer `speed`.
Search exhaustion after
finding a layout preserves that best-known result and discloses unproven optimality;
exhaustion before finding any layout is not proof of physical infeasibility.

Eligible cages may remain unused under the minimum-cage objective. To ensure
a reserved cage is never selected, explicitly protect it with `--exclude-port`
before planning; protection propagates to connected cages under the wiring model.
The manifest records resolved per-link roles, not unmatched selectors.

These are individual routed interfaces, **not logical neighbors or PortChannel
members**. No PortChannels, LACP groups, BGP peers, or neighbor VMs are generated.
Explicit PortChannel membership is not supported by this recipe.
Allocate one peer-address pair per routed child, a default
route through the numerically first traffic-backed routed child, and unique access
endpoints. Allocation is stable regardless of YAML list order. Either IPv4 or IPv6
is supported per scenario, not both simultaneously. These are dataplane pools:
they do not come from the testbed's `ptf_ip`/`ptf_ipv6` management settings or its
backplane addresses.

The shared recipe is `ansible/vars/topo_generic.yml`, selected by `topo: generic`
on any supported testbed. Do not create a hardware-specific topology recipe just
to change allocations. Its defaults use IPv6 documentation pools and VLAN 3000
for isolated testing; they are not reservations or a guarantee of conflict-free
deployment. Reuse them only where approved and valid. For testbed-specific
allocations, pass an optional `--overrides /private/path/allocations.yml` rather
than editing the shared source for each testbed. The override contains only the
`generic_topology` fields that differ. Explicit downlinks default to an empty list.
The planner rejects unset allocations and mixed address families.
Without explicit prefix lengths, routed links use /31 (IPv4) or /127 (IPv6), and
optional external destinations use /32 or /128. `external_destinations` is
omitted by default: only the default static route is generated. Supplying that
section adds one destination route per traffic-backed uplink; it must include a
valid `address_pool` and pass the same family, overlap, reservation, and capacity
checks. No external pool or destination addresses are synthesized when it is absent.

The shared defaults use automatic first-eight uplinks, not hardware-specific
child names:

```yaml
topology: {}
generic_topology:
  physical_links:
    uplinks: []
    downlinks: []
  routed_interfaces:
    address_pool: 2001:db8:1::/64
    prefix_length: 127
  access_vlan:
    vlan_id: 3000
    subnet: 2001:db8:2::/64
  transport:
    vlan_ids: null
```

No IPv4 override file is bundled. IPv4 remains supported through explicit
recipe settings or a private allocation override. Changing families must replace
both required pools, their family-specific prefix lengths, and the optional
external pool if supplied. Optional allocation overrides merge in low-to-high
precedence order.
Each scenario uses one family, not dual-stack. Create a fresh workspace for
another family or changed allocations; existing rendered stages remain frozen.
Recipes omitting the uplinks field must be migrated and replanned before
rendering; do not reuse a plan generated under the old cage-based role policy.
The planner resolves matched selectors and the automatic first-eight/default-
downlink rule. Rendering consumes those assignments and checks physical
consistency on each device; it no longer repeats selector/repetition policy
validation or chooses a new layout.

`reserved_networks` and `reserved_vlan_ids` are exclusion lists; they are not pools
to allocate from. Pool overlap, excluded allocations, invalid prefixes/VLANs, and
insufficient capacity are errors. Nothing automatically reserves addresses/VLANs,
checks live routes, or discovers free resources.

```bash
python3 ansible/scripts/plan_generic_topology.py \
    --hostname example-dut \
    --peer-hostname example-leaf \
    --links-csv ansible/files/sonic_example_links.csv \
    --platform-json /path/to/dut/platform.json \
    --peer-platform-json /path/to/peer/platform.json \
    --pg-profile-lookup /path/to/dut/pg_profile_lookup.ini \
    --output-dir /private/path/plan
```

Add `--overrides /path/to/group.yml --overrides /path/to/host.yml` for explicit
low-to-high, field-level overrides. Each file has a `generic_topology` mapping.
Repeat `--exclude-port` to protect additional DUT ports and their connected cages.
`--max-search-states` sets a positive search ceiling (default 100000).

The planner is an internal developer entry point. The operator workflow uses
`add-topo`, which collects missing inputs, plans, resolves roles, and prepares
canonical PORT/PTF mappings. Full configuration rendering and YANG validation
run under `deploy-mg`:

```bash
cd ansible
./testbed-cli.sh -t testbed.yaml add-topo example-generic \
    /absolute/path/to/password.txt \
    --peer-hostname example-leaf \
    --links-csv files/sonic_example_links.csv
```

This entry resolves exactly one DUT from the selected YAML or legacy CSV testbed
definition, records the testbed identity and definition digest, and forwards the
remaining planning options. It does not call legacy topology-loading/convergence
helpers. Inventory defaults to the testbed's `inv_name`; the vault-password file
is a positional argument. Paths remain relative to the caller's working directory;
`-t` defaults to `testbed.yaml`. The standalone Python entry also accepts
`--testbed NAME --testbed-file PATH` instead of `--hostname`; the two identity
selectors are mutually exclusive.
Operator commands select one internal directory per user/testbed automatically;
no `--workspace` option remains. The standalone developer example above uses an
explicit plan output, not a separately operated deployment stage.
`vars/topo_generic.yml` is the conventional default recipe. Explicit `--overrides`
files merge in low-to-high order; inventory remains a connection source, not an
implicit recipe merge source. Adding this file does not change any testbed's topology.

Recipe, snapshot, link-selection, search, and managed-ACL options belong to
add-topo preparation only. Deploy-mg, remove-topo, and recovery reject those
options instead of silently ignoring them. Inventory/vault settings remain
available to all actions; only cleanup/recovery accept `--scenario-dir`.

###### Read-only device input collection

During add-topo preparation, omit any of `--platform-json`, `--peer-platform-json`, or `--pg-profile-lookup` to
collect that asset from its device. Supplied local files are retained; supplying
all three keeps the internal planner offline. Add-topo still contacts devices
for installed-asset rendering even when all planning snapshots are supplied.

Collection invokes `collect_generic_inputs.yml` using Ansible inventory connection
settings, including inherited host/group authentication and SSH options. Repeat
`--inventory PATH` to combine inventory sources. The repository's
`multi_passwd_ssh` shell connection is supported without overriding its alternate-password
handling; network-CLI connections remain unsupported. Without an explicit inventory, the selected testbed's
`inv_name` is resolved relative to the testbed definition's directory. Each requested
hostname must match an inventory host exactly. The selected peer must be a SONiC
leaf with SSH shell access, not an EOS/network-CLI session. For peers in the `fanout`
group, existing SONiC fanout login variables follow repository precedence:
`fanout_tacacs` over `fanout_tacacs_sonic` over `fanout_sonic`.
Use `--vault-password-file PATH` when inventory credentials require Ansible Vault.
Credentials and inventory variable dumps are not copied into scenario artifacts.

The remote probe reads platform/HwSKU identity from CONFIG_DB with `sonic-cfggen`.
It reads `platform.json` from `/usr/share/sonic/device/<platform>/`, or from the
installed HwSKU subdirectory if the platform-level file is absent. Lookup selection
on both devices prefers `/usr/share/sonic/device/<platform>/pg_profile_lookup.ini`
and falls back to `<platform>/<HwSKU>/pg_profile_lookup.ini` **only when the
platform file is absent**. An existing invalid/incomplete file remains an error;
rows are never merged across files. The selected path and bytes are checked for
deployment drift, including appearance of a new higher-priority platform file.
Nothing copies lookup files. Explicit local
`--pg-profile-lookup` snapshots remain supported for offline planning.
Missing identity, unsupported file layouts, missing assets, failed authentication,
or unsuccessful collection stops planning; there is no guessed profile, cached
snapshot fallback, or configuration-changing recovery. Remote Python 3 and
`sonic-cfggen` are required. No configuration, breakout, password rotation, or
reload tasks are run.

Successful collection persists requested files under `OUTPUT_DIR.inputs/dut/`
and/or `OUTPUT_DIR.inputs/peer/`, plus `collection.json` recording host identity,
platform/HwSKU, and resolved remote paths. Use `--snapshot-dir PATH` to choose
another new directory outside the scenario output directory. Existing snapshot
directories are never reused or
overwritten, and failed collection does not publish partial snapshots. The
scenario manifest includes collection provenance and hashes of collected inputs.
Collected snapshots remain available even if subsequent offline planning fails.

Successful generation publishes a new directory atomically containing:

| Artifact | Purpose |
|---|---|
| `manifest.json` | Selected modes/children, protected cages, input/artifact SHA-256 digests, deterministic scenario identity, and pending validation |
| `coverage.json` | Required/covered modes and lookup cases, excluded modes, rejected candidates, and search status |
| `topology.yml` | Proposed no-VM host-interface bindings, complete planned DUT port order, and sealed snapshot of resolved recipe settings |
| `resolved_facts.json` | Desired paired children, original transport attributes, assigned buffer cases, roles, IPs, VLAN/SVI, and static routes |

Bindings are desired allocations based on the generated port-order map, **not
observed PTF connectivity or hardware PORT indices**. Source transport VLAN
attributes are retained; aggregated transport tags and isolated channels still
require provisioning and independent verification. Only the explicit generic
entry points below consume these artifacts; legacy minigraph loaders must not.

The initial plan manifest is explicitly `deployable: false`. Planning alone never
generates or applies complete device configurations. Rendering and operator-driven
deployment are separate stages below. Planning supports a single forwarding
namespace and advertised uniform or mixed breakout modes. An installed canonical
parser must independently agree with the planned child names, lane partitions,
aliases, and individual speeds; unrecognized mode syntax is not guessed.
Electrical compatibility and
hardware shared-resource constraints still require live validation.

On physical infeasibility, only diagnostic `coverage.json` is published and the
CLI exits 2. Allocation failures publish a review-only plan; matching-uplink
shortfalls remain reported planning objectives, not a render/deployment gate.
Mode/buffer coverage shortfalls alone do not block a new VLAN-scoped plan.
Invalid input/allocation settings
exit 1 without scenario artifacts. Existing output
directories are never overwritten. A search-limit report is not a proof that
no feasible layout exists.

##### Generic QoS/config rendering and manual deployment

The generic path is **not** the minigraph-plus-golden-override path. It builds
full-device reload inputs from running snapshots and re-rendered installed
QoS/buffer templates, preserves management and
unowned/protected port entries, and retires understood interfaces, VLANs,
PortChannels, and BGP sessions belonging to the selected ports. A PortChannel
shared with protected ports or an unknown retired-port reference is an error.
Unowned BGP sessions are preserved; no new BGP sessions are generated.
Static routes without `ifname` are resolved against the original connected
subnets in their route or explicit next-hop VRF before interfaces are retired.
Routes whose next hops belong entirely to retired interfaces are removed.
Shared, ambiguous, or mixed unresolved dependencies fail rather than removing
protected connectivity; wholly unresolved/recursive and unrelated routes are preserved.

For new scenarios, fully wired DUT cages connected to a different/shared fanout
keep their existing breakout but permit **DUT-only forwarding cleanup**.
The frozen `dut_forwarding_cleanup` policy records those cages and their lanes.
Their existing `PORT` entries, speed, FEC/autoneg, QoS/buffers, physical neighbors,
and management configuration remain unchanged. Obsolete DUT interface bindings,
VLAN memberships, wholly retired LAGs, and associated routing state are removed.
A VLAN/SVI is removed only when all its consumers are being retired; a VLAN
removed this way also loses its VLAN-scoped `DHCP_RELAY` entry. A VLAN
still serving another retained DUT port keeps its SVI and relay. Mixed-consumer LAGs/routes
fail rather than dropping unrelated connectivity.

This does not clean or reconfigure the shared fanout or root. The selected
leaf's protected root-facing trunk also remains untouched by this cleanup.
Explicitly excluded cages and incompletely wired cages retain full protection.
Existing sealed scenarios do not gain this cleanup automatically: use a fresh
workspace. The render report lists `forwarding_cleanup_ports` separately from
replaced ports. Breakout preservation is not a hitless guarantee during the
later full-device reload.

Breakout is represented only by the realized `PORT` entries (lanes, speed, alias,
and other port attributes). Generated DUT and leaf configurations omit
`BREAKOUT_CFG` entirely, including inherited entries for selected or protected
cages. This removes breakout metadata, not the protected `PORT` entries.
Selected modes remain in the scenario manifest for validation and traceability;
they are not duplicated into a second CONFIG_DB breakout table.

Connection reconciliation happens after the selected layouts and child roles
are resolved, before the planner publishes its scenario, and on each
device before reading its running configuration. Every selected DUT and leaf
child must have exactly one reciprocal connection, match its frozen layout,
cover the same physical wiring channels at the same speed, and carry a resolved
scenario role and a matching-speed buffer case. Missing, duplicate, or
inconsistent connections fail; rendering never selects a replacement breakout
or infers roles. Add-topo freezes layouts, roles, settings, and canonical PTF
mappings; deploy-mg renders that same layout without replanning.
Before invoking it, edit physical roles, address pools, VLANs, exclusions, and transport in this one
source file; do not edit generated `topology.yml` or resolved facts. No separate
editable role file is generated.
There is no finalization pass or intermediate `finalized/` stage.
Planning validates settings, resolves T0 forwarding and coverage, and publishes
the generated artifacts and input hashes. Inputs must not be edited concurrently;
the workflow no longer checks for source changes during collection/planning.
Rendering consumes this exact snapshot without rereading mutable recipe sources.
Explicit `--recipe`/`--overrides` inputs remain optional; if used,
edit those sources before preparation instead. Changed inputs require a fresh
workspace after planning. Mode/buffer gaps remain visible;
only valid physical/forwarding inputs can render.

Rendering regenerates affected `DEVICE_NEIGHBOR` entries from those resolved
connections, using the scenario's actual DUT/leaf inventory identities and
canonical remote child names. It preserves unaffected neighbor entries,
`DEVICE_METADATA` except for the DUT's explicit generic HwSKU identity, and
`DEVICE_NEIGHBOR_METADATA`; it does not invent remote device types or require
inventory identifiers to equal the device's native hostname. Old affected
neighbor entries are replaced even when a child reuses the parent's name.
Scenario uplink/downlink assignments remain separate from physical neighbor
identity: both roles can connect to the same transport leaf. QoS and buffer
templates use the same frozen physical directions for selected ports: DUT roles
come from the plan, and selected leaf ports are downlinks. Temporary render-only
adapters preserve truthful neighbor metadata and installed policy values.
The buffer adapter overrides selected-port classification in the reviewed
`buffers_defaults_objects.j2` contract, preserving native classification outside
the selection. Installed templates are not edited.
Installed lossy policy is applied as rendered, including explicitly disabled PFC.
Only when the installed policy enables PFC are selected lossless ingress PG
bindings and missing lossless profiles left to `buffermgrd`.
`render_report.json` records those required values. Apply loads the rendered
input; successful reload is followed directly by save of the current running
configuration. Baseline drift still stops stage/apply to avoid overwriting
intervening device changes. Installed assets and daemon state are not rechecked.

Initial rendering requires a single-ASIC SONiC device using **traditional
buffers** and the verified shared `qos_config.j2` and
`buffers_defaults_objects.j2` role-list/include contracts. Dynamic
buffer backends and other template families fail explicitly rather than receiving
invented profiles. Both devices must supply a matching installed lookup case.
Lookup selection follows the platform-first, missing-file-only HwSKU fallback above.
The installed `portconfig.BreakoutCfg` expands/validates the proposed children.
QoS rendering prefers the HwSKU `qos.json.j2`, with platform-level fallback when
absent. A temporary adapter seeds `PORT_UPLINK`/`PORT_DOWNLINK` from physical roles
and bypasses neighbor-based classification in the inspected shared template.
The full installed QoS policy renders once; no two vendor-specific macro names
are mandatory. Unknown template structures fail rather than guessing. Absolute
temporary includes respect cfggen's system-first search order. Installed templates
are never overwritten, including when asset names collide with wrapper names.
Cable cases are explicit generic inputs. The renderer does
not create `generic_lossless_*` profiles or materialize the selected
`pg_lossless_<speed>_<cable>_profile` objects. Instead, it omits affected
lossless `BUFFER_PG` bindings and records their expected daemon-generated
profiles/bindings in `render_report.json`, using the installed lookup values
and the ingress pool's static/dynamic threshold mode. Required pools, lossy
PGs, egress queue bindings/profiles, and protected buffer state remain present.
When installed policy enables PFC, existing target `pg_lossless_*` profiles are preserved only if their
values match expectations; stale ones fail because the traditional daemon
reuses rather than repairs them. For installed lossy policy, unreferenced selected
target profiles inherited from earlier configurations are omitted from the input,
so unused incompatible headroom is not programmed again. Retained consumers,
including protected and unknown references, prevent removal.
Unrelated profiles, including old unused generic profiles, are not purged.
Projected daemon allocations are included in offline pool-reservation checks.
References and installed YANG models are also checked.

Rendering uses installed lookup files without probing `buffermgrd`, its process
arguments, or its container lookup. Installed case availability and nonzero cable
inputs remain required to render the supported traditional-buffer configuration.
The workflow does not establish that the active daemon uses the same lookup,
edit startup commands, or restart services during preparation.

The supported lookup-based traditional daemon derives lossless PG indices from
`pfc_enable`, so enabled PFC priorities must map to the same-numbered PGs.
Nonidentity PFC-priority-to-PG mappings now fail explicitly rather than
silently relying on daemon behavior that does not honor them. PFC-to-queue
maps may still be nonidentity.
Generic-only TC-to-PG maps are cloned from installed policy and aligned to the
rendered/inherited PFC PG/queue mappings through the installed TC-to-queue classifier.
This enables lossless traffic even when the SKU's default classifier sends all
classes to PG0, without altering protected ports' classifier bindings. Ambiguous
or unreachable lossless queue mappings are rejected.
Existing shared pool sizes and a running `xoff` omitted by the template are
preserved. Pool type/mode changes and explicit `xoff` changes are rejected.
Conflicting installed static buffer profiles receive selected-port aliases,
preserving protected definitions and keeping the installed profile's values
and pool reference. PFC-enabled egress queues use the same selected-port alias,
not the conflicting protected profile. Other shared-policy conflicts still fail.

There is no manual `qos` input block. The direction-aware installed template
supplies per-port QoS, including enabled PFC priorities and PFC map bindings.
Only omitted `pfc_enable` fields, and omitted PFC map bindings when PFC is enabled,
fall back to running policy. New children inherit those fields from lane-overlapping
running ports, including grouped `PORT_QOS_MAP` bindings. Aggregation requires
all contributing ports to agree on each inherited field. Missing/ambiguous
running policy or explicitly invalid rendered fields fail rather than guessing.
Rendered fields always take precedence; an empty `pfc_enable` is valid lossy
policy and never falls back to enabled PFC from the running configuration.

###### Installed lossy policy

Some installed HwSKU templates explicitly disable PFC and omit legacy lossless
egress objects. Supplying planned uplink/downlink lists does not override that
policy. The renderer retains the installed lossy ingress/egress profiles,
direction-specific queues, classification, and disabled PFC. It does not enable
shared-template priority defaults, synthesize a lossless egress profile, require
PFC maps or lossless egress objects, or create lossless PG expectations for these ports.
Planning still validates the advertised speed/cable coverage matrix.

All selected ports receive their assigned runtime `CABLE_LENGTH`, regardless
of PFC policy. Existing cable-group entries for a selected port are updated to
that assignment; protected-port cable settings remain unchanged. PFC-disabled
cases also remain in the sealed planning artifacts and `render_report.json`
under `buffer_policy.lossy_cable_cases`.

The traditional daemon can recreate unused lossless profiles from nonzero cable
entries even with empty PFC priorities. The renderer declares these optional
definitions under `unused_buffer_profiles`, using the installed lookup and
ingress lossless pool's threshold mode.
They are not inserted into the input configuration or assigned to PGs. A case
shared with a PFC-enabled port remains a required lossless profile instead;
retained template/protected profiles are not made optional.

These projections are informational, not a runtime allowlist. Deployment no
longer compares complete CONFIG_DB contents with the rendered input or waits
for profile/PG convergence in CONFIG_DB/APPL_DB. Selected-link state is not a save gate; independent link and buffer
programming validation remains necessary.
Lossy mode does not exercise the assigned lossless headroom cases in hardware.

Reports identify `qos_policy: installed_lossy` and record shared-pool preservation,
static-profile aliases, and omitted unused selected headroom under `buffer_policy`.
Lossy-only reports have no `lossless_buffers` projections. There is no
`buffer_daemon` process/lookup fingerprint in new reports.
Required static objects, protected state, and unrelated profiles remain.

Historical daemon/report-version compatibility gates have been removed.
Prepare a fresh `add-topo` workspace to adopt current rendering behavior;
existing configuration artifacts are not regenerated automatically.
If a failed deployment left scenario-owned host/PTF resources, remove them using
`remove-topo` with that failed workspace before applying the new scenario.
Device configuration rollback does not remove those transport resources.

The former `--enable-lossless-adapter` option is removed. Previously rendered
override artifacts are not regenerated automatically; keep them and their backups
for recovery. Retire the old topology and archive its internal artifact directory
before preparing changed inputs, rather than editing or overwriting sealed artifacts:

```bash
./testbed-cli.sh -t testbed.yaml add-topo "$TB" "$VAULT" \
    --peer-hostname "$LEAF" --links-csv "$LINKS"
```

Include `--exclude-managed-acls` only when that exclusion remains intended.
Rendering does not apply, reload, or save configuration. Database verification
and successful rendering do not prove ASIC programming or physical links.
Switching to lossy policy does not resolve independent SDK/SerDes failures.

For new plans, `transport.vlan_ids: null` uses each selected DUT endpoint's own
CSV VLAN, not a sorted pool reassigned across endpoints. An explicit list, when
present, is only an allowlist; it cannot enable endpoints without CSV VLANs.
Planning applies that allowlist before selecting layouts and allocating
forwarding. Excluded endpoints remain physical-only; their wiring channels stay
available for compatible aggregation.
**One existing isolated transport VLAN per traffic-backed child is required.**
Physical-only children are excluded from transport allocation, even if an explicit
allowlist contains spare VLAN IDs. PTF indices remain compact across traffic links;
complete DUT port indices still include physical-only and protected ports.
Rendering still requires live leaf access ownership and tagged trunks; a CSV
entry alone is not proof that the root/host transport works.

The current lab CSV has 65 VLAN-backed DUT/leaf rows; the usable count is
computed from wiring and protection, without automatically excluding low-speed
cages. Modes exposing additional blank-VLAN children may participate in physical
coverage without creating additional traffic paths. Both physical and traffic
counts are derived and reported independently; uncovered combinations and
physical-only traffic behavior remain unqualified.
Earlier 102-link validation used separately approved transport extensions
`1941-1957,4073-4094`; those are historical infrastructure state, not new planner
capacity. This change does not remove shared VLANs or change existing deployments.
Frozen older scenarios retain their original transport contract. Use a fresh
workspace; do not edit sealed artifacts.
Use a fresh workspace rather than the previously frozen v4/v5 inputs; do not
reuse this lab's IDs for another testbed.

Before changing `topo` or `server`, retire any previous host/PTF topology using its original
definition and the normal lab maintenance procedure. Generic add-topo refuses to
take over an existing unlabelled/different-scenario PTF container.
The `server` setting may be a physical-host inventory name or a group such as
`server_75`. The host playbook intersects that selection with both `servers`
and `vm_host`, requiring exactly one eligible host before remote tasks.
Missing or ambiguous selections fail; neighbor VM members do not become host
targets. Keep the existing testbed group selector rather than replacing it
with a literal hostname. DUT, PTF management, group, and inventory settings
remain unchanged; this resolution does not edit the testbed.

To check only inventory resolution, without contacting the VM host:

```bash
ANSIBLE_LIBRARY=library:roles/vm_set/library \
ansible-playbook -i veos -i "$INV" generic_host.yml \
    --vault-password-file "$VAULT" --limit server_75,localhost \
    --tags generic_host_resolution \
    -e '{"generic_testbed": {"server": "server_75"}}'
```

This tag performs no Docker, interface, or fanout operations. It does not
prove transport readiness or substitute for post-provisioning PTF verification.
It also resolves an omitted `fp_mtu_size` from the existing
`roles/vm_set/vars/main.yml`, preserving any explicit inventory value. The normal
host path checks the shared interface against that MTU; it does not change the
shared interface to satisfy the check.
An authorized generic add-topo creates/binds only scenario-owned host/PTF
resources on existing transport. It never invokes root-fanout connection/save
playbooks, changes shared trunks, or reloads the DUT/leaf. Existing physical
transport is assumed; wiring information is still needed for compatible breakouts.
Before binding management connectivity, add-topo initializes PTF credentials
through the existing inventory-managed password task without logging secrets.
Removal accepts stopped, partially bound, or already-absent scenario containers;
it still rejects conflicting container labels or endpoint ownership and cleans
only verified scenario endpoints. Verification continues to require a running
container and every planned endpoint.
For `add-topo` and `remove-topo`, the `topo` field selects
`vars/topo_<topo>.yml`. A valid `generic_topology` section in that file selects
the generic lifecycle automatically; the name itself has no special meaning.
For example, `topo: generic_a` loads `vars/topo_generic_a.yml`. Automatic
add-topo preparation uses that matching recipe unless `--recipe` overrides it.
A topology file without `generic_topology` retains the traditional lifecycle,
which is not a dry run by default. Automatic detection rejects missing or invalid
topology files before either lifecycle can mutate infrastructure.

`deploy-mg` still requires explicit `--generic`, regardless of topology name or
recipe contents. Explicit `--generic` also remains available on add/remove-topo
as a backward-compatible override, independent of topology-file detection.
`recover-generic` needs no extra selector. Separate public planning, finalization,
and rendering commands have been removed; preparation belongs to add-topo.
`--scenario-dir` or `--print-data` on shared
commands require the generic lifecycle, selected either automatically for
add/remove-topo or explicitly with `--generic`. Paths alone do not select it.

The DUT output uses `<base-HwSKU>_generic`; the leaf keeps its original identity.
Rendering resolves base assets but creates no alias. During authorized apply only,
the workflow creates the sibling symlink `<base-HwSKU>_generic -> <base-HwSKU>`.
Conflicting paths are rejected. Correct pre-existing aliases are reused and
never claimed as owned; already-generic identities do not accumulate suffixes.
Recovery restores original metadata/configurations before removing an alias
created by this scenario, and checks its recorded inode/target before unlinking.

DATAACL/EVERFLOW membership follows actual lane overlap, including effective
membership through an old owned PortChannel. New children inherit it; aggregation
of ports with differing memberships fails. Protected ACL membership is preserved.
The error identifies each overlapping old port and its effective membership;
resolving it requires an explicit ACL migration decision, not automatically
unioning or dropping bindings. `PFC_WD.GLOBAL` is preserved as global watchdog
policy, while per-port watchdog references still require existing ports.

Other ACL tables bound to replaced physical ports or retired logical interfaces
fail explicitly before bindings are removed. Managed ACL bindings that cannot
be inherited, such as a retired VLAN binding, also require explicit migration
or the managed-ACL exclusion below. Custom physical ACL bindings on fixed-breakout
forwarding-cleanup ports remain unchanged.

When legacy DATAACL/EVERFLOW qualification is explicitly out of scope, pass
`--exclude-managed-acls` to `add-topo` during preparation. This opt-in omits
inherited DATAACL/EVERFLOW bindings on managed ports and retired owned LAGs on
both devices. It does not delete ACL tables, rules, mirror sessions, protected
bindings, or service-based management ACLs. Tables with no remaining bindings
are retained without the optional `ports` field; an empty leaf-list is rejected
by the inspected installed YANG parser.
Shared protected LAGs and unsupported retired-port references still fail closed,
including port-specific ACL rules that cannot safely survive the migration.
The default remains strict inheritance.
If another configuration entry still refers to a retired local interface,
rendering reports up to eight JSON-style locations and the referenced interface,
without dumping field values. Matching keys are identified by position rather
than echoed in full. Use those locations to decide the explicit migration;
ACL exclusion does not authorize deleting arbitrary residual configuration.
`PORT.description` is free text, not a local-interface binding; descriptions
containing remote port names are preserved verbatim and excluded from this scan.
`PORT` keys and other fields remain checked. Remote interface values in
`DEVICE_NEIGHBOR` are likewise not treated as retired local references.

Planned routed/access subnets must not overlap retained interfaces, including
SVIs on preserved VLANs. An overlap error identifies the planned address/network
and the retained table/interface/network. A VLAN ID collision is checked
separately: selecting a different subnet does not authorize overwriting a
retained VLAN. Inspect only the required running tables, choose approved unused
VLAN IDs and non-overlapping pools, or explicitly authorize migration of the
old resources. Update the recipe and create a new plan/workspace for changed
allocations; do not edit sealed `plan/` artifacts or simply retry unchanged.

This option can be used when retrying a failed render with an existing sealed
`plan/` stage; do not edit its JSON or remove earlier artifacts. It is passed
in the render request, confirmed by both device responses, and recorded in the
sealed rendered manifest under `policy.exclude_managed_acls`. Each device's
`render_report.json` entry lists `excluded_acl_bindings`. Deployment consumes
those sealed configurations; the option is rejected on actions other than add-topo.
Once rendered, the policy cannot be changed in place. Rendering itself does not
apply configuration.

Run from `ansible/`. Review the shared `vars/topo_generic.yml` defaults before
add-topo and supply an optional allocation override when needed.
No hardware-specific topology input is required. Generated scenario directories
remain private and separate per testbed. Multiple runs may read the same unchanged
source; do not concurrently edit it for different scenarios. Existing rendered
scenarios remain usable for transport removal and device recovery.

All generic commands share one workspace. The default is
`<system-temp>/sonic-generic-<UID>/<testbed>`, normally under `/tmp` and honoring
`TMPDIR`. It is stable for the same user, testbed, and temporary root; it is not
the most recently modified directory or a different random directory per command.
The layout is:

```text
/tmp/sonic-generic-<UID>/example-generic/
├── plan/
├── prepared/
└── rendered/
```

Each command prints the workspace. Add-topo writes `plan/`, requires valid
forwarding, and prepares canonical PORT ordering and existing leaf transport in
`prepared/`, without generating complete configurations or running QoS/YANG.
An existing plan is reused without rereading the recipe or choosing another layout.
Deploy-mg renders complete configurations into `rendered/`, then deploys unless
`--print-data` was supplied. Rendering must retain the prepared PORT/PTF/transport mapping.
Preparation and rendering share one scenario ownership ID, so PTF attachment,
device backups, removal, and recovery refer to the same scenario.
Retry mapping preparation with add-topo; retry rendering with deploy-mg.
Existing stages are reused, not regenerated. Remove-topo can use `prepared/`
even if rendering failed; recovery requires `rendered/` and device snapshots.
Older rendered scenarios remain usable for cached lifecycle operations.
A missing required stage fails locally rather than falling back to legacy deployment.
Workspace/stage directories must be private, owned by the current user, and not
symlinks. Failed runs and previews retain their artifacts. After a successful
paired reload/save, cleanup removes the local complete configs and known duplicate
`plan/`/`prepared/` files, plus recorded default `plan.inputs/` snapshots.
External snapshots and unknown files are never deleted.
An empty `plan/` or `prepared/` directory left after interrupted manifest removal
can be removed on retry, subject to the same directory ownership checks.
Nonempty stages without a manifest are not adopted or purged.
The compact `rendered/` stage retains ownership identity, topology, resolved
mappings, coverage, reports, and table counts for preview/removal/recovery.
Its manifest records `status: deployed`. On-device backup/helper bundles under
`/var/lib/sonic-generic/<scenario-id>/<role>/` remain unchanged; recovery uses
those bundles without requiring local complete configs. Repeating deploy-mg
does not reload an already-deployed scenario. Cleanup failure is reported separately
from successful persistence and does not roll back a saved deployment.
System temporary-file cleanup may still remove retained local metadata.

There is no `--workspace` option. Add-topo, deploy-mg, remove-topo, and recovery
automatically use the same directory when run as the same user with the same
temporary root. Keep that environment consistent across commands.
Existing stages are never overwritten or regenerated implicitly. Before preparing
changed inputs, retire the old topology, recover device state if needed, and
archive its artifact directory away from the automatic path; do not discard
recovery artifacts. `TMPDIR` remains the standard temporary-root setting.
`--scenario-dir` is accepted only by remove-topo and recover-generic, including
`/old/run/rendered` for cleanup/recovery of earlier custom-location runs.
Normal add-topo/deploy-mg reject it. Operator `--output-dir` is removed;
only the standalone developer planner retains explicit output selection.
An existing plan can only be reused if it belongs to that exact DUT and testbed.
After planning, recipe edits do not change rendering: select a fresh workspace
and plan again for another reviewed version. Invalid plans remain
review-only and never trigger device access. Best-effort mode/buffer gaps alone
do not make a new VLAN-scoped plan invalid.

```bash
# Preview using shared defaults, with optional allocation overrides when needed.

./testbed-cli.sh -t testbed.yaml add-topo example-generic \
    /absolute/path/to/password.txt \
    --peer-hostname example-leaf \
    --links-csv files/sonic_example_links.csv --print-data

./testbed-cli.sh -t testbed.yaml deploy-mg example-generic example-inventory \
    /absolute/path/to/password.txt --generic --print-data
```

Rendering contacts the devices and uses private temporary files, but does not
reload or save configuration. Its output adds `dut_config.json`, `leaf_config.json`,
and `render_report.json`; all artifacts are private (`0600`, directory `0700`).
**Complete configurations can contain credentials inherited from the baseline.
Keep these directories outside source control; do not attach them to PRs/logs.**
The rendered manifest records provenance hashes and lifecycle status.
Manifest/artifact hashes are not replayed as deployment gates. Device stage/apply
still check the configuration checksum, including the actual staged reload file,
so changing the YANG-validated configuration is rejected. Testbed identity and
settings must also match.

The examples explicitly use `--print-data`: fresh add-topo may collect/read devices
to prepare mappings; fresh deploy-mg may read both devices to render and
YANG-validate configurations. Neither preview provisions infrastructure or applies
configuration. Output contains planned operations, port/PTF/VLAN mappings,
coverage status, and configuration table counts, never inherited configuration values.
Cached previews are local-only. In an exclusively reserved maintenance window,
omit `--print-data` to execute add-topo first, then deploy-mg.
Add-topo provisions the scenario-owned PTF
container and host VLAN endpoints, uses the existing no-VM management/binding
helper, and leaves root-fanout connections and shared transport unchanged.
It never reloads the DUT/leaf. Compact PTF indices are
projected independently of DUT hardware indices.

There is no separate role-freeze or finalization command. The first add-topo
without `--print-data` prepares mappings and then attaches PTF in one invocation. Full
rendering is deferred to deploy-mg; a rendering/YANG failure leaves those PTF
resources attached but cannot stage or reload devices. Remove-topo can clean them
up using the prepared scenario. Existing stages are never silently regenerated
or overwritten; a changed recipe or layout requires a fresh workspace.

Deploy-mg first renders/YANG-validates the fixed prepared layout if needed,
checks the PTF endpoints, and stages **both** devices before reloading
either. It rejects intervening running-state changes, keeps private running
and startup backups under `/var/lib/sonic-generic/<scenario-id>/<role>/`, reloads
the complete artifacts (not minigraph), checks reload success, and saves only
after both devices reload successfully. There is no DUT/leaf link-state gate;
down selected ports do not block save or trigger rollback. Deployment does not
probe daemons or inspect CONFIG_DB/APPL_DB buffer convergence.
Save runs `config save -y` and accepts the startup file only when it matches
running snapshots taken immediately before and after the save/readback.
A changing or mismatched snapshot retries the save, up to three attempts;
command failures and an exhausted retry bound still trigger recovery.
This compares current running state, not the rendered input. Runtime additions
and other post-reload database differences are no longer rejected by a strict
artifact comparison.
No automatic `config qos reload` is appended. ASIC programming and packet/PFC
behavior still require hardware validation. A later failure attempts
rollback on every device on which a reload was attempted. Failed rollback is an
explicit manual-recovery condition, not a successful deployment. Keep console/
out-of-band access available; full reloads can flap protected links. Apply and
rollback retry only the installed CLI's explicit system/SwSS pre-reload readiness
rejection for up to 300 seconds, without `--force`. Other reload failures are not
retried. Reload errors identify the private async job and backup directory rather
than exposing configuration-bearing command output. A repeated
staging attempt never overwrites the original backups; use recovery and a fresh
collected plan for another attempt.

```bash
./testbed-cli.sh recover-generic example-generic example-inventory \
    /absolute/path/to/password.txt

./testbed-cli.sh remove-topo example-generic \
    /absolute/path/to/password.txt
```

These commands execute by default too; append `--print-data` to preview them.
Recovery restores running and saved configurations, not old host infrastructure.
Generic remove-topo removes only verified scenario-owned host/PTF resources; it
does not delete shared root VLANs. Packet-level isolation/forwarding and QoS/PFC
behavior still require operator-run testbed tests. The generic plan/facts are not
a replacement for a pytest topology/fixture adapter.
**This is not a drop-in nightly qualification workflow.** The existing pytest
testbed parser reads a named static topology file, not this workspace's resolved
topology/PTF mapping, and names starting with `generic` are classified as
unsupported. Existing minigraph-based restore helpers can replace this scenario
with older minigraph/golden-config state. Selecting a familiar topology name or
saving a golden snapshot does not fix those integration gaps. Generic rendering
does not run the full legacy golden-config generation/policy pipeline.
If the controller is terminated or recovery cannot reconnect, check any pending
asynchronous reload jobs before retrying recovery; do not assume the pair reverted.

###### Validation boundaries

The generic path uses the approved minimal safety-plus-YANG boundary:

| Phase | Validators/checks |
| --- | --- |
| Planning inputs | `load_recipe`, `port_declarations`, `load_device`, `load_lookup`, and `build_mapping`: schema/required fields, canonical unique selectors, advertised modes/lanes/aliases, unique lookup cases, exact CSV endpoints and protected wiring. |
| Layout and forwarding | `solve_layout`, `allocate_forwarding`, and `reconcile_neighbors`: matching complete physical channels/speeds, hard exclusions, first-eight roles, traffic-backed uplink/downlink availability, single-family nonoverlapping pools, reservations, prefix/capacity limits, VLAN validity, reciprocal neighbors and matching buffer cases. External-pool checks run only when that optional section is supplied. |
| Controller preflight | Exact identities/testbed, safe workspace/artifact paths, valid forwarding, prepared/rendered-stage readiness, unchanged PORT/PTF/transport mapping during rendering, preview/execution selection, and sealed managed-ACL policy. Coverage/repetition and recorded hashes are informational, not repeated policy gates. |
| Installed rendering | Single-ASIC traditional backend, canonical SONiC breakout-parser agreement, `validate_vlan_scope`, `validate_references`, retained-resource/ACL/forwarding conflict checks, and installed QoS/buffer parsing. `SonicYang.loadData` and `validate_data_tree` validate the complete configuration against installed models; altered tables without models fail. |
| Host/PTF | Exact VM-host resolution, scenario ownership, isolated VLAN IDs, parent/namespace/interface identity, and existing transport/trunk readiness; never take over unrelated containers/endpoints. |
| Device stage/apply | Validated-config checksum, unchanged running baseline, valid HwSKU alias, complete private backups, unchanged staged reload file, and guarded reload. No repeated asset, daemon, or dependency scan. |
| Reload/save | Successful reload, successful save, and startup-file comparison with the running snapshot. No selected-link gate, exact rendered CONFIG_DB comparison, or daemon/APPL_DB checks. |
| Recovery | Require complete snapshots, restore running/startup state, verify rollback CONFIG_DB, and remove only a journaled owned alias. |

Removed gates include repeated role/coverage/cleanup-policy validation, source-change
and artifact-hash replay, historical report-version checks, installed-asset
fingerprint replay, daemon startup/argument/lookup checks, and strict
CONFIG_DB/APPL_DB convergence and pre-save comparisons. Parsing and template
checks needed to produce correct configuration remain; not all rows in the
original validator inventory were separable deployment gates.

Historical offline validation exercised physical/forwarding correctness, installed YANG,
automatic preparation, native QoS rendering, protected resources, minimal
verify/save behavior, and ownership/recovery. No deployment was performed for
this simplification. Offline validation does
not certify electrical compatibility, installed-image reload behavior, ASIC/PFC
programming, or packet forwarding. Those require an authorized maintenance window
and physical testbed validation.

##### Legacy PORT-override deployment (without `--generic`)

The following workflow selects legacy minigraph deployment. Generic
scenarios must use the complete-configuration commands above instead.

```bash
# Deploy minigraph + golden config with PORT table generated from links.csv
./testbed-cli.sh deploy-mg <testbed-name> <inventory> <password> \
    -e port_override_from_links=true -e lab_name=<lab>
```

This single command:
1. Reads port speeds from `ansible/files/sonic_<lab>_links.csv` on the mgmt server
2. Reads the DUT's HwSKU from `ansible/files/sonic_<lab>_devices.csv`
3. On the DUT, rebuilds the PORT table from the local `platform.json` using those speeds
4. Applies minigraph + PORT override with `config load_minigraph --override_config -y`

##### Deploy without PORT override (default behavior)

Without `port_override_from_links`, the module uses minigraph PORT speeds and
adds FEC. This is the existing behavior and requires no extra flags:

```bash
./testbed-cli.sh deploy-mg <testbed-name> <inventory> <password>
```

##### Standalone generation (optional)

For debugging or offline use, the standalone script `generate_port_config.py`
can generate the same PORT table JSON on the mgmt server:

```bash
python3 ansible/scripts/generate_port_config.py \
    --links-csv ansible/files/sonic_example_links.csv \
    --devices-csv ansible/files/sonic_example_devices.csv \
    --hostname example-dut \
    --platform-json ~/sonic-buildimage/device/arista/x86_64-arista_7060x6_64pe/platform.json \
    --full-config \
    -o /tmp/port_config_override.json
```

##### Changing Breakout (update links.csv)

To remap `links.csv` for a new breakout layout, use the `update-breakout`
command in `testbed-cli.sh`, which wraps `update_links_for_breakout.py` and
automatically resolves the DUT hostname from the testbed definition:

```bash
# From the ansible/ directory

# Uniform breakout — all cages get the same mode
./testbed-cli.sh update-breakout example-t1-lag \
    files/sonic_example_links.csv 2x400G --dry-run

# Mixed breakout — different modes per port range
./testbed-cli.sh update-breakout example-t1-lag \
    files/sonic_example_links.csv "1x800G:0-255,2x400G:256-504" --dry-run

# Remove --dry-run to apply
```

Alternatively, call the script directly with an explicit hostname:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_example_links.csv \
    --hostname example-dut \
    --target-breakout 2x400G \
    --dry-run
```

The port range in mixed breakout refers to Ethernet port numbers. Each range
gets its own breakout mode. Cages are determined by `--lanes-per-cage` (default: 8).

###### What the Script Does

The script groups DUT ports by physical cage, maps existing source ports to
target ports in the new breakout, removes entries that don't exist in the new
layout, and generates expansion entries for any target ports that lack a source
mapping. This ensures the CSV is always complete for the new port layout. VLAN
assignments are updated sequentially and trunk VLAN ranges are adjusted.

###### Updating HwSku

Use `--hwsku` to update both `links.csv` and `devices.csv` in one command:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_example_links.csv \
    --hostname example-dut \
    --target-breakout 2x400G \
    --hwsku Arista-7060X6-64PE-O128S2
```

The script auto-detects the companion `devices.csv` from the `links.csv` path
and updates the HwSku column for the specified hostname.



#### End-to-End HWSKU Conversion (C256 → O128 Example)

This walkthrough converts a DUT from `Arista-7060X6-64PE-C256S2` (4x200G, 256 ports)
to `Arista-7060X6-64PE-O128S2` (2x400G, 128 ports).

##### Prerequisites

- Testbed name (e.g., `example-t1-lag`)
- Links CSV path (e.g., `ansible/files/sonic_example_links.csv`)
- Devices CSV path (e.g., `ansible/files/sonic_example_devices.csv`)
- Inventory file (e.g., `example-inventory`)
- Vault password file (e.g., `~/.password`)

##### Step 1: Pre-checks — verify current state

```bash
# Check current HWSKU and port count on DUT
ssh dut "show platform summary"
ssh dut "show interfaces status | wc -l"
ssh dut "show interfaces status | grep -c 'up'"
ssh dut "show bgp summary"
```

Save the output for comparison after conversion.

##### Step 2: Update links.csv for new breakout

Preview the changes first with `--dry-run`:

```bash
# From sonic-mgmt/ansible/ directory
./testbed-cli.sh update-breakout example-t1-lag \
    files/sonic_example_links.csv 2x400G --dry-run
```

Verify the output shows:
- Correct number of new DUT entries (128 ports for O128)
- VLANs preserved for existing ports, new VLANs assigned for new ports
- Trunk VLAN range updated for root fanout

Apply when satisfied:

```bash
./testbed-cli.sh update-breakout example-t1-lag \
    files/sonic_example_links.csv 2x400G
```

##### Step 3: Update devices.csv — change HwSKU

Use `--hwsku` during Step 2 to handle this automatically, or edit
`ansible/files/sonic_example_devices.csv` manually:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_example_links.csv \
    --hostname example-dut \
    --target-breakout 2x400G \
    --hwsku Arista-7060X6-64PE-O128S2
```

##### Step 4: Update the devices.csv and Redeploy leaf fanout(Uses another change in port_config_gen.py by PR:https://github.com/sonic-net/sonic-mgmt/pull/23536/changes)

The leaf fanout needs to be reconfigured for the new breakout and VLANs:

```bash
cd ansible
ansible-playbook -i example-inventory fanout.yml \
    -l example-fanout \
    --vault-password-file ~/.password
```

##### Step 5: Update root fanout VLAN trunks

The root fanout trunk ports need the updated VLAN range:

```bash
ansible-playbook -i example-inventory fanout_connect.yml \
    --vault-password-file ~/.password \
    -e dut=example-dut
```

##### Step 6: Deploy minigraph with PORT override

This generates minigraph with the new port layout, builds the golden config
(which rebuilds the PORT table from `platform.json`), and applies both:

```bash
./testbed-cli.sh deploy-mg example-t1-lag example-inventory ~/.password \
    -e port_override_from_links=true -e lab_name=example-inventory
```

What happens under the hood:
1. Playbook reads `links.csv` on the mgmt server → extracts `port_speeds` for 128 ports
2. `generate_golden_config_db` runs on the DUT, reads local `platform.json`
3. PORT table is rebuilt with correct lanes, aliases, indices, speed=400000, fec=rs
4. `config load_minigraph --override_config -y` applies minigraph + PORT override

No `port_config.ini` is read or needed at any step.

##### Step 7: Verify port status

Wait ~60 seconds for ports to come up, then verify:

```bash
# All ports should be operationally up
ssh dut "show interfaces status"

# Count should match expected (128 data ports + management)
ssh dut "show interfaces status | grep -c 'up'"

# Check for any ports that are admin up but oper down
ssh dut "show interfaces status | grep 'up.*down'"

# Verify port speeds are correct (all should be 400G)
ssh dut "show interfaces status | awk '{print \$5}' | sort | uniq -c"

# Verify PORT table in config_db has correct lanes and aliases
ssh dut "sonic-cfggen -d --var-json PORT" | python3 -m json.tool | head -30
```

##### Step 8: Verify BGP sessions

```bash
# All BGP neighbors should be in Established state
ssh dut "show bgp summary"

# Check for any non-established sessions
ssh dut "show bgp summary | grep -v Established | grep -v 'Neighbor\|entries'"

# Verify neighbor count matches expected topology
ssh dut "show bgp summary | grep -c Established"
```

### Validation strategy and current evidence

#### Layered acceptance

| Layer | Required check | Does not establish |
| --- | --- | --- |
| Offline inputs/planning | Schema, physical matching, protection, and valid deterministic allocations; coverage is reported. | Electrical compatibility, source immutability, or current lab ownership. |
| Installed rendering | Canonical parser, safe installed-template/lookup interpretation, dependency checks, and installed YANG. | Successful ASIC programming, active daemon lookup agreement, or link training. |
| Runtime configuration | Reload success, unchanged pre-apply baseline/config, and saved-state readback. | Exact rendered-table equality, daemon/buffer convergence, packet forwarding, or losslessness. |
| Host/PTF transport | Endpoint ownership/mappings and host-interface readiness. | DUT/leaf link state, correct routed next hops, or end-to-end forwarding. |
| Operator-run link checks | Selected ports up at both ends; not a deployment gate. | Packet forwarding or losslessness. |
| Data plane | Emulated-neighbor readiness, exact routes/next hops, marked packets with expected egress and rewrites. | All-port, congestion, PFC, or line-rate qualification from a short smoke test. |

The generic-workflow unit-test suites have been removed from this change.
Historical validation before their removal recorded **457** focused tests and
applicable pre-commit hooks passing after the validation/cleanup changes and the
transport-preparation/device-rendering split. That historical result is not current
regression coverage, the full repository's lab test suite, or a hardware deployment.

#### Demonstrated instance

The preceding lab bring-up provides bounded evidence, not platform-wide
certification:

- A scenario managed 102 DUT/leaf link pairs: four individual routed uplinks
  and 98 downlinks. Independent checks observed all 102 selected ports up at
  both ends and matching complete PORT layouts.
- The deployed selected-port policy was native installed **lossy** policy.
  No hardware lossless/PFC result is claimed.
- Separate approved maintenance repaired a protected transport-trunk
  autonegotiation mismatch. This was not automatic planner/renderer behavior.
- After explicit neighbor-discovery initialization, four routed paths each
  delivered 10/10 marked IPv6 packets, 40/40 total. Checks included hop-limit
  64 to 63 and expected source/destination MAC rewriting.
- The four exact routes and corresponding next-hop objects were observed in
  ASIC_DB. A cold unresolved path had not forwarded before initialization.
- No persistent responder was installed. Dynamic emulated neighbors can fail
  again when responses stop; the smoke result is not all-102-port forwarding,
  line-rate, sustained stability, or congestion proof.

Raw configuration-bearing evidence remains private outside the repository.
The HLD records aggregate outcomes rather than embedding device credentials,
complete snapshots, or lab-specific allocation lists.
These are historical observations, not a new device audit performed for this
document. A changed protected baseline requires fresh rendering; do not replay
an older sealed artifact that would reverse an approved maintenance repair.

#### Cable-retention live test, 2026-10-26

A fresh 65-link scenario retained all six assigned cable values with installed
PFC disabled, using eight routed uplinks and 57 downlinks. Installed YANG
validation exposed and prompted fixes for a retired VLAN's residual DHCP relay
and an emptied ACL port leaf-list; all 287 deployment regressions and applicable
hooks passed after those fixes.

Both devices reloaded and passed their 65 selected-interface link checks.
A read-only DUT sample observed all assigned cable values, eight daemon-created
`pg_lossless_<speed>_<cable>_profile` definitions, no enabled PFC bindings, and
no lossless PG bindings. These unused profiles were not declared by that run's
lossy verification contract. Both devices therefore failed the save precheck
with `BUFFER_PROFILE` drift, and neither saved the new configuration.
Automatic rollback completed; independent read-only checks confirmed original
running configurations and byte-identical original startup files on both devices.
At the end of that attempt, scenario-owned host/PTF transport remained provisioned;
root bindings were not cleaned. No packet-forwarding or lossless hardware
qualification was performed.

This is a failed deployment with successful recovery, not persistent acceptance
of cable retention. A subsequent verifier revision allowed exact projected
unused profiles, but the current minimal boundary removes that database gate
altogether. Neither change converts this historical rollback into a successful
saved deployment; fresh hardware validation is still required.

#### Current lifecycle deployment report, 2026-10-27

The operator reported successful deployment after retiring the previous
scenario-owned PTF resources and rerunning the split add-topo/deploy-mg workflow.
This is an operator report from the private prototype, not an independently
audited deployment of this public branch; the image version was not captured.

The inspected rendered artifacts contain 95 selected physical connections:
65 have CSV-backed traffic transport and 30 are physical-only. The first eight
physical DUT children have uplink roles, but seven of those lack transport,
leaving one configured routed uplink. Installed PFC policy is disabled on all
selected ports. The supplied interface-status excerpt includes operationally
down ports; successful reload/save is not link or packet-forwarding acceptance.
No new all-port, ASIC, packet, lossless, congestion, or line-rate qualification
is claimed.

#### Remaining acceptance work

Before treating this as repeatable qualification, validate cold/warm neighbor
behavior with maintained responders, all selected mappings and traffic paths,
isolation, save/reboot/recovery behavior, and repeated-run stability.
Lossless operation additionally requires installed PFC-enabled policy, valid
hardware pool/headroom combinations, ASIC programming checks, and actual
PFC/congestion traffic tests. A lossy deployment cannot substitute for those.

### Alternatives considered

| Alternative | Decision and reason |
| --- | --- |
| A static HwSKU and topology for every mixture | Avoid as the primary model: duplicates layout definitions and increases maintenance. Existing vendor assets remain prerequisites. |
| Select DUT and leaf modes independently | Reject: independently legal choices may disagree on physical channel aggregation or speed. |
| Modify maximum-breakout wiring for every scenario | Reject: wiring is a physical input; realized layouts are generated projections, not rewrites of source cabling. |
| Reuse legacy minigraph plus a PORT-only override | Keep as a separate legacy feature, not this workflow: a new port layout also needs coherent forwarding, references, QoS, neighbors, and transport. |
| Emit both `PORT` and `BREAKOUT_CFG` | Reject for this path: use one realized configuration representation and preserve planning metadata separately. |
| Classify QoS by spoofed neighbors/types | Reject: physical neighbors must remain truthful; use explicit direction in a reviewed adapter. |
| Force lossless policy onto an installed lossy template | Reject: changes policy and can create incompatible hardware headroom/pool combinations. |
| Infer generic lifecycle from a `generic*` prefix or only a mandatory flag | Use named-recipe content for add/remove; retain explicit deploy selection to avoid silently switching the device configuration backend. |
| Invent transport VLANs or adopt an existing PTF container | Reject: capacity is not ownership; reservations and scenario ownership must be explicit. |

### Limitations and future work

The following are future directions, **not implemented capabilities or
committed delivery dates**:

- Add explicit forwarding adapters for other topology families, routed
  downlinks, LAG/BGP, dual-stack, and additional device/ASIC arrangements.
- Integrate the generated topology/PTF facts into pytest fixtures, topology
  classification, nightly selection, and generic-aware restore helpers.
  The current static testbed parser does not automatically consume this
  workspace, and names beginning with `generic` are currently unsupported
  by that parser. Legacy minigraph restore can replace the scenario.
- Define a native upstream QoS direction-input contract to reduce reliance on
  the reviewed temporary adapter, and qualify more template/backend families.
- Integrate persistent emulated-neighbor setup and data-plane acceptance into
  the lifecycle rather than relying on separate smoke-test preparation.
- Extend hardware qualification across platforms, lossless policies, all-port
  traffic, restart/recovery, and larger solver search spaces.
- Consider integration with reservation/connection services; the current
  workflow does not acquire distributed leases or allocate shared resources.

The immediate design remains intentionally bounded: preserve vendor policy,
make decisions and evidence inspectable, and fail explicitly outside known
contracts instead of claiming a universal topology generator.

### Implementation map

Paths are relative to the repository root; linked source is the implementation
authority for this draft.

| Component | Responsibility |
| --- | --- |
| [map_breakout_links.py](../../ansible/scripts/map_breakout_links.py) | Mode/channel parsing, inventory normalization, and protection propagation. |
| [plan_generic_topology.py](../../ansible/scripts/plan_generic_topology.py) | Recipe validation, lifecycle detection helper, joint solver, coverage, allocations, workspace, and plan publication. |
| [collect_generic_device.py](../../ansible/scripts/collect_generic_device.py), [collect_generic_inputs.yml](../../ansible/collect_generic_inputs.yml) | Authenticated read-only input collection and provenance. |
| [generic_topology_cli.py](../../ansible/scripts/generic_topology_cli.py) | Fixed layout/PTF preparation, deferred rendering publication, and paired deployment orchestration. |
| [generic_config.py](../../ansible/scripts/generic_config.py) | Canonical ports, dependency/neighbor reconciliation, forwarding, QoS adaptation, buffer ownership, and YANG validation. |
| [generic_buffers.j2](../../ansible/templates/generic_buffers.j2) | Render-only installed buffer-template adapter. |
| [generic_device_action.py](../../ansible/scripts/generic_device_action.py) | Stage/apply/save/rollback, baseline/config protection, saved-state readback, and alias journal. |
| [generic_devices.yml](../../ansible/generic_devices.yml) | Two-device remote execution, private staging, asynchronous reloads, and reload/save result checks. |
| [generic_host.yml](../../ansible/generic_host.yml) | Unique host resolution and scenario-owned PTF/VLAN endpoint lifecycle. |
| [testbed-cli.sh](../../ansible/testbed-cli.sh) | Shared-command routing and explicit generic stage commands. |
| [topo_generic.yml](../../ansible/vars/topo_generic.yml) | Shared hardware-neutral IPv6 recipe defaults; not resource reservations. |

### References

External references were consulted on October 26, 2026. Upstream branch links
are background references, not pinned deployed-image specifications.

- [SONiC Dynamic Port Breakout HLD][dpb-hld].
- [Run Time Buffers Configuration Update design][buffer-design].
- [SONiC Configuration Database Manual][config-db-manual].
- [sonic-mgmt Testbed V2 HLD](README.testbed.Testbed_v2.hld.md).
- [sonic-mgmt OCS Integration HLD](README.testbed.OCS.HLD.md).

[dpb-hld]: https://github.com/sonic-net/SONiC/blob/master/doc/dynamic-port-breakout/sonic-dynamic-port-breakout-HLD.md
[buffer-design]: https://github.com/sonic-net/SONiC/wiki/Run-Time-Buffers-Configuration-Update-design
[config-db-manual]: https://github.com/sonic-net/sonic-buildimage/blob/master/src/sonic-yang-models/doc/Configuration.md
