# Generic HwSKU and Topology Generation

## High Level Design

**Status:** Draft for review. This document describes the local sonic-mgmt
prototype as inspected on October 26, 2026. It is not a claim of upstream
acceptance, support on every platform, or complete nightly-test integration.

### Revision

| Revision | Date | Description |
| --- | --- | --- |
| 0.1 | 2026-10-26 | Initial design covering joint DUT/leaf planning, reviewed topology recipes, installed QoS policy, isolated PTF transport, and guarded deployment/recovery. |

### Table of Contents

- [1. Overview and motivation](#1-overview-and-motivation)
- [2. Relationship to existing designs](#2-relationship-to-existing-designs)
- [3. Requirements](#3-requirements)
- [4. Scope](#4-scope)
- [5. Definitions and design invariants](#5-definitions-and-design-invariants)
- [6. Architecture](#6-architecture)
- [7. Inputs and recipe contract](#7-inputs-and-recipe-contract)
- [8. Joint breakout planning](#8-joint-breakout-planning)
- [9. Artifacts and review lifecycle](#9-artifacts-and-review-lifecycle)
- [10. Complete configuration rendering](#10-complete-configuration-rendering)
- [11. QoS and buffer ownership](#11-qos-and-buffer-ownership)
- [12. Leaf, root, and PTF transport](#12-leaf-root-and-ptf-transport)
- [13. CLI and deployment lifecycle](#13-cli-and-deployment-lifecycle)
- [14. Failure handling and recovery](#14-failure-handling-and-recovery)
- [15. Validation strategy and current evidence](#15-validation-strategy-and-current-evidence)
- [16. Alternatives considered](#16-alternatives-considered)
- [17. Limitations and future work](#17-limitations-and-future-work)
- [18. Implementation map](#18-implementation-map)
- [19. References](#19-references)

## 1. Overview and motivation

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

This HLD explains the architecture and design decisions. The
[operator/developer guide](generic_hwsku_port_config.md) contains detailed
procedures and also documents a separate legacy PORT-override workflow.

## 2. Relationship to existing designs

The document follows the requirements, components, data-contract, workflow, and
validation structure used by existing sonic-mgmt HLDs. The following designs
provide context, not a claim that their entire implementations are used here.

| Reference | Relevant idea | Boundary of this design |
| --- | --- | --- |
| [Testbed V2 HLD](README.testbed.Testbed_v2.hld.md) | Separate physical connection metadata from logical VLAN connectivity and testbed lifecycle. | This prototype consumes connection-graph files and explicit transport allocations. It does not implement Testbed V2's connection database, daemons, or dynamic allocation service. |
| [OCS integration HLD](README.testbed.OCS.HLD.md) | Separate architecture from setup instructions; validate configuration, operational state, and traffic independently. | No OCS control or optical-circuit orchestration is introduced. |
| [Dynamic Port Breakout HLD][dpb-hld] | Use platform-advertised modes, ordered lanes, and canonical child-port naming; consider dependent configuration. | This prototype renders complete configurations and reloads two devices. It does not promise DPB's nondisruptive runtime breakout behavior, and intentionally emits no `BREAKOUT_CFG`. |
| [Run Time Buffers Configuration Update design][buffer-design] | Select headroom from speed/cable lookup inputs and let the buffer manager own runtime profile generation. | Installed policy must actually enable PFC. Disabled PFC is not overridden, and the active daemon/lookup contract is checked rather than assumed. |
| [Configuration Database Manual][config-db-manual] | Distinguish traditional and dynamic buffer models and their configuration objects. | Only the inspected single-ASIC traditional backend is supported. A buffer pool's `mode: dynamic` is not the same as `buffer_model: dynamic`. |

Upstream documents describe general contracts. The installed device assets and
the inspected prototype determine compatibility for a particular deployment.
In particular, a shared template pathname is not evidence that an installed
template is identical to current upstream `master`.

## 3. Requirements

| ID | Requirement | Enforcement or evidence |
| --- | --- | --- |
| R1 | Derive ports from advertised platform capabilities rather than maintaining a static file for every layout. | Platform parsing plus independent installed canonical-parser validation. |
| R2 | Select compatible DUT and SONiC-leaf layouts jointly over actual wiring. | Exact channel-set/speed matching on both endpoints. |
| R3 | Preserve resources outside the managed scope. | Whole-cage protection, dependent-configuration checks, baseline/asset drift checks. |
| R4 | Target every eligible DUT mode/operating combination and every in-scope lookup speed/cable case. | Explicit coverage report; incomplete plans cannot render/deploy. |
| R5 | Provide at least N physical uplinks for one complete eligible combination; default N is four. | Initial solver input, frozen manifest policy, and finalization/render validation. |
| R6 | Assign physical direction per realized child port, independently of logical forwarding. | Explicit selectors, default downlinks, truthful reciprocal neighbors. |
| R7 | Reuse installed QoS/buffer values and ownership rather than inventing hardware policy. | Reviewed template adapter, installed lookup rows, per-port PFC decisions, daemon verification. |
| R8 | Permit operator review after layout selection without silently replanning. | Immutable layout plus finalization of edited recorded recipe sources. |
| R9 | Make physical-port, DUT-index, transport-VLAN, and PTF-index mappings explicit. | Resolved facts, generated topology, and rendered transport report. |
| R10 | Require explicit authorization for infrastructure and device mutation. | Generic dry-run/apply gates and separate collect/render/host/device phases. |
| R11 | Validate both devices before persistence and retain recovery information. | Pairwise stage/apply/verify/save orchestration and private backups. |
| R12 | Preserve traditional lifecycle behavior without topology-name heuristics. | Content-based add/remove routing; explicit generic deploy selector. |
| R13 | Keep complete configurations and inherited credentials private. | Private workspaces, restricted files, suppressed configuration-bearing output. |

Coverage, database convergence, link state, and packet correctness are separate
requirements. None is a substitute for the others.

## 4. Scope

### In scope

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

### Out of scope

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

## 5. Definitions and design invariants

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

- A cage selects one mode advertised for that cage. All its realized children
  participate unless the cage was protected before planning.
- A child consumes complete wiring channels and matches exactly one complete
  peer child at the same speed. Peer mode names need not be identical.
- Protected cages are not reassigned to make a plan appear complete.
- Selecting `Ethernet0` assigns that realized child, not every sibling of a cage
  that happens to share its name.
- The realized `PORT` table is authoritative. Selected mode metadata lives in
  the manifest; the entire output `BREAKOUT_CFG` table is omitted.
- A rendered scenario is not a hardware qualification result.

## 6. Architecture

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
                     plan/ (frozen layout)
                            |
                  operator reviews/edits recipe
                            |
                            v
                 finalized/ (sealed settings)
                            |
             read-only installed rendering on both devices
                            |
                            v
                 rendered/ (complete private configs)
                            |
          +-----------------+-------------------+
          |                                     |
          v                                     v
  add-topo --apply                    deploy-mg --generic --apply
  scenario-owned PTF                 verify host -> stage both
  host VLAN endpoints                -> apply both -> verify both
  existing root binding              -> save both
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

## 7. Inputs and recipe contract

| Input | Authority and purpose |
| --- | --- |
| `testbed.yaml` or legacy testbed CSV | DUT identity, topology name, inventory, host/group selector, and PTF management/container settings. |
| `vars/topo_<name>.yml` | Reviewed physical selectors, forwarding allocations, exclusions, and transport IDs. |
| Maximum-breakout links CSV | Actual DUT/leaf channels, remote endpoints, and explicit transport/FEC/AN/link-training attributes. |
| DUT and leaf `platform.json` | Ordered hardware lanes, aliases, and advertised modes. |
| Planning `pg_profile_lookup.ini` | Supported DUT speed/cable cases and their vendor-supplied values. |
| Installed device assets | Canonical parser, actual lookup files, QoS/buffer templates, device identity, and YANG models used during rendering. |
| Running configuration on each device | Preserved baseline and ownership/dependency context, fingerprinted for deployment. |
| Ansible inventory | Authenticated connections and existing host/fanout settings, not an implicit forwarding-recipe override source. |

Collection prefers platform-level `platform.json` and `pg_profile_lookup.ini`,
with HwSKU fallback only when the corresponding platform file is absent.
Invalid or incomplete preferred assets are not repaired by merging fallback
data. Rendering prefers HwSKU QoS templates, with platform-level fallback when
absent. Source selection and asset contents are recorded for drift checks.

### Recipe example

The following is a complete **offline illustration**, not a lab reservation.
Child names must match the selected device, and the addresses/VLAN must be
replaced with approved allocations before deployment. `transport.vlan_ids: null`
requires sufficient valid existing transport; it does not request allocation.

```yaml
topology: {}
generic_topology:
  physical_links:
    uplinks: [Ethernet0, Ethernet1, Ethernet8, Ethernet9]
    downlinks: []
  routed_interfaces:
    address_pool: 2001:db8:1::/64
    prefix_length: 127
  access_vlan:
    vlan_id: 1000
    subnet: 2001:db8:2::/64
  external_destinations:
    address_pool: 2001:db8:3::/64
    prefix_length: 128
  constraints:
    reserved_networks: []
    reserved_vlan_ids: []
  transport:
    vlan_ids: null
```

The same schema can live in `topo_generic_a.yml`, `topo_generic_b.yml`, or another
validly named recipe. A testbed entry's `topo: generic_a` selects
`vars/topo_generic_a.yml`; the name is not a topology-family prefix contract.

Explicit `--overrides` files merge in low-to-high order. Their paths and order
are retained. All required allocations and selectors must be supplied; unknown
fields and the retired YAML repetition constraint are rejected.
`--min-same-breakout-uplinks N` is a planning CLI input, not a recipe field.

Selectors absent from the realized layout are reported and ignored. Every
remaining selected child defaults to downlink. Duplicate/malformed selectors
and opposing explicit roles on an existing child are errors.
Reserved networks/VLANs are exclusions, not allocation pools.

## 8. Joint breakout planning

### 8.1 Normalize channels and protect resources

Expand the advertised maximum-child geometry using ordered platform lanes;
do not equate hardware lane IDs with Ethernet suffixes. Resolve source aliases,
reject ambiguous geometry or overlapping resources, and map both channel ends.

Protect whole cages touched by excluded ports, incomplete wiring, or
out-of-scope neighbors, then propagate protection across coupled cages.
Dedicated cages whose maximum aggregate advertised bandwidth is at most 25G
are protected by default. `--include-low-speed-cages` explicitly opts them back
in; it does not cancel other protection.

### 8.2 Enumerate legal choices and physical constraints

For every eligible cage, enumerate advertised modes and lookup-backed operating
combinations. Uniform modes use one selected speed for their group.
Composite modes retain ordered groups and explicit total lane counts, such as
`4x100G(4)+1x400G(4)`. This is permitted only when advertised; an arbitrary
`1x100G+1x200G` mixture is not synthesized.

Reject a candidate if a child splits a wiring channel, spans incompatible peer
cages, or aggregates conflicting explicit AN/FEC/link-training attributes.
Prune choices that have no compatible counterpart. Matching uses complete
channel sets and individual speeds, allowing reversed channel order.

### 8.3 Coverage and search objective

The solver chooses one choice for every eligible DUT and leaf cage. Its
lexicographic preference is:

1. A layout that can receive the requested forwarding allocations.
2. Physical-cage coverage of the greatest number of required DUT combinations.
3. One combination satisfying the matching-uplink minimum.
4. The largest matching-uplink count, capped at that minimum.
5. Coverage of the greatest number of distinct lookup speed/cable cases.

Every required combination needs at least one physical cage. Separately, each
required lookup row needs a distinct matching-speed active child; additional
children reuse cases deterministically. A cable case is a qualification input,
not a measurement of the attached cable.

N matching uplinks means N physical DUT children in **one full mode/operating
combination**. Two `2x200G` cages can provide four matching uplinks when both
children of each are uplinks. Four uplinks split across different combinations
cannot pool their counts. Composite-mode counts use the full ordered
combination, not separate per-component requirements.

Lookup speeds confined to protected DUT cages are reported as excluded cases.
Speeds not advertised anywhere remain visible as unmet requirements.
In-scope `0m` cable cases are rejected for the supported traditional
daemon-owned model.

Search is bounded, by default at 100000 states. Capacity bounds do not count
mutually exclusive choices from a single cage as simultaneous resources.
A found best-known layout survives search exhaustion, but optimality is
reported as unproven. Exhaustion without a layout means unknown feasibility,
not proven impossibility.

### 8.4 Resolve roles and forwarding

Match roles against realized child names, allocate routed address pairs and
external destination prefixes, and allocate the shared downlink VLAN/SVI and
host endpoints. The current scenario requires at least one actual uplink and
downlink. Numeric port ordering makes forwarding allocation deterministic;
the default route uses the first routed uplink.

Produce exactly one reciprocal DUT/leaf connection for every selected child.
Validate identities, child membership, channel sets, speed, and case assignment
before publishing artifacts and again before remote rendering.

## 9. Artifacts and review lifecycle

The workspace has fixed, private stages rather than an implicit "latest run":

```text
WORKSPACE/
  plan/       frozen physical layouts; proposed roles/settings
  finalized/  same layouts; reviewed and sealed roles/settings
  rendered/   complete configs; installed validation and transport report
```

| Artifact | Contract |
| --- | --- |
| `manifest.json` | Scenario ID, schema version, identities, layouts, protected cages, policy, provenance, and artifact hashes. |
| `coverage.json` | Required/covered combinations and cases, exclusions, repetition counts, candidate rejections, and search status. |
| `resolved_facts.json` | Exact child pairs, channels, roles, assigned cases, forwarding, DUT indices, and compact PTF indices. |
| `topology.yml` | Generated host bindings, DUT port order, sealed recipe settings, and rendered transport mapping when available. |
| `dut_config.json`, `leaf_config.json` | Rendered complete reload inputs; present only after rendering. |
| `render_report.json` | Per-device baseline/asset digests, validation results, ownership, transport, and declared daemon outputs when applicable. |

Current manifests use schema version 3. A uniform layout's `speed` is a scalar;
a composite layout's `speed` is an ordered group array. Each child still has
its own scalar speed.

The editable source remains the recorded topology recipe and optional overrides.
There is no separate editable `port_roles.yml` in the current implementation.
Finalization rereads those sources in their recorded order, checks for concurrent
edits, recomputes roles/forwarding/coverage, and seals their hashes **without
calling the layout solver**. It may update the qualifying repetition target
after role edits; rendering must then honor that sealed target.

`render-generic` performs finalization if needed. Once `finalized/` exists,
rendering uses it without rereading mutable recipe contents. Fixing missing
physical coverage requires replanning, not editing generated JSON. After
finalization, use a fresh workspace for a changed scenario.

An initial plan has `deployable: false`, even when coverage is complete.
Incomplete plans are review-only. Only complete, finalized, successfully
rendered artifacts become eligible for explicit apply.

Directories are published atomically and existing stages are not overwritten.
SHA-256 digests detect accidental changes and bind artifacts to their manifest;
they are not signatures, a resource reservation, or protection from a privileged
actor rewriting the entire workspace.
The default workspace is under the system temporary directory, so a private
persistent `--workspace` is recommended for long-lived deployment/recovery.

## 10. Complete configuration rendering

Rendering is separate from legacy minigraph plus golden-config PORT overrides.
It reads each device's running baseline, validates the frozen physical plan
against the installed `portconfig.BreakoutCfg`, and builds a complete reload
input. It uses temporary files but does not reload or save configuration.

| Configuration area | Managed behavior | Preserved or rejected boundary |
| --- | --- | --- |
| `PORT` | Replace selected cage realizations with canonical children. | Preserve protected port definitions; reject unsupported geometry. |
| `BREAKOUT_CFG` | Omit the entire table, including inherited entries. | Protected `PORT` entries remain; selected modes stay in the manifest. |
| Interfaces, VLANs, LAGs, BGP | Retire understood dependencies owned by replaced ports; generate current routed/access/static forwarding. | Preserve unowned objects; reject shared protected LAGs, retained subnet/VLAN collisions, and unknown retired-port references. No new LAG/BGP is generated. |
| Neighbor tables | Rebuild affected reciprocal physical neighbors. | Keep unaffected neighbors and truthful local/remote identities; do not spoof types for QoS. |
| DATAACL/EVERFLOW | Inherit effective membership through old lane overlap and owned LAGs. | Conflicting aggregation fails; protected bindings remain. |
| QoS/buffers | Render installed policy for realized ports and explicit roles. | Keep protected bindings/shared policy; reject unsupported conflicts. |
| Management/unrelated state | Carry forward the baseline. | A full-device reload can still interrupt protected traffic. |

`--exclude-managed-acls` is a render-only, explicitly recorded opt-out from
DATAACL/EVERFLOW bindings on managed ports. It is not permission to delete ACL
rules, tables, mirror sessions, management ACLs, or unknown dependencies.

The DUT output identity is `<base-HwSKU>_generic`; the leaf identity is unchanged.
This is an alias to existing base assets, not a newly installed SKU package.
Rendering creates no device alias. Authorized apply creates the sibling symlink
only if safe, reuses a correct existing alias without claiming ownership, and
journals a newly created alias for recovery. Repeated runs do not add suffixes.

Installed YANG validation and reference checks run before publication. Complete
configs inherit private baseline data and must not be attached to public PRs,
demo output, or logs. Use selected coverage/report fields for demonstrations.

## 11. QoS and buffer ownership

### 11.1 Roles choose policy; installed templates provide values

```text
Realized PORT + physical roles + truthful device identity
                              |
                              v
           installed HwSKU/platform qos.json.j2
             + reviewed render-only role adapter
                              |
                              v
       PORT_QOS_MAP / QUEUE / classifier / buffer bindings
```

The installed shared `qos_config.j2` contract uses uplink/downlink lists.
The temporary adapter supplies explicit lists and bypasses only its inferred
neighbor-direction classification. It preserves truthful neighbor tables and
the installed policy, renders once, and does not require two vendor-specific
macros. Unknown wrapper/classifier structures fail rather than receiving guessed
variables. Installed files are not overwritten.

DUT lists follow resolved physical roles. Selected transport-leaf ports are
downlinks for this adapter. Physical role does not itself determine whether a
port is lossless; installed rendered/inherited PFC policy determines that.

QoS is **rendered** during `render-generic` and **applied** with the complete
configuration during authorized `deploy-mg`. No new vendor QoS template is
installed by this workflow.

### 11.2 Native lossy and PFC-enabled paths

| Property | Installed PFC disabled | Installed PFC enabled |
| --- | --- | --- |
| Policy selection | Explicit empty `pfc_enable` is authoritative. | Use template-derived priorities/maps and validated inheritance only for omitted fields. |
| Static policy | Keep installed lossy profiles, queues, maps, and schedulers. | Keep required static pools, lossy PGs, egress queues/profiles, and protected policy. |
| Runtime cable input | Omit selected lossy ports from every runtime cable group; retain assigned cases in planning/report metadata. | Supply the assigned nonzero cable case. |
| Lossless ingress headroom | Do not synthesize or expect selected lossless headroom/PGs. | Omit selected lossless PG inputs; let the supported traditional daemon generate the declared profiles/PG bindings. |
| Runtime verification | Verify complete rendered configuration without arbitrary buffer drift. | Additionally wait for declared CONFIG_DB/APPL_DB daemon outputs. |

These decisions are per-port, so installed policy can produce a mixed scenario.
The device-level report says `installed_lossless` when lossless expectations
exist; that does not imply every selected port has PFC enabled.
There is no lossy/lossless selection flag. The former
`--enable-lossless-adapter` is removed; old override artifacts are rejected for
new deployment but retained for recovery.

The lossy cable omission prevents the inspected traditional daemon from creating
unused headroom from speed/cable events even when PFC is empty.
Cases remain visible in `buffer_policy.lossy_cable_cases`; this is planning
coverage, **not hardware exercise of lossless headroom**. Unreferenced selected
daemon-target profiles inherited from earlier attempts are omitted, but retained
protected/unknown consumers prevent removal. Unrelated profiles are not purged.

### 11.3 Lookup and daemon contract

Buffer numeric values come from each device's installed assets. Both devices
must support the assigned speed/cable cases; their hardware-specific numeric
values need not equal each other. No headroom formula is invented by planning.

For PFC-enabled ports, rendering checks the actual running traditional
`buffermgrd`, its `-l` lookup, and agreement with the selected installed rows.
Dynamic-calculation startup, divergent lookup data, unsupported PFC-to-PG
mapping, and missing lossless objects fail. Enabled PFC priorities must map to
same-numbered PGs; PFC-to-queue maps may differ. A selected-port TC-to-PG map
can be derived from installed classification to reach the declared lossless
queues without rewriting protected bindings.

Shared pool policy is preserved, including a running `xoff` omitted by a
template. Conflicting static profiles can receive selected-port aliases with
unchanged installed values. Stale retained daemon-target values are not assumed
to repair themselves. Projected reservations include expected daemon additions.

The input deliberately differs from the converged configuration when daemon
outputs are expected. Verification permits only those declared additions and
save persists the verified converged running state. There is no automatic
`config qos reload`. Database/YANG success is not proof that an ASIC accepts
every pool/profile combination.

## 12. Leaf, root, and PTF transport

Each selected physical link requires one isolated transport VLAN. With explicit
`transport.vlan_ids`, IDs must already be reserved/provisioned on the tagged
leaf/root/host path and must not have unowned access consumers.
With `null`, only explicit source connection-graph IDs with valid running leaf
ownership may be reused. The renderer does not discover free IDs or build
arbitrary root-switch configuration.

For L selected links and V distinct valid candidates, `V < L` is a capacity
shortfall, not proof that any existing path works. Expanding shared transport
requires a separate approved infrastructure operation.

The authoritative rendered mapping is:

```text
resolved DUT child
    -> reciprocal leaf child
    -> render_report.json: peer.transport entry
    -> transport VLAN
    -> compact PTF index / eth<index>
```

Generated `topology.yml.generic_transport` carries the transport projection.
Canonical rendering updates the complete DUT port order, including protected
ports, independently from compact PTF numbering. Do not choose a capture
interface by matching an Ethernet suffix.

The host playbook resolves `testbed.server` as a literal host or group,
intersected with both `servers` and `vm_host`, and requires exactly one result
before remote host tasks. It preserves inventory authentication and checks the
existing shared NIC's state/MTU instead of changing the shared NIC.

Container ownership uses `sonic.generic.scenario`; endpoint aliases use
`sonic-generic:<scenario-id>`. Existing unlabelled or different-scenario
containers/endpoints are rejected, not adopted. Existing no-VM binding helpers
provide PTF management and data interfaces. Removal checks ownership before
deleting resources and leaves shared root VLANs intact.

An authorized add-topo also invokes existing root fanout connection logic,
including its running-to-startup save. It is not merely container creation.
This does not provision missing arbitrary transport VLANs or reload DUT/leaf.

PTF endpoint creation does not create a persistent ARP/NDP responder. Tests must
initialize and maintain their emulated neighbors; static routes alone do not
guarantee usable next hops or ASIC route programming.

## 13. CLI and deployment lifecycle

### 13.1 Lifecycle selection

For unflagged `add-topo` and `remove-topo`:

1. Read exactly one matching testbed entry without legacy topology side effects.
2. Validate its `topo` name and load `vars/topo_<topo>.yml`.
3. A valid `generic_topology` section selects the generic lifecycle.
4. A valid mapping without that section selects the traditional lifecycle.
5. Missing/malformed files or invalid generic recipe structure fail before either path
   mutates infrastructure.

Automatic preparation receives the matching named recipe unless `--recipe`
overrides it. A generic-looking name without the marker is still traditional.
Legacy multi-DUT entries are not rejected by generic-only detection.
Explicit `--generic` remains a compatibility override for add/remove and
bypasses automatic topology-file detection.

`deploy-mg` remains explicit: **`--generic` is required regardless of name or
recipe content**. Omitting it selects legacy minigraph deployment, which is
not a generic dry run. Explicit `plan-generic`, `finalize-generic`,
`render-generic`, and `recover-generic` need no selector.
Direct `plan-generic` defaults to `vars/topo_generic.yml`; custom names require
an explicit `--recipe`.

### 13.2 Operation boundaries

| Operation | Default effect | Mutation boundary |
| --- | --- | --- |
| `plan-generic` | Offline when all snapshots are supplied; otherwise authenticated read-only collection. | Creates local plan/snapshots; no live configuration changes. |
| `finalize-generic` | Local review finalization without replanning. | Creates a new sealed stage only. |
| `render-generic` | Read-only device inspection/rendering with temporary files. | Creates private complete configs; no reload/save. |
| Generic `add-topo` with no rendered stage | Freeze a plan; with `--finalize-roles`, finalize/render reviewed inputs. | Initial planning stops for review even with `--apply`; collection/render may contact devices. |
| Generic `add-topo` with rendered stage | Local-only dry run. | `--apply` provisions owned host/PTF resources and invokes existing root binding/save. |
| Generic `deploy-mg` | Local-only dry run of rendered scenario. | `--apply` authorizes staged DUT/leaf reload, verify, and save. |
| Generic `remove-topo` | Local-only dry run. | `--apply` removes verified owned host/PTF resources, not device configuration/shared root VLANs. |
| `recover-generic` | Local-only dry run. | `--apply` restores staged device configurations; it does not reconstruct previous host infrastructure. |

These dry-run guarantees apply to the selected **generic** path, not traditional
commands. A default add-topo that still needs planning/rendering is not wholly
offline, even though it does not apply configuration.

### 13.3 Explicit staged example

Run from `ansible/`. Set the variables to the selected testbed, inventory,
vault-password file, SONiC leaf, links file, and a new private workspace.
The example assumes `topo: generic_a` and a reviewed
`vars/topo_generic_a.yml`.

```bash
./testbed-cli.sh -t testbed.yaml plan-generic "$TB" \
    --inventory "$INV" --vault-password-file "$VAULT" \
    --peer-hostname "$LEAF" --links-csv "$LINKS" \
    --recipe vars/topo_generic_a.yml --workspace "$WORK"

# Review plan/coverage.json and edit the recorded recipe if required.
./testbed-cli.sh -t testbed.yaml finalize-generic "$TB" --workspace "$WORK"

./testbed-cli.sh -t testbed.yaml render-generic "$TB" "$INV" "$VAULT" \
    --workspace "$WORK"

./testbed-cli.sh -t testbed.yaml add-topo "$TB" "$VAULT" \
    --workspace "$WORK"

./testbed-cli.sh -t testbed.yaml deploy-mg "$TB" "$INV" "$VAULT" \
    --generic --workspace "$WORK"
```

The final two commands are dry runs of an existing rendered stage.
Only after review, lab reservation, and explicit authorization should an
operator append `--apply` to add-topo and then deploy-mg.
The separate automatic add-topo path uses `--finalize-roles` to confirm review;
it cannot skip review merely because `--apply` was supplied.

## 14. Failure handling and recovery

### Deployment ordering

The controller verifies scenario integrity/testbed settings and rejects removed
lossless-override artifacts. Authorized deploy then:

1. Verifies scenario-owned host/PTF endpoints.
2. Stages **both devices**, checking their baseline, installed assets, lookup
   selection, and alias compatibility; saves private running/startup backups.
3. Applies both complete configurations.
4. Verifies both configurations, declared daemon outputs, and selected links.
5. Saves both only after both have verified, and reads back saved state.

Each phase must succeed before the next starts. This is phase coordination,
not a distributed atomic transaction. Backups live under
`/var/lib/sonic-generic/<scenario-id>/<role>/` and are not overwritten by a
repeat staging attempt.

| Failure | Behavior |
| --- | --- |
| Invalid input or unknown template contract | Reject rather than invent capabilities or policy. |
| Physical infeasibility or bounded search without a solution | Publish diagnostic coverage; distinguish proven failure from search-limit uncertainty. |
| Coverage/allocation shortfall | Publish a review-only plan; block rendering/deployment. |
| Render/YANG/dependency conflict | Do not publish a complete rendered stage; preserve earlier stages for inspection/retry. |
| Baseline/installed-asset/lookup drift | Reject stale deployment; collect/render fresh rather than overwrite changed state. |
| Host/container ownership mismatch | Refuse takeover; retire previous topology using its original definition. |
| Stage failure | Abort before device reload; retain diagnostic/staging state. |
| Apply/verify/save failure or handled interruption | Request rollback on both devices; restore only devices with a recorded reload attempt. |
| Recovery failure or controller loss | Retain backups/job identifiers; require explicit manual recovery and out-of-band access as needed. |

CONFIG_DB and, where applicable, APPL_DB verification allow only declared daemon
additions. Equivalent grouped PG keys are normalized, overlapping bindings
rejected, and missing/empty tables treated equivalently. Unexpected profiles or
protected-state changes are failures, not tolerated background convergence.

Reload retries are limited to the inspected CLI's explicit pre-mutation
system/SwSS readiness rejection. Failed reloads are not blindly retried or
forced. Asynchronous jobs can outlive controller connectivity; check pending
jobs before repeating recovery.

Recovery reloads the running backup and restores the original startup file and
its metadata. Only a scenario-created alias with the recorded inode/target can
be removed, after configuration restoration. Correct pre-existing aliases are
not removed.

Host/root mutations are outside the device configuration rollback transaction.
Removing the generic PTF topology is separate from restoring DUT/leaf configs.
An exclusive maintenance window is required; preserved protected definitions
do not imply uninterrupted protected links during full-device reload.

## 15. Validation strategy and current evidence

### Layered acceptance

| Layer | Required check | Does not establish |
| --- | --- | --- |
| Offline inputs/planning | Schema, physical matching, protection, coverage, deterministic allocations, role/finalization integrity. | Electrical compatibility or current lab ownership. |
| Installed rendering | Canonical parser, installed templates/lookups, dependency checks, YANG validation, baseline/asset hashes. | Successful ASIC programming or link training. |
| Runtime configuration | CONFIG_DB plus declared APPL_DB outputs; no unrelated drift; saved-state readback. | Packet forwarding, losslessness, or every hardware constraint. |
| Operational links/transport | Selected ports up, correct endpoint ownership/mappings, functional trunks. | Correct routed next hops or end-to-end packet headers. |
| Data plane | Emulated-neighbor readiness, exact routes/next hops, marked packets with expected egress and rewrites. | All-port, congestion, PFC, or line-rate qualification from a short smoke test. |

Focused offline suites cover channel parsing/protection, uniform/composite
modes, every-combination coverage, one-combination repetition, review-only
plans, immutable finalization, lifecycle selection, QoS policy, daemon
convergence, drift, and owned recovery. They are:

- `unit_test_map_breakout_links.py`
- `unit_test_plan_generic_topology.py`
- `unit_test_generic_deployment.py`

Immediately before this documentation revision, all **408** tests in those
three suites passed, together with applicable pre-commit hooks, Bash syntax,
and whitespace checks. This is not the full repository's lab test suite.

### Demonstrated instance

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

### Remaining acceptance work

Before treating this as repeatable qualification, validate cold/warm neighbor
behavior with maintained responders, all selected mappings and traffic paths,
isolation, save/reboot/recovery behavior, and repeated-run stability.
Lossless operation additionally requires installed PFC-enabled policy, valid
hardware pool/headroom combinations, ASIC programming checks, and actual
PFC/congestion traffic tests. A lossy deployment cannot substitute for those.

## 16. Alternatives considered

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

## 17. Limitations and future work

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

## 18. Implementation map

Paths are relative to the repository root; linked source is the implementation
authority for this draft.

| Component | Responsibility |
| --- | --- |
| [map_breakout_links.py](../../ansible/scripts/map_breakout_links.py) | Mode/channel parsing, inventory normalization, and protection propagation. |
| [plan_generic_topology.py](../../ansible/scripts/plan_generic_topology.py) | Recipe validation, lifecycle detection helper, joint solver, coverage, allocations, workspace, and plan publication. |
| [collect_generic_device.py](../../ansible/scripts/collect_generic_device.py), [collect_generic_inputs.yml](../../ansible/collect_generic_inputs.yml) | Authenticated read-only input collection and provenance. |
| [generic_topology_cli.py](../../ansible/scripts/generic_topology_cli.py) | Integrity checks, finalization, automatic preparation, rendering publication, and paired deployment orchestration. |
| [generic_config.py](../../ansible/scripts/generic_config.py) | Canonical ports, dependency/neighbor reconciliation, forwarding, QoS adaptation, buffer ownership, and YANG validation. |
| [generic_buffers.j2](../../ansible/templates/generic_buffers.j2) | Render-only installed buffer-template adapter. |
| [generic_device_action.py](../../ansible/scripts/generic_device_action.py) | Stage/apply/verify/save/rollback, drift checks, daemon convergence, and alias journal. |
| [generic_devices.yml](../../ansible/generic_devices.yml) | Two-device remote execution, private staging, asynchronous reloads, and operational link checks. |
| [generic_host.yml](../../ansible/generic_host.yml) | Unique host resolution and scenario-owned PTF/VLAN endpoint lifecycle. |
| [testbed-cli.sh](../../ansible/testbed-cli.sh) | Shared-command routing and explicit generic stage commands. |
| [topo_generic.yml](../../ansible/vars/topo_generic.yml) | Shared editable recipe with synthetic selectors and unset allocations; supply approved testbed settings. |
| [Generic unit tests](../../tests/common/unit_tests/) | Three focused offline regression suites named in Section 15. |

## 19. References

External references were consulted on October 26, 2026. Upstream branch links
are background references, not pinned deployed-image specifications.

- [SONiC Dynamic Port Breakout HLD][dpb-hld].
- [Run Time Buffers Configuration Update design][buffer-design].
- [SONiC Configuration Database Manual][config-db-manual].
- [sonic-mgmt Testbed V2 HLD](README.testbed.Testbed_v2.hld.md).
- [sonic-mgmt OCS Integration HLD](README.testbed.OCS.HLD.md).
- [Generic HwSKU operator/developer guide](generic_hwsku_port_config.md).

[dpb-hld]: https://github.com/sonic-net/SONiC/blob/master/doc/dynamic-port-breakout/sonic-dynamic-port-breakout-HLD.md
[buffer-design]: https://github.com/sonic-net/SONiC/wiki/Run-Time-Buffers-Configuration-Update-design
[config-db-manual]: https://github.com/sonic-net/sonic-buildimage/blob/master/src/sonic-yang-models/doc/Configuration.md
