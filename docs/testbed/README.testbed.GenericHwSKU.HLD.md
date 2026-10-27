# Generic HwSKU and Topology Generation

## High Level Design

**Status:** Draft for review. This document describes the local sonic-mgmt
prototype as inspected on October 27, 2026. It is not a claim of upstream
acceptance, support on every platform, or complete nightly-test integration.

### Revision

| Revision | Date | Description |
| --- | --- | --- |
| 0.1 | 2026-10-26 | Initial design covering joint DUT/leaf planning, reviewed topology recipes, installed QoS policy, isolated PTF transport, and guarded deployment/recovery. |
| 0.2 | 2026-10-26 | VLAN-backed best-effort planning, automatic first-eight uplinks, and consolidated add-topo/deploy-mg workflow. |
| 0.3 | 2026-10-26 | Include low-speed cages by default, subject to the same wiring, VLAN eligibility, and explicit protection checks. |
| 0.4 | 2026-10-26 | Separate fixed shared-connection breakout from DUT-only obsolete forwarding cleanup. |
| 0.5 | 2026-10-26 | Shared hardware-neutral IPv6 defaults with an optional IPv4 allocation override and per-testbed overrides. |
| 0.6 | 2026-10-26 | Retain assigned cables with PFC disabled; record failed-save recovery and preparation corrections. |
| 0.7 | 2026-10-27 | Validate optional unused daemon profiles; separate physical/link coverage from CSV-backed traffic provisioning. |
| 0.8 | 2026-10-27 | Remove redundant finalization and the bundled IPv4 overlay; make external destinations optional with default-only routing; document validator phases and daemon startup handling. |
| 0.9 | 2026-10-27 | Reduce validation to physical/input correctness, ownership/recovery, installed YANG, and basic reload/link/save checks; remove repeated policy/asset and strict daemon/database gates. |
| 0.10 | 2026-10-27 | Remove the workspace CLI option; operator commands automatically share per-user/testbed artifact storage. |
| 0.11 | 2026-10-27 | Remove operator output selection and finalization metadata/scaffolding; restrict older-scenario selection to cleanup/recovery. |
| 0.12 | 2026-10-27 | Scope preparation flags to add-topo; remove unused forwarding/internal arguments, unreachable ACL checks, duplicate inventory validation, and the inactive headroom-omission override. |
| 0.13 | 2026-10-27 | Remove automatic DUT/leaf selected-link verification; save directly after successful paired reloads, retaining recovery and host/PTF checks. |
| 0.14 | 2026-10-27 | Limit add-topo to fixed layout/PTF preparation and attachment on existing transport; move full device rendering/YANG to deploy-mg and remove generic root-fanout mutation. |

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
| [Run Time Buffers Configuration Update design][buffer-design] | Select headroom from speed/cable lookup inputs and let the buffer manager own runtime profile generation. | Disabled PFC is not overridden. Rendering uses installed lookups; the active daemon/lookup contract is no longer probed. |
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
| R4 | Maximize mode/operating and lookup-case coverage within valid physical wiring. | CSV VLANs constrain traffic provisioning, not physical child selection; report both coverage scopes. |
| R5 | With an empty source uplink list, select the first eight realized physical DUT ports numerically. | Generated YAML records roles; no matching-mode/speed requirement by default. |
| R6 | Assign physical direction per realized child port, independently of logical forwarding. | Explicit selectors, default downlinks, truthful reciprocal neighbors. |
| R7 | Reuse installed QoS/buffer values and ownership rather than inventing hardware policy. | Reviewed template adapter, installed lookup rows, and per-port PFC decisions. Runtime buffer qualification remains external. |
| R8 | Prepare mappings in add-topo; render and deploy the same frozen layout in deploy-mg. | Immutable plan/prepared/rendered stages, stable ownership ID, and no silent replanning. |
| R9 | Make physical-port, DUT-index, transport-VLAN, and PTF-index mappings explicit. | Resolved facts, generated topology, and rendered transport report. |
| R10 | Require explicit authorization for infrastructure and device mutation. | Generic dry-run/apply gates and separate collect/render/host/device phases. |
| R11 | Check both device reloads before persistence and retain recovery information. | Pairwise stage/apply/save orchestration and private backups. |
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
  add-topo --apply                    deploy-mg --generic
  scenario-owned PTF                 render full configs + YANG
  host VLAN endpoints                -> rendered/ (same ownership ID)
  existing transport untouched        --apply: verify host -> stage both
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

Use one shared `vars/topo_generic.yml`, selected by `topo: generic`, across
supported testbeds. Its hardware-neutral IPv6 defaults are documentation
allocations, not lab reservations. Optional per-testbed allocation overrides
avoid hardware-specific topology copies. No IPv4 override is bundled; explicit
IPv4 recipe/override values remain supported. One family is supported per
scenario, not simultaneous dual-stack. Existing valid custom recipe names
remain compatible, but are not required for different hardware or address pools.

Explicit `--overrides` files merge in low-to-high order. Their paths and order
are retained. All required allocations and selectors must be supplied; unknown
fields and the retired YAML repetition constraint are rejected.
`external_destinations` is optional and omitted from the shared recipe.
Without it, routing uses only a default route through the first traffic-backed
uplink; supplying it additionally allocates one destination route per routed
uplink and validates the extra pool. Routed addressing and the access SVI remain
required in both cases.
An empty uplink list selects the first eight realized physical DUT ports in
numeric order. Generated `topology.yml` receives explicit resolved role lists;
the source recipe stays empty. The current forwarding model also needs a
downlink. Explicit nonempty selectors remain supported.
`--min-same-breakout-uplinks N` is an optional legacy planning CLI input for
explicit selectors, not a recipe field; matching modes/speeds are not required
by default.

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
Low-speed cages are not automatically protected: there is no minimum bandwidth
cutoff or required opt-in flag. They participate when their wiring is eligible,
and their supported combinations and lookup cases
contribute to coverage. Existing sealed scenarios retain their original scope;
use a fresh workspace to include newly eligible cages.

New CLI plans permit children and whole wired cages without CSV VLANs for physical
coverage. They receive PORT/neighbor/QoS configuration, but no automatic link checks,
traffic forwarding, transport VLAN or PTF index. Only traffic-backed endpoints
receive those allocations. The manifest freezes `unmapped_children: physical_only`;
`coverage.json.traffic_coverage` lists unqualified physical-only links independently
of mode/buffer coverage. No missing VLAN becomes an invented tag or shared-trunk
change. Hard protection and complete physical wiring remain mandatory.

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
3. Coverage of the greatest number of distinct lookup speed/cable cases.

Full coverage needs at least one physical cage per required combination.
Separately, each required lookup row needs a distinct matching-speed active child; additional
children reuse cases deterministically. A cable case is a qualification input,
not a measurement of the attached cable. Mode/case gaps remain unqualified but
do not block new best-effort plans satisfying the hard deployment requirements.

Matching-uplink repetition is disabled by default (`scope: none`, minimum zero).
The eight automatic uplinks need not share a mode/speed. With explicit selectors
and a legacy positive CLI minimum, the solver prioritizes a matching group and
its capped count before coverage. Older plans record their original
matching-group constraints.

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
  plan/       sealed physical layouts, roles, forwarding, settings, and input hashes
  prepared/   canonical PORT/PTF order and existing transport; no complete device configs
  rendered/   complete configs; installed validation and transport report
```

| Artifact | Contract |
| --- | --- |
| `manifest.json` | Scenario ID, schema version, identities, layouts, protected cages, policy, provenance, and artifact hashes. |
| `coverage.json` | Required/covered combinations and cases, exclusions, repetition counts, candidate rejections, and search status. |
| `resolved_facts.json` | Exact child pairs, channels, roles, assigned cases, forwarding, DUT indices, and compact PTF indices. |
| `topology.yml` | Generated host bindings, DUT port order, sealed recipe settings, and rendered transport mapping when available. |
| `preparation_report.json` | Canonical device port ordering and existing leaf transport needed for PTF attachment; no QoS/configuration rendering or YANG validation. |
| `dut_config.json`, `leaf_config.json` | Rendered complete reload inputs; present only after rendering. |
| `render_report.json` | Per-device baseline/asset digests, validation results, ownership, transport, and declared daemon outputs when applicable. |

Current manifests use schema version 3. A uniform layout's `speed` is a scalar;
a composite layout's `speed` is an ordered group array. Each child still has
its own scalar speed.

The editable source remains the recorded topology recipe and optional overrides.
There is no separate editable `port_roles.yml` in the current implementation.
Planning records resolved roles, allocations, coverage, and provenance in one
pass. No finalization marker or intermediate finalization stage is needed.

Add-topo plans and prepares canonical PORT/PTF mappings, without a finalization
command or complete device rendering. Review recipe inputs before running it.
Deploy-mg renders the fixed prepared layout without rereading mutable recipes.
Fixing physical coverage requires a fresh workspace, not editing generated JSON.
Retry mapping preparation with add-topo and rendering/YANG failures with deploy-mg.
Existing stages are reused. The scenario ownership ID is fixed by preparation
and preserved during rendering; artifact hashes remain stage-specific provenance.
Remove-topo can clean up prepared PTF resources even before rendering succeeds.
Recovery requires rendered artifacts and existing device snapshots.
Older rendered artifacts remain available for cached lifecycle operations.
Concurrent source edits are unsupported, but no longer detected by hash replay.

An initial plan has `deployable: false`, even when coverage is complete.
New VLAN-scoped plans may have incomplete mode/buffer coverage while
`coverage.deployment_eligible` is true. They still require valid forwarding,
consistent physical connections, successful installed rendering/YANG, and
explicit apply. Invalid forwarding blocks rendering; coverage and repetition
shortfalls are reported rather than rechecked as deployment gates.

Directories are published atomically and existing stages are not overwritten.
Manifest/input/artifact hashes are provenance rather than replayed gates.
Stage/apply retain the validated-config checksum and running-baseline protection,
including a checksum of the actual staged reload file. These are not signatures
or protection from an actor rewriting the entire workspace.
Artifact storage is selected automatically under the system temporary directory;
there is no workspace CLI option. Run lifecycle commands as the same user with
the same temporary root, and preserve the directory for cleanup/recovery.
Older rendered scenarios remain explicitly selectable with `--scenario-dir`
for remove-topo and recover-generic only. Normal add-topo/deploy-mg use automatic
storage exclusively; operator `--output-dir` is removed. Explicit output remains
available in the standalone developer planner.

## 10. Complete configuration rendering

Rendering is separate from legacy minigraph plus golden-config PORT overrides.
It reads each device's running baseline, validates the frozen physical plan
against the installed `portconfig.BreakoutCfg`, and builds a complete reload
input. It uses temporary files but does not reload or save configuration.

| Configuration area | Managed behavior | Preserved or rejected boundary |
| --- | --- | --- |
| `PORT` | Replace selected cage realizations with canonical children. | Preserve protected port definitions; reject unsupported geometry. |
| `BREAKOUT_CFG` | Omit the entire table, including inherited entries. | Protected `PORT` entries remain; selected modes stay in the manifest. |
| Interfaces, VLANs, LAGs, BGP | Retire understood dependencies owned by replaced ports and frozen DUT forwarding-cleanup ports; generate current routed/access/static forwarding. | Preserve other consumers; reject mixed-consumer LAGs/routes, retained subnet/VLAN collisions, and unknown retired-port references. No new LAG/BGP is generated. |
| Neighbor tables | Rebuild affected reciprocal physical neighbors. | Keep unaffected neighbors and truthful local/remote identities; do not spoof types for QoS. |
| DATAACL/EVERFLOW | Inherit effective membership through old lane overlap and owned LAGs. | Conflicting aggregation fails; protected bindings remain. |
| QoS/buffers | Render installed policy for realized ports and explicit roles. | Keep protected bindings/shared policy; reject unsupported conflicts. |
| Management/unrelated state | Carry forward the baseline. | A full-device reload can still interrupt protected traffic. |

Breakout protection is distinct from forwarding ownership. New plans freeze
`dut_forwarding_cleanup` cage/lane mappings for fully wired DUT connections to
other/shared fanouts, unless explicitly excluded. Their existing PORT layout,
speed, physical neighbors, and QoS/buffers stay intact, while obsolete DUT
VLAN/SVI, interface, LAG, and associated route/BGP bindings may be retired.
Wholly retired VLANs also lose their VLAN-scoped DHCP relay entries; retained
VLANs keep their relays. VLANs with retained consumers survive; mixed-consumer
LAGs/routes fail closed. ACL tables/rules survive removal of their last port
binding, with the optional empty `ports` field omitted for installed YANG parsing.
Neither the shared fanout nor the root is cleaned, and the selected leaf's
root-facing trunk is not forwarding-cleaned. Reports identify forwarding-only
cleanup ports separately. Older sealed scenarios retain their original scope;
the new policy requires a fresh workspace.

`--exclude-managed-acls` is an add-topo preparation-only, explicitly recorded opt-out from
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

QoS is **rendered** during deploy-mg and **applied** with the complete
configuration during authorized `deploy-mg`. No new vendor QoS template is
installed by this workflow.

### 11.2 Native lossy and PFC-enabled paths

| Property | Installed PFC disabled | Installed PFC enabled |
| --- | --- | --- |
| Policy selection | Explicit empty `pfc_enable` is authoritative. | Use template-derived priorities/maps and validated inheritance only for omitted fields. |
| Static policy | Keep installed lossy profiles, queues, maps, and schedulers. | Keep required static pools, lossy PGs, egress queues/profiles, and protected policy. |
| Runtime cable input | Supply the assigned cable case; retain it in planning/report metadata too. | Supply the assigned nonzero cable case. |
| Lossless ingress headroom | Do not synthesize or bind headroom. Declare exact optional unused profiles when the installed pool/lookup supports them. | Omit selected lossless PG inputs; let the supported traditional daemon generate the declared profiles/PG bindings. |
| Runtime checks | Check reload success and save readback; no selected-link gate. | Same minimum; no daemon/CONFIG_DB/APPL_DB convergence gate. |

These decisions are per-port, so installed policy can produce a mixed scenario.
The device-level report says `installed_lossless` when lossless expectations
exist; that does not imply every selected port has PFC enabled.
There is no lossy/lossless selection flag. The former
`--enable-lossless-adapter` is removed. Historical report-version compatibility
checks have also been removed; fresh rendering is needed to adopt current policy.

Assigned runtime cable values are retained regardless of PFC policy, including
in existing cable groups for selected ports. Protected cable settings are unchanged.
The inspected traditional daemon can create unused headroom from these
speed/cable events even when PFC is empty. Reports declare optional additions as
`unused_buffer_profiles`, with lookup-backed values for inspection only.
These are not a runtime allowlist. Fresh rendering and installed-image
deployment are still required to qualify the policy.
Cases remain visible in `buffer_policy.lossy_cable_cases`; this is planning
coverage, **not hardware exercise of lossless headroom**. Unreferenced selected
daemon-target profiles inherited from earlier attempts are omitted, but retained
protected/unknown consumers prevent removal. Unrelated profiles are not purged.

### 11.3 Lookup and daemon contract

Buffer numeric values come from each device's installed assets. Both devices
must support the assigned speed/cable cases; their hardware-specific numeric
values need not equal each other. No headroom formula is invented by planning.

Rendering does not query running `buffermgrd` processes, arguments, or lookup data.
It still rejects unsupported PFC-to-PG mapping and missing installed lossless
objects needed to generate configuration. Enabled PFC priorities must map to
same-numbered PGs; PFC-to-queue maps may differ. A selected-port TC-to-PG map
can be derived from installed classification to reach the declared lossless
queues without rewriting protected bindings.

Shared pool policy is preserved, including a running `xoff` omitted by a
template. Conflicting static profiles can receive selected-port aliases with
unchanged installed values. Stale retained daemon-target values are not assumed
to repair themselves. Projected reservations include expected daemon additions.

The input deliberately differs from the converged configuration when daemon
outputs are expected. Verification no longer checks those projections;
save persists the current running state with startup readback. There is no automatic
`config qos reload`. Database/YANG success is not proof that an ASIC accepts
every pool/profile combination.

## 12. Leaf, root, and PTF transport

Each traffic-backed physical link requires one isolated transport VLAN. New plans
freeze the selected DUT endpoint's existing CSV VLAN rather than pooling tags
across endpoints. `transport.vlan_ids: null` uses those IDs; an explicit list
can only restrict them. Live leaf access ownership and tagged trunk membership
are still mandatory, even when an allowlist is supplied. Older scenarios retain
their original explicit/implicit allocation contract. The renderer does not
discover free IDs or build arbitrary root-switch configuration.
Children without CSV-backed endpoints remain physical-only and cannot consume
spare IDs from an allowlist. They have null transport/PTF fields and no generated
routed/access forwarding. At least one traffic-backed uplink and downlink remains
required by the current T0 forwarding model.

For L traffic-provisioned links and V distinct valid candidates, `V < L` is a capacity
shortfall, not proof that any existing path works. Expanding shared transport
requires a separate approved infrastructure operation.

The authoritative prepared mapping, retained during full rendering, is:

```text
resolved DUT child
    -> reciprocal leaf child
    -> preparation_report.json: peer.transport entry
    -> transport VLAN
    -> compact PTF index / eth<index>
```

Generated `topology.yml.generic_transport` carries the transport projection.
Canonical preparation records the complete DUT port order, including protected
ports, independently from compact PTF numbering; rendering must preserve it. Do not choose a capture
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

An authorized add-topo attaches PTF to that existing transport only. It never
invokes root-fanout connection/save playbooks, provisions missing shared VLANs,
or reloads DUT/leaf configurations.

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
not a generic dry run. `recover-generic` needs no selector.
Separate public planning, finalization, and rendering commands have been removed;
their internal stages run under add-topo (layout/mappings) and deploy-mg (full rendering).

### 13.2 Operation boundaries

| Operation | Default effect | Mutation boundary |
| --- | --- | --- |
| Generic `add-topo` with no prepared stage | Collect missing inputs, plan, and prepare canonical PORT/PTF/transport mappings. | Read-only device access and private stages; only `--apply` attaches scenario-owned host/PTF resources to existing transport. |
| Generic `add-topo` with prepared/cached rendered stage | Local-only dry run. | `--apply` attaches owned host/PTF resources; root-fanout/shared trunks remain untouched. |
| Generic `deploy-mg` | Render full configs and validate installed YANG if no rendered stage exists; otherwise reuse it locally. | Rendering reads devices and uses temporary files; only `--apply` authorizes staged DUT/leaf reload and save, without selected-link verification. |
| Generic `remove-topo` | Local-only dry run. | `--apply` removes verified owned host/PTF resources, not device configuration/shared root VLANs. |
| `recover-generic` | Local-only dry run. | `--apply` restores staged device configurations; it does not reconstruct previous host infrastructure. |

These dry-run guarantees apply to the selected **generic** path, not traditional
commands. Fresh add-topo preparation and fresh deploy-mg rendering are not wholly
offline, even though neither applies configuration without `--apply`.

### 13.3 Two-command example

Run from `ansible/`. Set the variables to the selected testbed, inventory,
vault-password file, SONiC leaf, and links file.
The example assumes `topo: generic` and reviewed shared
`vars/topo_generic.yml` defaults, with optional allocation overrides when needed.

```bash
./testbed-cli.sh -t testbed.yaml add-topo "$TB" "$VAULT" \
    --peer-hostname "$LEAF" --links-csv "$LINKS"

./testbed-cli.sh -t testbed.yaml deploy-mg "$TB" "$INV" "$VAULT" \
    --generic
```

Both commands default to dry run. Add-topo may contact devices to collect and
prepare mappings; deploy-mg may contact them to render full configs and validate YANG.
Inventory and the named
recipe default from the testbed. Both commands automatically use the same
per-user/testbed directory; no operator-supplied workspace is needed.
After recipe review, lab reservation, and explicit authorization, append
`--apply` to add-topo and then deploy-mg. A fresh add-topo with `--apply` completes
preparation and then provisions immediately; there is no intermediate freeze gate.
Host/PTF attachment requires successful mapping preparation, not full rendering.
Root-fanout configuration is never changed by the generic path. A later render
failure leaves prepared PTF resources available for retry or remove-topo cleanup.
For inspection first, omit `--apply`, review coverage/preparation and render
reports, then repeat the commands with `--apply`.
Changed inputs require retiring the old topology and archiving its artifact
directory before new preparation; deploy-mg never prepares or replans.

## 14. Failure handling and recovery

### Deployment ordering

The controller checks exact scenario/testbed identity, rendered-stage readiness,
and explicit apply. Deploy-mg first renders/YANG-validates any prepared-only
scenario, requiring the same canonical PORT order and leaf transport. Authorized deploy then:

1. Verifies scenario-owned host/PTF endpoints.
2. Stages **both devices**, checking the validated configuration, running baseline,
   and alias compatibility; saves private running/startup backups.
3. Applies both complete configurations.
4. Checks reload success on both devices.
5. Saves both after both reloads succeed, and reads back saved state.

Each phase must succeed before the next starts. This is phase coordination,
not a distributed atomic transaction. Backups live under
`/var/lib/sonic-generic/<scenario-id>/<role>/` and are not overwritten by a
repeat staging attempt.

| Failure | Behavior |
| --- | --- |
| Invalid input or unknown template contract | Reject rather than invent capabilities or policy. |
| Physical infeasibility or bounded search without a solution | Publish diagnostic coverage; distinguish proven failure from search-limit uncertainty. |
| Mode/buffer coverage shortfall | Report unqualified cases; new best-effort plans may proceed if hard deployment requirements pass. |
| Forwarding/allocation failure | Publish a review-only plan; block rendering. Matching-uplink coverage is informational. |
| Render/YANG/dependency conflict | Do not publish a complete rendered stage; preserve earlier stages for inspection/retry. |
| Running-baseline or staged-config change | Reject deployment rather than overwrite intervening changes or bypass installed YANG validation. |
| Host/container ownership mismatch | Refuse takeover; retire previous topology using its original definition. |
| Stage failure | Abort before device reload; retain diagnostic/staging state. |
| Apply/save failure or handled interruption | Request rollback on both devices; restore only devices with a recorded reload attempt. |
| Recovery failure or controller loss | Retain backups/job identifiers; require explicit manual recovery and out-of-band access as needed. |

There is no automatic DUT/leaf selected-interface link verification. Down links
do not block persistence or trigger rollback. Deployment also does not compare
whole CONFIG_DB contents, inspect APPL_DB, or probe daemon startup/arguments/
lookup fingerprints. Save checks command success and startup readback against
the running snapshot. Down links, runtime policy drift, or missing headroom can
therefore go undetected; this is the explicitly reduced boundary, not hardware
or buffer qualification.

Reload retries are limited to the inspected CLI's explicit pre-mutation
system/SwSS readiness rejection. Failed reloads are not blindly retried or
forced. Asynchronous jobs can outlive controller connectivity; check pending
jobs before repeating recovery.

Recovery reloads the running backup and restores the original startup file and
its metadata. Only a scenario-created alias with the recorded inode/target can
be removed, after configuration restoration. Correct pre-existing aliases are
not removed.

Host/PTF mutations are outside the device configuration rollback transaction.
The generic path never modifies root-fanout connections or shared trunks.
Removing the generic PTF topology is separate from restoring DUT/leaf configs.
An exclusive maintenance window is required; preserved protected definitions
do not imply uninterrupted protected links during full-device reload.

## 15. Validation strategy and current evidence

### Layered acceptance

| Layer | Required check | Does not establish |
| --- | --- | --- |
| Offline inputs/planning | Schema, physical matching, protection, and valid deterministic allocations; coverage is reported. | Electrical compatibility, source immutability, or current lab ownership. |
| Installed rendering | Canonical parser, safe installed-template/lookup interpretation, dependency checks, and installed YANG. | Successful ASIC programming, active daemon lookup agreement, or link training. |
| Runtime configuration | Reload success, unchanged pre-apply baseline/config, and saved-state readback. | Exact rendered-table equality, daemon/buffer convergence, packet forwarding, or losslessness. |
| Host/PTF transport | Endpoint ownership/mappings and host-interface readiness. | DUT/leaf link state, correct routed next hops, or end-to-end forwarding. |
| Operator-run link checks | Selected ports up at both ends; not a deployment gate. | Packet forwarding or losslessness. |
| Data plane | Emulated-neighbor readiness, exact routes/next hops, marked packets with expected egress and rewrites. | All-port, congestion, PFC, or line-rate qualification from a short smoke test. |

Focused offline suites cover channel parsing/protection, uniform/composite
modes, VLAN endpoint scope, best-effort coverage, automatic first-eight uplinks,
legacy repetition, review-only invalid plans, immutable stages, one-invocation
preparation, retry/cached-stage validation, lifecycle selection, QoS policy,
fixed-breakout DUT forwarding cleanup, shared-consumer guards, minimal runtime
checks, validated-config protection, and owned recovery. They are:

- `unit_test_map_breakout_links.py`
- `unit_test_plan_generic_topology.py`
- `unit_test_generic_deployment.py`

The reduced-boundary suites replace obsolete strict-convergence and repeated-policy
tests with YANG, minimal save, validated-config, and recovery regressions.
All **457** focused tests and applicable pre-commit hooks passed after the
validation/cleanup changes and the transport-preparation/device-rendering split.
This is not the full repository's lab test suite or a hardware deployment.

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

### Cable-retention live test, 2026-10-26

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

### Current lifecycle deployment report, 2026-10-27

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
| [generic_topology_cli.py](../../ansible/scripts/generic_topology_cli.py) | Fixed layout/PTF preparation, deferred rendering publication, and paired deployment orchestration. |
| [generic_config.py](../../ansible/scripts/generic_config.py) | Canonical ports, dependency/neighbor reconciliation, forwarding, QoS adaptation, buffer ownership, and YANG validation. |
| [generic_buffers.j2](../../ansible/templates/generic_buffers.j2) | Render-only installed buffer-template adapter. |
| [generic_device_action.py](../../ansible/scripts/generic_device_action.py) | Stage/apply/save/rollback, baseline/config protection, saved-state readback, and alias journal. |
| [generic_devices.yml](../../ansible/generic_devices.yml) | Two-device remote execution, private staging, asynchronous reloads, and reload/save result checks. |
| [generic_host.yml](../../ansible/generic_host.yml) | Unique host resolution and scenario-owned PTF/VLAN endpoint lifecycle. |
| [testbed-cli.sh](../../ansible/testbed-cli.sh) | Shared-command routing and explicit generic stage commands. |
| [topo_generic.yml](../../ansible/vars/topo_generic.yml) | Shared hardware-neutral IPv6 recipe defaults; not resource reservations. |
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
