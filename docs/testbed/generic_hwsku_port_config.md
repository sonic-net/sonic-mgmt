# Generic HwSKU PORT Table Generation — Without port_config.ini

For the joint DUT/leaf architecture, requirements, ownership boundaries, and
validation strategy, see the [Generic HwSKU and Topology HLD](README.testbed.GenericHwSKU.HLD.md).
This guide covers operational details for both that generic workflow and the
separate legacy PORT-override path.

## Problem

Each HwSKU variant (e.g., `Arista-7060X6-64PE-O128S2`, `-C256S2`, `-C224O8`) traditionally
requires its own `port_config.ini` file in `sonic-buildimage`. Changing the breakout layout
means creating a new HwSKU name, a new directory, a new `port_config.ini`, and a new
`sonic-buildimage` PR. This doesn't scale.

## Solution

Generate the PORT table dynamically at deploy time using the existing Ansible playbook
(`config_sonic_basedon_testbed.yml`) and the `generate_golden_config_db` module — no
`port_config.ini`, `hwsku.json`, or manual file copies needed.

The playbook uses two data sources already available in every testbed:

- **`links.csv`** — the lab topology file on the sonic-mgmt server. Provides port names
  and speeds (the "what").
- **`platform.json`** — the hardware description already present on the DUT at
  `/usr/share/sonic/device/<platform>/platform.json`. Provides physical lanes, aliases,
  indices, and valid breakout modes (the "how").

## Architecture

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

## How It Works

### Step 1: Playbook extracts port speeds from links.csv

When `port_override_from_links=true` is passed to the playbook, a task
delegated to `localhost` reads `links.csv` and `devices.csv` to extract:

- **port_speeds** — `{port_name: speed}` for the target DUT hostname
- **hwsku** — the HwSKU string from `devices.csv`

These are passed to the `generate_golden_config_db` Ansible module as parameters.

### Step 2: Module rebuilds PORT table from platform.json on the DUT

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

### Step 3: Minigraph + golden config applied together

The playbook runs `config load_minigraph --override_config -y`, which:

- Loads all config_db tables from minigraph (BGP, VLAN, LOOPBACK, etc.)
- Overrides the PORT table with the one from `golden_config_db.json`

The result is a PORT table with correct lanes, aliases, indices, speeds, and
FEC — derived entirely from `links.csv` + `platform.json`, with no
`port_config.ini` involved.


### Fallback Behavior

If `platform.json` is missing or has no `interfaces` section, the module falls
back to using the minigraph PORT table directly, adding `fec: rs` for ports
with speeds ≥ 200G. This preserves backward compatibility with DUTs that lack
`platform.json`.

## Usage

### Read-only maximum-breakout link inventory

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

### Offline joint DUT/leaf planning and generic forwarding

`ansible/scripts/plan_generic_topology.py` consumes the same read-only snapshots
(local files or collected through inventory), plus a generic-forwarding recipe.
It selects one advertised mode and operating-speed combination
per eligible DUT/SONiC-leaf cage, jointly rather than independently. All children
of each selected mode participate. Whole-cage protection from the inventory is
preserved.

Low-speed cages participate on the same basis as higher-speed cages; there is
no minimum cage-bandwidth cutoff. This includes the lab's `Ethernet512` and
`Ethernet520`, each advertising `1x25G[10G]`, when their wiring and CSV VLAN
endpoints are eligible. No opt-in flag is needed. Explicit `--exclude-port`,
out-of-scope neighbors, incomplete wiring, and CSV VLAN eligibility still apply,
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

New CLI plans restrict every realized DUT and leaf child name to an endpoint with
a nonempty, single `VlanID` in the wiring CSV. Whole-cage layouts may combine
blank-VLAN sibling wiring channels, but cannot expose blank-VLAN child names.
Cages with no VLAN-backed endpoints are protected, with protection propagated
across their peers. The usable count is derived, never hardcoded to 64.

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
block deployment when `coverage.json.deployment_eligible` is true. Forwarding,
the frozen role policy, and all render/ownership checks remain
mandatory. Older sealed plans retain their coverage-complete requirement.

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
selected VLAN-backed DUT ports in numeric Ethernet order. Planning and
finalization write explicit uplink/downlink lists into generated `topology.yml`;
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
Older sealed plans retain their original repetition requirements; replan to
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
The current T0 forwarding scenario routes uplinks individually and puts downlinks
in one access VLAN/SVI. This is an explicit scenario policy, not the definition of
physical direction; arbitrary routed-downlink forwarding is not implemented.
It needs at least one actual uplink and downlink and sufficient approved pools.
Otherwise the physical plan remains review-only, with an allocation error.

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

All eligible cages participate; there is no implicit spare/unselected eligible
cage. To leave a cage unused, explicitly protect it with `--exclude-port` before
planning (which also protects connected cages under the wiring model).
The manifest records resolved per-link roles, not unmatched selectors.

These are individual routed interfaces, **not logical neighbors or PortChannel
members**. No PortChannels, LACP groups, BGP peers, or neighbor VMs are generated.
Explicit PortChannel membership is not supported by this recipe.
Allocate one peer-address pair and destination prefix per routed child, a default
route through the numerically first matched routed child, and unique access
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
external destinations use /32 or /128.

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
  external_destinations:
    address_pool: 2001:db8:3::/64
    prefix_length: 128
  transport:
    vlan_ids: null
```

For IPv4, add `--overrides vars/generic_ipv4.yml` to the initial add-topo command.
That allocation-only example uses the following documentation pools, inheriting
the role, VLAN ID, and transport defaults from the same topology:

```yaml
generic_topology:
  routed_interfaces:
    address_pool: 192.0.2.0/24
    prefix_length: 31
  access_vlan:
    subnet: 198.51.100.0/24
  external_destinations:
    address_pool: 203.0.113.0/24
    prefix_length: 32
```

This is an override, not a second topology. Changing families must replace all
three address pools and the family-specific prefix lengths. Optional allocation
overrides can follow it in low-to-high precedence order, for example
`--overrides vars/generic_ipv4.yml --overrides /private/path/allocations.yml`.
Each scenario uses one family, not dual-stack. Create a fresh workspace for
another family or changed allocations; existing rendered stages remain frozen.
Recipes omitting the uplinks field must be migrated and replanned before
rendering; do not reuse a plan generated under the old cage-based role policy.
Rendering checks the resolved roles against matched uplink selectors, the
automatic first-eight/default-downlink rule, and any legacy matching count frozen in the manifest
against the selected DUT layout before contacting either device. Rendering
verifies the planning decision; it does not read a repetition constraint from
the forwarding YAML or choose a new layout.

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
    --workspace /private/path/workspace
```

Add `--overrides /path/to/group.yml --overrides /path/to/host.yml` for explicit
low-to-high, field-level overrides. Each file has a `generic_topology` mapping.
Repeat `--exclude-port` to protect additional DUT ports and their connected cages.
`--max-search-states` sets a positive search ceiling (default 100000).

The planner is an internal developer entry point. The operator workflow uses
`add-topo`, which collects missing inputs, plans, resolves roles, and renders
both configurations in one invocation:

```bash
cd ansible
./testbed-cli.sh -t testbed.yaml add-topo example-generic \
    /absolute/path/to/password.txt \
    --peer-hostname example-leaf \
    --links-csv files/sonic_example_links.csv \
    --workspace /private/path/workspace
```

This entry resolves exactly one DUT from the selected YAML or legacy CSV testbed
definition, records the testbed identity and definition digest, and forwards the
remaining planning options. It does not call legacy topology-loading/convergence
helpers. Inventory defaults to the testbed's `inv_name`; the vault-password file
is a positional argument. Paths remain relative to the caller's working directory;
`-t` defaults to `testbed.yaml`. The standalone Python entry also accepts
`--testbed NAME --testbed-file PATH` instead of `--hostname`; the two identity
selectors are mutually exclusive.
`--workspace` is optional; the shared workspace and fixed stage locations are
described below. These examples write the frozen plan under `WORKSPACE/plan/`.
`vars/topo_generic.yml` is the conventional default recipe. Explicit `--overrides`
files merge in low-to-high order; inventory remains a connection source, not an
implicit recipe merge source. Adding this file does not change any testbed's topology.

#### Read-only device input collection

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
CLI exits 2. Allocation or matching-uplink shortfalls publish a review-only plan.
Mode/buffer coverage shortfalls alone do not block a new VLAN-scoped plan.
Invalid input/allocation settings
exit 1 without scenario artifacts. Existing output
directories are never overwritten. A search-limit report is not a proof that
no feasible layout exists.

### Generic QoS/config rendering and manual deployment

The generic path is **not** the minigraph-plus-golden-override path. It builds
full-device reload inputs from running snapshots and re-rendered installed
QoS/buffer templates, preserves management and
unowned/protected port entries, and retires understood interfaces, VLANs,
PortChannels, and BGP sessions belonging to the selected ports. A PortChannel
shared with protected ports or an unknown retired-port reference is an error.
Unowned BGP sessions are preserved; no new BGP sessions are generated.

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
are resolved, before the planner publishes its scenario. The same validation is
repeated locally before add-topo rendering contacts either device, and on each
device before reading its running configuration. Every selected DUT and leaf
child must have exactly one reciprocal connection, match its frozen layout,
cover the same physical wiring channels at the same speed, and carry a resolved
scenario role and a matching-speed buffer case. Missing, duplicate, or
inconsistent connections fail; rendering never selects a replacement breakout
or infers roles. Add-topo freezes layouts, resolves roles, finalizes settings,
and renders in one invocation; no separate freeze/review confirmation is required.
Before invoking it, edit physical roles, address pools, VLANs, exclusions, and transport in this one
source file; do not edit generated `topology.yml` or resolved facts. No separate
editable role file is generated.
Internal finalization validates settings and regenerates role assignments,
T0 forwarding, and coverage without calling the solver. It rereads the exact
recipe paths recorded at planning, in their original merge order, checks for
concurrent edits, and records their final hashes. The resolved settings are
sealed in the generated `topology.yml`; rendering/deployment use this snapshot
without rereading the mutable source. The original planning hashes are retained
separately. Explicit `--recipe`/`--overrides` inputs remain optional; if used,
edit those sources before preparation instead. Changed inputs require a fresh
workspace after finalization. Mode/buffer gaps remain visible;
only plans meeting the frozen deployment requirements can render or deploy.

Rendering regenerates affected `DEVICE_NEIGHBOR` entries from those resolved
connections, using the scenario's actual DUT/leaf inventory identities and
canonical remote child names. It preserves unaffected neighbor entries,
`DEVICE_METADATA` except for the DUT's explicit generic HwSKU identity, and
`DEVICE_NEIGHBOR_METADATA`; it does not invent remote device types or require
inventory identifiers to equal the device's native hostname. Old affected
neighbor entries are replaced even when a child reuses the parent's name.
Scenario uplink/downlink assignments remain separate from physical neighbor
identity: both roles can connect to the same transport leaf. The QoS template
context preserves truthful neighbor tables and uses the explicit-role adapter.
Installed lossy policy is applied as rendered, including explicitly disabled PFC.
Only when the installed policy enables PFC are selected lossless ingress PG
bindings and missing lossless profiles left to `buffermgrd`.
`render_report.json` records those required values. Apply loads the rendered
input; verification waits for declared daemon outputs when present, and save
persists the verified running configuration.
Existing baseline/asset drift checks stop deployment rather than silently
reconciling a different scenario at apply time.

Initial rendering requires a single-ASIC SONiC device using **traditional
buffers** and the verified shared `qos_config.j2` role-list contract. Dynamic
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

When installed policy enables PFC, read-only rendering requires Docker access to
the single-ASIC `swss` container.
It checks the running `buffermgrd` arguments and reads its actual `-l` lookup
inside that container. Every selected case must match the selected installed lookup;
asset fallback does not change the daemon's startup path.
Dynamic-calculation (`-a`) startup, absent/ambiguous daemon processes,
missing/divergent cases, and `0m` cables fail explicitly. The `0m` restriction
is also enforced before planning freezes any layout: snapshots containing
`0m` are rejected for this daemon-owned backend. Supply a nonzero-cable planning
snapshot rather than editing installed assets. The active lookup
path/content digest is recorded and checked again at stage, apply, verify, and
save. The operator must arrange the installed daemon's lookup support before
rendering; the generic workflow does not edit startup commands or restart
services during preparation.

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
and pool reference. Other shared-policy conflicts still fail.

There is no manual `qos` input block. The direction-aware installed template
supplies per-port QoS, including enabled PFC priorities and PFC map bindings.
Only omitted `pfc_enable` fields, and omitted PFC map bindings when PFC is enabled,
fall back to running policy. New children inherit those fields from lane-overlapping
running ports, including grouped `PORT_QOS_MAP` bindings. Aggregation requires
all contributing ports to agree on each inherited field. Missing/ambiguous
running policy or explicitly invalid rendered fields fail rather than guessing.
Rendered fields always take precedence; an empty `pfc_enable` is valid lossy
policy and never falls back to enabled PFC from the running configuration.

#### Installed lossy policy

Some installed HwSKU templates explicitly disable PFC and omit legacy lossless
egress objects. Supplying planned uplink/downlink lists does not override that
policy. The renderer retains the installed lossy ingress/egress profiles,
direction-specific queues, classification, and disabled PFC. It does not enable
shared-template priority defaults, synthesize a lossless egress profile, require
PFC maps or lossless egress objects, or project daemon headroom for these ports.
Planning still validates the advertised speed/cable coverage matrix.

All selected ports receive their assigned runtime `CABLE_LENGTH`, regardless
of PFC policy. Existing cable-group entries for a selected port are updated to
that assignment; protected-port cable settings remain unchanged. PFC-disabled
cases also remain in the sealed planning artifacts and `render_report.json`
under `buffer_policy.lossy_cable_cases`.

The traditional daemon can recreate unused lossless profiles from nonzero cable
entries even with empty PFC priorities. Runtime verification still rejects
undeclared buffer drift; retaining cable entries does not waive that check or
enable PFC. This policy needs fresh installed-image validation before deployment.
Lossy mode does not exercise the assigned lossless headroom cases in hardware.

Reports identify `qos_policy: installed_lossy` and record shared-pool preservation,
static-profile aliases, and omitted unused selected headroom under `buffer_policy`.
Lossy-only reports have no `lossless_buffers` or `buffer_daemon` expectations.
Required static objects, protected state, and unrelated profiles remain.

The former `--enable-lossless-adapter` option is removed. Previously rendered
override artifacts cannot be deployed with the updated controller; keep them
and their backups for recovery. Prepare a fresh workspace using installed policy
instead of editing or overwriting sealed artifacts:

```bash
./testbed-cli.sh -t testbed.yaml add-topo "$TB" "$VAULT" \
    --peer-hostname "$LEAF" --links-csv "$LINKS" --workspace "$NEW_WORKSPACE"
```

Include `--exclude-managed-acls` only when that exclusion remains intended.
Rendering does not apply, reload, or save configuration. Database verification
and successful rendering do not prove ASIC programming or physical links.
Switching to lossy policy does not resolve independent SDK/SerDes failures.

For new plans, `transport.vlan_ids: null` uses each selected DUT endpoint's own
CSV VLAN, not a sorted pool reassigned across endpoints. An explicit list, when
present, is only an allowlist; it cannot enable endpoints without CSV VLANs.
**One existing isolated transport VLAN per active child is required.**
Rendering still requires live leaf access ownership and tagged trunks; a CSV
entry alone is not proof that the root/host transport works.

The usable endpoint count is computed from CSV wiring and protection, without
an automatic low-speed exclusion. With one allowed name per cage, whole-cage
single-child modes can participate; modes exposing extra blank-VLAN child names
cannot. Uncovered combinations remain unqualified rather than forcing a larger
layout or inventing transport capacity. Existing shared VLANs are not removed.
Frozen older scenarios retain their original transport contract. Use a fresh
workspace and approved allocations; do not edit sealed artifacts or reuse
another testbed's VLAN reservations.

Before changing `topo` or `server`, retire any previous host/PTF topology using its original
definition and the normal lab maintenance procedure. Generic add-topo refuses to
take over an existing unlabelled/different-scenario PTF container.
The `server` setting may be a physical-host inventory name or a group such as
`example_server_group`. The host playbook intersects that selection with both `servers`
and `vm_host`, requiring exactly one eligible host before remote tasks.
Missing or ambiguous selections fail; neighbor VM members do not become host
targets. Keep the existing testbed group selector rather than replacing it
with a literal hostname. DUT, PTF management, group, and inventory settings
remain unchanged; this resolution does not edit the testbed.

To check only inventory resolution, without contacting the VM host:

```bash
ANSIBLE_LIBRARY=library:roles/vm_set/library \
ansible-playbook -i veos -i "$INV" generic_host.yml \
    --vault-password-file "$VAULT" --limit example_server_group,localhost \
    --tags generic_host_resolution \
    -e '{"generic_testbed": {"server": "example_server_group"}}'
```

This tag performs no Docker, interface, or fanout operations. It does not
prove transport readiness or substitute for post-provisioning PTF verification.
It also resolves an omitted `fp_mtu_size` from the existing
`roles/vm_set/vars/main.yml`, preserving any explicit inventory value. The normal
host path checks the shared interface against that MTU; it does not change the
shared interface to satisfy the check.
An authorized generic add-topo also invokes the existing root-fanout connection
playbook, including its root running-to-startup save. It is a host/fanout mutation,
not just container creation, even though it does not reload the DUT or leaf.
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
`--workspace`, `--scenario-dir`, or `--apply` on shared
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
allocations; do not edit sealed `finalized/` artifacts or simply retry unchanged.

This option can be used when retrying a failed render with an existing sealed
`finalized/` stage; do not edit its JSON or remove earlier artifacts. It is passed
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
source; do not concurrently edit it for different scenarios. Older plans without
recorded `recipe_paths` must be regenerated before finalization.

All generic commands share one workspace. The default is
`<system-temp>/sonic-generic-<UID>/<testbed>`, normally under `/tmp` and honoring
`TMPDIR`. It is stable for the same user, testbed, and temporary root; it is not
the most recently modified directory or a different random directory per command.
The layout is:

```text
/tmp/sonic-generic-<UID>/example-generic/
├── plan/
├── finalized/
└── rendered/
```

Each command prints the workspace. Add-topo writes `plan/`, finalizes into
`finalized/`, checks deployment eligibility, then renders into `rendered/`.
All preparation stages run in the same invocation, including with `--apply`.
If `finalized/` already exists, rendering
uses that sealed stage without rereading the recipe or rerunning finalization.
Retry a failed preparation with the same add-topo command and workspace.
Once `rendered/` exists, add-topo reuses it without planning or rendering again.
Remove-topo, deploy-mg, and recovery require that same `rendered/`; a missing stage
fails locally rather than preparing, triggering a legacy deployment, or selecting another run.
Workspace/stage directories must be private, owned by the current user, and not
symlinks. Files remain after command exit; there is no automatic cleanup, but
system temporary-file cleanup may remove them.

Use optional `--workspace /private/persistent/path` on **every command** to select
the same alternative location, especially for long-lived validation/recovery.
No input/output path arguments are needed otherwise. Existing stages are never
overwritten. For another attempt, select a new workspace; old random temporary
workspaces can be reused by passing their exact root with `--workspace`.
Explicit `--scenario-dir` selects an already rendered stage, while `--output-dir`
selects an add-topo preparation workspace. Neither can be combined with
`--workspace`, and they cannot be combined with each other.
An existing finalized stage can only be reused if it belongs to that exact plan
and testbed.
After finalization, recipe edits do not change rendering: select a fresh workspace
and plan again for another reviewed version. Invalid finalized stages remain
review-only and never trigger device access. Best-effort mode/buffer gaps alone
do not make a new VLAN-scoped finalized stage invalid.

```bash
# Use the shared defaults, with optional allocation overrides when needed.

./testbed-cli.sh -t testbed.yaml add-topo example-generic \
    /absolute/path/to/password.txt \
    --peer-hostname example-leaf \
    --links-csv files/sonic_example_links.csv

./testbed-cli.sh -t testbed.yaml deploy-mg example-generic example_inventory \
    /absolute/path/to/password.txt --generic
```

Rendering contacts the devices and uses private temporary files, but does not
reload or save configuration. Its output adds `dut_config.json`, `leaf_config.json`,
and `render_report.json`; all artifacts are private (`0600`, directory `0700`).
**Complete configurations can contain credentials inherited from the baseline.
Keep these directories outside source control; do not attach them to PRs/logs.**
The finalized manifest hashes all artifacts and records that explicit operator apply is
required. Modified artifacts or mismatched testbed settings are rejected.

Both commands above default to **dry run**: fresh add-topo may collect/read
devices and render, but does not provision infrastructure or apply configuration;
deploy-mg is local-only without `--apply`. Review coverage and rendered reports,
not full configuration-bearing files in shared logs.
In an exclusively reserved maintenance window, explicitly append `--apply` to each:
first add-topo, then deploy-mg. With `--apply`, add-topo provisions the scenario-owned PTF
container and host VLAN endpoints, uses the existing no-VM management/binding
helper, and reconnects existing connection-graph root transport without cleaning
other testbed bindings. It never reloads the DUT/leaf. Compact PTF indices are
projected independently of DUT hardware indices.

There is no separate role-freeze or finalization command. The first add-topo
with `--apply` prepares and then provisions in one invocation, but only after
rendering has successfully published a deployment-eligible scenario. A rendering
failure cannot reach host/root provisioning. Existing stages are never silently
regenerated or overwritten; a changed recipe or layout requires a fresh workspace.

Deploy-mg checks the PTF endpoints and stages **both** devices before reloading
either. It rejects running-state or installed-asset drift, keeps private running
and startup backups under `/var/lib/sonic-generic/<scenario-id>/<role>/`, reloads
the complete artifacts (not minigraph), checks CONFIG_DB read-back and selected
link state, and saves only after both devices verify. Verification waits up to
120 seconds per device for the declared lossless profiles/PG bindings to
converge in CONFIG_DB and APPL_DB. Only those expected additions are permitted;
wrong values, extra profiles/bindings, or changes to protected/template-owned
CONFIG_DB state fail. An absent table and an empty table are equivalent because
Redis does not retain empty tables; nonempty table contents must still match.
Equivalent grouped PG keys are compared by port/index,
with overlapping bindings rejected. Save persists and reads back the validated
converged configuration, not the intentionally incomplete input artifact.
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
./testbed-cli.sh recover-generic example-generic example_inventory \
    /absolute/path/to/password.txt --apply

./testbed-cli.sh remove-topo example-generic \
    /absolute/path/to/password.txt --apply
```

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

#### Validation boundaries

Focused offline tests exercise compatible layouts, every-mode/speed repetition,
review-only shortfalls, frozen role finalization, automatic preparation, asset
fallback/drift, ACL inheritance, temporary QoS adaptation, daemon convergence, and
alias ownership/recovery. Installed DUT/leaf templates were inspected read-only;
neither topology nor device configuration was changed. Offline validation does
not certify electrical compatibility, installed-image reload behavior, ASIC/PFC
programming, or packet forwarding. Those require an authorized maintenance window
and physical testbed validation.

### Legacy PORT-override deployment (without `--generic`)

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

### Deploy without PORT override (default behavior)

Without `port_override_from_links`, the module uses minigraph PORT speeds and
adds FEC. This is the existing behavior and requires no extra flags:

```bash
./testbed-cli.sh deploy-mg <testbed-name> <inventory> <password>
```

### Standalone generation (optional)

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

### Changing Breakout (update links.csv)

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

#### What the Script Does

The script groups DUT ports by physical cage, maps existing source ports to
target ports in the new breakout, removes entries that don't exist in the new
layout, and generates expansion entries for any target ports that lack a source
mapping. This ensures the CSV is always complete for the new port layout. VLAN
assignments are updated sequentially and trunk VLAN ranges are adjusted.

#### Updating HwSku

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



## End-to-End HWSKU Conversion (C256 → O128 Example)

This walkthrough converts a DUT from `Arista-7060X6-64PE-C256S2` (4x200G, 256 ports)
to `Arista-7060X6-64PE-O128S2` (2x400G, 128 ports).

### Prerequisites

- Testbed name (e.g., `example-t1-lag`)
- Links CSV path (e.g., `ansible/files/sonic_example_links.csv`)
- Devices CSV path (e.g., `ansible/files/sonic_example_devices.csv`)
- Inventory file (e.g., `example_inventory`)
- Vault password file (e.g., `~/.password`)

### Step 1: Pre-checks — verify current state

```bash
# Check current HWSKU and port count on DUT
ssh dut "show platform summary"
ssh dut "show interfaces status | wc -l"
ssh dut "show interfaces status | grep -c 'up'"
ssh dut "show bgp summary"
```

Save the output for comparison after conversion.

### Step 2: Update links.csv for new breakout

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

### Step 3: Update devices.csv — change HwSKU

Use `--hwsku` during Step 2 to handle this automatically, or edit
`ansible/files/sonic_example_devices.csv` manually:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_example_links.csv \
    --hostname example-dut \
    --target-breakout 2x400G \
    --hwsku Arista-7060X6-64PE-O128S2
```

### Step 4: Update the devices.csv and Redeploy leaf fanout(Uses another change in port_config_gen.py by PR:https://github.com/sonic-net/sonic-mgmt/pull/23536/changes)

The leaf fanout needs to be reconfigured for the new breakout and VLANs:

```bash
cd ansible
ansible-playbook -i example_inventory fanout.yml \
    -l example-fanout \
    --vault-password-file ~/.password
```

### Step 5: Update root fanout VLAN trunks

The root fanout trunk ports need the updated VLAN range:

```bash
ansible-playbook -i example_inventory fanout_connect.yml \
    --vault-password-file ~/.password \
    -e dut=example-dut
```

### Step 6: Deploy minigraph with PORT override

This generates minigraph with the new port layout, builds the golden config
(which rebuilds the PORT table from `platform.json`), and applies both:

```bash
./testbed-cli.sh deploy-mg example-t1-lag example_inventory ~/.password \
    -e port_override_from_links=true -e lab_name=example
```

What happens under the hood:
1. Playbook reads `links.csv` on the mgmt server → extracts `port_speeds` for 128 ports
2. `generate_golden_config_db` runs on the DUT, reads local `platform.json`
3. PORT table is rebuilt with correct lanes, aliases, indices, speed=400000, fec=rs
4. `config load_minigraph --override_config -y` applies minigraph + PORT override

No `port_config.ini` is read or needed at any step.

### Step 7: Verify port status

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

### Step 8: Verify BGP sessions

```bash
# All BGP neighbors should be in Established state
ssh dut "show bgp summary"

# Check for any non-established sessions
ssh dut "show bgp summary | grep -v Established | grep -v 'Neighbor\|entries'"

# Verify neighbor count matches expected topology
ssh dut "show bgp summary | grep -c Established"
```
