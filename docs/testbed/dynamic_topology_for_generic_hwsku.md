# Dynamic Topology for Generic HWSKU — sonic-mgmt Design

## Table of Content

- [1 Revision](#1-revision)
- [2 Scope](#2-scope)
- [3 Definitions/Abbreviations](#3-definitionsabbreviations)
- [4 Problem Statement](#4-problem-statement)
  - [4.1 Topology binding is positional](#41-topology-binding-is-positional)
  - [4.2 Generic HWSKU makes breakout a free variable](#42-generic-hwsku-makes-breakout-a-free-variable)
  - [4.3 Why the failure is silent](#43-why-the-failure-is-silent)
  - [4.4 What already landed, and what it does not cover](#44-what-already-landed-and-what-it-does-not-cover)
- [5 Requirements](#5-requirements)
- [6 Architecture Design](#6-architecture-design)
- [7 High-Level Design](#7-high-level-design)
  - [7.1 Separate topology intent from topology binding](#71-separate-topology-intent-from-topology-binding)
  - [7.2 Breakout mode in links.csv](#72-breakout-mode-in-linkscsv)
  - [7.3 The neighbor binding file](#73-the-neighbor-binding-file)
  - [7.4 Keying model](#74-keying-model)
  - [7.5 Generation pipeline](#75-generation-pipeline)
    - [7.5.1 Inputs and what each determines](#751-inputs-and-what-each-determines)
    - [7.5.2 Express intent over cages, not port indices](#752-express-intent-over-cages-not-port-indices)
    - [7.5.3 Generation algorithm](#753-generation-algorithm)
    - [7.5.4 Scaling semantics](#754-scaling-semantics)
    - [7.5.5 Required generator properties](#755-required-generator-properties)
    - [7.5.6 Bootstrapping existing topologies](#756-bootstrapping-existing-topologies)
  - [7.6 Consistency gates](#76-consistency-gates)
  - [7.7 VM allocation and capacity](#77-vm-allocation-and-capacity)
  - [7.8 Operational workflow](#78-operational-workflow)
- [8 Impacted Components](#8-impacted-components)
- [9 Migration Plan](#9-migration-plan)
- [10 Testing and Validation](#10-testing-and-validation)
  - [10.1 Layer 0 — Artifact equivalence](#101-layer-0--artifact-equivalence)
  - [10.2 Layer 1 — CONFIG_DB equivalence](#102-layer-1--config_db-equivalence)
  - [10.3 Layer 2 — Functional and skip accounting](#103-layer-2--functional-and-skip-accounting)
  - [10.4 Layer 3 — Guardrails](#104-layer-3--guardrails)
- [11 Restrictions and Limitations](#11-restrictions-and-limitations)
- [12 Open Questions](#12-open-questions)
- [13 References](#13-references)

---

## 1 Revision

| Rev | Date | Author | Change Description |
|:---:|:-----|:-------|:-------------------|
| 0.1 | 10/13/2026 | Bing Wang | Initial version |

## 2 Scope

This document describes a design for **dynamic topology** in `sonic-mgmt`, enabling testbed
deployment and qualification when the DUT port breakout layout is determined at deploy time
rather than baked into a pre-defined HWSKU name.

It is a companion to the [Generic HWSKU HLD](https://github.com/sonic-net/SONiC/pull/2309).
That document covers the `sonic-buildimage` artifact model; this document covers the
`sonic-mgmt` topology and testbed model that Generic HWSKU invalidates.

Out of scope: the `sonic-buildimage` platform artifact convergence itself (§7.2 of the
Generic HWSKU HLD), and SAI profile delivery (covered by
[SONiC#2571](https://github.com/sonic-net/SONiC/pull/2571)).

## 3 Definitions/Abbreviations

| Term | Definition |
|------|------------|
| Topology intent | The logical shape of a test topology: how many neighbors, of what role, with what ASN/addressing plan. Independent of breakout. |
| Topology binding | The mapping from a concrete DUT port to a concrete neighbor (VM or PTF host interface). Depends on breakout. |
| Cage | A physical front-panel port (QSFP/OSFP connector) with a fixed set of SerDes lanes. |
| Subport | One logical port carved out of a cage by a breakout mode. |
| Breakout mode | A rule splitting a cage's lanes into logical ports, e.g. `1x800G`, `2x400G`, `4x200G`. |
| Base HWSKU | The per-platform default HWSKU at minimum breakout, referenced by `default_sku`. |
| Neighbor binding file | The new per-testbed artifact proposed by this document. |

## 4 Problem Statement

### 4.1 Topology binding is positional

`sonic-mgmt` has **193 pre-defined topology files** under `ansible/vars/topo_*.yml`. They
describe the topology binding as **integer offsets**, not port names:

```yaml
# ansible/vars/topo_t0.yml
topology:
  host_interfaces:
    - 0
    - 1
    ...
  VMs:
    ARISTA01T1:
      vlans:
        - 28
      vm_offset: 0
```

Those integers are consumed by `ansible/library/topo_facts.py:358-374` and resolved during
minigraph generation by indexing directly into the ordered list produced by the `port_alias`
module. From `ansible/templates/minigraph_dpg.j2:212`:

```jinja
{% set intf_alias = port_alias[vm_topo_config['vm'][vms[index]]['interface_indexes'][dut_index|int][0]] %}
<AttachTo>{{ port_alias_map[intf_alias] }}</AttachTo>
```

The same pattern appears at `minigraph_dpg.j2:230`, `:331`, and in reverse at `:360`
(`port_alias.index(cable['dut_intf'])`).

The resolution chain is therefore:

```
topo_*.yml index  ->  port_alias[i]  ->  alias  ->  port name
```

**The ordering of `port_alias`'s output is load-bearing semantics for the entire testbed,
and nothing asserts it.**

### 4.2 Generic HWSKU makes breakout a free variable

Today, breakout is fixed and encoded in the HWSKU name. Selecting
`Arista-7060X6-64PE-B-C512S2` implicitly guarantees how many ports exist and in what order,
so index `28` reliably denotes one physical lane.

Generic HWSKU removes that guarantee. Per §7.2.7 of the Generic HWSKU HLD, non-default HWSKU
folders are no longer generated; `PORT` and `BREAKOUT_CFG` come from the active configuration.
Breakout becomes a deploy-time choice.

Two variables that were previously welded together are now independent:

| | Today | Under Generic HWSKU |
|---|---|---|
| Breakout | Fixed, encoded in the HWSKU name | **Dynamic**, chosen at deploy time |
| Topology | Static, 193 files of integer offsets | Still static |

A changed breakout changes both the **length** and the **ordering** of the `port_alias` list.
The topology file continues to say `28`, and `28` continues to resolve — to a different port.

### 4.3 Why the failure is silent

This is the critical property of the problem. A positional binding against a changed list
does not raise; it silently returns the wrong element. Consequences:

1. Neighbor VMs attach to the wrong DUT ports.
2. Tests fail in ways that do not point at the cause, **or pass while validating the wrong ports.**

The second outcome is the dangerous one, and it is invisible to pass/fail reporting.

This compounds with existing silent-degradation behavior in the test layer. For example
`tests/platform_tests/conftest.py:30-53`:

```python
f_path = os.path.join('/usr/share/sonic/device', platform, hwsku, 'hwsku.json')
intf_skip_list[dut.hostname] = []
dut.has_sku = True
try:
    out = dut.command("cat {}".format(f_path))
    ...
except Exception:
    # hwsku.json does not exist will return empty skip list
    dut.has_sku = False
```

A missing HWSKU folder yields an empty skip list and `has_sku = False` rather than an error,
so the suite runs with weaker filtering instead of reporting a misconfiguration.

### 4.4 What already landed, and what it does not cover

Three PRs have merged under the Generic HWSKU banner:

| PR | Scope |
|---|---|
| [#23534](https://github.com/sonic-net/sonic-mgmt/pull/23534) | `platform.json` support in `port_alias` |
| [#23536](https://github.com/sonic-net/sonic-mgmt/pull/23536) | `platform.json` support in `port_config_gen` |
| [#23052](https://github.com/sonic-net/sonic-mgmt/pull/23052) | Golden-config PORT generation, `generate_port_config.py`, `update_links_for_breakout.py` |

These deliver **"a HWSKU folder without `port_config.ini`"** — not **"no HWSKU folder."**
`ansible/library/port_alias.py:114-118` gates the JSON path on the per-HWSKU file existing:

```python
hwsku_dir = os.path.join(platform_dir, self.hwsku)
hwsku_json_file = os.path.join(hwsku_dir, HWSKU_JSON)
if parse_platform_json_file is not None and os.path.isfile(hwsku_json_file):
```

`_get_portmap_from_json` re-reads `<platform_dir>/<self.hwsku>/hwsku.json` at `:149`, and the
INI fallback at `:131-143` also hardcodes `self.hwsku`. With `FILE_PATH = '/usr/share/sonic/device'`
(`:61`, i.e. the DUT image), once non-default folders stop being generated,
`get_portconfig_path()` returns `None` and `get_portmap()` raises at `:234-239`.

Ordering makes this unrecoverable through the existing escape hatch: `port_alias` is invoked at
`ansible/config_sonic_basedon_testbed.yml:275` and `:285`, while the golden-config PORT override
is applied at `:916-924` and is gated behind an opt-in `port_override_from_links` flag.
**The failure occurs ~640 lines before the mechanism that would have fixed it.**

Separately, `update_links_for_breakout.py` (529 lines, added by #23052) remaps **`links.csv`**
for a new breakout. It does not touch `topo_*.yml`, VM allocation, or the positional binding.
One leg of a three-legged consistency problem has tooling.

## 5 Requirements

1. A testbed must deploy correctly when breakout is chosen at deploy time and no
   breakout-specific HWSKU folder exists in the image.
2. The topology binding must be **nominal**, not positional. A stale or mismatched binding
   must fail loudly at deploy time, never silently resolve to a different port.
3. Topology **intent** (`t0`, `t1`, `lt2-o128`) must remain a first-class, stable label for
   test selection and parameter lookup.
4. The number of artifacts must not grow as `topologies x breakout_modes`.
5. Breakout-dependent artifacts must be **generated and verifiable**, not hand-authored.
6. Existing pre-defined topologies must continue to work unchanged during transition.
7. There must be a mechanical way to prove that a dynamically bound topology is equivalent
   to the pre-defined topology it replaces.

## 6 Architecture Design

No new runtime component is introduced. The change is to the testbed artifact model and the
deployment pipeline in `sonic-mgmt`.

```
                       breakout-independent          breakout-dependent
                     +----------------------+      +--------------------+
   topology intent   |  topo_<name>.yml     |      |   links.csv        |  physical cabling
   (roles, ASN plan) |   - configuration_   |      |    + breakout mode |  (lab-owned)
                     |     properties       |      +---------+----------+
                     |   - configuration    |                |
                     +----------+-----------+                |
                                |                            |
                                |      platform.json (cages, breakout_modes)
                                |                 |          |
                                v                 v          v
                         +--------------------------------------------+
                         |            binding generator               |
                         +----------------------+---------------------+
                                                |
                                                v
                                  +-------------------------------+
                                  |  neighbor binding file        |  (generated, checked in)
                                  |  port/cage -> neighbor, role  |
                                  +---------------+---------------+
                                                  |
                      consistency gates ----------+
                                                  v
                                       minigraph / golden_config_db
                                                  |
                                                  v
                                              CONFIG_DB
```

## 7 High-Level Design

### 7.1 Separate topology intent from topology binding

`topo_*.yml` currently conflates three concerns. Only the first is breakout-dependent:

| Section | Lines in `topo_t0.yml` | Breakout-dependent | Moves out |
|---|---|---|---|
| `topology:` — `host_interfaces`, `VMs`, `vlans`, `vm_offset` | 1–104 | **Yes** | **Yes** |
| `configuration_properties:` — `dut_asn`, `spine_asn`, `podset_number`, `tor_subnet_size` | 105–121 | No | No |
| `configuration:` — per-VM BGP, interfaces, addressing | 122–209 | No (derivable) | No |

The extracted section is the **minority** of content, and the ratio worsens with scale:
`topo_t1-lag.yml` is 685 lines and `topo_t2.yml` is **2004 lines**.

This separation is a hard requirement, not a convenience. **123 test files** reference
`tbinfo['topo']`, **76** key off the literal `topo['name']`, and **46** off `topo_type` —
including QoS parameter selection, which looks up `topo-<topology>` keys in
`tests/qos/files/qos_params.*.yaml`. Replacing the topology concept wholesale would require
touching all of them.

> **Design rule:** topology name = intent; neighbor binding file = binding.
> Dynamic topology replaces the `topology:` section, not the topology.

### 7.2 Breakout mode in links.csv

`links.csv` is already per-lab, per-testbed, and describes physical reality. It gains an
explicit breakout mode per DUT cage, making the deployed layout declarative rather than
implied by an HWSKU name. `update_links_for_breakout.py` already understands uniform and
mixed breakout expressions (e.g. `"1x800G:0-255,2x400G:256-504"`) and can be extended to
emit this column rather than only rewriting port rows.

### 7.3 The neighbor binding file

A new per-testbed artifact declares, for each DUT port, the neighbor it attaches to and that
neighbor's role. Illustrative shape:

```yaml
# ansible/files/neighbors/<testbed>.yml
dut: str4-7060x6-64pe-11
topology: t0                 # intent label; selects topo_t0.yml for configuration
breakout_ref: sonic_str4_links.csv

bindings:
  - cage: 0
    subport: 0
    port: Ethernet0
    neighbor: null
    role: host_interface
    ptf_index: 0
  - cage: 7
    subport: 0
    port: Ethernet56
    neighbor: ARISTA01T1
    role: uplink
```

Properties:

- **Nominal.** Binding is by name, never by offset. Removes the `port_alias[i]` dependency.
- **Explicit roles.** `host_interface`, `uplink`, `disabled` replace the implicit meaning
  carried today by membership in `host_interfaces` vs `disabled_host_interfaces` vs `VMs`.
- **Carries no configuration.** ASN/addressing stay in topology intent.

### 7.4 Keying model

Port names are themselves breakout-dependent: one cage yields `Ethernet256` under `1x800G`
but `Ethernet256/258/260/262` under `4x200G`. Two options:

| | Key by port name | Key by cage + subport |
|---|---|---|
| Readability | High; matches `links.csv` | Lower; needs indirection |
| Stability across breakout | **None** — file must be regenerated | **Structural** — survives rebreakout |
| Source of truth | Derived from breakout | `platform.json` cage map |
| Staleness risk | Silent if not regenerated | Low |

`platform.json` is already organized by cage, and `generate_port_table_from_platform()`
already walks cage-by-cage, so the cage data is available at no extra cost.

**Recommendation:** key on `(cage, subport)` as the canonical identity and carry the resolved
`port` name as a **derived, verified** field. This gives readable diffs while keeping the
authoritative key stable. A mismatch between the recorded `port` and the port derived from
`(cage, subport, breakout)` is a hard deploy-time error (see §7.6).

### 7.5 Generation pipeline

The binding file **must be generated**, never hand-authored. A hand-maintained file per
(testbed x breakout) relocates the HWSKU explosion into the lab, where it is worse: no review,
no CI, no diff.

Checking the output in — rather than generating at deploy time — is deliberate: it makes the
binding reviewable, diffable, and greppable, and it lets CI detect drift.

#### 7.5.1 Inputs and what each determines

| Input | Supplies | Determines role? |
|---|---|---|
| `platform.json` | cage to lanes map, legal `breakout_modes` | No |
| `links.csv` | cabled ports, speed, fanout VLAN | **Constrains** — an uncabled port cannot host a neighbor |
| Topology intent | counts, roles, ASN plan | **Yes** — the only source of role |

`links.csv` has the schema
`StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode,AutoNeg`. It therefore
identifies which DUT ports are cabled, at what speed, and on which fanout VLAN — but it does
not name the logical neighbor. Closing that gap is the generator's job.

#### 7.5.2 Express intent over cages, not port indices

Cages are breakout-invariant; logical ports are not. Topology intent therefore declares role
partitions over **cages**:

```yaml
# topology intent - breakout independent
port_roles:
  - role: host_interface
    cages: 0-27
    scaling: scale            # more breakout -> more servers
  - role: uplink
    cages: 28-31
    neighbor_type: T1
    scaling: grouped          # subports aggregate into one LAG
    group_by: cage
```

Under `1x800G` this yields 28 host interfaces and 4 uplinks, identical to today's
`topo_t0.yml`. Under `4x200G` it yields 112 host interfaces and still 4 uplinks, each now a
4-member LAG. **The physical meaning of a cage never moves**, which is the property flat
indices cannot provide.

#### 7.5.3 Generation algorithm

```
1. EXPAND     cages -> logical ports
              for each cage c with breakout mode m:
                ports(c) = split(lanes(c), m)
                        -> (cage, subport, name, alias, speed, lanes)
              [reuse generate_port_table_from_platform()]

2. FILTER     drop management ports
              drop ports absent from links.csv (uncabled)
              carry BandWidth and VlanID forward

3. PARTITION  resolve intent cage ranges -> port sets
              (cage-keyed, therefore breakout invariant)

4. SCALE      apply per-role scaling semantics (7.5.4)

5. GROUP      aggregate subports into neighbors per group_by
              (LAG arity falls out of the breakout mode)

6. NAME       assign ARISTA01T1, ARISTA02T1, ... in (cage, subport) order

7. ALLOCATE   VM index = position in the ordered neighbor list
              (replaces static vm_offset)

8. EMIT       write binding file, run gates G1 and G3
```

#### 7.5.4 Scaling semantics

When a cage splits four ways, does that mean four times the neighbors, or one neighbor with a
four times wider LAG? Today the question cannot be asked, because breakout is frozen at image
build time. Dynamic topology forces it to be declared per role:

| Mode | Neighbor count | Port use | Typical use |
|---|---|---|---|
| `fixed` | Constant | Consume N ports, mark the remainder `disabled` | Topologies requiring an exact shape |
| `scale` | **Function of breakout** | All ports in the partition | `t0` host interfaces, scale tests |
| `grouped` | Constant | All ports, aggregated per cage | `t1-lag` uplinks — the LAG widens instead |

`topo_t1-lag.yml` illustrates the ambiguity. `ARISTA01T2` is bound to `vlans: [0, 1]`, a
two-port LAG. Under a four-way breakout, `grouped` preserves eight T2 neighbors with
eight-member LAGs, while `scale` produces thirty-two neighbors with two-member LAGs. Both are
legitimate; the choice is test intent and must be explicit.

#### 7.5.5 Required generator properties

- **Deterministic.** `(cage, subport)` is the sort key throughout, so identical inputs always
  produce byte-identical output. Without this, diffs are unreviewable and the equivalence
  oracle in §10.2 is worthless.
- **Idempotent.** Re-running produces a zero diff. This is precisely gate G2.
- **Total.** Intent that demands more neighbors than the breakout can supply fails at G3 or G4
  with an explicit message, never a partial binding.

#### 7.5.6 Bootstrapping existing topologies

Intent files for the 193 existing topologies are not written by hand. They are
reverse-engineered mechanically:

```
for each (topo_*.yml, HWSKU) pair in use:
    index -> port_alias[index] -> port name -> (cage, subport)    via port_config.ini
    infer cage ranges per role
    if contiguous and unambiguous -> emit intent file
    else                          -> flag for human review
```

Regenerating the binding from the inferred intent and asserting that the resulting minigraph
is byte-identical to today's gives this tool a second role: it is also the Phase 2 equivalence
oracle described in §9. Note that it depends on `port_config.ini` and the pre-defined
topologies still existing, which is a further reason for the ordering constraint in §9.

### 7.6 Consistency gates

Three artifacts must agree: `platform.json` (what the hardware can do), `links.csv` (what is
cabled, at what breakout), and the neighbor binding file (what attaches where). Today only
one has tooling. Each gate below is **mandatory and blocking**; an optional gate reintroduces
exactly the silent-drift class this design eliminates.

| Gate | Check | When |
|---|---|---|
| G1 Breakout validity | Every breakout mode in `links.csv` exists in that cage's `breakout_modes` | Pre-deploy |
| G2 Freshness | Every `port` in the binding file equals the port derived from `(cage, subport, breakout)` | Pre-deploy |
| G3 Coverage | Every port implied by breakout is bound or explicitly `disabled`; no binding references a nonexistent port | Pre-deploy |
| G4 Capacity | Required neighbor count fits the testbed server's VM budget | Pre-deploy |
| G5 Realization | Post-deploy LLDP neighbor on each DUT port matches the bound neighbor | Post-deploy |

G5 is the backstop that would have caught the original silent mis-binding, and it is worth
implementing even before the rest of this design lands.

### 7.7 VM allocation and capacity

`vm_offset` is a positional index into the VM pool and shares the fragility of
`host_interfaces` indices. Under dynamic breakout the neighbor count varies, so allocation
must become derived from the binding file rather than statically authored. A high-radix
breakout can exceed the testbed server's capacity; G4 turns that into a clear precondition
failure instead of a confusing mid-deploy error.

### 7.8 Operational workflow

The practical effect of this design is that **a breakout change becomes a data-only pull
request in a single repository.**

Today, changing the breakout of a testbed requires a new HWSKU:

```
decide breakout
  +-> sonic-buildimage PR: new HWSKU folder
  |     port_config.ini, hwsku.json, qos.json.j2,
  |     buffers_*.j2, sai.profile, config.bcm          <- cross repo, gated on image build
  +-> sonic-mgmt PR: new topo_*.yml if no port count matches
  +-> update devices.csv HwSku and links.csv
  +-> testbed-cli.sh add-topo / deploy-mg
```

Under this design:

```
decide breakout
  +-> testbed-cli.sh update-breakout <testbed> <links-csv> "2x400G"   (exists today)
  +-> testbed-cli.sh gen-binding <testbed>                            (new)
  +-> sonic-mgmt PR: links.csv + binding file only                    <- data only
  +-> testbed-cli.sh add-topo / deploy-mg
```

No new HWSKU, no new topology file, no `sonic-buildimage` change, and no image rebuild.

The gates from §7.6 are positioned so that each class of failure surfaces at the cheapest
possible point:

```
AUTHOR
  1. update-breakout   rewrites links.csv port rows and breakout mode
  2. gen-binding       emits binding file
                       |- G1 breakout mode legal for cage
                       |- G3 every port bound or explicitly disabled
                       +- emits (cage, subport) plus derived port name
CI (on the pull request)
  3. re-run generator, assert zero diff      <- G2 freshness
     re-run G1 and G3, check VM budget       <- G4 capacity
DEPLOY
  4. add-topo          VM count and allocation derived from binding file
  5. deploy-mg         minigraph built from nominal bindings
                       golden_config_db PORT from links.csv + platform.json
                       config load_minigraph --override_config
  6. G5 realization    LLDP neighbor == bound neighbor        <- blocking
TEST
  7. pytest            topology name still selects parameters
```

Artifact ownership and change frequency:

| Artifact | Owner | Changes with breakout | Authored or generated |
|---|---|---|---|
| `platform.json` | Vendor / buildimage | No | Authored once per platform |
| `links.csv` | Lab | **Yes** | Tool-rewritten |
| Neighbor binding file | Test | **Yes** | **Generated only** |
| Topology intent | Test | No | Authored once per topology |
| `devices.csv` HwSku | Lab | Qualification identity only | Authored |

The artifact count stops growing because the only two artifacts that change per breakout are
machine-generated, while the hand-authored artifact — topology intent — does not change at all.

This also makes the "optimized" qualification model of Generic HWSKU HLD §7.3.1 mechanical.
Running broad coverage on representative variants and delta coverage elsewhere becomes a loop
over breakout modes (`update-breakout` → `gen-binding` → `deploy-mg` → test), where today it
requires authoring one HWSKU per point in the sweep.

## 8 Impacted Components

| Component | Required change |
|---|---|
| `ansible/library/port_alias.py` | Resolve a concrete HWSKU to the base HWSKU; stop requiring `<hwsku>/hwsku.json` to exist (`:114-118`, `:131-143`, `:149`, `:234-239`) |
| `ansible/templates/minigraph_dpg.j2` | Replace positional `port_alias[i]` lookups with nominal binding (`:212`, `:230`, `:331`, `:360`) |
| `ansible/library/topo_facts.py` | Emit bindings from the neighbor file; retain intent parsing (`:358-374`) |
| `ansible/config_sonic_basedon_testbed.yml` | Move/condition the `port_alias` step (`:275`, `:285`) relative to golden-config generation (`:916-924`); remove hardcoded breakout fixups (e.g. `:994-1006`) |
| `ansible/library/generate_golden_config_db.py` | Consume the binding file; decide the `DEVICE_METADATA.hwsku` value |
| `ansible/scripts/update_links_for_breakout.py` | Emit breakout mode column; trigger binding regeneration |
| `ansible/roles/vm_set/` | Derive VM allocation from bindings rather than `vm_offset` |
| `tests/platform_tests/conftest.py` | Distinguish "absent metadata" from "valid base metadata"; stop swallowing all exceptions (`:30-53`) |
| `tests/qos/qos_sai_base.py` | ASIC identification must not depend on a breakout HWSKU name appearing in vendor lists |
| Test code at large | **246 distinct hardcoded HWSKU names** across `tests/` and `ansible/` |

## 9 Migration Plan

Adoption is incremental and must not regress existing testbeds.

1. **Phase 0 — Backstop.** Implement G5 (post-deploy LLDP realization check) against today's
   pre-defined topologies. Independent of everything else and immediately useful.
2. **Phase 1 — Generator.** Build the binding generator and emit files for existing
   (topology, HWSKU) pairs. Do not consume them yet.
3. **Phase 2 — Oracle.** Prove equivalence: for each existing topology, the generated binding
   must produce a byte-identical minigraph/CONFIG_DB (§10.2). This is the acceptance gate.
4. **Phase 3 — Consume.** Switch minigraph generation to the nominal binding behind a flag;
   keep positional resolution as fallback.
5. **Phase 4 — Dynamic.** Enable deploy-time breakout selection; `port_alias` base-HWSKU
   resolution lands here.
6. **Phase 5 — Remove.** Retire positional resolution once all testbeds are migrated.

> **Ordering constraint.** Phases 1–2 depend on pre-defined topologies and per-breakout HWSKU
> folders still existing — they are the only ground truth available. If Generic HWSKU removes
> those artifacts first, the equivalence oracle is permanently unavailable and this design can
> only ever be spot-checked. **The generator and oracle must land before folder removal begins.**

## 10 Testing and Validation

Generic HWSKU and dynamic topology add no user-visible feature. The entire claim is an
**equivalence** claim:

> A device deployed from base HWSKU + dynamic binding behaves identically to one deployed
> from the legacy per-breakout HWSKU folder and pre-defined topology.

Validation is therefore structured as equivalence testing, not feature testing.

### 10.1 Layer 0 — Artifact equivalence

No DUT required; runs in PR CI. Highest value per unit cost.

- **0a. PORT-table golden test.** For every existing `<platform>/<hwsku>/port_config.ini`,
  run the generic path (`generate_port_table_from_platform()`) and assert the result matches
  field-for-field — `name, lanes, alias, index, speed, fec` — **and in the same order**.
  Ordering is semantics (§4.1), so set equality is insufficient. Iterate every
  `breakout_modes` entry in `platform.json`, not only the HWSKUs that happen to exist today;
  uneven splits are the likeliest break. *No such test exists today.*
- **0b. `port_alias` equivalence.** Identical output with the HWSKU folder present versus
  base-only.
- **0c. Template fallback equivalence.** Render `qos.json.j2`, `buffers_defaults_*.j2`,
  `pg_profile_lookup.ini` with the HWSKU-local copy removed; assert byte-identical output.
- **0d. Binding generator unit tests.** Uniform and mixed breakout, disabled interfaces,
  multi-DUT, multi-ASIC, and each consistency gate's failure mode.
- **0e. Resolver unit tests.** Concrete to base, already-base, unknown SKU, per-slot/per-ASIC.

### 10.2 Layer 1 — CONFIG_DB equivalence

DUT required, no traffic. This is the acceptance gate.

- **1a.** Deploy the same testbed two ways — legacy HWSKU + pre-defined topology, versus base
  HWSKU + dynamic binding — and diff CONFIG_DB: `PORT`, `BREAKOUT_CFG`, `BUFFER_POOL`,
  `BUFFER_PROFILE`, `BUFFER_PG`, `BUFFER_QUEUE`, `QUEUE`, `WRED_PROFILE`, `DSCP_TO_TC_MAP`,
  `TC_TO_QUEUE_MAP`, `PORT_QOS_MAP`, `CABLE_LENGTH`. Permitted differences must be an explicit
  reviewed allowlist, not a fuzzy comparison. If CONFIG_DB is identical, downstream behavior
  is identical by construction — converting a multi-day qualification into a minutes-long diff.
- **1b.** ASIC_DB equivalence for port, queue, ingress-PG, and buffer objects. CONFIG_DB can
  match while SAI attributes diverge — relevant given SONiC#2571 moves `sai.profile` KV pairs
  into CONFIG_DB.
- **1c.** Absence assertion: verify the breakout HWSKU folder is genuinely not present, so CI
  cannot pass for the wrong reason.

### 10.3 Layer 2 — Functional and skip accounting

Running `t0`/`t1` on a base and a derived variant is necessary but weak on its own, because
missing metadata degrades silently (§4.3) — a run can go green simply by skipping more.

- **2a.** Diff **skip and collection counts** between legacy and dynamic runs. Any newly
  skipped test is a finding until justified. This is the cheapest defense against the entire
  silent-degradation class.
- **2b.** G5 realization check as a standing post-deploy gate.

### 10.4 Layer 3 — Guardrails

- **3a.** Lint test failing on *new* hardcoded breakout HWSKU names in `tests/`, with the
  existing 246 grandfathered into an allowlist that may only shrink.
- **3b.** CI check that checked-in binding files are current with respect to their
  `links.csv` and `platform.json` (gate G2 enforced at review time).

## 11 Restrictions and Limitations

- Better suited to new platforms than retrofitting existing ones.
- The equivalence oracle (§10.2) exists only during transition (§9).
- Topologies with hand-tuned, breakout-specific special cases must be reviewed individually;
  the generator cannot infer intent that was never written down.
- Platforms whose `platform.json` lacks a complete or accurate `breakout_modes` map cannot
  participate until that data is corrected.

## 12 Open Questions

1. **What value should `DEVICE_METADATA|localhost|hwsku` carry** — base HWSKU, concrete
   qualification HWSKU, or both in separate fields? `generate_golden_config_db.py` currently
   writes the supplied value directly with no mapping. Several consumers key off it, including
   QoS ASIC identification.
2. **Where does the concrete-to-base HWSKU mapping live** — inventory, `default_sku`, a
   platform-level file, or a `sonic-mgmt` helper? No such mapping exists today.
3. **Should topology intent files be reduced further?** `configuration:` (per-VM BGP and
   addressing) is largely derivable from `configuration_properties:` plus the binding; making
   it derived would shrink `topo_t2.yml` substantially but is a separate refactor.
4. **One file or two?** Extending `links.csv` with neighbor columns yields a single source of
   truth but mixes lab-owned cabling with test-owned intent. This document proposes two files
   with a mandatory gate; the ownership tradeoff should be confirmed.
5. **How is the "optimized" qualification model expressed?** §7.3.1 of the Generic HWSKU HLD
   proposes full coverage on representative variants and delta coverage elsewhere. No tier or
   marker concept exists in `sonic-mgmt` to express this.
6. **Does `links.csv` carry enough data** to derive breakout unambiguously for every platform,
   or is an explicit per-cage breakout column required in all cases?

## 13 References

- [Generic HWSKU HLD (SONiC#2309)](https://github.com/sonic-net/SONiC/pull/2309)
- [Dynamic SAI Profile Configuration via CONFIG_DB (SONiC#2571)](https://github.com/sonic-net/SONiC/pull/2571)
- [Infra changes to support generic HWSKU (sonic-mgmt#23052)](https://github.com/sonic-net/sonic-mgmt/pull/23052)
- [platform.json support in port_alias (sonic-mgmt#23534)](https://github.com/sonic-net/sonic-mgmt/pull/23534)
- [platform.json support in port_config_gen (sonic-mgmt#23536)](https://github.com/sonic-net/sonic-mgmt/pull/23536)
- [Generic HwSKU PORT Table Generation](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/generic_hwsku_port_config.md)
- [SONiC Dynamic Port Breakout HLD](https://github.com/sonic-net/SONiC/blob/master/doc/dynamic-port-breakout/sonic-dynamic-port-breakout-HLD.md)
- [Unified SAI profile and SDK configuration (sonic-buildimage#25720)](https://github.com/sonic-net/sonic-buildimage/issues/25720)
