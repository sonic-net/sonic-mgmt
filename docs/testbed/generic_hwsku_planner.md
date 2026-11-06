# Offline Generic HWSKU planner

`ansible/module_utils/generic_hwsku.py` plans one deterministic mixed-breakout
scenario from recorded capabilities, wiring, policy and reserved resources.
It performs no file/device I/O and does not change `add-topo`, `deploy-mg`,
`remove-topo` or ordinary topology behavior. Live collection, configuration
rendering/application, recovery and pytest integration are separate work.

## API

```python
from ansible.module_utils.generic_hwsku import (
    canonical_json, plan_scenario, validate_manifest,
)

manifest = plan_scenario(snapshot, defaults, group_settings, host_settings)
validate_manifest(manifest, snapshot, defaults, group_settings, host_settings)
serialized = canonical_json(manifest)
```

Settings merge field by field: DUT settings override inventory-group settings,
which override shared defaults. All settings below are mandatory after merging;
the planner never supplies an unapproved N, profile or address allocation.
Inputs and manifests are JSON-compatible dictionaries; callers own artifact
storage and must validate a saved manifest against its original snapshot before
consuming it. Digests detect modification, not authorization or trust.

## Snapshot contract, schema 1

The top-level fields are `schema_version: 1`, `dut`, `devices`, `links`,
`endpoints`, `lookup`, `supported_profiles`, `sources`, and optional
`excluded_lookup`. Unknown fields, duplicate identities and malformed values
are errors. Speeds are positive integers in Mbps; lanes, channels, indices,
capacities and headroom costs are nonnegative integers, not booleans.

| Record | Fields and meaning |
|---|---|
| Device | `name`, `platform`, `base_hwsku`, `realized_hwsku`, `image`, `asic_count`, `dedicated`, `port_capacity`, `headroom_capacity`, `cages` |
| Cage | `name`, `group`, `protected_reason` (empty if eligible), `modes` |
| Expansion | `id` (unique within cage), `name` (canonical advertised mode), `group_mode`, `ports` |
| Port | `name`, `alias`, `index`, ordered `lanes`, physical `channels`, `speed`, `fec`, `autoneg`, supported `cables` |
| Physical link | `dut_cage`, `dut_channel`, `leaf`, `leaf_cage`, `leaf_channel`, `excluded_reason` (empty if eligible) |
| Reserved transport endpoint | `id`, `leaf`, `cage`, `channels`, `ptf_index`, `trunk`, `vlan`, `host_interface`, `roles` (a nonempty subset of `routed`, `access`) |
| Supported lookup row | `speed`, `cable`, `headroom` |
| Excluded lookup row | `speed`, `cable`, `reason`, `evidence_sha256` |

`sources` contains lowercase SHA256 digests under `capabilities`, `parser`,
`links`, `lookup` and `policy`. The collector must bind them to the actual
installed platform/canonical parser output, unchanged baseline connectivity,
effective lookup and reviewed policy. Device/image/ownership assertions must
also be verified by the future live collector; an offline planner cannot
establish that a supplied assertion is true.

Each device must be a dedicated, reserved single-ASIC device on the same
platform as the DUT. All non-DUT devices are leaf peers. Capacities are the
verified **available scenario budget after reserving unrelated baseline
usage**, not raw ASIC maxima. `port_capacity` includes inactive children of a
selected leaf expansion. Policy must provide conservative additive `headroom`
costs and available per-device `headroom_capacity` for the supported profile.
The planner sums these supplied costs on both active ends; it does not compute
buffer-manager thresholds, derive pool sizes, or replace live convergence
checks. A platform without this verified policy is not ready for collection.

The collector supplies every canonical expansion, including alternate-speed
variants and mixed-speed children. Variants have distinct expansion IDs but
retain their canonical advertised mode name. Every expansion of a cage must
describe the same complete physical lane/channel set. ASIC lane order is
preserved. The planner never divides lanes, parses a breakout string, invents
aliases, assumes FEC, or infers connectivity from Ethernet interface numbers.

`group_mode` is a platform-policy compatibility token: selected expansions in
one device's shared `group` must agree on it. Independent cages use distinct
groups. Excluded channels protect both whole cages; protection propagates
through shared groups and their connected peers. Protected-only capabilities
are listed separately, never counted as executed/covered.

Every physical channel has at most one peer. A DUT child must map to exactly
one complete peer child with matching speed/FEC/autoneg. A transport endpoint's
channels must be contained in that child's connected peer channels. Thus a
merged child selects one existing endpoint; it does not merge baseline VLANs.
Selected endpoints cannot share a PTF index, host interface, endpoint ID or
`(trunk, vlan)`. Different trunks may legitimately reuse a VLAN number.

`lookup` contains all required physically supported `(speed, cable)` pairs,
with policy-provided costs; there is no artificial cable-by-mode Cartesian
product. A pair whose speed exists only on protected cages is explicitly
excluded. Other unsupported rows must be moved to `excluded_lookup` with
evidence, not silently dropped to make a plan fit.

## Settings

| Field | Constraint |
|---|---|
| `min_subports` | N >= 1 distinct DUT children per eligible advertised mode/operating-speed combination |
| `routed_ports` | Exact positive routed-port count; at least one separate access port is also required |
| `access_vlan` | Reviewed DUT access VLAN, 1-4094; separate from leaf/PTF transport VLANs |
| `routed_network` | Dedicated canonical IPv4 pool with room for one /31 DUT/PTF pair per routed port |
| `access_network` | Nonoverlapping IPv4 pool with gateway and a separate PTF peer per access port; /30 or larger |
| `profile` | A member of recorded `supported_profiles` |
| `max_search_nodes` | Positive deterministic search budget; exhaustion is not proof of infeasibility |

Addresses and roles are assigned while satisfying resource constraints.
Routed ports receive stable /31 pairs; access ports share the access gateway
but have distinct PTF addresses. The traffic witnesses cover both directions
between a routed anchor and every other selected endpoint. These are planned
paths, not generated SAI test results or proof of packet forwarding.

## Search and manifest

Stable ordering selects the most constrained uncovered demand first. Bounded
backtracking jointly assigns DUT/leaf expansions, supported cable rows,
transport and forwarding roles. Remaining per-cage capacity provides an upper
bound for pruning. Every child of a selected DUT expansion must be connected;
unconnected children of selected leaf expansions remain explicitly inactive.
The first complete solution is accepted, not a minimum-cage optimum.

The manifest records schema/planner versions, source/device/image identity,
effective settings, required coverage, exclusions, canonical layout, endpoint
mapping/addresses, headroom witnesses and directed traffic paths. Coverage
witnesses name distinct children for every required mode/speed and lookup
pair. Its scenario ID binds normalized inputs and layout; separate SHA256
digests bind layout, mapping and the entire manifest. The whole-manifest
digest is computed before adding its own `manifest_sha256` field.

`validate_manifest` independently replays the declared selections against
canonical input facts, resource limits and coverage requirements, then rebuilds
and compares all witnesses and digests. It does **not** repeat the search or
trust a success flag. Treat the serialized manifest as frozen; deployment and
tests must consume it rather than replan. Observed DB bindings and execution
results belong in separate version-bound evidence.

Errors are explicit: `InvalidInput`, `PrerequisiteError`, `InfeasiblePlan`,
`SearchBudgetExceeded` and `InvalidManifest`. No error returns a partial
success manifest, reduces N or removes a required capability. Successful
offline planning is neither device readiness nor qualification acceptance.

## Offline validation

```text
python -m pytest --noconftest ansible/module_utils/test_generic_hwsku.py
pre-commit run --files ansible/module_utils/generic_hwsku.py ansible/module_utils/test_generic_hwsku.py docs/testbed/generic_hwsku_planner.md
```

The tests use only synthetic devices, expansions, wiring and policy. They do
not reserve a lab, reload a DUT or establish hardware/SAI behavior.
