# Generic HWSKU deployment design

Status: experimental Generic planning, deployment and recovery integration.
Deployment smoke is not full L1/MMU qualification. The constraints and
qualification boundaries below are explicit; reference implementations are
prior art, not evidence that a target image or platform is supported.

## Goals and boundaries

- Use the existing `testbed.yaml` and normal `add-topo`, `deploy-mg` and
  `remove-topo` commands.
- Support one single-ASIC DUT and dedicated, controlled, same-platform SONiC
  leaf peers. Protect shared/different-platform peers and their connected
  cages/shared groups.
- Produce one immutable mixed-breakout layout for physical checks and available
  traffic together. Missing traffic is visible, not counted as a pass.
- Discover inputs from actual installed SONiC assets and observed state instead
  of requiring a hand-written per-bed runtime policy.
- Preserve unrelated configuration and provide durable, independently verified
  recovery. No image upgrade, new SAI API, threshold reimplementation or
  general-purpose runner is introduced.

## Data flow

```text
installed platform + module evidence + effective lookup + applied buffers
unchanged wiring + actual transport/management + optional settings
                              |
                  normalize and validate
                              |
                deterministic bounded MRV
                              |
             frozen layout / coverage / endpoints
                              |
         installed template rendering + native YANG validation
                              |
              add-topo -> deploy-mg -> smoke
                              |
             observed configuration / traffic evidence
                              |
                   remove-topo recovery
```

The manifest binds source/image identities, canonical expansions, physical
connections, addresses, resource/coverage witnesses and integrity digests.
Independent validation replays the witnesses without trusting a success flag or
repeating the search. Deployment and tests consume the frozen result.
Scheduled execution also seals the actual source SHA and platform plan owner
into the input-policy identity. Equal layouts retain deterministic planning,
while distinct executions cannot collide with another owner's native stage.

## Automatic inputs and resource accounting

Freeze positive service-module EEPROM evidence separately from ASIC speed
support. A 10GBASE optical SFP with 10.3G nominal line rate limits service-mode
selection to 10G; the advertised HWSKU 25G request and its missing coverage stay
visible. Recheck the same module facts at native operation boundaries. This
changes neither primary coverage requirements nor the strict health/traffic
checks, and adds no user-supplied policy.

Read both controlled ends' installed `platform.json` and canonical breakout
parser. Preserve lane order, aliases, indices, alternate speeds and mixed modes;
do not derive wiring from Ethernet numbers or divide lanes manually.
Multi-lane CSV rows are exact channel units, not evidence of lane orientation.
An eligible finer breakout needs correspondingly finer verified connectivity.
Resolve CSV names using the installed base-HWSKU port mapping through an explicit
canonical-parser file selection, recording its source hashes. A current mixed
breakout, or the same name/speed appearing in several alternative modes, cannot
replace that baseline wiring identity.

Effective lookup coverage must be unambiguous and consistent across controlled
devices. Unsupported-speed exclusions need source evidence. Select installed
`buffers_dynamic.json.j2` or `buffers.json.j2`, plus `qos.json.j2`, preserving
resolved template identities and dependency hashes.

Use the installed canonical logical-port bound and reclaim only the original
allocations of cages selected in the final layout. Headroom accounting assumes
zero spare MMU memory. Costs use actual lossless PG counts and lookup `size`, or
private `xon` only when observed shared-pool/profile state proves that model.
Unselected/protected allocations cannot be spent.

The installed buffer/QoS policy is authoritative, not an unconditional
lossless assumption. A fully observed PFC-disabled SKU with zero-sized ingress
PGs uses the explicit `lossy` profile and zero lossless-headroom cost, retaining
every physical mode/cable obligation. Generated installed-template output must
prove that same policy before device writes. This is not lossless/MMU
qualification. Missing PGs, enabled PFC, nonzero/unresolved reservations and
mixed lossy/lossless controlled devices do not receive this admission.

FEC/AN comes from canonical output or unambiguous baseline lane owners; absent
values retain installed/default semantics. Shared groups require actual
compatibility metadata. Missing facts fail explicitly.

## Deterministic MRV and generated counts

For each eligible `(mode, speed)`, planner version 4 computes the requested count:

```text
N = max(canonical same-speed children for that mode,
        required lookup cable rows at that speed,
        optional min_subports lower bound)
```

This is the chosen deterministic implementation of combined platform/lookup
coverage, not a verbatim meeting formula. Minimum speed alone is insufficient.
N counts distinct logical children, including children sharing a physical
`PORT.index`; an optional override can increase, not reduce, coverage.

Primary data-port mode and lookup demands remain hard requirements.
Source-verified service ports with limited capacity use best effort while
retaining their requests and every shortfall. This implementation chooses
warning-and-continue, not silent exclusion or a claim of full qualification.

The installed SN5640-C512S2 platform/HWSKU contract identifies exactly two
single-lane, single-child `1x25G[10G]` cages without inferring Ethernet numbers.
Other platforms remain strict until their service-role contract is verified.
After finding the first feasible primary layout, bounded service allocation
maximizes covered service mode/speeds, lookup rows and requested counts around
that primary witness. It retains requested N=6 alongside actual media-feasible
coverage, all missing rows and
`SERVICE_COVERAGE_INCOMPLETE`. Independent validation replays this report.
Service allocation shares the cumulative search budget; exhaustion still fails.
Service ports can also supply real traffic paths, without weakening primary
coverage or an exact routed-port override.

MRV chooses the most constrained uncovered demand first with stable tie-breaks.
Bounded backtracking jointly selects DUT/leaf modes, cable assignments and real
independent transport/forwarding roles. It accepts the first complete feasible
solution, not a minimum-cage optimum.

The routed count is generated from feasible endpoints, with at least one separate
access endpoint for packet paths. An optional positive `routed_ports` is exact.
If traffic is proven infeasible and no override requires it, the same planner
may retain the complete physical requirements without packet cases. Both attempts
share one node budget. Timeout is unknown/failure, never a fallback trigger or
permission to drop modes, N or lookup rows.

## Configuration generation

- Start with separate original running/startup snapshots. Replace managed PORTs
  and their unambiguous dependencies while retaining protected configuration.
- Detach only managed PORT memberships/bindings from shared VLANs and ACL tables.
  Preserve shared SVIs/routes, protected memberships, ACL definitions/rules and
  unselected bindings. Protected address overlaps and L3-backed transport VLANs
  still fail; unknown or rule-level PORT dependencies are not rewritten.
- Remove a baseline BGP neighbor only when its explicit `local_addr` is an
  address removed with a managed interface. Preserve other neighbors and globals.
  Remove managed PORT watchdog rows with the replaced QoS bindings, retaining
  protected watchdogs/globals. Neighbor peer PORT names and PORT descriptions are
  not interpreted as local interface dependencies.
- Render the installed templates against candidate PORTs, frozen CABLE_LENGTH
  and actual physical DEVICE_NEIGHBOR rows. Use SONiC's supported `cable_length`
  macro hook instead of inventing topology roles or vendor thresholds.
- For the traditional buffer manager, freeze its unbound speed/cable profile
  cache closure from the hash-pinned installed lookup and ingress pool mode.
  Preserve existing definitions and PG bindings; copy lookup fields without
  calculating thresholds. Under a source-verified fully lossy policy only,
  normalize an unbound shared-headroom cache definition's reserved size to at
  least XON+XOFF when the retained pool is nonshared. Keep its vendor XON/XOFF
  and threshold fields unchanged. This prevents invalid SAI cache objects and
  asynchronous drift without resizing pools, enabling PFC or claiming active
  lossless headroom.
- Project full-device template output onto managed PORTs, retaining protected
  PORT rows. Namespace conflicting buffer profiles without changing their
  installed attributes. Only an explicitly PFC-disabled, zero-PG/queue-reserved
  candidate may retain compatible shared pools with their exact original
  size/xoff. Each retained pool's size+xoff plus full candidate reservations
  (including port-level profiles) must fit its installed full-device template
  footprint; that footprint must fit observed SDK MMU capacity.
  This adds no lossless-headroom credit or shared-pool resize. Other shared global
  changes, unknown targets and mixed managed/protected selectors still fail.
- Resolve PG/queue objects through consistent COUNTERS_DB name, parent-port and
  index maps, then verify the actual ASIC object and its buffer profile/pool.
  Do not assume switch-created objects persist read-only PORT/INDEX attributes
  in ASIC_DB, or treat a missing counter mapping as successful readiness.
- Keep unused leaf children admin-down. Require buffer/QoS coverage on active
  children and check actual reservation usage, including inactive/new and removed
  old children, before claiming convergence.
- Use only existing CSV transport VLANs and verified leaf tagged uplinks.
  Separate them from an unused DUT access VLAN and checked benchmark address pools.
  Never invent missing transport or merge baseline VLANs for a merged child.
- Reuse a verified locally installed immutable PTF image without pulling.
  Configure independent interfaces/MACs, responders and generated forwarding paths.
  Explicitly set and verify creator aliases after link creation and namespace
  moves; an accepted `ip link add ... alias` alone is not ownership evidence.
  Do not add BGP VMs, LAGs or new VRFs.
- `deploy-mg` changes only final DUT forwarding/buffer/QoS state; it does not
  replan PORTs/cables or reapply the leaf configuration.

## Standard physical TestPlan integration

The platform reserves the existing physical bed, while the source selects its
`<original>-generic` row from the same YAML file. For the current experiment:

```text
physical reservation: example-t0
Generic scenario:     example-t0-generic
```

`setup_container_params` supplies
`-e SONIC_GENERIC_TESTBED=example-t0-generic`.
The three normal preparation commands validate that the scenario belongs to the
requested physical bed and that both rows retain identical physical/management
bindings. Original-topology cleanup clears this selector to prevent recursion.
Ordinary commands remain unchanged when the variable is absent.

Pytest selects the same Generic row through
`--testbed=example-t0-generic --topology=generic,any`.
The deployment smoke also uses `--skip_sanity --disable_loganalyzer`, skips
legacy pre/post-test behavior, and sets `skip_restart_ptf=true`.
It does not skip Generic configuration/link/buffer/QoS validation.
Preparation must still perform real original cleanup and Generic add/deploy.
For image upgrades, the standard NIGHTLY scheduler's remove/add precedes its
image stage. Set `skip_remove_add_topo_for_nightly=true` and explicitly enable
`SONIC_GENERIC_BOOTSTRAP_DEPLOY=1`: the post-upgrade deploy entry collects fresh
facts and runs actual cleanup/add/readiness/deploy. No frozen Generic source or
original configuration may cross an image upgrade. Ordinary missing-add
rejection and terminal/recovery holds remain unchanged without this opt-in.

The scheduler injects the real `ELASTICTEST_TEST_PLAN_ID`. That identity binds
the frozen operation; it does not itself grant a reservation. The normal caller
must own the DUT and every whole-device-reloaded leaf. Never manually pre-lock
and then submit a plan or overwrite another owner's lease.

## Recovery and evidence

Record intent before every possibly applied operation, then independently read
back actual state. Use compare-and-swap/drift guards; do not overwrite unexplained
external changes or replace the original snapshots with partial deployment.

Readiness failures belong to the attempted `add-topo` or `deploy-mg` phase;
successful compensation does not make deployment successful. Retain the first
causal phase/stage/error before recovery. A caller may retry `add-topo` after a
failed attempt reaches `RESTORED`, but only after independently rereading every
frozen original resource. Append a numbered attempt with new operation identities;
retain all earlier operations, failures and original artifacts without replanning.
Drift blocks reentry and requires a recovery hold. Successful explicit teardown
remains terminal. Packet admission binds the current attempt, so an older ready
report or a compensated failure cannot qualify the retry.

The native writer may wait up to 300 seconds for SONiC's exact pre-mutation
System/SwSS reload-readiness rejection, without `-f`. Every attempt rechecks
installed sources and unchanged running/startup originals; unrelated errors or
drift remain failures. Keep reload output and native receipts per operation so
recovery cannot overwrite the first apply cause.
Temporarily absent frozen optical fields during xcvrd restart have a separate
bounded 300-second wait; changed positive values still reject immediately.
Recheck installed source bytes after that wait and retain all running/startup
CAS guards. Per-call native failure receipts preserve failed source/capture
checks even when no write receipt exists; failures never become success.

`remove-topo` uses saved native inputs, scope and transaction artifacts without
recollecting or replanning, even if current settings/source change. Verify the
frozen bundle/physical binding and original owner. Restore original running and
exact startup bytes/metadata independently, remove only owned host/VLAN state and
delete only created, unused aliases.

The Generic host baseline is verified absence after original-topology cleanup;
recovery does not promise to recreate the previous T0 PTF/VM topology. Original
topology preparation and platform health/lease release are separate checks.
Recovery verifies original configurations and owned-resource state; it does not
require original admin-down or otherwise baseline-down ports to become up.

The scheduled smoke verifies actual frozen resources and applied health, runs
only genuine available packet paths, and records sanitized version-bound evidence
in the test log. Its session finalizer verifies Generic recovery after the
ordinary module config/core checks. The deployed layout remains unchanged for
those checks; restoring inside the body would trigger their legacy repair and
overwrite the recovered originals. Keep global checks enabled, and still run
guarded recovery after a failed smoke body.
Recovery failure is non-success and emits a private hold receipt. The caller must
retain/quarantine unsafe resources, preserve originals and resolve the failure
before release; a zero-retention unconditional-release profile is unsuitable.

Full configs/originals remain in private scenario storage, never PR comments or
public logs. Deployment reports keep `qualification_pass=false`; no-path layouts
explicitly report `traffic_executed=false`.

## Delivery and acceptance

The four implementation boundaries remain: planner/manifest; deployment/recovery;
generated pytest/L1/platform integration; QoS/MMU integration. Planning and
deployment/recovery include focused regression coverage. Full generated
pytest/L1, QoS/MMU integration and the platform qualification matrix remain
separate work.

Offline tests cover determinism, automatic counts, canonical/wiring constraints,
protected resources, template boundaries, shell routing, failure/retry and frozen
recovery. They do not prove installed-image support or ASIC behavior.
Physical evidence must bind actual executed SHA, image, scenario, case results and
verified recovery. A TestPlan creation or a preparation pass is not deployment,
traffic or qualification success.
