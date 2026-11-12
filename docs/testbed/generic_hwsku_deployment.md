# Named Generic HWSKU testbed deployment

This is the experimental Generic deployment/recovery integration using the
offline planner. Offline checks are not a physical-deployment result or full HLD/MMU
qualification. Ordinary topology entries and commands remain unchanged.
The named `topo: generic` entry selects the experimental path automatically.

## Admission

Use a Linux controller inside the approved lab execution environment. The caller
must verify the current reservation for the DUT and every whole-device-reloaded
leaf. A plan ID in the environment is provenance, not permission to take a bed.
Do not cancel another plan, change an image, clear preparation failures or change
shared peers to admit this experiment.

Add a `<original-testbed>-generic` entry to the existing `ansible/testbed.yaml`,
not a separate testbed/request file. Keep the original entry and use the same
DUT, server, PTF group and management addresses. Set `topo: generic`, disable
legacy automatic recovery for the experimental entry, and add:

```yaml
generic_hwsku:
  baseline_testbed: example-t0
  leaves:
    - leaf-example
  protected_peers:
    - protected-leaf-example
```

The example names above are placeholders, not an installed physical inventory.
This change intentionally adds no lab-specific testbed row. Copy an existing
authorized baseline row, preserve all its physical/management fields, and set
the new row's `conf-name`, `topo: generic`, `auto_recover: false` and Generic scope.
Read-only collection generates the runtime inputs without a hand-written per-bed
capability policy. Missing installed facts still block execution with a concrete
reason; adding the entry does not prove deployment readiness.
`vars/topo_generic.yml` is the shared empty
topology descriptor used by the existing testbed reader, not another testbed
definition or a static port mapping. The frozen manifest owns those mappings.

Automatically derived inputs:

`protected_peers` may be omitted when empty. Every connected peer must still
be explicitly controlled or protected; omission does not authorize other peers.

| Input | Source and boundary |
| --- | --- |
| Capability and identity | Actual installed image, platform.json, canonical parser and explicit installed base-HWSKU port mapping on each controlled device, with source hashes |
| N | Maximum of canonical same-speed children, required lookup cable rows at that speed and optional upward `min_subports` |
| Routed count | Feasible independent real endpoints and routed/access roles within deterministic MRV; optional `routed_ports` remains exact |
| Lookup and profile | Unambiguous installed lookup and converged applied PG/profile/pool data; lossless, or positively verified PFC-disabled zero-sized lossy ingress PGs. Mixed device policies are rejected; unsupported-speed exclusions are source-bound |
| Resources | Canonical logical-port bound and reclaimed baseline allocations of selected cages only; zero assumed MMU spare |
| FEC/AN and groups | Canonical output or exact unambiguous lane-owner baseline values; absent values preserve defaults. Shared groups require actual compatibility metadata |
| Buffer/QoS templates | Installed SKU/platform `buffers_dynamic.json.j2` or `buffers.json.j2`, plus `qos.json.j2`; resolved symlinks and included assets retain source hashes |
| Cable and neighbors | Frozen cable macro through SONiC's supported hook and actual verified physical neighbors, not invented topology roles |
| Transport | Unchanged CSV VLANs, baseline tagged leaf uplinks, observed parent MTU and immutable installed PTF image identity |
| Access VLAN and addresses | Unused DUT VLAN plus checked shared benchmark address defaults; this does not create missing transport VLANs |

Repository files establish conventions, not the target image's contents. Native
rendering rechecks installed template hashes; device staging validates complete
candidate configs with the installed YANG and rechecks image/platform/parser
sources. Actual link/ASIC/buffer/QoS convergence remains mandatory. Neither a
self-asserted image-support flag nor generated facts grant execution authority.
The approved caller must retain/quarantine unsafe resources on failed recovery.

For an observed `buffer_model: dynamic`, installed templates may emit
`DEFAULT_LOSSLESS_BUFFER_PARAMETER`, `LOSSLESS_TRAFFIC_PATTERN` and the literal
`BUFFER_PG.profile: "NULL"` sentinel. Only that PG reference is deferred to
buffermgr; actual APPL profiles, ASIC bindings and reservation limits must still
converge. Traditional/unknown models cannot use this exception, and protected
global policy cannot be changed by the generated tables.
Only a frozen dynamic model with a positive shared-headroom ratio may treat
`ingress_lossless_pool.xoff: "0"` as automatic sizing. Applied APPL/ASIC values,
the original PG reservation budget and matching observed/live MMU capacity still
gate readiness; fixed XOFF values and traditional/unknown models remain exact.

### One physical layout, separate evidence

There are no mutually exclusive L1 and traffic admission profiles. Every eligible
primary data-port mode/speed and lookup obligation remains mandatory. The
source-verified two-port service exception uses best effort: retain requested
and actual counts plus every missing lookup row, emit
`GENERIC_COVERAGE_WARNING`, and continue with `PLAN_READY_WITH_WARNINGS`.
This does not declare complete coverage or qualification. All selected DUT
children have compatible controllable physical peers and configured cable inputs;
only genuine independent transport endpoints receive forwarding addresses.
After original cleanup, an absent PTF uses read-only inspection of the locally
installed image selected by the ordinary registry and testbed image/tag
conventions; it never pulls an image to manufacture readiness.
Missing transport is reported under `coverage.traffic.unavailable`, not counted
as packet success or reclassified as physical exclusion.

When no routed/access path is provably feasible, automatic planning can retain
the complete physical layout without packet cases. An explicit routed override
cannot silently fall back. Search exhaustion is always a failure. The chosen N
formula and cumulative MRV budget are documented in the planner contract.

Optional overrides belong under `generic_hwsku.settings`; legacy `policy.settings`
is accepted for compatibility. No hand-written device/resource/template policy is
required. Increasing `min_subports` requests extra coverage; explicit routed
counts must fit. Other former policy sections are rejected rather than trusted.

The adapter accepts one single-ASIC DUT and dedicated SONiC leaves. Multi-lane
CSV rows are exact channel units, not inferred lane-to-lane orientation; eligible
finer breakouts require finer verified connectivity. Protected coarse wiring
does not block unrelated eligible cages. Startup symlinks, hardlinks or extended metadata are
rejected by the native writer rather than restored incompletely.

## Lifecycle

Select the Generic entry using the ordinary testbed name argument. Existing
inventory/vault arguments and Ansible verbosity options are unchanged:

```bash
./testbed-cli.sh -t testbed.yaml add-topo example-t0-generic "$VAULT" -vv
./testbed-cli.sh -t testbed.yaml deploy-mg example-t0-generic "$INVENTORY" "$VAULT" -vv
./testbed-cli.sh -t testbed.yaml remove-topo example-t0-generic "$VAULT" -vv
```

No `--generic-request`, separate request path or `--generic` switch is required.
The controller also exposes `preflight`, `smoke` and `status` through
`ansible/scripts/generic_hwsku_lifecycle.py`; its `--help` lists the arguments.
Deployment preflight and mutating commands require the actual scheduler-injected
`ELASTICTEST_TEST_PLAN_ID`. Missing ownership is rejected before collection or
freezing inputs; do not invent an ID to bypass reservation admission.

For a standard physical TestPlan, reserve the original physical name and set:

```text
setup_container_params: -e SONIC_GENERIC_TESTBED=example-t0-generic
common_param: --testbed=example-t0-generic --topology=generic,any --skip_sanity --disable_loganalyzer
skip_remove_add_topo_for_nightly: false
skip_unnecessary_preparation_steps: false
skip_restart_ptf: true
skip_pre_post_test: true
```

The selector validates the original/Generic relationship before routing the three
preparation commands. Pytest uses the same alias. Original cleanup clears the
selector; ordinary commands are unchanged without it. Leave image URL empty for
a no-upgrade experiment and leave add/remove/deploy extra parameters empty.
The deployment smoke records safe actual-configuration/health evidence to the
test log. A session-scoped finalizer attempts verified `remove-topo` after the
ordinary module config/core checks, including when the smoke body fails.
Restoring inside the test body would make the legacy configuration guard
mistake the original baseline for drift and reapply the deployed configuration.
The global checks remain enabled and cleanup failures remain errors. Configure the
caller to retain failed recovery for inspection rather than releasing an unsafe
bed. The admission and evidence sections define the reservation, recovery and
qualification boundaries.

For an image-upgrading NIGHTLY plan, the standard scheduler orders topology
add **before** image upgrade. Do not initialize a Generic transaction there:
upgrading would invalidate its installed-source and original-config snapshots.
Keep the nonempty image URL and `skip_unnecessary_preparation_steps=false`,
but set `skip_remove_add_topo_for_nightly=true` and append
`-e SONIC_GENERIC_BOOTSTRAP_DEPLOY=1` to `setup_container_params`.
The post-upgrade `deploy-mg` collects fresh image facts, cleans the original
host topology, and executes the real Generic add/readiness/deploy sequence.
Without that explicit opt-in, a missing add transaction still blocks deploy.
Terminal or failed-restoration transactions are never restarted by this mode.
Verify the actual collected DUT image; a requested URL is not upgrade evidence.

Initial `remove-topo` invokes the **original topology's host cleanup** without
requiring new Generic collection/planning/assets first. Cleanup receipts belong
to the original platform plan, and native host staging rechecks absence before
Generic mutation. Ordinary serial/parallel cleanup errors are propagated, not
masked by a final success echo. Remnants
block admission. The Generic host baseline is the resulting verified absence
of the old PTF/transport, not a promise to recreate the previous T0 container.
Original DUT/leaf running and startup configurations are captured independently.
Original host cleanup addresses `generic_hwsku.baseline_testbed`, never the
Generic entry recursively. Both entries' physical/management binding is frozen;
changing their shared slot does not silently rebind an existing transaction.
Cleanup-only failures before transaction creation can release the workspace to
the next plan only after fresh, host-only PTF-absence readback, authenticated
owner/scope/source and an explicit no-Generic-configuration guard. This readback
does not require a usable PTF image or collect DUT/leaf planning facts. The guard
is durably changed before transaction creation; a missing journal after that
point cannot be reclassified as cleanup-only. Uninstrumented old receipts need
inspection, and all old failure/hold artifacts remain retained.

`add-topo` uses one frozen manifest, renders installed buffer/QoS templates
against candidate PORT/CABLE_LENGTH and physical neighbors, validates complete configs on each image,
and runs the durable transaction. Every write has an earlier intent and later
independent native observation. The fresh PTF has scenario/operation labels,
independent logical interfaces/MACs, exact reserved VLANs and kernel neighbor
responders. Shared parents/bridges are not reconfigured.

`deploy-mg` consumes the frozen bundle. Only DUT running/startup are changed;
leaf configuration, ports, cables and transport are not replanned or reapplied.
Readiness checks selected carriers, actual ASIC port objects, named APPL
buffer profiles, matching applied ASIC profile/pool attributes and QoS objects.
Frozen PORT speed and lane assignments must match STATE_DB operational speed
and actual ASIC PORT attributes. Buffer profiles require one effective static
or dynamic threshold and the matching ASIC profile threshold mode.
Every selected port must have an actual ASIC PORT object, not just counter
mappings. Applied QoS map types and complete key/value entries must match the
frozen definitions; port PFC bitmaps and combined/asymmetric mode must match
the frozen policy. Unwritten PFC attributes use documented SAI zero/combined
defaults only after the actual port object is established.
Residual PGs in reclaimed headroom scope must have complete, numeric lossless
threshold/reservation evidence. A partially populated lossless profile blocks
readiness instead of disappearing from the budget.
This is deployment convergence, not complete MMU behavior validation.

A failed add/readiness check records its original cause before compensation.
If the platform retries `add-topo` after verified restoration, the transaction
first rechecks every original running/startup/host/alias value, then appends a
new numbered attempt with distinct operation IDs. Earlier history and originals
are retained; no journal is deleted or reset, and the layout is not replanned.
Drift or incomplete restoration blocks retry. The caller controls retries; this
adds no autonomous loop. A successful explicit `remove-topo` remains terminal.
Reports expose the zero-based `attempt`; smoke requires a ready report from that
same attempt, not an earlier compensated deployment.

Native `config reload -y` waits at most 300 seconds, in intervals of at most
five seconds, only for the exact pre-mutation System/SwSS readiness rejection.
Before every attempt and after each rejection it independently verifies the
frozen running state, original startup bytes/metadata and installed sources.
Other errors, possible writes and drift fail immediately; `-f` is never added.
Operation-specific reload logs and receipts preserve the original apply failure
when compensation records its own result.
Frozen optical evidence may temporarily disappear while xcvrd restarts. Wait
at most 300 seconds for all required fields to return, then recheck installed
source bytes and the normal conditional-write guards. Any positively different
module value still fails immediately; persistent absence is not accepted.
Private per-call failure receipts also retain source/capture errors that occur
outside a native write, without returning success or exposing full configs.

`smoke` requires controller `DUT_READY` and core `DEPLOYED` for the same bundle.
It independently rereads all running/startup/host/alias resources, including
exact startup bytes/metadata and unchanged aliases, without calling a mutation
method. When paths exist it checks every endpoint gateway and all frozen
independent forwarding paths with expected egress MAC, payload and decremented
TTL. Otherwise it checks physical bindings and applied buffer/QoS readiness
without launching packet traffic, returning `traffic_executed: false` and
`traffic_status: BLOCKED_NO_INDEPENDENT_PATH`. Actual reservation accounting also
includes inactive/new and removed old children, so stale PG allocations cannot
silently spend reclaimed memory twice.
The deployment-only pytest entry is `generic_hwsku/test_deployment_smoke.py`,
marked `generic` rather than T0. Use the approved diagnostic runner's
`--topology generic,any --skip_sanity --disable_loganalyzer` controls; the
ordinary T0 sanity/minigraph path is not a Generic validation substitute.

For Generic only, the ordinary module config/core guard snapshots the deployed
running configuration in memory without reading or writing shared
`running_golden_config*.json` artifacts. Their bytes, metadata or original
absence remain unchanged. Core/drift checks stay enabled and finish before
session-finalized Generic recovery; ordinary topology cache behavior is unchanged.
This module-check baseline never replaces frozen transaction originals, which
smoke still verifies independently.
On a Generic core/config check failure, the framework retains the failure but
does not run legacy config-save/reload repair. Only the owned session finalizer
may restore frozen resources. Unknown configuration drift still blocks that
conditional recovery and requires a reservation hold; it is never normalized
or adopted as a new baseline.

Final `remove-topo` restores distinct original running and exact startup
bytes/mode/uid/gid, removes only owned PTF/VLAN resources, and deletes only
created, now-unreferenced HWSKU aliases. Interrupted alias publication retains
pre-publication inode ownership evidence. Repeated recovery uses the retained
originals, never a partially deployed replacement baseline. Recovery uses saved
native inputs, scope and transaction artifacts without recollection, rendering or
replanning, even when current settings/source change. Physical binding drift,
missing originals or a different plan owner fail safely with retained evidence.

## Evidence and failure handling

Private originals, templates, operation readbacks, journal and reports live
under ignored `.generic_hwsku/<testbed>/runs/<platform-plan-id>/`, restricted to
their owner. The per-testbed active index stays locked through each CLI phase
and its final receipt, preventing a concurrent plan from switching during
preparation, configuration or recovery. Pytest
uses the same selector. A different plan starts a fresh directory only after
the previous restoration report and authenticated terminal journal agree.
Legacy same-owner workspaces remain recoverable in their original location.
Old directories and absolute artifact paths are never moved, deleted or rebound;
failed/unverified restoration blocks a new run instead of being skipped.
An owner-bound preflight failure may close its claim without restoration only
when no scenario inputs were frozen and no native intent, transaction or hold
exists; its read-only diagnostics are retained.
Collection attempts use fresh directories, so a failed collection cannot reuse stale facts.
Custom workspace paths never change an existing parent directory's permissions.
On POSIX, group/world-writable parents are rejected; an existing workspace must
already satisfy the private ownership/permission contract rather than being
silently adopted. New private directories use the existing native permission helper.
Native readbacks travel as private fetched files, not credential-redacted
Ansible result dictionaries or desired-value echoes. Never publish this directory.
Successful template rendering removes its remote temporary directory only
after the results are transferred privately. Rendering or transfer failure
retains that call's private remote directory, including template stderr, and
reports its host/path without printing configuration or stderr contents.

Reports include generated physical/traffic coverage and availability, keep
`qualification_pass: false` for this deployment/smoke runner, and distinguish
`NOT_READY`, `TOPO_READY`, `DUT_READY`, `SMOKE_PASSED`,
`FAILED_RESTORED`, `FAILED_UNVERIFIED`, `RESTORE_FAILED` and `RESTORED`.
Restoration failure is exit code 4, not success. Both failed restoration and
unverified possibly-applied writes emit a private `recovery-required.json` hold.
Preserve all recovery evidence.
Device and host failure receipts retain the first operation error even if its
follow-up capture fails, and transaction restore errors retain their causal
messages. Each failed host command keeps separate private stderr evidence, so
a subsequent capture failure cannot overwrite the original command's output.
The adapter does not acquire/release platform reservations: the approved caller
must retain/quarantine affected resources on failed restoration. **Do not use a
mutating scheduler profile that unconditionally releases an unsafe bed.**
`RESTORED` proves owned Generic resources/baselines, not platform lease release;
verify lease/health separately. Full generated pytest/L1 and QoS/MMU qualification
remain separate follow-up stages.

The physical smoke entry is `tests/generic_hwsku/test_deployment_smoke.py`.
Offline self-test suites are not included in this public deployment change.
