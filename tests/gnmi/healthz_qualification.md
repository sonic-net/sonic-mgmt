# Healthz qualification on a lab DUT

For final installed-image qualification, run this procedure after the host
services, management common, and gNMI packages are built and installed on an
authorized lab DUT. The read-only baseline observes retained state. Opt-in
controlled cases publish independent producer transitions or change an explicitly
selected installed DLDD demo signal to create reversible fault episodes. They
restore the selected signal and do not install or change DLDD rules.

## Fresh review hardening, 2026-11-09 UTC

The installed-source follow-up used host commit
`bc1b693046220df8c067e5d468bbc5d591043faa`, management-common
`6d5b7ef932e795a8ed3f174cceacd1e6a429c4e4`, and gNMI
`1f40bb832ffe37e6dcd4c4e77ed0e85a624bd7b7`. The final full-model telemetry
ELF is 58,193,024 bytes, SHA256
`defa924760ac970f60ef993346ba5f9a36586f7bc7686c2fae25fd8044a49fac`.
The derived installed gNMI image is
`sha256:e0f218de0508eb173d60c1a8a4fb3be80131d1a8a4e95dc5623fbc8ee9c16956`.
These are compatible host-file overlays and a derived image, not a newly
built and booted full SONiC image.

- All 398 scoped Python tests and five subtests passed locally and on native
  DUT Python 3.13. These are overlapping executions of the same suite.
  Both host-health/FEATURE integration groups passed 16 cases. Five focused
  acceptance-test checks reject empty source qualification and distinguish
  legitimate observations from unauthorized catalog changes.
- The normal full-model build passed. All 21 translator tests passed normally
  and with race instrumentation; the Healthz/artifact/auth suites passed 52
  normal tests and 51 race tests. Full generated bindings and dependency
  compatibility were checked. Unfiltered vet findings remain exactly two in
  translib and 119 in gNMI, with no additions or removals.
- Eight new private functional cases and all 19 existing safe failure groups
  passed on the DUT. They cover action/recheck gating, async single flight,
  dynamic discovery/replacement, timeout output, durable transition replay,
  interrupted tiny archive staging, DSE get/action/query failures and recovery,
  private Redis transport, file errors and emulated I2C. Vendor callbacks and
  I2C tools are test implementations; physical ASIC/I2C recovery is unqualified.
- Four tiny real systemd outcomes passed using the installed health checker:
  declared normal exit 3 is healthy without restarting; failed exit 1, ordinary
  stopped exit 0 and undeclared exit 3 remain unhealthy. The deployed DLDD unit
  reads back `Restart=on-failure` and `SuccessExitStatus=3`. Existing unrelated
  FEATURE/container behavior was preserved.
- Real gNOI File.Put delivered a safe appended mock rule. Two explicit runs of
  the installed watcher service, 31 seconds apart, respected the configured
  30-second settle check and caused actual DLDD restart/activation. The
  packaged five-minute timer was unchanged; its natural polling deadline was
  not the test clock. Original inbox/active bytes, owners and modes were
  restored through File.Put and the same watcher path afterward.
- The final native client sent valid module-qualified component and fault
  PathElem names. A synchronized ON_CHANGE stream contained the exact initial
  INACTIVE episode, then post-sync ACTIVE and INACTIVE with matching origin
  and occurrence values. Qualified GET returned both states. A fully qualified
  component-health GET also passed using an explicit protobuf path.
- The final image passed all 23 isolated TLS role/trust probes, read-only
  Get/List, standard Check with `event_id` returning Unimplemented, and exact
  retained artifact transfer. The largest transfer returned one header,
  12,292 data frames and one trailer containing 50,347,739 bytes with SHA256
  `83e97027055f6a307ee36a004913a45a40f4c643a8ed158a2d146210f0921d8b`.
  Existing events, acknowledgements, archive bytes and protected identities
  were preserved; owned mock inputs and temporary listeners were removed.

Live validation exposed an earlier routing gap in common `b667b663`: valid
qualified component names reached an empty subscription mapping before the
notification resolver. The final shared path comparison normalizer fixes
routing as well as key binding and preserves original qualified paths. Its
full-entry regression fails against that earlier source and passes in the
final native build and live server.

Initial test attempts remain distinct from final passes. The first native
Python run hit an overly tight test-only address-space cap; the corrected
bounded run passed. An expired retained-fault fixture caused a guarded gNMI
rollback. A 120-second activation wait was shorter than the packaged watcher
polling interval. The first direct protocol client used unsupported GET type
STATE; the final client uses supported ALL. The stock gnmi_get XPath parser
rejects qualified list names locally, so that form uses `pbpath`. A local
management-path loss occurred after the final test completed; the builder
path verified the same boot ID and completed restoration receipts.

Full scoped Ruff, Bandit, normal/strict mypy, Pyright, compilation and schema
checks retain inherited and advisory findings. No new production normal-type,
Ruff-correctness or Bandit findings remain; strict/style debt is not presented
as clean. Full sonic-mgmt testbed execution, full-image boot/upgrade, forwarding,
peak load, soak and physical vendor recovery are not qualified by these checks.
The restored seven-rule lab baseline remains DEGRADED for three missing inputs.
No OOM/exhaustion test or kernel-policy change was made in this follow-up.
The DUT remains at `vm.panic_on_oom=2`, which still prevents claiming that a
memory-cgroup OOM is contained to DLDD; a compatible platform policy is required.

## Qualified baseline, 2026-10-08 UTC

The 2026-10-08 qualification used `sonic-host-services` commit
`49402b82add74823e9910baaf21be77bfcdc34f4`, `sonic-gnmi` commit
`70bdfe99a941d255848254bea51fb42fe4719a57`, and `sonic-mgmt-common` commit
`e7a1ad8b24987c9bd277793ab487e0bea653279a` on lab DUT `172.25.43.65`.
Earlier September candidate runs used different sources, stream ownership and
artifacts; their results do not qualify these final versions.

- Host tests: 148 focused, 1069 full (13 integration cases deselected,
  22 warnings), and 13 integration tests passed. The official host Make gate
  passed 1069 tests (13 deselected, 19 warnings), and the wheel build exited 0.
  Scoped Ruff/compilation and pinned Linux Go Healthz/Artifact tests passed.
- Official gNMI Debian and container Make targets passed. The installed host
  wheel SHA256 is `b9ec1c26f62ad67cdd7316a27c74c089b96f372c342a2ef8f950f19a23089bfa`.
  The final deployed gNMI image is
  `sha256:736b6ab3ec9997018e68bcbf579dcd5de7a25d43c1eb1fdfc82fee66ec30ce27`;
  its telemetry SHA256 is
  `49ba73e1184eb432ef70ddbac15557e128b271be89185dccde0ae693589e2b36`.
  Source, package, runtime and archive hashes were checked.
- Installed Get/List/Artifact, repeated Acknowledge without archive deletion,
  default acknowledgement filtering, standard Check returning Unimplemented,
  and OpenConfig GET passed. The controlled DLDD SERVICE event used a new
  Healthz archive ID as its event and first ArtifactHeader ID. Recovery used a
  distinct opaque ID and advertised no older archive.
- A synchronized ON_CHANGE subscriber observed activation, a timestamp-only
  asserted observation, and recovery. Only two events were added;
  unhealthy-count advanced 15 to 16 once. Routine refresh, DLDD restart and
  host reconnect checks created no duplicate event.
- All 23 live TLS role/trust probes passed. Final preservation checks recorded
  78 to 82 events, 12 to 13 acknowledgements, and 17 to 18 archives, exactly the
  controlled additions. Prior events, acknowledgement, archives, rules and
  signal data were preserved; temporary listener/certificate resources were
  removed. Required services were active with no failed units or recent
  production errors.
- A native same-image reboot passed on the preceding image
  `sha256:5dff9c66686804b847cb768c36beb5fa50637c7ad747ed79954ea8b8c1e3b322`
  with the same host wheel. Its 78 events, 12 acknowledgements and 17 archives
  survived. Redis loss produced a durable history gap, without invented events
  or HEALTHY from missing fault rows; known PORT UNHEALTHY/count 6 was
  republished before an RPC. This reboot does not qualify image `736b6ab3`.
- The official unsigned whitebox Cisco installer Make completed with exit 0.
  `sonic-cisco-8000.bin` is 2,367,274,991 bytes, SHA256
  `cb379d708d8a4414a0c8ff2c90e4930e94a64c951970dd8d7ae1c49c7ee4d061`.
  A combined payload audit passed. The original strict inspector remains exit
  1: two wheel/digest findings were resolved by byte-identical contents and
  timestamp-only ZIP differences; its duplicate Regex finding counted one
  package's internal module twice. RECORD hashes and the actual embedded
  Python/extension import independently passed. The installer was not installed
  or booted.
- The shared grpcurl streaming helper's seven standalone unit regressions
  passed. The full sonic-mgmt harness was excluded by the user; focused live
  checks do not claim pytest framework execution.

Private Redis 8.0.2 tests verified wrong-type and complete-batch stream-ID
capacity preflight, watched contention/expiry, normal refresh, and
whole-transaction maxmemory rejection. Publication is qualified under stable
command permissions. Administrative command-ACL changes during EXEC and
crash/power-loss durability remain outside that verified boundary. With the
ID-only fault contract, lost/trimmed transitions are explicitly unrecoverable;
Healthz records a gap and preserves known state rather than reconstructing
missing events. Image upgrade and secure boot remain unverified. Device clocks
were unsynchronized, so no precise cross-host boot or operation duration is
claimed.

Preserve the live Healthz catalog, acknowledgements and archives when rolling
back packages or containers. A captured SQLite backup is evidence; restoring it
over the live catalog can discard events written after the snapshot.

This committed record is self-contained. Detailed raw reports and hash receipts
remain in the lab handoff; links to private workspace staging directories are
not part of this repository's qualification procedure.

## Publication retry follow-up, 2026-10-09

Host commit `1c817fe2ffad56f2d7ee88a031064f62ed00cd20` propagates the existing
publication result. A rejected metadata refresh must preserve the pending retry
for a failed recovery. One regression reproduced the dropped retry before the
fix and verifies that a later successful retry emits exactly one recovery.
Exact-source Linux validation passed 149 focused tests, 1070 full tests
(13 integration cases deselected, 22 warnings), 13 integration tests, scoped
Ruff and compilation. Both image repositories reference this producer revision.

As of the October 9 record, this follow-up had not been deployed to the DUT or
included in a rebuilt full installer. The October live and installer results
remain qualification of host commit `49402b82`. The November 8 validation below
uses a later deployed host revision that includes the retry correction.

## Current-source validation, 2026-11-08

Functional validation on lab DUT `172.25.43.65` passed, but host OOM containment
failed under its normal kernel policy. The temporary-policy follow-up below
does **not** establish memory-fault isolation for deployments retaining that
normal policy.

The deployed host source was
`ba1969208273e54c4fb424f651ac00db88fbb207`, with utilities
`83fc3c17c2f30b0f94f22ad72000632bde108ba8`. The unchanged Healthz backend
was checked for installed-source/hash parity. The corresponding gNMI and
management-common source references are
`1f40bb832ffe37e6dcd4c4e77ed0e85a624bd7b7` and
`687efc2724be38e20ee175925190f51f4ceb9f9c`. These references do not imply a
new full-image installation: the host wheel build passed, but no new complete
image was built, installed or intentionally boot-qualified in this campaign.

| Area | Result and boundary |
| --- | --- |
| Scoped host tests | 330 DLDD/Healthz tests passed locally and natively on the DUT. Native execution does not turn mocked unit boundaries into hardware integration tests. |
| Combined focused Python validation | 440 tests passed across host, utilities, Cisco DSE, legacy debug collection and gRPC helpers, plus two existing FEATURE service-health contract checks. |
| Rule execution | Live fixtures covered Redis, file, CLI, Python and dynamic DSE sources; comparisons/correlation; inventory changes; localized runtime failures; and healthy, fault and recovery states. |
| Local actions and collection | CLI and DSE actions exercised completion, wait/recheck and execution-error/timeout paths. Static/DSE logs, normalized file collection and captured action output were inspected in collected artifacts. |
| Telemetry and RPCs | Actual fault telemetry was checked through `FAULT_INFO` and its OpenConfig mapping, separately from Healthz component state and artifact RPCs. Get/List, acknowledgement/filtering, pending/missing artifacts, invalid requests and synchronized ON_CHANGE paths were exercised. |
| Large artifact/concurrency | A 48 MiB payload was packaged and retrieved through the actual Artifact RPC; reconstructed bytes matched the advertised size and SHA-256. Concurrent metadata calls completed within 1.53 seconds. This measures this DUT/load, not an unconditional latency guarantee. |
| TLS authorization | All 23 role/trust cases passed on an isolated loopback listener. Repeated acknowledgement preserved the campaign archive. Temporary TLS/configuration/IPC resources were cleaned, with production gNMI identity unchanged during these probes. |
| CPU enforcement | A disposable `CPUQuota=20%` unit measured 20.0069% aggregate CPU usage. This verifies that scoped CPU test, not every deployment profile. |
| OOM containment | **FAIL:** exhausting an isolated 64 MiB memory-limited unit caused a host kernel panic/reboot. Kernel/kdump evidence identified a memory-cgroup OOM with host `vm.panic_on_oom=2`. A unit memory limit and `OOMPolicy` do not override that host panic policy. |
| Remaining fault injection | The panic interrupted task-limit exhaustion and explicit disposable-unit crash/restart checks; the follow-up below completes them. Live BROKEN-lifetime injection remains unrun. |

Normal host mypy retained 30 findings and Pyright retained 50 errors, unchanged
from the clean baseline. The static-analysis result is not a zero-findings
claim. Focused tests and CI checks do not substitute for the unrun full image,
full sonic-mgmt harness or service-failure qualification.

After the unexpected reboot, the original seven-rule ruleset and vendor wrapper
were restored. The reboot is failure evidence, not successful reboot
qualification. `/tmp`-only raw output was lost; durable `/var/tmp` fixture/RPC
records, archives and baseline data remained available. Preserve that evidence
and resolve the host OOM policy before repeating memory-exhaustion testing.

### Capped-unit follow-up under temporary OOM policy

With explicit authorization, `vm.panic_on_oom` was changed at runtime from `2`
to `1` for the disposable-unit tests and restored to `2` afterward. No persistent
kernel configuration changed. The detached controller had a 150-second limit
and an independent `ExecStopPost` restoration hook. Both normal and stop-time
cleanup verified that all five owned units were stopped and their cgroups were
empty before restoring the original policy.

All five cases passed:

| Case | Observed result |
| --- | --- |
| CPU | `CPUQuota=20%` measured 20.099% aggregate CPU with throttling. |
| Memory | The 64 MiB unit reached a 67,108,864-byte peak and terminated with `Result=oom-kill`, signal 9. The host remained running. |
| Tasks | `TasksMax=16` admitted the main process plus 15 worker threads; the next thread failed and the cgroup limit counter increased. |
| Crash cleanup | Killing only the disposable main process terminated and reaped its child, even though the child had created a new session. The cgroup was empty after stop. |
| Restart | An exit-7 failure caused exactly one automatic restart, followed by a successful exit from a different process. |

The boot ID, production service process identities and container start times
were unchanged throughout the follow-up. No production service was deliberately
killed or restarted. The original seven rules and vendor module remained in
place. Local evidence contains the per-case reports, unit journals, policy
receipts and both restoration-path receipts; its bundle SHA-256 is
`21332003565aedd11d9b04e0b2f3e7382ca7559b2147fa165399754efe73a642`.

This qualifies the scoped tests under policy `1`. The DUT now has policy `2`
again, so the deployment blocker for service-only OOM recovery remains.

## Failure-hardening follow-up, 2026-11-09 UTC

This follow-up supersedes the earlier statements that the BROKEN-lifetime
campaign was unrun and that DLDD lacked bounded file samples, default Redis
deadlines, default query timeouts, or an execution watchdog. The earlier
kernel-panic result remains valid. **Host failure handling, native Go,
corrected OpenConfig GET/ON_CHANGE, and the deployed Healthz RPC checks pass.
Production OOM isolation remains blocked by the host kernel policy.**

The deployed host source is
`47527541f0d2f996249d95cd71d0d4af73c1c48d`, following bounded-failure commit
`7679cad7e004f4647249daf3ef59bfe51d4f01d5`. All 37 installed DLDD Python
module hashes match the final host commit; the 38 source members also include
one JSON file. Four changed Python files were deployed atomically with backups.
The native wheel build passed and 44 DLDD/Healthz members were verified; its
SHA-256 is
`8e3dd4da9d81dda4eeeda8f6e94f3da46db8742f5b07bb1df896776d19dd5863`.
This was a source overlay and wheel verification, not a new SONiC image boot.

The active gNMI container image is
`sha256:62b580fd5baafdee609d6856803cec03da7b824584fd63941ea170cbe0a10832`.
Its Linux ELF SHA-256 is
`36a1f5000139630dfcdc6bacca779731ba8bacf409f9f34098146519ab437a1e`,
built normally from gNMI `1f40bb832ffe37e6dcd4c4e77ed0e85a624bd7b7` and
management-common `2fb9a0ee73b977dee8324d88abdb33c6eb80fc2f` with full model
generation. Current image model inputs and generated Go/schema compatibility
were verified; the earlier reduced-model candidate was never deployed.

| Area | Result and boundary |
| --- | --- |
| Scoped Python tests | 368 DLDD/Healthz tests passed locally in 42.28 seconds and on native DUT Python in 41.07 seconds. They retain mocked boundaries on the DUT. Five lifecycle cases passed again natively after test-only type refinements, in 19.347 seconds by JUnit. |
| Private failure campaign | 19 groups passed: 16 actual-service/private-Redis groups plus direct Redis, emulated-I2C and file/durable-I/O component groups. Synthetic platform callbacks and a Healthz protocol double do not qualify production D-Bus, archives or hardware. |
| I2C service path | A separate actual-service case passed source nonzero exit, timeout/recovery, peer progress, emulated local set and post-action recheck. Default command paths were bound to private tools; no physical I2C/ASIC write was performed. |
| Process and admission failures | Disposable actual-service units passed native-GIL watchdog recovery, SIGSEGV restart, 120-second monitor nonprogress, restart limiting and TERM-ignoring child cleanup. Admission reached 32 tasks and 64 FDs and recovered through the same ActionRunner. The GIL watchdog used six seconds, stop timeout two seconds, and restart delay one second with a two-start limiter; these are explicit test overrides. No production crash was injected. |
| Dynamic BROKEN lifetime | The earlier strict unclean-restart failure was reproduced and fixed. A four-child actual-service campaign sharing private Redis passed unclean same-generation BROKEN restoration before sampling, clean restart reevaluation, retained fault/action identity and new-checksum behavior. The strict campaign passed again against committed host `47527541`, in 15.478 seconds. |
| Native Go | The full-model normal build passed. Focused native suites passed 18 fault/component-Healthz tests (56 including subtests), 52 Healthz/artifact/authorization tests (79 including subtests), and 51 Healthz/artifact tests with the race detector (78 including subtests). These are focused suites, not every translib/gNMI test. |
| Keyed OpenConfig fault mapping | The request-bound-node defect was reproduced and fixed. Isolated binder/mapper/response tests passed 14 functions and 33 subcases, including five new red/green regressions. Actual keyed GET and synchronized ON_CHANGE then passed on the new image: initial `INACTIVE` at occurrence 4, sync, `ACTIVE` at occurrence 5, then `INACTIVE` still at occurrence 5, with stable origin `1794194416`. The original seven rules were restored. |
| Deployed RPCs and artifact | All 23 TLS role/trust cases and 11 live Healthz metadata, acknowledgement, unsupported-operation and negative-path cases passed on the new image. The actual Artifact RPC streamed 50,347,739 bytes; reconstructed SHA-256 was `83e97027055f6a307ee36a004913a45a40f4c643a8ed158a2d146210f0921d8b`, exactly matching the archive. |

The host changes add five-second Redis connect/read-inactivity waits, bounded
file/sysfs raw samples, a 30-second default artifact-query timeout, bounded
callback admission, monitor progress escalation and primary-loop-only systemd
watchdog notification. The packaged watchdog is 120 seconds and uses SIGKILL.
These do not impose a total Redis/DNS deadline, bound glob or kernel-driver
execution, forcibly cancel vendor threads, stop uninterruptible kernel work,
or roll back hardware effects. Generic Healthz remains a separate host service.

The final static inventory covers 133 Python and four Go files; 108 Python
scanner commands completed. Host production/test normal-mypy and Pyright
finding multisets add no diagnostics versus the clean baseline. The scan is
not clean: legacy correctness/security findings remain, and the campaign
helper/test scope retains 42 normal-mypy and 115 Pyright findings
(635 strict-mypy findings). Those helper findings are new, reviewed debt,
not pre-existing production findings. The 26 probe regressions and seven
deployment-helper mock tests pass with clean normal-mypy/Pyright scopes.
Native Go vet retains 121 inherited diagnostics; every diagnosed file is
byte-identical to its previously installed source, and no finding names a
Healthz or fault-mapper implementation file. No static finding was suppressed.

The intermediate production probes also retain their failures: P2 was blocked
by the test unit's socket-group configuration; P3 rejected valid scalar
TypedValue leaves because its verifier expected a JSON object. These were
qualification-helper failures, not additional product defects. The corrected
P4 probe passed the exact synchronized fault episode above.

Final preservation checks retained all 146 prior events, 22 prior component
aggregates and 20 archives, with 16 acknowledgements. The 156-event total has
exactly ten additions for the controlled lab component, all without artifacts.
The original seven rules and vendor code were restored; no fixture processes
remained. Boot identity and OOM policy were unchanged.

The earlier cgroup OOM panic under `vm.panic_on_oom=2` is still a production
deployment blocker. Policy remains `2`; no OOM injection or kernel-policy
change was part of this hardening follow-up. Retain the pre-fix failures and
their passing replacements as separate evidence. Image branches pin the
qualified producer commits; publication and CI status are tracked separately.
Full SONiC image boot/upgrade, forwarding traffic, power-loss durability and a
production soak are not established by these scoped results.

## Inputs and transport

### Automated pytest cases

`test_gnoi_healthz.py` checks installed aggregate-to-gNMI GET mapping, stored
Get/List/default acknowledgement filtering, and NotFound for unassessed
components. Its three controlled cases are opt-in. The generic archive and
no-archive cases publish only their own unique producer/component records to
`HEALTHZ_TRANSITIONS`; the archived case submits one small file through host
D-Bus. The DLDD case changes an explicitly selected installed demo signal
between `HEALTHY` and `FAULT`, checks the scalar-only fault artifact ID, and
restores the signal's original bytes and ownership/mode. It does not install
or edit rules. Every case synchronizes ON_CHANGE before activation and verifies
post-sync activation and recovery. It checks the asserted observation through
GET with unchanged event IDs/count; it does not separately assert timestamp-only
ON_CHANGE delivery. The focused live qualification above covered that delivery.
Archive ID, frame ordering, size/SHA256, idempotent acknowledgement and filtering
are checked in the applicable cases.

From `sonic-mgmt/tests`, use the usual testbed options with this selection
during an exclusive lab Healthz write window:

```sh
pytest gnmi/test_gnoi_healthz.py gnmi/test_gnoi_healthz_auth.py \
  --healthz-controlled-episodes \
  --healthz-dldd-component DLDD_DEMO_SERVICE \
  --healthz-dldd-signal /var/tmp/dldd-demo-20260929/cli_status
```

Without the controlled option, all three episode cases skip before TLS setup.
Without both DLDD options, only that case skips before TLS setup, with the
missing-input reason. Archive cases require a free slot in the installed
20-archive store so they do not prune retained artifacts. Test events and their
archive follow normal Healthz retention; teardown clears each controlled
source and removes its temporary input file. A teardown failure is a test
failure. The baseline and authorization cases use the existing `gnmi_tls`
fixture, which configures certificates, restarts gNMI, and rolls configuration
back afterward; schedule that interruption with other gNOI qualification.

`test_gnoi_healthz_auth.py` checks all five RPCs under `gnoi_readwrite`,
`gnoi_readonly`, and `gnoi_noaccess`, plus TLS handshake rejection without a
client certificate. Missing valid IDs distinguish authorization from method
execution without acknowledging an unrelated event. It verifies that catalog
contents remain unchanged and restores the certificate's original role.

The shared grpcurl streaming helper has standalone malformed/truncated-frame
and request/metadata regression tests:

```sh
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/unit_test_ptf_grpc.py
```

Record the DUT image and installed package versions. Use one known DLDD component
with no unrelated active fault, and a separate component for the independent
producer. Record these IDs as the episodes run:

| Input | Required observation |
| --- | --- |
| Archive episode | An `ACTIVE` DLDD fault with a **new** Healthz reservation and submitted archive, followed by its `INACTIVE` transition. Record the reservation ID and the two event IDs. |
| No-archive episode | An `ACTIVE` DLDD fault without a new archive, followed by its `INACTIVE` transition. Record the two event IDs. |
| Independent producer | A controlled non-DLDD source publishes active, asserted observation, and inactive records to `HEALTHZ_TRANSITIONS` without creating `FAULT_INFO`. Record its producer, source key, transition IDs, and event IDs. |

The DLDD fixture must publish an initial or changed fault state to the bounded
`HEALTHZ_TRANSITIONS` stream with `producer`, `source_key`, a stable
`transition_id`, `component`, `component_type`, `symptom`, `active` (`1` or `0`),
and `observed_at` (Unix seconds). A new archive adds `artifact_id` from
Healthz `reserve_artifact({})` before publication; DLDD then collects its own
concrete files and calls Healthz `submit_artifact` with that ID and the files.
The host `artifact_status` must progress from `PENDING` to `COMPLETED`, or an
explicit failure must be reported through `fail_artifact`. An asserted sample
of an already active source uses `kind=observation`, `producer`, `source_key`,
`component`, and `observed_at`; it carries no new transition ID or event.
Use a new transition ID for every real publication. DLDD does not reconstruct
or replay a lost transition from `FAULT_INFO` after restart; duplicate delivery
of an existing stream record must remain idempotent.

Keep the ON_CHANGE subscription running before each controlled transition.
Use the existing `gnmi_tls` fixture in
`tests/common/fixtures/grpc_fixtures.py` for a matched TLS client when its
certificate/configuration changes and gNMI restart are authorized. Its
`gnmi_tls.grpc.call_unary()` method can issue Healthz Get, List, and
Acknowledge; `gnmi_tls.pygnmi_client` can issue gNMI Get and Subscribe. The
fixture tears down its certificates and rolls back its configuration. If
already configured credentials are available, use them for read-only baseline
queries without invoking this fixture. The UDS fixture may install `grpcurl`
on the DUT and needs the same operational review.

For each gNOI call, use a standard component path with exactly these elements:

```json
{"elem":[{"name":"components"},{"name":"component","key":{"name":"<component>"}}]}
```

The service is `gnoi.healthz.Healthz`. Example calls inside a test using
`gnmi_tls` are:

```python
path = {"elem": [
    {"name": "components"},
    {"name": "component", "key": {"name": component}},
]}
get = gnmi_tls.grpc.call_unary("gnoi.healthz.Healthz", "Get", {"path": path})
all_events = gnmi_tls.grpc.call_unary(
    "gnoi.healthz.Healthz", "List",
    {"path": path, "includeAcknowledged": True},
)
state = gnmi_tls.pygnmi_client.get(
    f"/openconfig-platform:components/component[name={component}]/healthz/state"
)
ack = gnmi_tls.grpc.call_unary(
    "gnoi.healthz.Healthz", "Acknowledge",
    {"path": path, "id": archive_event_id},
)
```

`Get` returns `component`; `List` returns `statuses`. Use the component name
key exactly as published in OpenConfig platform data. Keep the complete RPC
responses and timestamps as evidence. For each transition, consume a bounded
subscription on a separate client while the external fixture changes the
fault. `subscribe()` returns a lazy generator; constructing it or collecting
it with `list()` before triggering the fixture does not establish a concurrent
subscriber. The fixture client can still make independent gNMI Get calls:

```python
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from tests.common.pygnmi_client import PygnmiClient, StreamMode

base = gnmi_tls.pygnmi_client
subscriber = PygnmiClient(
    base.host, base.port, plaintext=base.plaintext,
    ca_cert=base.ca_cert, client_cert=base.client_cert,
    client_key=base.client_key,
)
synced = Event()

def collect():
    messages = []
    for message in subscriber.subscribe(
        f"openconfig://components/component[name={component}]/healthz/state",
        stream_mode=StreamMode.ON_CHANGE,
        collect_seconds=60,
    ):
        messages.append(message)
        if message.get("sync_response"):
            synced.set()
    return messages

with ThreadPoolExecutor(max_workers=1) as pool:
    pending = pool.submit(collect)
    assert synced.wait(30), "Healthz ON_CHANGE did not synchronize"
    trigger_controlled_transition()  # Replace with the approved external fixture.
    notifications = pending.result(timeout=65)

sync_index = next(i for i, message in enumerate(notifications)
                  if message.get("sync_response"))
post_sync = notifications[sync_index + 1:]
```

Evaluate the expected update in `post_sync`, not in the initial snapshot.
Use a fresh subscription for each transition or leave the same collector
running while the fixture makes multiple changes.

## Checks

1. **Baseline.** Read `FAULT_INFO`, `COMPONENT_HEALTH_INFO`, and gNMI
   `healthz/state` and the fault subtree. A missing aggregate must not be
   interpreted as `HEALTHY`; a state-only GET can return NotFound. Record
   `unhealthy-count` and `last-unhealthy` before each episode.
2. **Archive episode, active.** Confirm an `ACTIVE` `FAULT_INFO` row and its
   `HEALTHZ_TRANSITIONS` record with the reserved `healthz-*.tar.gz` ID. Confirm
   Healthz owns the archive under `/var/lib/sonic/healthz/artifacts/` after
   `submit_artifact`; DLDD supplies concrete files rather than packaging the
   final archive. Without calling gNOI, gNMI GET and a post-sync ON_CHANGE
   notification must show `UNHEALTHY`; the count increases once for the
   component health transition. `Get.component` is the latest `UNHEALTHY`
   event, and its ID equals the reserved archive ID. If packaging is observed
   while pending, `Get` must omit its ArtifactHeader; after completion, the
   first ArtifactHeader has that ID. `List.statuses` includes the event.
3. **Artifact.** Call `Artifact` with that ID using the same TLS credentials.
   Capture the entire stream and check header, one or more data frames, then
   trailer. The file name is the archive basename, MIME type is
   `application/gzip`, and size and SHA-256 match the reconstructed bytes.
   `PtfGrpc.call_server_streaming()` forwards the Artifact request and decodes
   every adjacent JSON frame, including multi-line grpcurl output. A malformed
   frame fails the call. For a separate raw capture, run the following on the PTF host with the fixture's
   certificate paths and target; decode and concatenate the JSON `bytes`
   frames before checking the header hash. Do not modify the archive on the
   DUT.

   ```sh
   grpcurl -cacert '<ca-cert>' -cert '<client-cert>' -key '<client-key>' \
     -d '{"id":"<archive-id>"}' '<target>' gnoi.healthz.Healthz/Artifact \
     > healthz-artifact-frames.json
   ```
4. **Acknowledgement.** Call `Acknowledge` twice with the exact component
   `path` and active event `id`. Both responses must return `status` with the
   same ID and `acknowledged=true`. Default `List.statuses` excludes it;
   `includeAcknowledged=true` includes it. `Artifact` still retrieves the
   archive after acknowledgement.
5. **Observation and recovery.** While the fault is active, confirm an
   asserted sample produces one `kind=observation` record. gNMI GET and a
   post-sync ON_CHANGE notification show `last-unhealthy` advanced to that
   confirmed sample time in nanoseconds, while status,
   `unhealthy-count`, event count, and event IDs remain fixed. Confirm the
   `INACTIVE` fault row and its distinct transition record. gNMI GET and
   ON_CHANGE report `HEALTHY` after the last active fault clears;
   `unhealthy-count` does not increase and `last-unhealthy` stays at the last
   asserted sample time. `Get` returns a distinct recovery event without the
   old artifact header; the earlier event remains in
   `List(includeAcknowledged=true)`.
6. **No-archive episode.** Repeat active and recovery observations with a
   DLDD rule that does not collect an archive. Both events have persisted,
   nonempty, distinct opaque IDs and no artifact header. Count rises once on
   the new `HEALTHY` to `UNHEALTHY` transition, not on recovery.
7. **Independent producer.** Use an approved fixture with a unique non-DLDD
   `producer` and `source_key` on `HEALTHZ_TRANSITIONS`. Publish an active
   transition, a later asserted observation, and an inactive transition for
   its own component, without a `FAULT_INFO` row or artifact. Confirm gNMI
   GET/ON_CHANGE and gNOI Get/List report `UNHEALTHY`, then `HEALTHY`; count
   rises only on activation and `last-unhealthy` advances on the observation.
   Confirm the two transition IDs create distinct opaque events, while the
   observation creates none. Deliver the same inactive transition again with
   its original ID; it must not add an event or increment the count.
   Confirm an absent `FAULT_INFO` row does not clear an active source; publish the
   explicit inactive transition before removing the fixture. If no approved
   independent producer fixture is available, record this check as `UNRUN`.
8. **Persistence and authorization.** After an approved host service and gNMI
   restart, repeat Get/List and gNMI GET: retained IDs, acknowledgement,
   and count remain stable, with no duplicate event after stream replay. Check
   host service logs for checkpoint/reconnect errors. Verify Get/List/Artifact
   with read access, and Check/Acknowledge with write access. Standard Check with and
   without `eventId` returns `Unimplemented`; collection success is not a
   health assessment. Keep any legacy `/healthz/*-info` diagnostic-path
   result separate from standard component-path results.

An initial ON_CHANGE subscription snapshot alone does not establish transition
delivery. If parent relationships are published, repeat Get on the parent and
check its known child statuses; otherwise report exact-component support.

## Result record

For each check record `PASS`, `FAIL`, or `UNRUN`, the DUT image/package
versions, UTC timestamps, component and event IDs, gNMI notifications, gNOI
responses, stream records, artifact reservation/status, and relevant
service/Redis errors. Record an `UNRUN` reason when
the controlled fault fixture, installation, restart authority, or authenticated
DUT access is unavailable. A bounded stream gap must be reported by the host
backend; do not infer missing events from the current fault snapshot or claim
unlimited history through Redis loss or trimming.
