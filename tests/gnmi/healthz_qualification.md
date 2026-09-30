# Healthz qualification on a lab DUT

For final installed-image qualification, run this procedure after the host
services, management common, and gNMI packages are built and installed on an
authorized lab DUT. Use approved fixtures for two controlled DLDD fault episodes
and one independent producer episode. The procedure observes their transitions;
it does not create a fault or change a DLDD rule.

## Build and partial live evidence, 2026-09-26–28 UTC

The first observations in this section used the earlier DLDD-specific stream
and DLDD-owned archives. The later corrected-source observations identify
their own package and container versions. Keep evidence from those versions
separate when assessing the checks below.

The manual run in [live validation](../../../../dldd-healthz-live-validation-20260926.md)
used a reversible host Python overlay and an extracted trixie telemetry binary
overlay, rather than an installed image. The trixie management-common and gNMI
Debian packages and a direct host wheel built. The official SONiC host-wheel
Make target also passed: its own pytest run reported 1006 passed and 13
deselected; the separately excluded DLDD integration tier passed 13/13. The
wheel SHA256 is
`32567ba36ed1d76263fee6d66f383ffd32184704dad6ee22e355efad827d8088`.
That earlier wheel was not installed on the DUT. Real Redis and host D-Bus checks
covered archive and archive-free fault transitions, overlap, repeated
detection, acknowledgement, catalog restart and projection recovery. With the
Go 1.25.9 test-override telemetry binary, standard gNOI Get/List returned
retained events and default acknowledged filtering; repeated Acknowledge
preserved the archive; Check with and without an event ID returned
Unimplemented; Artifact returned a complete
stream whose header SHA-256 matched the on-device archive. gNMI GET returned component
HEALTHY, count 2, last-unhealthy, and the existing fault subtree. A read-only
STREAM ON_CHANGE subscriber synchronized before a fresh source change. Its
first run received UNHEALTHY/count 3 but stopped at its configured
two-notification limit before recovery. A second run received
UNHEALTHY/count 4, an asserted refresh with the same count and advanced
last-unhealthy, then HEALTHY/count 4 on clear. The archived ACTIVE event ID
`dldd-fededf145be54b779c52d6916e68a4c5.tar.gz` and archive-free recovery
ID `hz-3d738893f258453c99af8bd29a506867` were distinct. Original rules
were restored to their baseline SHA in both inbox and active files, the two
synthetic source hashes were removed, and final gNMI GET was HEALTHY/count 4.
A scoped host-service restart afterward preserved checkpoint
`1790468323595-0`, nine catalog events, the first archive acknowledgement,
aggregate HEALTHY/count 4, and SQLite integrity; gNOI Get/List and gNMI GET
remained consistent.

The repeated standard Go 1.26.5 Trixie gNMI package (SHA256
`9511fba24c6651c4427200c9bb56e33904239819999c85a361b80b2b5e571f9f`)
produced telemetry SHA256
`c7ee2d5ba2a5b105f7812ab668581447f126408958fd936a20b9d216211f1d85`.
That final binary passed a separate read-only DUT smoke after only `gnmi-native`
restarted: Get retained the latest HEALTHY event, List returned all nine
events when acknowledgement was included, Artifact returned a complete
350-byte disk-matching stream, and gNMI GET returned HEALTHY/count 4 and the
remaining INACTIVE fault row. The older fault row expired under normal
retention. Original rules and source keys remained restored; services and
system health matched their baseline. This smoke did not start a new
ON_CHANGE subscription or inject a new fault.

The official `docker-sonic-gnmi.gz` target then built with exit 0; its
config-engine prerequisite passed 344 tests. The image archive SHA256 was
`435a0774559cf997f5240c52ef6d99939afd0e3f17fb022ea6c9d6fcc2e73f13`.
The archive matched on the DUT, and that first official image
`sha256:76905983f8f44c2037f2fd64f82b0b411569044f59d5fe93eb06f84bf59eb3cb`
replaced the running gNMI container at 06:20:01 UTC on 2026-09-27. That
container reported `sonic-gnmi=0.1`, `sonic-mgmt-common=1.0.0`, and the final
telemetry binary SHA256 above. Post-deployment Get/List/Artifact, standard
Check (Unimplemented), gNMI state GET, D-Bus, and SQLite checks passed. The
old image and container were preserved for rollback.

A controlled archived fault episode on that official image synchronized its
ON_CHANGE subscriber before activation. It delivered UNHEALTHY/count 5,
an active refresh, then HEALTHY/count 5 after recovery. The fault subtree
mapped the new row ACTIVE then INACTIVE. The ACTIVE event and new archive shared
ID `dldd-58fe6c03d2c84f2bad5942552ca17f14.tar.gz`; the recovery event had
distinct opaque ID `hz-277f5c9edfc84ae0916f6f24967f1f9d` and no artifact.
Original rules and source keys were restored; final services, logs, and system
health matched the baseline. The [raw ON_CHANGE log](../../../../dldd-healthz-onchange-official-container-20260927.log)
contains sync and post-sync transitions, not only an initial snapshot.

A revised official gNMI image was subsequently built (archive SHA256
`54c208a8db7220bfe427e9ef8259b971a957ef53c4a907ab0ad886dbd918f835`)
and activated at 06:41 UTC on 2026-09-28. Image
`sha256:56421128476619d90fee694dabf7c96bc36fcf667d28f1b93e70433e1329683b`
replaced the first official image, which was preserved for rollback. The new
image passed read-only Get/List/Artifact, Check (Unimplemented), repeated
Acknowledge, and gNMI state GET against the retained 11-event catalog. The
archive event ID still matched ArtifactHeader ID/basename and the 349-byte
disk archive SHA256; the aggregate remained HEALTHY/count 5. A read-only
ON_CHANGE subscription synchronized at 06:43:27.714 UTC, then ended at its
12-second no-fault deadline without a post-sync transition. Final service,
SQLite, checkpoint, rules, source-key, journal, and system-health checks
matched the baseline; no rollback was needed. The fault-driven ON_CHANGE
sequence above belongs to the first official image.

A later controlled fixture on the revised image also passed. A fresh
ON_CHANGE subscriber synchronized at 07:35:44.181 UTC, received
UNHEALTHY/count 7 at 07:35:58.921, then HEALTHY/count 7 at 07:36:13.963. A
new archived ACTIVE event used its archive ID as the first ArtifactHeader ID;
the first and repeated Acknowledge preserved the archive and default List
filtered the acknowledged event. The overlapping fault held the component
UNHEALTHY until final clear, whose event had a distinct opaque ID and no
artifact. Rules, test source keys, services, logs, SQLite integrity and
baseline health were restored by 07:39:50 UTC. The [expanded verification
record](../../../../dldd-healthz-expanded-verification-20260927.md) has the
event IDs, checksums and current evidence limits.

The exact revised host source then passed the Trixie full suite (1007 passed,
13 integration tests deselected), a separate 13/13 DLDD integration tier, and
an official SONiC Make wheel build. The revised wheel SHA256 is
`caa452d909299eb6eed447a038132c7730d5350fc5d0e95328fc74f1a6e0b876`.
It was temporarily installed through the DUT normal path, with packaged file
hashes matching source. A controlled archived 0→1 fault produced one ACTIVE
stream/catalog event whose ID and first ArtifactHeader ID equaled archive
`dldd-305549e9c97647d1b45629e04132c475.tar.gz`, and UNHEALTHY/count 8.
The 350-byte gzip archive and stream matched SHA256
`3ba7d588c40124eabaafce90b2ff96750a9903fb8642f27081d394c6759dc226`.
An asserted refresh advanced `last_detection_time` 1790582110→1790582122
without another event; 1→0 produced distinct opaque HEALTHY event
`hz-6899d3c792c74c85a37a7ab5d624675e` without artifact and HEALTHY/count 8.
Original rules and all seven preinstall host code/script hashes were restored,
test keys removed, services
and timer active, SQLite quick_check `ok` with 18 events and two existing
acknowledgements and checkpoint `1790582253992-0`, and gNOI/gNMI GET remained
HEALTHY/count 8. The gNMI image and container did not change. The preinstall
package RECORD was restored byte-identically; two generated `.pyc` caches
were recreated from restored scripts because their original bytes were
unavailable. A new-event Ack/List was not exercised against this temporary
revised Python backend; the revised-image fixture above covered Ack/List.
The [temporary DUT report](../../../../.staging/healthz-host-wheel-20260928-001/README.md)
and [hash manifest](../../../../.staging/healthz-host-wheel-20260928-001/evidence-sha256.txt)
contain the detailed checks; final post-rollback log SHA256 is
`f755e6377b9de6c68bacd85ae3f7be863e349feea08a5dc6aa67c8d77af57fd0`.

After that temporary install, the DUT host code was restored to its preinstall
overlay. Synthetic private Redis execution faults demonstrated that the earlier
WATCH/MULTI/EXEC producer could lose or duplicate a transition despite its
normal-path DUT pass. At that historical stage, generic stream and artifact API
deployment, full boot-image qualification, deployed TLS authorization, device
reboot, inactive-only first publication, and a shared-stream gap were `UNRUN`.
Public and whitebox image pins existed as local commits and had not been pushed.

## Corrected generic-boundary qualification, 2026-09-28 UTC

The [exact-source host wheel](../../../../.staging/host-final-20260928-001/README.md)
(258,105 bytes, SHA256
`11e58826f91510f4b5da3971140891e702254fb1e2e66bb0e2f676869416f4ac`)
passed the official Make target and was [installed on the DUT](../../../../evidence/healthz-host-final-install-20260928T1701Z/README.md).
All eight installed changed Python modules matched the wheel. The populated
SQLite catalog retained its prior 18 events and two acknowledgements, passed
`quick_check`, and recorded the one-time old-stream-tail migration gap. A
[derived telemetry-only gNMI test image](../../../../evidence/healthz-gnmi-final-activation-20260928T1647Z/README.md)
(`sha256:146d95e90b9a4b8701167bbd636fbf235cc40f3b729d9401b60a99e55cdc7f10`)
was activated. It retains the prior image's package metadata: the corrected
official gNMI Make run stopped at its Microsoft GPG download prerequisite and
did not produce a new Debian package or official container.

The controlled corrected-source fixture completed by 17:24 UTC. Archived
`UNHEALTHY` event 19, its new Healthz archive, and the first ArtifactHeader
shared ID `healthz-69011cf69f6c4b58b6ab63c786a8874a.tar.gz`; the 482-byte
gzip stream and disk archive matched SHA256
`f66534571fa4f662ddab45307ed7b96c790d3266abf8bb57a398ae3c30a90770`.
Repeated Acknowledge retained that archive. Asserted refreshes advanced
`last_detection_time` without another status event or count. Overlapping plain
`UNHEALTHY` event 20 had an opaque ID and did not increment unhealthy-count;
clearing the archived source kept the component unhealthy, and the final plain
clear created opaque `HEALTHY` event 21. A subscriber synchronized before the
fixture and received `UNHEALTHY/count 9` then `HEALTHY/count 9` ON_CHANGE
updates. Original rules were restored, the two synthetic keys were deleted,
and SQLite `quick_check` passed with 21 events and three acknowledgements.
The raw fixture evidence is retained under the root-only DUT directory
`/host/healthz-corrected-qualification-20260928T1708Z/live-evidence/`;
[preparation and baseline](../../../../evidence/healthz-corrected-phase1-20260928T1708Z/README.md)
are available locally.

The [scoped restart persistence check](../../../../evidence/healthz-corrected-restart-persistence-20260928T1731Z/README.md)
passed through 17:33:47 UTC. Hostservice, DLDD and gNMI were restarted in
turn. The host catalog retained 21 events, three acknowledgements, sources,
aggregate and artifact; DLDD replay advanced only the generic checkpoint and
created no duplicate event. The same candidate gNMI container and immutable
image restarted. Postrestart Get/List returned the retained event set
(18 default, 21 with acknowledgements), Artifact streamed the same 482-byte
archive with its disk-matching header SHA256, and gNMI GET remained
`HEALTHY/count 9`. Original rules, absent synthetic keys, active services,
zero failed units and clean error-priority journals were confirmed.

As of 2026-09-28, device reboot, an official corrected gNMI package and boot image, deployed TLS
roles, independent producer, inactive-only first publication, and live
Redis-loss handling remain unverified. The exact-source private Redis
producer/worker/SQLite run passed 28/28 checks and reproduced strict
partial-`EXEC` atomicity failure; its log is under
`vxr-slurm-255:/nobackup/grboudre/healthz/.codex-sonic-builds/redis-e2e-final-20260928-002/run.log`
(SHA256 `ad9173fa7bf2fe66e6d063da843e6781204f525f8669d8e7ca79a19ad8a12036`).
No such failure was induced on the DUT.

## Installed package and live qualification, 2026-09-30 UTC

The [follow-up run](../../../../evidence/healthz-fixes-20260930/PLAN.md)
built and deployed an exact-source host wheel (SHA256
`3f8da71233fc43364475c9a3e847d922022e8d761ee5d5cb2f86ee2ac32b8db0`)
and a gNMI package using the repository's Debian packaging (SHA256
`a911d6bce37f03b1358ea13a127d9dadfd239db328598661b0d4bcac93351c9e`).
The running replacement gNMI image is
`sha256:54d21902b191e3ea6076c13278c2bbb24cdf3a779b61d6f884aecde0baf9bb28`.
The host suite passed 1052 tests with 13 deselected; the separate DLDD
integration tier passed 13/13, focused tests passed 128/128, and Ruff and
compileall passed. Focused Go Healthz and Artifact tests passed in both
`gnmi_server` and `sonic_service_client`. The host wheel contents and gNMI
binary were checked against the tested source and package.

On the installed packages, a controlled DLDD fault received archive/event ID
`healthz-e15162aadc5e45d5bced15ad33f870bc.tar.gz`, matching the first
ArtifactHeader ID. The selected query and log were present in the archive.
Get/List, default acknowledgement filtering, repeated Acknowledge, Artifact
streaming, OpenConfig GET, and standard Check returning Unimplemented passed.
Routine refresh and scoped DLDD/host restarts created no duplicate event.
Recovery produced distinct opaque ID
`hz-11dcae3a9dc746048f879eb75e45198b` with no artifact. The fault row
retained only scalar `healthz_artifact_id` as Healthz-specific data. A raw
`STATE_DB` gNMI GET of `/FAULT_INFO` returned that ID. A fresh
ON_CHANGE subscriber synchronized before an independent source transition and
received both UNHEALTHY/count 13 and HEALTHY/count 13 updates; see the
[captured subscription](../../../../evidence/healthz-fixes-20260930/onchange-live-v2/result.txt).
The [final DUT check](../../../../evidence/healthz-fixes-20260930/final-dut-status.txt)
reported all three services active, zero failed units, SQLite `quick_check=ok`,
53 retained events, 10 acknowledgements, no active sources or pending
artifacts, and the original rule checksum restored. A 49 MiB archive submission
completed while concurrent Get/List/Acknowledge calls each returned in about
1.5 seconds. An isolated Redis 8 check confirmed startup detection of
`XADD MAXLEN` trimming using `entries-added > length` when
`max-deleted-entry-id` remains `0-0`.

An isolated normal SONiC Make rebuild of the gNMI Debian target stopped at its
`sonic_yang_mgmt` prerequisite because offline pip could not obtain
`jsondiff==2.2.1`; the Make image target was not run. Full boot-image
build/reboot, deployed TLS authorization, and SpyTest qualification remain
unverified. Strict Redis row/stream atomicity under
execution-time errors remains unresolved. The package pins and source commits
are local; none were pushed. The earlier historical observations above describe
their dated candidate versions and do not replace this installed-package result.

## Inputs and transport

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
   `PtfGrpc.call_server_streaming()` currently parses only whole or line-wise
   JSON. Use `grpcurl` directly with the fixture's TLS certificate paths and
   target for this capture if its multi-line output cannot be parsed by that
   helper. For example, run the following on the PTF host with the fixture's
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
