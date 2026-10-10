# Healthz qualification on a lab DUT

For final installed-image qualification, run this procedure after the host
services, management common, and gNMI packages are built and installed on an
authorized lab DUT. The read-only baseline observes retained state. Opt-in
controlled cases publish independent producer transitions or change an explicitly
selected installed DLDD demo signal to create reversible fault episodes. They
restore the selected signal and do not install or change DLDD rules.

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

This follow-up has not been deployed to the DUT or included in a rebuilt full
installer. The live and installer results above remain qualification of host
commit `49402b82`; they are not evidence for the later retry correction.

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
