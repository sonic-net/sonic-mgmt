# DLDD Healthz qualification on a lab DUT

For final installed-image qualification, run this procedure after the host
services, management common, and gNMI packages are built and installed on an
authorized lab DUT. It observes two controlled DLDD fault episodes; it does not
create a fault or change a DLDD rule. A separate, approved fixture must provide
the fault transitions.

## Partial live evidence, 2026-09-26–27 UTC

The manual run in [live validation](../../../../dldd-healthz-live-validation-20260926.md)
used a reversible host Python overlay and an extracted trixie telemetry binary
overlay, rather than an installed image. The trixie management-common and gNMI
Debian packages and a direct host wheel built; the full SONiC host-wheel target
is still pending. Real Redis and host D-Bus checks covered archive and
archive-free fault transitions, overlap, repeated detection, acknowledgement,
catalog restart and projection recovery. With the updated telemetry binary,
standard gNOI Get/List returned retained events and default acknowledged
filtering; repeated Acknowledge preserved the archive; Check with and without
an event ID returned Unimplemented; Artifact returned a complete stream whose
header SHA-256 matched the on-device archive. gNMI GET returned component
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

These observations do not close the full procedure. Live
authentication/read-only checks, full package installation, device reboot,
inactive-only first publication, and a shared-stream gap remain pending.
Record each of those as `UNRUN` until separately evidenced. The ON_CHANGE
result above includes post-sync transition notifications, not only an initial
snapshot. Public and whitebox image pins remain unchanged.

## Inputs and transport

Record the DUT image and installed package versions. Use one known component
with no unrelated active fault, and record these IDs as the two episodes run:

| Input | Required observation |
| --- | --- |
| Archive episode | An `ACTIVE` DLDD fault with a **new** archive, followed by its `INACTIVE` transition. Record the archive ID and the two event IDs. |
| No-archive episode | An `ACTIVE` DLDD fault without a new archive, followed by its `INACTIVE` transition. Record the two event IDs. |

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
responses and timestamps as evidence. For each transition, start a bounded
subscription before the external fixture changes the fault:

```python
from tests.common.pygnmi_client import StreamMode

notifications = list(gnmi_tls.pygnmi_client.subscribe(
    f"openconfig://components/component[name={component}]/healthz/state",
    stream_mode=StreamMode.ON_CHANGE,
    collect_seconds=60,
))
```

## Checks

1. **Baseline.** Read `FAULT_INFO`, `COMPONENT_HEALTH_INFO`, and the gNMI
   component `healthz/state` and fault subtree. A missing Healthz aggregate
   must not be interpreted as `HEALTHY`. Record the current
   `unhealthy-count` and `last-unhealthy` before triggering either episode.
2. **Archive episode, active.** Confirm an `ACTIVE` `FAULT_INFO` row and one
   corresponding `DLDD_FAULT_TRANSITIONS` entry. Without calling gNOI, the
   gNMI GET and ON_CHANGE update must show `UNHEALTHY`; the count increases
   once for the component health transition. `Get.component` is the latest
   `UNHEALTHY` event. Its ID equals the newly assigned DLDD archive ID.
   While the archive is still being built, its artifact header is absent;
   repeat `Get` after the final archive appears and confirm that the first
   artifact header has that same ID. `List.statuses` includes the event.
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
5. **Archive episode, recovery.** Confirm the `INACTIVE` fault row and
   transition record. gNMI GET and ON_CHANGE report `HEALTHY` after the last
   active fault clears; `unhealthy-count` does not increase on clear and
   `last-unhealthy` remains the confirmed unhealthy observation time. `Get`
   returns the recovery event. Its ID differs from the earlier archive/event
   ID. If the retained `INACTIVE` fault row still references that archive,
   the recovery event does not advertise it a second time. The earlier event
   remains in `List(includeAcknowledged=true)`.
6. **No-archive episode.** Repeat active and recovery observations with a
   DLDD rule that does not collect an archive. Both events have persisted,
   nonempty, distinct opaque IDs and no artifact header. Count rises once on
   the new `HEALTHY` to `UNHEALTHY` transition, not on recovery.
7. **Persistence and authorization.** After an approved host service and gNMI
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
responses, and relevant service/Redis errors. Record an `UNRUN` reason when
the controlled fault fixture, installation, restart authority, or authenticated
DUT access is unavailable. A bounded stream gap must be reported by the host
backend; do not infer missing events from the current fault snapshot or claim
unlimited history through Redis loss or trimming.
