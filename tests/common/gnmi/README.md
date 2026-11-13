# Minimal Python gNMI client derived from pygnmi

`GnmiClient` trims pygnmi's **Get, Set and Subscribe** building blocks, using grpcio and protobuf;
it does not import pygnmi. Existing fixture and business tests are not switched
by this change. Certificate creation, DUT configuration and recovery remain with
their existing owners. No Capabilities RPC is issued, implicitly or explicitly.

```python
from contextlib import closing
from tests.common.gnmi import GnmiClient

client = GnmiClient(host, port, ca_cert=ca, client_cert=cert, client_key=key)
client.set(update=[("sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", '{"Vnet1":{"vni":"1000"}}')])
result = client.get("sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni")
assert result["notification"][0]["update"][0]["val"] == "1000"
with closing(client.subscribe("COUNTERS/Ethernet0", target="COUNTERS_DB", count=3)) as responses:
    for response in responses:
        print(response)
```

## Supported contract

- `get(paths, datatype="all", encoding="json_ietf", target=None, prefix="")`:
  returns `{"notification": [...]}`. Paths accept strings or this package's
  `gnmi_pb2.Path`. String syntax supports `origin:`, `origin://`, selectors such
  as `interface[name=Ethernet0]`, and escaped slashes in path elements.
- `set(update=None, replace=None, delete=None, encoding="json_ietf", ...)`:
  update/replace take `(path, value)` pairs. **Strings are already-encoded JSON**,
  matching current PyPI pygnmi 0.8.15 callers: pass `'"Public"'` for a JSON string,
  or pass a dict for a JSON object. BYTES/PROTO require bytes; ASCII requires str.
  An explicit `gnmi_pb2.TypedValue` is also accepted. Response has timestamp,
  prefix, target and per-operation response entries.
- `subscribe` returns a generator of dicts. ONCE yields notifications then sync;
  POLL yields `poll_count` synchronized batches **including the initial snapshot**
  (there are `poll_count - 1` explicit Poll requests). STREAM coalesces the initial
  snapshot to sync, then yields each notification; EVENTS skips initial coalescing
  because it has no sync. `count` counts yielded batches/messages, not fields.
  Per-path mode/sample/heartbeat/suppress_redundant and prefix/target/encoding/
  updates_only/allow_aggregation/qos are supported; all intervals use seconds.
  The single-notification batch shape cannot represent mixed prefix/origin/target/
  timestamp/atomic metadata: such POLL or initial STREAM batches raise an explicit
  error rather than attaching updates to the wrong prefix. ONCE does not coalesce.
- Typed values retain JSON/scalar/bytes values (including zero, false and
  double_val); leaflists become lists. Any/Decimal64 remain protobuf messages.
  This is the subset needed by existing tests, not a full pygnmi replacement API.

## Lifecycle and intentional differences

Construction is lazy. Unary calls open/close their own channel and explicitly
apply `timeout`; TLS cert files are reread on each call. There is no client-global
channel or close method. A subscription owns its channel until exhausted or
closed: use `contextlib.closing` for early breaks. Do not fork Ansible while a
subscription is active; use an already-established control connection if needed.

`timeout` bounds a whole ONCE snapshot or each synchronized POLL batch. STREAM
ends normally at `collect_seconds` or `count`. Server errors and premature EOF
raise `GnmiClientError`, rather than returning an empty success. RPC errors are
chained as `__cause__`, retaining `.code()`/`.details()`; deadline errors use
`GnmiClientTimeoutError`. No retry or automatic encoding negotiation occurs.

No username/JWT authentication, extensions, deprecated aliases, arbitrary
passthrough options or private pygnmi subscriber hooks are provided. Existing
AAA code catching `gNMIException`, private `_build_client` users, Capabilities
tests, and any fixture migration need explicit adaptation in a separate change.

## Source and dependencies

### Handwritten client source

Derived from the published **pygnmi 0.8.15 wheel**, not the GitHub tag:

- Artifact: `pygnmi-0.8.15-py3-none-any.whl`
- SHA256: `e72859070c7dc3618b578e48c76521db6d627b64a92b496ab886f3ff93a1a396`
- Source: https://pypi.org/project/pygnmi/0.8.15/
- BSD-3-Clause copyright and license: `LICENSE.pygnmi`.

The correspondence is deliberately kept visible in `client.py`:

| Upstream source | Retained/adapted part |
| --- | --- |
| `create_gnmi_path.py:11–102` | `gnmi_path_generator` / `gnmi_path_degenerator`: extract selectors before splitting path elements and reconstruct sorted keys |
| `client.py:1420–1451` | `construct_update_message`: strings are pre-encoded JSON; dicts are serialized; repeated update/replace entries |
| `client.py:1035–1247` | `_Subscriber`: request queue with POLL/STOP, receiver queue, bounded `get_update`, collection until sync and update/delete merging |
| `client.py:405–767,1265–1387` | Get/Set request/response field shapes and `telemetryParser`; share value/notification decoding instead of copying repetitive branches |

Unused CLI/debug printing, automatic certificate retrieval, Capabilities/encoding
negotiation, diff/retry, authentication extensions and alias support are omitted.
The three upstream subscriber subclasses are folded into mode selection in the
single `_Subscriber`; the existing bounded public generator remains a thin wrapper.

Necessary adaptations are explicit: local protobuf imports; IPv6 normalization;
explicit RPC deadlines; receiver errors/EOF queued to the caller; retained RPC
cancel and worker joins; finite receive queue; no eager Poll before the initial
snapshot; EVENTS delivery without sync. Path parsing adds escaped-slash handling
and selector validation. Decoding preserves double/zero/false/bytes and reports
invalid JSON rather than swallowing parser errors. Incompatible batch metadata
is rejected rather than overwritten as in upstream. These are intentional limits
and fixes, not a promise of bug-for-bug or full pygnmi API compatibility.

### Generated protocol modules

Three generated modules under `proto/` come from OpenConfig gNMI **v0.8.0**,
commit `c1b4525a810ffdaa3f4960d3cd88987a58d8e204` (Apache-2.0; license included).
Like pygnmi, this package ships the generated Python files and imports them
directly. There is no download, generation step or custom version/hash check.
Runtime needs only grpcio and protobuf; pygnmi, grpcio-tools and protoc are not
required by this client. Existing environments can use their installed runtime
packages; this client does not install packages or enforce an exact version.

The checked-in modules use relative imports and a small private descriptor pool
to coexist with other gNMI clients during migration. No wire fields are changed.
Source versions above document provenance, not runtime requirements.

## Optional developer tests

```sh
python -m pytest --noconftest --confcutdir=tests/common/unit_tests -o addopts= \
  tests/common/unit_tests/unit_test_gnmi_client.py -q
```

These tests are not part of client startup. They require pytest/cryptography and run local gRPC servers,
including mTLS and IPv6. They do not prove SONiC DUT/fixture integration. Use a
clean virtual environment without pygnmi for the dependency-removal check.

Validated locally: Python 3.10, grpcio 1.62.3 / protobuf 4.25.8, and grpcio 1.76.0 /
protobuf 6.33.6. Both environments omit pygnmi. No DUT or CI execution is claimed.
