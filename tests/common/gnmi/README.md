# Minimal Python gNMI client

`GnmiClient` implements **Get, Set and Subscribe**, using grpcio and protobuf;
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

## Protocol provenance and generation

Three generated modules under `proto/` come from OpenConfig gNMI **v0.8.0**,
commit `c1b4525a810ffdaa3f4960d3cd88987a58d8e204` (Apache-2.0; license included).
`proto/generate.py` verifies SHA256 hashes of both upstream protos and LICENSE.
It normalizes the gnmi_ext import, generates with **grpcio-tools==1.62.3**, and
uses relative Python imports and a package-private descriptor pool. That pool
allows coexistence with old pygnmi/other generated gNMI schemas during migration.
No schema fields or wire names are changed. Runtime needs grpcio and protobuf;
grpcio-tools is only needed to regenerate, not to run the client.

```sh
python tests/common/gnmi/proto/generate.py
python -m pytest --noconftest --confcutdir=tests/common/unit_tests -o addopts= \
  tests/common/unit_tests/unit_test_gnmi_client.py -q
```

Offline tests require pytest/cryptography and run actual local gRPC servers,
including mTLS and IPv6. They do not prove SONiC DUT/fixture integration. Use a
clean virtual environment without pygnmi for the dependency-removal check.

Validated locally: Python 3.10, grpcio 1.62.3 / protobuf 4.25.8, and grpcio 1.76.0 /
protobuf 6.33.6. Both environments omit pygnmi. No DUT or CI execution is claimed.
