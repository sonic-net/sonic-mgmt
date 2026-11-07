# gnmi_client

A small Python utility for sending gNMI `Set` / `Get` / `Delete` requests to
the `gnmi` container running on a SONiC DPU. It is primarily used to push
DASH (Disaggregated API for SONiC Hosts) configuration into `DPU_APPL_DB`,
encoded as protobuf, and asynchronously sent to dpu in zmq via the SONiC gNMI server.

The tool is built on top of [`pygnmi`](https://github.com/akarneliuk/pygnmi)
for the wire protocol, and the `dash_api` python package for protobuf
message definitions.

## Layout

```
tools/gnmi_client/
├── gnmi_client/           # python package
│   ├── __init__.py
│   ├── __main__.py        # CLI entry point
│   ├── gnmi_utils.py      # pygnmi-based set/get helpers
│   └── proto_utils.py     # JSON ⇄ DASH protobuf conversion
└── templates/             # Jinja2 templates of operations
```

## Where to run it

The command is intended to be run from the **sonic-mgmt container**, the
same container used to deploy and test SONiC. The container provides
Python 3, the `dash_api` package, `pygnmi`, `jinja2`, and network
reachability to the DUT and its DPUs.

Open a shell in the container (see the top-level `sonic-mgmt`
[README.md](../../README.md) for full setup):

```bash
docker exec -it --user $USER <container-name> /bin/bash
```

From inside the container, change into this tool's directory:

```bash
cd /data/sonic-mgmt/tools/gnmi_client
```

`gnmi_client` is a Python package, so it is invoked with `python -m`. When
the current directory is `tools/gnmi_client/`, Python automatically adds it
to `sys.path` and resolves the `gnmi_client` package. From anywhere else,
set `PYTHONPATH` to the parent of the package:

```bash
PYTHONPATH=/data/sonic-mgmt/tools/gnmi_client python3 -m gnmi_client ...
```

## Command usage

```
python3 -m gnmi_client [global options] <subcommand> [subcommand options]
```

### Global options

| Flag                 | Default            | Description |
|----------------------|--------------------|-------------|
| `-t, --target`       | `127.0.0.1:8080`   | gNMI server address as `host:port`. |
| `-u, --username`     | `cisco`            | Username for gNMI authentication. |
| `-p, --password`     | `cisco123`         | Password for gNMI authentication. |
| `-d, --debug`        | off                | Enable debug-level logging. |
| `-i, --dpu_index`    | `0`                | DPU index `[0-7]`, exposed to templates as `{{ dpu_index }}` and used in the gNMI path `/sonic-db:DPU_APPL_DB/dpu<N>/...`. |
| `-n, --num_dpus`     | `1`                | Number of DPUs on the switch `[1-8]`; exposed to templates as `{{ num_dpus }}`. |
| `-s, --sleep_secs`   | `0`                | Seconds to sleep before each batch. |
| `-b, --batch_val`    | `10`               | Number of operations per gNMI request batch. |

### Subcommands

All subcommands operate either on a Jinja2 **template file** (`-f`) or on a
single explicit gNMI **xpath** (`-x`).

| Subcommand | Options              | Notes |
|------------|----------------------|-------|
| `update`   | `-f <template>`      | Performs gNMI Update for every entry in the template. |
| `replace`  | `-f <template>`      | Performs gNMI Replace for every entry. |
| `delete`   | `-f <template>` or `-x <xpath>` | When `-f` is used, the file's operations are reversed before being sent. |
| `get`      | `-f <template>` or `-x <xpath>` | Decodes the proto response and prints the parsed message. |

### Examples

Push a DASH appliance config (template form):
```bash
python3 -m gnmi_client \
    --target 10.0.0.1:8080 \
    --username admin --password secret \
    --dpu_index 0 --num_dpus 8 \
    update --filename templates/pl_config_amd_0_appliance.j2
```

Read one object by xpath:
```bash
python3 -m gnmi_client -t 127.0.0.1:8080 \
    get -x /sonic-db:DPU_APPL_DB/dpu0/DASH_APPLIANCE_TABLE[key=100]
```

Delete one object by xpath:
```bash
python3 -m gnmi_client -t 127.0.0.1:8080 \
    delete -x /sonic-db:DPU_APPL_DB/dpu0/DASH_APPLIANCE_TABLE[key=100]
```

Push a large config with batching and inter-batch delay:
```bash
python3 -m gnmi_client \
    --batch_val 500 --sleep_secs 1 \
    update -f templates/v2v_snake_combined.j2
```

## Template format

Templates are [Jinja2](https://jinja.palletsprojects.com/) files that render
to a JSON document describing one or more operations. The renderer is given
these variables:

- `op`        — `"SET"`, `"REP"`, `"DEL"`, or `"GET"` depending on the subcommand.
- `dpu_index` — the value passed via `-i/--dpu_index`.
- `num_dpus`  — the value passed via `-n/--num_dpus`.

After rendering, the JSON must be one of two shapes:

### 1. Flat list (single chunk)

A JSON array of operation objects. All entries are sent in the same batch
flow, grouped into batches of `--batch_val`.

```json
[
    {
        "DASH_APPLIANCE_TABLE:123": {
            "sip": "3.2.1.{{ dpu_index }}",
            "vm_vni": "10000"
        },
        "OP": "{{ op }}"
    }
]
```

### 2. List of chunks

A JSON array of arrays. Each inner array is processed independently in
order. A `--sleep_secs` (or, if zero, a small default) delay is inserted
between chunks. This is useful for multi-step provisioning where one set of
objects must exist before the next is sent.

```json
[
    [
        { "DASH_APPLIANCE_TABLE:123": { "sip": "3.2.1.0", "vm_vni": "10000" }, "OP": "{{ op }}" }
    ],
    [
        { "DASH_ROUTING_TYPE_TABLE:vnet": { "action_name": "a", "action_type": "maprouting" }, "OP": "{{ op }}" }
    ]
]
```

### Operation object schema

Each entry in a chunk is a JSON object with:

- An `"OP"` key with one of `SET`, `REP`, `DEL`, `GET`. Normally rendered
  from `{{ op }}` and therefore determined by the subcommand used.
- Exactly one other key of the form `"<TABLE_NAME>:<KEY>"`, whose value is
  the JSON representation of the DASH proto message (or a list of messages,
  for repeated types such as `DASH_ROUTING_TYPE_TABLE` items).

Examples:

```json
{ "DASH_APPLIANCE_TABLE:1":     { "sip": "3.2.1.0", "vm_vni": "600" }, "OP": "SET" }
{ "DASH_VNET_TABLE:Vnet1":      { "vni": "1000", "guid": "..." },      "OP": "REP" }
{ "DASH_ROUTING_TYPE_TABLE:privatelink": [
    { "action_name": "action1", "action_type": "4_to_6" },
    { "action_name": "action2", "action_type": "staticencap",
      "encap_type": "nvgre", "vni": "100" }
  ], "OP": "SET" }
{ "DASH_ENI_TABLE:eni0":         { },                                  "OP": "DEL" }
```

### How an entry is translated to gNMI

For an entry `"DASH_FOO_TABLE:K": { ... }` and DPU index `n`, the tool:

1. Builds the gNMI xpath
   `/sonic-db:DPU_APPL_DB/dpu<n>/DASH_FOO_TABLE[key=K]`.
2. For `SET`/`REP`: encodes the value dict into the matching protobuf
   message (`dash_api.foo_pb2.Foo`) via `proto_utils.json_to_proto`, and
   sends it as `TypedValue.proto_bytes` with `encoding=proto`.
3. For `DEL`: sends a gNMI Delete on the xpath. When invoked from a
   template, `delete` reverses the entry order so deletions happen in the
   opposite order of creation.
4. For `GET`: sends a gNMI Get on the xpath, parses the returned
   `proto_bytes` back into a `dash_api` message, and prints it.

### Table name → protobuf type mapping

`proto_utils.py` derives the protobuf module and class **dynamically** from
the `DASH_<NAME>_TABLE` segment of each operation key, so most new DASH
tables work without any code change as long as the corresponding
`dash_api` python module exists. The default rule is:

```
DASH_<NAME>_TABLE   →   dash_api.<name>_pb2.<CamelCaseName>
```

The transformation:

1. Strip the `DASH_` prefix and `_TABLE` suffix to get `<NAME>` (e.g.
   `APPLIANCE`, `VNET`, `ENI`, `VNET_MAPPING`).
2. Lower-case it to build the module path: `dash_api.<name>_pb2`
   (e.g. `dash_api.appliance_pb2`, `dash_api.vnet_mapping_pb2`).
3. Convert it to CamelCase to get the class name: `<CamelCaseName>`
   (e.g. `Appliance`, `Vnet`, `Eni`, `VnetMapping`).
4. `importlib.import_module()` loads the module and `getattr()` resolves
   the class. The same class is used both for **encoding** outbound
   `SET`/`REP` payloads (`json_to_proto`) and for **decoding** the
   `proto_bytes` returned by `GET` (`from_pb`).

Examples produced by this rule:

| Template key                          | Module                          | Class           |
|---------------------------------------|---------------------------------|-----------------|
| `DASH_APPLIANCE_TABLE:1`              | `dash_api.appliance_pb2`        | `Appliance`     |
| `DASH_VNET_TABLE:Vnet1`               | `dash_api.vnet_pb2`             | `Vnet`          |
| `DASH_ENI_TABLE:eni0`                 | `dash_api.eni_pb2`              | `Eni`           |
| `DASH_VNET_MAPPING_TABLE:Vnet1:1.1.1.1` | `dash_api.vnet_mapping_pb2`   | `VnetMapping`   |

#### Special cases

A few tables don't follow the default rule because the underlying
`dash_api` module is named differently or the value has a different shape.
These are hard-coded in `proto_utils.py`:

- `DASH_ROUTING_TYPE_TABLE` → `dash_api.route_type_pb2.RouteType`
  (note `route_type_pb2`, **not** `routing_type_pb2`). The value may be
  either a single object or a **list** of `RouteTypeItem`s, e.g.:
  ```json
  "DASH_ROUTING_TYPE_TABLE:privatelink": [
      { "action_name": "action1", "action_type": "4_to_6" },
      { "action_name": "action2", "action_type": "staticencap",
        "encap_type": "nvgre", "vni": "100" }
  ]
  ```
  Both `json_to_proto` and `from_pb` short-circuit on this name and use
  `RouteType` directly.

If you add a new DASH table whose `dash_api` module name does not match
the default lower-case rule, add a matching branch in `proto_utils.py`
(`get_message_from_table_name` for encode, `from_pb` for decode).

## Troubleshooting

- `ModuleNotFoundError: No module named 'gnmi_client'`
  — Run from `tools/gnmi_client/` or set
  `PYTHONPATH=/data/sonic-mgmt/tools/gnmi_client`.
- `ModuleNotFoundError: No module named 'dash_api.<x>_pb2'`
  — The dash_api package version inside the sonic-mgmt container does not
  yet define that table. Update the `dash_api` package on the container.
- gNMI errors are logged with their gRPC `code()` / `details()` /
  `debug_error_string()` when available. Run with `-d` for full debug
  output, including the protobuf payload that was sent.
