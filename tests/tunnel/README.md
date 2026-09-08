# Tunnel object scale tests

These control-plane tests discover how many generated tunnel objects can be
programmed, up to a configurable safety limit. They do not send traffic or test
route scale. Run them on an idle, dedicated hardware DUT: capacity discovery can
exhaust shared ASIC resources, and expected resource errors disable log analysis
for these tests.

## Test cases

- `test_tunnel_scale.py::test_ipinip_tunnel_scale` creates distinct IP-in-IP
  tunnels in CONFIG_DB and checks APPL_DB and ASIC tunnel/termination counts.
- `test_vxlan_tunnel_scale.py::test_vxlan_tunnel_scale` creates distinct VXLAN
  tunnels, each activated by a default-scope VNET. It checks CONFIG_DB and APPL_DB
  propagation and the ASIC object graph: one tunnel, one termination, four maps,
  and two map entries per generated tunnel, with no additional virtual routers.
  A local-loopback-sourced hardware preflight verifies this graph before scaling.

Both tests establish a stable baseline, add objects in batches, and retry a
nonconverging batch one object at a time. Generated objects are removed in a
`finally` block, and counts must return to the baseline. Existing generated
object names are preserved by starting after the highest existing index.

VXLAN additionally restores shared switch attributes and removes VNETs before
their tunnels. It rejects APPL_DB propagation failures and first-object ASIC
calibration failures rather than reporting them as a capacity measurement.

## Requirements and scope

- Use the standard sonic-mgmt pytest environment and inventory/DUT fixtures.
  All shared Python helpers are already in sonic-mgmt; no extra package,
  PTF script, topology configuration, or DUT inventory is supplied by this suite.
- Both tests are topology-independent (`topology("any")`). Use a single-ASIC DUT;
  IP-in-IP database operations are not namespace-aware. VXLAN has a single-ASIC
  runtime check, but its switch setup fixture executes before that check, so do
  not schedule it on a multi-ASIC DUT.
- VXLAN is marked for Broadcom, Mellanox, and Cisco-8000 ASICs. A supported ASIC
  marker is not a guarantee that every hardware/image combination implements
  the expected object graph. An IPv4 loopback and VXLAN/VNET support are required.
- IP-in-IP requires the configured tunnel attributes to be supported by the
  hardware/image. It does not currently distinguish all programming errors from
  capacity exhaustion; inspect failure diagnostics before interpreting a boundary.
- Generated addresses come from the benchmark range `198.18.0.0/15`; they are
  synthetic tunnel endpoints, not management addresses. VXLAN checks generated
  source-IP and VNI collisions. Scale sources are not configured as local
  interfaces, so the DUT must accept these sources independently of preflight.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--tunnel-scale-limit` | 256 | Maximum additional IP-in-IP tunnels |
| `--tunnel-scale-batch-size` | 8 | IP-in-IP tunnels per batch |
| `--vxlan-tunnel-scale-limit` | 256 | Maximum additional VXLAN/VNET pairs |
| `--vxlan-tunnel-scale-batch-size` | 8 | VXLAN/VNET pairs per batch |

Limits and batch sizes must be positive integers, and batch size must not exceed
the corresponding limit. To perform a one-object smoke test, set both the limit
and batch size for that tunnel type to 1. Select either test by its node ID under
`tunnel/` when invoking pytest from the `tests/` directory, together with the
normal inventory and testbed arguments for your environment.

## Results

`TUNNEL_SCALE_RESULT` log records and the JUnit `tunnel_scale_result` property
report preexisting and newly programmed generated objects. Reaching the safety
limit reports a **lower bound**, not the hardware maximum. A nonconverging
individual addition reports the observed boundary and first failed generated
total; review diagnostics to determine the underlying limiting resource.
VXLAN results reflect the combined tunnel/VNET object footprint, not an isolated
tunnel-table capacity. `TUNNEL_SCALE_CLEANUP` reports restoration of baseline counts.
