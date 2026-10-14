# Snappi MACsec Ingress to Plain IPv4 Egress HLD

## Document information

### Authors

- Varun Aiyaswamy Kannan
- Amit Pawar
- Amol Rawal
- Dinesh Kumar Sellappan

### Version information

| Version | Date | Description |
| --- | --- | --- |
| 1.0 | 2026-08-31 | Initial Snappi MACsec architecture HLD |

## 1. Scope

This document describes the reusable Snappi MACsec architecture for a
two-ingress, one-egress test topology:

- Both ingress links use MACsec.
- The single egress link uses plain Ethernet and IPv4.
- Traffic from both ingress links converges on the same egress port.
- Egress-only tracking distinguishes traffic by ingress source and priority.
- MACsec overhead is removed before traffic reaches the plain egress link.

PFC, congestion, and scheduler tests consume this architecture, but their
individual traffic patterns and pass/fail criteria are outside this HLD.

## 2. Goals

- Establish MKA and MACsec on each TGEN-to-DUT ingress link.
- Keep the DUT-to-TGEN egress link unencrypted.
- Support priorities 0 through 6 for each ingress source.
- Preserve per-source, per-priority traffic visibility after flows merge.
- Provide correct packet-loss and throughput accounting across MACsec
  decapsulation.
- Restore all temporary DUT configuration after the test.

## 3. Reference topology

```text
TGEN port 1
MACsec endpoint, port_id 1
        | encrypted Ethernet + IPv4
        v
  DUT ingress 1 -- MACsec validation and decryption --+
                                                      |
                                                      +--> DUT forwarding
                                                      |        |
  DUT ingress 2 -- MACsec validation and decryption --+        v
        ^                                               Plain DUT egress
        | encrypted Ethernet + IPv4                     port_id 0
TGEN port 2                                                   |
MACsec endpoint, port_id 2                                   | plain Ethernet + IPv4
                                                             v
                                                    TGEN port 0
                                                    IPv4 endpoint bank
                                                    and egress-only tracking
```

The port-role convention is:

| `port_id` | Direction | Security | Snappi interface type |
| --- | --- | --- | --- |
| `0` | DUT egress / TGEN receive | Plain IPv4 | `IPInterface` |
| `1` | TGEN transmit / DUT ingress | MACsec | `MacsecInterface` |
| `2` | TGEN transmit / DUT ingress | MACsec | `MacsecInterface` |

The implementation assumes that `port_id == 0` is the only egress and every
`port_id >= 1` is a MACsec ingress.

## 4. Architectural layers

### 4.1 Link security

MKA establishes keys and secure channels for each ingress link. MACsec:

- Adds a SecTAG.
- Encrypts the protected portion of the frame.
- Adds an integrity check value (ICV).
- Uses the SCI and packet number for secure-association and replay handling.

The DUT validates and decrypts each ingress frame before normal forwarding.

### 4.2 Forwarding

After MACsec decapsulation, the DUT forwards an ordinary Ethernet/IPv4 packet.
The egress interface is not configured for MACsec, so no SecTAG or ICV is
present on the egress wire.

### 4.3 QoS classification

The traffic's DSCP and Ethernet PFC queue fields determine the DUT
priority/priority-group/queue classification.

PGID does **not** configure the DUT queue. PGID is a traffic-generator
measurement identity used to distinguish flows in IxNetwork statistics.

### 4.4 Measurement

Traffic from two ingress sources merges at one egress port. The architecture
therefore creates a distinct plain IPv4 egress endpoint for every combination
of:

```text
ingress source × priority
```

Selecting one of these endpoints gives IxNetwork enough information to produce
separate PGID statistics for otherwise similar traffic.

## 5. Enabling MACsec mode

The option is declared in
[`tests/conftest.py`](../../conftest.py):

```python
parser.addoption(
    "--snappi_macsec",
    action="store_true",
    default=False,
    help="Enable macsec on tgen links of testbed",
)
```

Append the option to the normal Snappi pytest command:

```bash
pytest <test-path> \
    --testbed=<testbed> \
    --inventory=<inventory> \
    --snappi_macsec
```

`--snappi_macsec` controls the Snappi/TGEN MACsec path. It is different from
`--enable_macsec`, which is used by the separate SONiC-link MACsec test path.

The current implementation detects the option with:

```python
"--snappi_macsec" in sys.argv
```

When enabled, `setup_dut_ports()` bypasses the normal VLAN, port-channel,
routed-interface, and fallback P2P setup paths and invokes
`__intf_config_macsec()`.

## 6. `__intf_config_macsec`

The implementation is in
[`tests/common/snappi_tests/snappi_fixtures.py`](../../common/snappi_tests/snappi_fixtures.py).

### 6.1 DUT port discovery

The function first selects Snappi ports whose `peer_device` matches the current
DUT. Each selected port contains its physical peer port, `port_id`, ASIC
namespace, and addressing information.

### 6.2 Address preparation

For each selected DUT interface, the function:

1. Reads the existing IPv4 interface subnet.
2. Adds a temporary address if the interface has no IPv4 subnet.
3. Uses a `/31`-style fallback for MACsec ingress links.
4. Ensures the plain egress subnet is large enough for all virtual egress
   endpoints.
5. Records original and applied subnets for cleanup.
6. Derives the TGEN address, DUT gateway, prefix, TGEN MAC, and DUT interface
   MAC.

### 6.3 DUT MACsec configuration

For every `port_id >= 1`, the function:

1. Loads `256_XPN_SCI` from
   [`macsec_profile.json`](../macsec_profile.json).
2. Removes stale instances of the same Snappi MACsec profile.
3. Installs the profile once per participating DUT.
4. Enables the profile on the ingress interface.
5. Installs a static ARP entry for the TGEN IPv4/MAC pair.

The profile uses GCM-AES-XPN-256, SCI transmission, MKA PSK configuration, and
timer-based rekeying.

### 6.4 TGEN MACsec device creation

For every `port_id >= 1`, the function creates:

- One Snappi device.
- One Ethernet interface attached to that physical TGEN port.
- One IPv4 address and gateway.
- A MACsec SecY in encapsulation/encrypt-only mode.
- A transmit secure channel and packet-number configuration.
- An MKA instance with PSK, cipher, actor priority, and rekey settings.
- A `SnappiPortConfig` with type `MacsecInterface`.

### 6.5 Plain egress device creation

For `port_id == 0`, the function creates:

- Multiple ordinary Ethernet/IPv4 devices.
- A `SnappiPortConfig` of type `IPInterface` for every device.
- One egress-only tracking configuration attached to physical port 0.

MACsec is deliberately absent from this port.

## 7. Egress endpoint count and prefix length

Seven priority slots are currently supported for each ingress source:

```text
priority = 0..6
```

If `N` is the total number of physical TGEN ports, including egress:

```text
ingress_count = N - 1
egress_endpoint_count = 7 × ingress_count
```

The fixture calculates:

```python
num_of_non_macsec_snappi_devices = 7 * (len(snappi_ports) - 1)
static_prefix_length = subnet_mask_from_hosts(
    num_of_non_macsec_snappi_devices + 3
)
```

The resulting common topologies are:

| Topology | Egress endpoints | Host request | Prefix |
| --- | ---: | ---: | --- |
| 1 ingress + 1 egress | 7 | 10 | `/28` |
| 2 ingress + 1 egress | 14 | 17 | `/27` |

The prefix is therefore calculated from endpoint capacity; it is not selected
based on the test name.

The caller adds three addresses for the DUT address and reserved headroom.
`subnet_mask_from_hosts()` also accounts for the network and broadcast
addresses when selecting the smallest suitable IPv4 prefix. This produces a
conservative subnet size.

If the existing egress prefix is too narrow, the fixture temporarily replaces
it with `40.1.1.1/<calculated-prefix>` and records the original subnet for
restoration.

## 8. Flow priority to egress endpoint mapping

The egress device name is generated using:

```python
left, right = divmod(device_index, 7)
ip_stack.name = f"Ipv4 Port {left}_{right}"
```

Where:

- `left` identifies the ingress-source block.
- `right` identifies the priority slot.

For two ingress sources, the intended endpoint layout is:

| Device index / PGID | Ingress source | Priority |
| ---: | ---: | ---: |
| 0-6 | `port_id 1` | 0-6 |
| 7-13 | `port_id 2` | 0-6 |

The destination index is encoded as:

```text
PGID = (tx_port_id - 1) × 7 + priority
```

Examples:

| `tx_port_id` | Priority | Destination index / PGID |
| ---: | ---: | ---: |
| 1 | 3 | 3 |
| 1 | 6 | 6 |
| 2 | 3 | 10 |
| 2 | 6 | 13 |

The flow builder must:

1. Select the MACsec source device associated with the ingress port.
2. Select the destination device from that source's seven-entry block.
3. Set device endpoint mode to `ONE_TO_ONE`.
4. Set DSCP and PFC queue fields for actual DUT QoS classification.
5. Record the flow name to logical priority in `flow_name_prio_map`.

The common flow generators currently select only the last MACsec device as the
source. A two-ingress flow builder must explicitly select both source devices
and their corresponding destination blocks.

## 9. PGID to priority mapping

IxNetwork Flow Statistics report the encoded endpoint identity as PGID.

The logical priority is recovered with:

```python
priority = int(row["PGID"]) % 7
```

Examples:

| PGID | Logical priority |
| ---: | ---: |
| 3 | 3 |
| 6 | 6 |
| 10 | 3 |
| 13 | 6 |

The modulo operation is required because both ingress sources use the same
logical priorities but occupy different PGID blocks.

A MACsec statistics row must not be selected using PGID alone. The safe
identity is:

```text
(Tx Port, Rx Port, PGID)
```

Filter by Tx and Rx port first. Apply `PGID % 7` only when the verification
rule needs the logical priority shared across ingress sources.

## 10. Egress-only tracking

Egress tracking is configured in two phases.

### 10.1 Snappi configuration

`__intf_config_macsec()` attaches `config.egress_only_tracking` to physical
egress port 0:

- Filter choice: `auto_macsec`
- Metric tag name: `ipv4_dscp`
- Receive offset: 0
- Metric length: 8 bits
- Transmit offset: custom offset 0

The metric tag name is descriptive. The complete signature and extraction
rules are finalized through IxNetwork after the Snappi configuration is
applied.

### 10.2 IxNetwork runtime configuration

In
[`tests/common/snappi_tests/traffic_generation.py`](../../common/snappi_tests/traffic_generation.py),
`run_traffic()`:

1. Disables automatic MACsec egress-only configuration on every traffic item.
2. Clears normal traffic-item `TrackBy` fields.
3. Selects a 12-byte egress-only signature.
4. Builds the signature from the first egress endpoint MAC and IPv4 EtherType.
5. Sets signature offset 2 and the signature mask.
6. Configures egress extraction at offsets 0 and 52.
7. Uses separate masks to distinguish ingress-source PGID blocks.

The resulting IxNetwork Flow Statistics rows expose:

- `PGID`
- `Tx Port`
- `Rx Port`
- `Tx Frames`
- `Rx Frames`
- `Tx Frame Rate`

## 11. Traffic execution

After `api.set_config(config)`, MACsec mode performs additional IxNetwork
configuration:

1. Disable MKA delay protection.
2. Disable gratuitous ARP transmission on StaticMacsec objects.
3. Set each ingress endpoint's `DutSciMac` to the MAC of its owning DUT
   interface.
4. Install the egress-only tracking signature.
5. Clear DUT MACsec and interface/QoS counters.
6. Start all protocol sessions.
7. Verify that no protocol sessions are down or not started.
8. Install static ARP entries for all virtual egress endpoints.
9. Generate every IxNetwork traffic item.
10. Apply traffic.
11. Start stateless traffic with the blocking IxNetwork API.

For a two-ingress topology, `DutSciMac` must be resolved independently for both
ingress interfaces, including their owning line card or ASIC namespace.

## 12. Statistics differences

### 12.1 Non-MACsec

The non-MACsec path uses Snappi flow metric objects:

```text
metric.name
metric.frames_tx
metric.frames_rx
metric.loss
metric.transmit
```

Flows are identified directly by their configured names.

### 12.2 MACsec

The MACsec path uses dictionary-like rows from the IxNetwork Flow Statistics
view:

```text
row["PGID"]
row["Tx Port"]
row["Rx Port"]
row["Tx Frames"]
row["Rx Frames"]
row["Tx Frame Rate"]
```

`flow_name_prio_map` preserves the relationship between a configured flow name
and its logical priority. The final statistics row is selected using Tx port,
Rx port, and PGID.

### 12.3 Loss

For a selected MACsec row:

```text
loss_percent = 100 × (Tx Frames - Rx Frames) / Tx Frames
```

Rows with zero transmitted frames must be ignored or handled separately to
avoid division by zero and false flow matches.

### 12.4 Flow completion

The intended MACsec completion rule is:

```text
selected rows are non-empty AND every selected Tx Frame Rate equals zero
```

The current implementation uses `!= [0]` in the MACsec stop loop. That
condition is inverted relative to the intended behavior and can report that
traffic stopped while it is still active.

Some generic MACsec verification paths also compare `PGID == priority`, which
only identifies the first ingress block. PGIDs 7 through 13 require Tx/Rx port
filtering and modulo normalization.

## 13. MACsec throughput accounting

MACsec changes the number of bytes on the ingress wire but does not change the
number of forwarded packets.

The protected ingress frame contains:

```text
16-byte SecTAG + 16-byte ICV = 32 bytes MACsec overhead
```

The DUT removes these 32 bytes before transmitting the plain egress frame.

### 13.1 Current suite convention

For a configured MACsec ingress frame size `L`, the egress-equivalent rate
factor is:

```text
scale = (L - 32 + 20) / (L + 20)
```

Where:

- `32` is the SecTAG and ICV removed before egress.
- `20` is the preamble/SFD and inter-packet gap used for line-rate accounting.

For a 1024-byte frame:

```text
scale = (1024 - 32 + 20) / (1024 + 20)
      = 1012 / 1044
      = 0.96935
```

A 20% encrypted-ingress load therefore contributes approximately:

```text
20% × 0.96935 = 19.387%
```

of plain-egress line rate.

### 13.2 Two-ingress aggregation

Scale every protected ingress demand before comparing the total with the plain
egress capacity:

```text
plain_egress_demand =
    sum(ingress_rate[i] × scale[i] for each ingress i)
```

This scaled demand must be used for:

- Oversubscription calculations.
- Expected scheduler allocation.
- Expected aggregate loss.
- Ingress-byte to egress-byte throughput comparisons.

Packet counts can still be compared directly after selecting the correct
source, destination, and PGID.

### 13.3 Frame-size convention

The formula above assumes `L` is the encrypted ingress frame size, matching the
current test calculation.

If a traffic-generator API defines `L` as the plaintext size before MACsec
encapsulation, the ingress denominator becomes:

```text
L + 32 + 20
```

The frame-size semantics must therefore be confirmed before reusing the factor
in another flow builder.

## 14. Cleanup

MACsec cleanup is handled by `cleanup_config()` and fixture teardown:

1. Remove temporary egress addressing.
2. Restore the original egress subnet when one was replaced.
3. Disable MACsec on every enabled ingress interface.
4. Delete the Snappi MACsec profile from every participating DUT.
5. Clear global bookkeeping for enabled ports and configured profiles.
6. Remove temporary routes or destination state created by setup.

Tests must invoke cleanup from a `finally` block so configuration is restored
even after traffic generation or verification fails.

## 15. Design invariants

- Physical `port_id 0` is the single plain egress.
- Every physical `port_id >= 1` is a MACsec ingress.
- Priorities are currently limited to 0 through 6.
- The egress endpoint bank contains seven devices per ingress source.
- MKA sessions are up before data traffic begins.
- `DutSciMac` matches the DUT interface connected to each MACsec endpoint.
- Static routes and ARP entries exist for every virtual egress endpoint.
- Every flow uses the destination block belonging to its ingress source.
- Statistics are filtered by Tx port and Rx port before PGID normalization.
- Teardown executes even if setup, traffic, or verification fails.

## 16. Code ownership

| File | Responsibility |
| --- | --- |
| [`tests/conftest.py`](../../conftest.py) | Declares `--snappi_macsec` |
| [`tests/common/snappi_tests/snappi_fixtures.py`](../../common/snappi_tests/snappi_fixtures.py) | MACsec fixture selection, DUT/TGEN interface setup, egress endpoint creation, and cleanup |
| [`tests/common/snappi_tests/snappi_helpers.py`](../../common/snappi_tests/snappi_helpers.py) | Prefix calculation and IxNetwork statistics helpers |
| [`tests/common/snappi_tests/traffic_generation.py`](../../common/snappi_tests/traffic_generation.py) | Flow endpoint selection, IxNetwork runtime setup, traffic control, statistics collection, and verification |
| [`tests/common/snappi_tests/variables.py`](../../common/snappi_tests/variables.py) | Default non-MACsec egress gateway |
| [`tests/snappi_tests/macsec_profile.json`](../macsec_profile.json) | DUT MACsec and Snappi MKA profile parameters |
