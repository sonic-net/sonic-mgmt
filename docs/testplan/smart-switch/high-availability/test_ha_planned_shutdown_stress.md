# SmartSwitch DASH HA High-Traffic Stress Test

## Contents

- [Intent](#intent)
- [Bring-up overview](#bring-up-overview)
- [Prerequisites](#prerequisites)
- [Topology](#topology)
- [1. Fanout: L3 routing](#1-fanout-l3-routing)
- [2. DUT IP on Eth96](#2-dut-ip-on-eth96)
- [3. Steer GRE return + HA traffic through the fanout](#3-steer-gre-return--ha-traffic-through-the-fanout)
- [4. Pause the test at a known-good state](#4-pause-the-test-at-a-known-good-state)
- [5. IxNetwork traffic item construction](#5-ixnetwork-traffic-item-construction)
- [6. Verification](#6-verification)
- [Running the test](#running-the-test)
- [Test Matrix](#test-matrix)

## Intent

This test exercises **SmartSwitch DASH HA under high traffic load**: it drives
millions of concurrent flows through the DASH pipeline while repeatedly
cycling the DPU pair through planned HA shutdown/restart, verifying that flows
stay serviced and stay in sync between the primary and secondary DPUs with no
drops.

To generate that load we use an **Ixia (IxNetwork)** traffic generator instead
of PTF — Ixia can sustain line-rate / millions-of-flows that PTF cannot. Ixia
only has two ports in the testbed (**3.1 TX** and **3.2 RX**), so to get its
traffic to and from the DUTs we add a **dedicated "direct" physical link** in
the testbed: each DUT's `Ethernet96` is cabled to an L3 fanout switch, and all
heavy traffic classes are deliberately steered over that link —

- **ingress** test traffic (Ixia → DUT),
- **egress** GRE/NVGRE return (DUT → Ixia),
- inter-DUT **HA flow-sync** (DP/CP channel), and
- DPU-down **VxLAN re-encap** to the peer.

Steering this load over the direct fanout link bypasses the regular T2 cEOS
uplinks, which are rate-limited and drop packets under stress.

## Bring-up overview

Steps to get an IxNetwork-generated VxLAN frame to traverse DASH on the DPU
and have the NVGRE return packet captured on a separate Ixia receive port.

Two Ixia ports: **3.1** (TX) and **3.2** (RX). The fanout acts as an L3
router with ECMP: TX traffic from Ixia is routed to either DUT via ECMP,
processed by the DPU, and the GRE return is routed back through the fanout
to the Ixia RX port. IxNetwork L3 emulation handles ARP on both Ixia ports.

## Prerequisites

**Infrastructure:**
- Two SmartSwitch DUTs (MtFuji-dut01, MtFuji-dut02) with DPUs, deployed in
  a `t1-smartswitch-ha` testbed topology
- SONiC fanout switch at `1.2.31.91` (admin/password) with ports:
  - Ethernet208 → DUT1 Ethernet96
  - Ethernet216 → DUT2 Ethernet96
  - Ethernet224 → Ixia port 3.1 (TX)
  - Ethernet240 → Ixia port 3.2 (RX)
- Ixia chassis with IxNetwork, ports 3.1 and 3.2 physically wired
- sonic-mgmt container with SSH access to both DUTs and the fanout

**DUT/DPU state (handled by pytest fixtures):**
- DASH HA config deployed on both DPU pairs (`setup_ha_config`, `setup_dash_ha_from_json`)
- DASH privatelink config applied (`common_setup_teardown`)
- HA activated on both sides (`activate_dash_ha_from_json`)
- gNMI server running (`setup_gnmi_server`)
- NPU–DPU connectivity established (`setup_npu_dpu`)

**What the test configures automatically (no manual setup needed):**
- Fanout L3: IPs on all 4 interfaces + static routes (ECMP, PE_PA, HA)
- Eth96 brought admin-up + IPs on both DUTs (10.99.2.2/30, 10.99.3.2/30)
- Route steering: PE_PA (101.1.2.3/32) via fanout gateway on each DUT
- HA steering: peer DPU PA /24 + peer NPU Loopback0 /32 via fanout gateway

**IxNetwork (manual — configure before pressing `c` at breakpoint #1):**
- Topology on port 3.1 (TX): IP 10.99.1.2/30, gateway 10.99.1.1
- Topology on port 3.2 (RX): IP 10.99.4.2/30, gateway 10.99.4.1
- Traffic item: VxLAN(VNI=2001) wrapping inner IPv4/UDP|TCP, with the inner
  L4 ports varied by a UDF to scale DPU flows (see section 5)

## Topology

```
   Ixia 3.1 (TX)                              Ixia 3.2 (RX)
   10.99.1.2/30                                10.99.4.2/30
        │                                           │
        ▼                                           ▼
   ┌─── Fanout L3 Router (1.2.31.91) ──────────────────────────────┐
   │   Eth224: 10.99.1.1/30  (→ Ixia TX)                           │
   │   Eth208: 10.99.2.1/30  (→ DUT1)                              │
   │   Eth216: 10.99.3.1/30  (→ DUT2)                              │
   │   Eth240: 10.99.4.1/30  (→ Ixia RX)                           │
   │                                                                │
   │   Routes:                                                      │
   │     3.2.1.0/32   ECMP via 10.99.2.2 + 10.99.3.2               │
   │     101.1.2.3/32 via 10.99.4.2                                 │
   │     20.0.200.0/24 via 10.99.2.2 (DUT1 DPUs)                   │
   │     20.0.201.0/24 via 10.99.3.2 (DUT2 DPUs)                   │
   │     10.1.0.32/32 via 10.99.2.2 (DUT1 Lo0)                     │
   │     10.1.0.33/32 via 10.99.3.2 (DUT2 Lo0)                     │
   └────────────────────────────────────────────────────────────────┘
              │                              │
     DUT1 Eth96: 10.99.2.2/30      DUT2 Eth96: 10.99.3.2/30
     MtFuji-dut01 (NPU+DPU)       MtFuji-dut02 (NPU+DPU)
```

Per-link /30 wiring (.1 = fanout side, .2 = device side of each /30):

```
                         +-------------------------------+
                         |     L3 FANOUT (1.2.31.91)     |
                         |   SONiC, routes all 4 /30s    |
                         +---+------+--------+------+----+
              Eth224 .1 /    Eth208 .1 |  Eth216 .1 \    \ Eth240 .1
        10.99.1.0/30   /  10.99.2.0/30 | 10.99.3.0/30 \   \ 10.99.4.0/30
                      /               |               \   \
               .2    /          .2    |          .2    \   \   .2
         +---------+        +---------+--+   +--+---------+   +---------+
         | IXIA    |        |  DUT1      |   |  DUT2      |   | IXIA    |
         | 3.1 TX  |        | MtFuji-01  |   | MtFuji-02  |   | 3.2 RX  |
         |10.99.1.2|        | Eth96      |   | Eth96      |   |10.99.4.2|
         +---------+        |10.99.2.2   |   |10.99.3.2   |   +---------+
                            | Lo0        |   | Lo0        |
                            | 10.1.0.32  |   | 10.1.0.33  |
                            +------------+   +------------+
```

Key prefixes routed over the fanout (and the function that programs each on
the DUTs):

| Function | Prefix | Steered to | Purpose |
| -------- | ------ | ---------- | ------- |
| `_configure_fanout_l3` | 3.2.1.0/32 (APPLIANCE_VIP) | ECMP → DUT1 (.2.2) + DUT2 (.3.2) | ingress |
| `_apply_ixia_steering` | 101.1.2.3/32 (PE_PA) | Ixia 3.2 RX (.4.2) | egress (GRE return) |
| `_apply_direct_link_ha_steering` | 20.0.200.0/24 → DUT1 (.2.2), 20.0.201.0/24 → DUT2 (.3.2) | peer DUT | peer DPU PA (HA DP/CP + flow-sync) |
| `_apply_direct_link_ha_steering` | 10.1.0.32/32 → DUT1 (.2.2), 10.1.0.33/32 → DUT2 (.3.2) | peer DUT | peer Lo0 (DPU-down VxLAN re-encap) |

| Entity              | Address                                  |
| ------------------- | ---------------------------------------- |
| Ixia 3.1 (TX)      | 10.99.1.2/30, gateway 10.99.1.1          |
| Ixia 3.2 (RX)      | 10.99.4.2/30, gateway 10.99.4.1          |
| DUT1 Eth96          | 10.99.2.2/30, MAC 24:d5:e4:35:09:40      |
| DUT2 Eth96          | 10.99.3.2/30, MAC ba:db:ad:1e:df:c0      |
| DPU0 midplane       | 20.0.200.1, MAC b0:8d:57:cd:35:cf        |
| APPLIANCE_VIP       | 3.2.1.0 (outer src of GRE return)        |
| PE_PA               | 101.1.2.3 (outer dst of GRE return)      |
| VNI                 | 2001 (forward VxLAN), 100 (return NVGRE) |
| Fanout IP           | 1.2.31.91 (admin/password, SONiC)        |

Traffic flow:

```
Ixia TX (3.1) → Fanout → ECMP to DUT1/DUT2 → DPU processes →
GRE return → Fanout → Ixia RX (3.2)
```

## 1. Fanout: L3 routing

> **Automated by the test.** `test_ha_planned_shutdown_stress.py` SSHs
> into the fanout (via paramiko, `FANOUT_IP = 1.2.31.91`) and configures
> IPs + routes in `_configure_fanout_l3()`. Teardown removes them via
> `_remove_fanout_l3()`. The commands below are only needed for manual
> bring-up / standalone Ixia experiments.

Assign IPs to the four fanout interfaces (point-to-point /30 subnets):

```bash
# fanout (ssh admin@1.2.31.91)
sudo config interface ip add Ethernet224 10.99.1.1/30   # → Ixia TX
sudo config interface ip add Ethernet208 10.99.2.1/30   # → DUT1
sudo config interface ip add Ethernet216 10.99.3.1/30   # → DUT2
sudo config interface ip add Ethernet240 10.99.4.1/30   # → Ixia RX
```

Install routes:

```bash
# ECMP to both DUTs for inbound VxLAN (APPLIANCE_VIP)
sudo ip route replace 3.2.1.0/32 nexthop via 10.99.2.2 nexthop via 10.99.3.2

# GRE return to Ixia RX
sudo ip route replace 101.1.2.3/32 via 10.99.4.2

# HA inter-DUT: peer DPU PA subnets
sudo ip route replace 20.0.200.0/24 via 10.99.2.2   # DUT1's DPUs
sudo ip route replace 20.0.201.0/24 via 10.99.3.2   # DUT2's DPUs

# HA inter-DUT: peer NPU Loopback0
sudo ip route replace 10.1.0.32/32 via 10.99.2.2    # DUT1 Lo0
sudo ip route replace 10.1.0.33/32 via 10.99.3.2    # DUT2 Lo0
```

## 2. DUT IP on Eth96

> **Automated by the test.** `_apply_eth96_ips` brings Eth96 admin-up and
> adds these IPs in setup; `_remove_eth96_ips` removes them in teardown.

```bash
# DUT1
sudo config interface startup Ethernet96
sudo config interface ip add Ethernet96 10.99.2.2/30

# DUT2
sudo config interface startup Ethernet96
sudo config interface ip add Ethernet96 10.99.3.2/30

# Sanity: DUTs can ping their fanout gateway
ping -c 3 -I Ethernet96 10.99.2.1     # from DUT1
ping -c 3 -I Ethernet96 10.99.3.1     # from DUT2
```

## 3. Steer GRE return + HA traffic through the fanout

> **Automated by the test.** `_apply_ixia_steering` and
> `_apply_direct_link_ha_steering` install these routes; teardown removes them.

Each DUT routes all relevant prefixes via its fanout gateway. The fanout
then forwards to the correct destination via its routing table. No static ARP
is needed — the fanout is a real L3 device and responds to ARP.

```bash
# DUT1: GRE return → fanout → Ixia RX
sudo ip route replace 101.1.2.3/32 via 10.99.2.1 dev Ethernet96

# DUT1: HA traffic → fanout → DUT2
sudo ip route replace 20.0.201.0/24 via 10.99.2.1 dev Ethernet96
sudo ip route replace 10.1.0.33/32 via 10.99.2.1 dev Ethernet96

# DUT2: GRE return → fanout → Ixia RX
sudo ip route replace 101.1.2.3/32 via 10.99.3.1 dev Ethernet96

# DUT2: HA traffic → fanout → DUT1
sudo ip route replace 20.0.200.0/24 via 10.99.3.1 dev Ethernet96
sudo ip route replace 10.1.0.32/32 via 10.99.3.1 dev Ethernet96
```

### Verify HA-sync packets are on the wire

While paused at the test's breakpoint #1, on either DUT:

```bash
sudo tcpdump -nni Ethernet96 'udp port 11368 or udp port 11362'
```

You should see a steady stream of UDP/11368 frames once Ixia traffic is
flowing, plus periodic CP-channel and probe packets even when idle
(`dpu_bfd_probe_interval_in_ms: 1000`).

### Caveats

- The kernel route disappears on `config reload`. The test reapplies it on
  every run; for manual experiments, redo the `ip route replace`.
- Both the peer DPU PA /24 and peer NPU Loopback0 /32 are steered through
  the fanout to bypass cEOS T2 uplinks (capacity limited under stress).

## 4. Pause the test at a known-good state

`test_ha_planned_shutdown_stress.py` drops into `pdb` at **breakpoint #1**
after all DUT/DPU programming and steering is complete (HA active, DASH ACLs
installed). From the pdb prompt you can:

- start/stop IxNetwork traffic items;
- run shell commands on the DUTs in another window;
- type `c` to begin the HA stress iterations, or `q` to abort cleanly.

## 5. IxNetwork traffic item construction

### IxNetwork topology (configure once, persists in .ixncfg)

| Port | Role | IP         | Gateway    | Subnet |
| ---- | ---- | ---------- | ---------- | ------ |
| 3.1  | TX   | 10.99.1.2  | 10.99.1.1  | /30    |
| 3.2  | RX   | 10.99.4.2  | 10.99.4.1  | /30    |

After adding the topology, verify ARP resolves (green arrow in IxNetwork).
The fanout responds to ARP on both ports.

### Traffic item (raw or protocol-based)

Build the VxLAN-encapsulated frame. IxNetwork resolves L2 automatically
from the topology (dst MAC = fanout Eth224 MAC, src MAC = Ixia 3.1 MAC).

| Layer         | Field    | Value                            |
| ------------- | -------- | -------------------------------- |
| Outer IPv4    | src      | 1.9.1.1 (VM1_PA)                |
| Outer IPv4    | dst      | 3.2.1.0 (APPLIANCE_VIP)         |
| Outer IPv4    | proto    | 17 (UDP)                         |
| Outer IPv4    | TTL      | 64                               |
| Outer UDP     | dport    | 4789 (VxLAN)                     |
| VxLAN         | VNI      | 2001                             |
| Inner Eth     | src      | ENI_MAC                          |
| Inner Eth     | dst      | REMOTE_MAC                       |
| Inner Eth     | type     | 0x0800 (IPv4)                    |
| Inner IPv4    | src      | 10.0.0.11 (VM1_CA)               |
| Inner IPv4    | dst      | 10.2.0.100 (PE_CA)               |
| Inner IPv4    | proto    | 17 (UDP) or 6 (TCP)              |
| Inner L4      | sport    | UDF counter (see below)          |
| Inner L4      | dport    | UDF counter (see below)          |
| Payload       |          | 58 bytes incrementing (00..39)   |

Inner L4 may be UDP or TCP. For TCP, set proto=6 and the control bits per
test case (SYN to open a flow, ACK for data, FIN-ACK/RST to clear). Let the
inner IP and L4 checksums auto-generate.

### Known-good raw frame (UDP)

This is the exact 150-byte frame (no FCS) that traverses DASH and produces
an NVGRE return. Paste it as a raw/custom stream to bypass per-layer editor
quirks, or use it to verify a protocol-built frame byte-for-byte. All length
and checksum fields are valid.

```
6C03B5D20FD00011223344550800450000880001000040115C611901010103020100142312B500740000080000000007D10043BE6525FA67F4939FEFC47E08004500005600010000401166260A00000B0A0200641A8511D700428F51000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536373839
```

Field breakdown:

| Offset | Layer / Field        | Bytes          | Value                       |
| ------ | -------------------- | -------------- | --------------------------- |
| 0x00   | Outer Eth dst        | `6C03B5D20FD0` | fanout Eth224 MAC           |
| 0x06   | Outer Eth src        | `001122334455` | test source                 |
| 0x0C   | EtherType            | `0800`         | IPv4                        |
| 0x0E   | Outer IPv4           | `45000088…`    | len 136, TTL 64, proto UDP  |
| 0x18   | Outer IP checksum    | `5C61`         | valid                       |
| 0x1A   | Outer src IP         | `19010101`     | 25.1.1.1 (underlay src)     |
| 0x1E   | Outer dst IP         | `03020100`     | 3.2.1.0 (APPLIANCE_VIP)     |
| 0x22   | Outer UDP sport      | `1423`         | 5155 (VxLAN entropy)        |
| 0x24   | Outer UDP dport      | `12B5`         | 4789 (VxLAN)                |
| 0x26   | Outer UDP len        | `0074`         | 116                         |
| 0x2A   | VxLAN flags+VNI      | `08…0007D1`    | I-bit, VNI 2001             |
| 0x36   | Inner Eth dst        | `43BE6525FA67` | REMOTE_MAC                  |
| 0x3C   | Inner Eth src        | `F4939FEFC47E` | ENI_MAC                     |
| 0x42   | Inner EtherType      | `0800`         | IPv4                        |
| 0x44   | Inner IPv4           | `45000056…`    | len 86, TTL 64, proto UDP   |
| 0x4A   | Inner IP checksum    | `6626`         | valid                       |
| 0x4C   | Inner src IP         | `0A00000B`     | 10.0.0.11 (VM1_CA)          |
| 0x50   | Inner dst IP         | `0A020064`     | 10.2.0.100 (PE_CA)          |
| 0x54   | Inner UDP sport      | `1A85`         | 6789                        |
| 0x56   | Inner UDP dport      | `11D7`         | 4567                        |
| 0x58   | Inner UDP len        | `0042`         | 66                          |
| 0x5A   | Inner UDP checksum   | `8F51`         | valid                       |
| 0x5C   | Payload (58 B)       | `0001…39`      | incrementing 0x00–0x39      |

> The outer src IP in this frame is 25.1.1.1; the DASH pipeline keys on the
> inner packet + VNI, so the outer src is cosmetic. The inner UDP ports
> (offset 0x54) are what the UDF varies to scale flows.

Layered view (same frame, grouped by encapsulation):

```
Outer Ethernet
  dst MAC      6C:03:B5:D2:0F:D0   fanout Eth224
  src MAC      00:11:22:33:44:55   test source
  EtherType    0x0800              IPv4
Outer IPv4
  total len    136
  TTL / proto  64 / 17 (UDP)
  checksum     0x5C61              valid
  src          25.1.1.1            underlay src
  dst          3.2.1.0             APPLIANCE_VIP
Outer UDP
  sport        5155                VxLAN entropy
  dport        4789                VxLAN
  length       116
VxLAN
  flags        0x08                I-bit (valid VNI)
  VNI          2001                VNET1_VNI
Inner Ethernet
  dst MAC      43:BE:65:25:FA:67   REMOTE_MAC
  src MAC      F4:93:9F:EF:C4:7E   ENI_MAC
  EtherType    0x0800              IPv4
Inner IPv4
  total len    86
  TTL / proto  64 / 17 (UDP)
  checksum     0x6626              valid
  src          10.0.0.11           VM1_CA
  dst          10.2.0.100          PE_CA
Inner UDP
  sport        6789                (UDF varies)
  dport        4567                (UDF varies)
  length       66
  checksum     0x8F51              valid
Payload
  58 bytes     00 01 02 … 37 38 39 incrementing
```


### UDF for flow generation

| Parameter    | Value                                        |
| ------------ | -------------------------------------------- |
| Offset       | 84 bytes from start of frame (inner UDP)     |
| Size         | 32 bits (covers sport + dport)               |
| Mode         | Counter                                      |
| Init value   | 0                                            |
| Step         | 1                                            |
| Repeat count | 5,000,000                                    |
| Result       | 5M unique 5-tuples × 2 bidir = 10M DPU flows |

### Send rate

- Bring-up: 10 fps
- Stress testing: 10M pps (or 1 Gbps line rate for bandwidth tests)

## 6. Verification

On DUT1 (or whichever DUT is being targeted):

```bash
sonic-clear counters
# start IxNetwork traffic
show interfaces counters | grep -E "IFACE|Ethernet96"
```

Expected:

- `Ethernet96` `RX_OK` ≈ number of frames sent, `RX_DRP` does **not** increment
- `Ethernet96` `TX_OK` increments with the NVGRE returns
- DPU midplane RX bps rises from baseline (DPU is processing)

On Ixia 3.2 (RX port), expected capture:

```
Outer L2:   dst=<Ixia 3.2 MAC>  src=<fanout Eth240 MAC>  type=0x0800
Outer IPv4: src=3.2.1.0         dst=101.1.2.3            proto=47 (GRE)
            TTL=62 (64 → DUT decrements → fanout decrements)
GRE:        proto=0x6558 (Transparent Ethernet Bridging → NVGRE)
NVGRE VSID: 0x000064 (100)
Inner L2:   <NAT46 result> type=0x86dd (IPv6)
Inner IPv6: fd41:.../UDP → 2603:.../UDP
```

The IPv6 inner payload is the DASH NAT46 transformation of the IPv4 inner
payload sent in.

## Running the test

```bash
# BRK env var controls breakpoints: ends (default), mid, none
BRK=mid pytest test_ha_planned_shutdown_stress.py \
    --inventory ../ansible/veos_vtb \
    --host-pattern all \
    --testbed_file testbed.yaml \
    --testbed vms-kvm-t1-smartswitch-ha \
    -d MtFuji-dut01,MtFuji-dut02 \
    -H MtFuji-dut01-dpu-0,MtFuji-dut02-dpu-0 \
    -s  # required for breakpoint() to work
```

**Breakpoint modes (`BRK` env var):**

| Mode   | Behavior                                                                 |
| ------ | ------------------------------------------------------------------------ |
| `ends` | Break before Ixia start + after all iterations (default)                 |
| `mid`  | `ends` + once after primary-dead and once after secondary-dead (iter 1)  |
| `none` | Fully automated, no breakpoints                                          |

Breakpoints (when `BRK != none`):
1. **Breakpoint #1** — after all DUT/DPU programming and steering is
   complete. Start IxNetwork traffic (TX on 3.1, capture on 3.2), then `c`.
2. **Breakpoint #2** — after all HA iterations complete (HA still active).
   Stop traffic, record TX/RX counts, then `c` to proceed to cleanup.

If an iteration fails, a breakpoint fires with live state preserved
for debugging (regardless of BRK mode).

> **Note on Ixia vs PTF:** the route steering exists because Ixia only sees
> ports 3.1/3.2, so the NVGRE return must be routed through the fanout to the
> RX port. PTF (veth into every DUT port) captured the return on any egress
> port without steering. This is a measurement constraint, not a datapath
> difference.

---

## Test Matrix

Each test below has its own **Issues** line — add notes, links, or bug
references there as you run them.

### Test 1 — `BRK=none`, UDP low
Run low-rate UDP traffic; verify test runs to completion automatically.
- **Issues:**

### Test 2 — `BRK=none`, UDP high
Run high-rate UDP traffic; verify test runs to completion automatically.
- **Issues:**
  - https://github.com/sonic-net/sonic-mgmt/pull/25058#pullrequestreview-4492341205

### Test 3 — `BRK=ends`, UDP low
At breakpoint #1 (HA established): start UDP low stream, clear stats,
continue. At breakpoint #2: verify RX count matches TX count. Ensure test
passes.
- **Issues:**

### Test 4 — `BRK=ends`, UDP high
Same as (3) but with high-rate UDP traffic.
- **Issues:**

### Test 5 — `BRK=ends`, TCP SYN + ACK
At breakpoint #1: send TCP SYN stream at 1Mpps (simulating 1Mcps) to establish sessions; 
verify `flows -summary` shows 10M flows on each primary and secondary. Start TCP
ACK stream, clear stats, continue. At breakpoint #2: verify RX matches TX.
Ensure test passes.
- **Issues:**
  - Some sessions are not created. Requires lower rate or sending the same stream twice to get full 10M flows.

### Test 6 — `BRK=ends`, TCP SYN + FIN-ACK
Same as (5), but after ACK stream, send TCP FIN-ACK stream; verify sessions
are cleared.
- **Issues:**
  - Does not work to clear sessions

### Test 7 — `BRK=ends`, TCP SYN + RST
Same as (6), but use TCP RST to clear sessions instead of FIN-ACK.
- **Issues:**

### Test 8 — `BRK=mid`, TCP SYN + ACK (20M)
Same as (5) for initial 10M flows. During first mid breakpoint (primary
down): add another 10M flows on secondary for 20M total. Continue test;
verify all 20M flows sync to primary with no drops.
- **Issues:**

### Test 9 — `BRK=ends`, uplink-down (single-DUT path)
Simulate an uplink failure by collapsing the APPLIANCE_VIP ECMP route into
a single next-hop so all ingress traffic lands on one DUT. On the fanout,
replace the ECMP route with a single path to DUT1 (or DUT2):
```bash
# fanout: ECMP → single next-hop (simulates the other uplink being down)
sudo ip route replace 3.2.1.0/32 via 10.99.2.2     # all traffic → DUT1 only
# restore ECMP afterwards:
sudo ip route replace 3.2.1.0/32 nexthop via 10.99.2.2 nexthop via 10.99.3.2
```
At breakpoint #1: start traffic, confirm all flows land on the single
chosen DUT, clear stats, continue. Run HA cycles; verify flows stay on
(and sync from) the active DUT with no drops. At breakpoint #2: verify RX
matches TX, then restore the ECMP route.
- **Issues:**
  - TBD (not executed yet)
