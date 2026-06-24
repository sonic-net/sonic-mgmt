# SmartSwitch DASH HA High-Traffic Stress Test

## Contents

- [Intent](#intent)
- [Bring-up overview](#bring-up-overview)
- [Testbed-agnostic design](#testbed-agnostic-design)
- [Configuration (make it your own)](#configuration-make-it-your-own)
- [Prerequisites](#prerequisites)
- [Topology](#topology)
- [1. Fanout: L3 routing](#1-fanout-l3-routing)
- [2. DUT IP on the direct link](#2-dut-ip-on-the-direct-link)
- [3. Steer GRE return + HA traffic through the fanout](#3-steer-gre-return--ha-traffic-through-the-fanout)
- [4. IxNetwork traffic item construction](#4-ixnetwork-traffic-item-construction)
- [5. Verification](#5-verification)
- [Running the test](#running-the-test)
- [Test Matrix](#test-matrix)

## Intent

This test exercises **SmartSwitch DASH HA under high traffic load**: it drives
millions of concurrent flows through the DASH pipeline while repeatedly
cycling the DPU pair through planned HA shutdown/restart, verifying that flows
stay serviced and stay in sync between the primary and secondary DPUs with no
drops.

To generate that load we use an **Ixia (IxNetwork)** traffic generator instead
of PTF — Ixia can sustain the line-rate / millions-of-flows that PTF cannot. To
carry the high traffic load without drops between the two DUTs (and to/from
Ixia), we add a **dedicated "direct" physical link** in the testbed: each DUT's
direct link interface is cabled to an L3 fanout switch, and all heavy
traffic classes are deliberately steered over that link —

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

## Testbed-agnostic design

This test is testbed-agnostic. Every testbed-specific value — the SONiC L3
fanout connection and port wiring, the per-DUT direct-link addressing, the
Ixia emulation IPs, the steered underlay prefixes and the stress-loop pacing —
is read from a YAML config file rather than hardcoded.

The default config is
[`tests/ha/configs/ha_stress_ixia.yaml`](../../../../tests/ha/configs/ha_stress_ixia.yaml),
which doubles as a template and as the MtFuji reference testbed's values.

Values that can be inferred from the DUTs (each DUT's Loopback0 and DPU PA
subnet) are derived automatically, so most testbeds only need to edit the
fanout/direct-link/Ixia sections. See
[Configuration (make it your own)](#configuration-make-it-your-own) for the
full key-by-key reference and the command to point the test at your own YAML.

## Prerequisites

> **All the IPs, interfaces, and credentials below are the values for the
> MtFuji *reference* testbed and double as the defaults in
> [`tests/ha/configs/ha_stress_ixia.yaml`](../../../../tests/ha/configs/ha_stress_ixia.yaml).
> They are **not** hardcoded in the test — see
> [Configuration](#configuration-make-it-your-own) to adapt them to your own
> testbed. The only hard requirements are the *roles*: an L3 fanout reachable
> over SSH, one direct DUT↔fanout link per DUT, and two Ixia ports.**

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
- Direct-link interface (`direct_link.dut_interface`, Eth96 on MtFuji) brought
  admin-up + IPs on both DUTs (10.99.2.2/30, 10.99.3.2/30)
- Route steering: PE_PA (101.1.2.3/32) via fanout gateway on each DUT
- HA steering: peer DPU PA /24 + peer NPU Loopback0 /32 via fanout gateway

**IxNetwork (manual — configure before pressing `c` at pause #1):**
- Topology on port 3.1 (TX): IP 10.99.1.2/30, gateway 10.99.1.1
- Topology on port 3.2 (RX): IP 10.99.4.2/30, gateway 10.99.4.1
- Traffic item: VxLAN(VNI=2001) wrapping inner IPv4/UDP|TCP, with the inner
  L4 ports varied by a UDF to scale DPU flows (see section 4)

## Configuration (make it your own)

The test reads **all** testbed-specific values from a YAML config file, so no
source edits are needed to run it elsewhere. The default/template config is
[`tests/ha/configs/ha_stress_ixia.yaml`](../../../../tests/ha/configs/ha_stress_ixia.yaml).
Copy it, edit it for your testbed, and point the test at it:

```bash
./run_tests.sh -n <testbed> -d <duts> -H <dpus> -t t1-smartswitch-ha \
    -c ha/test_ha_planned_shutdown_stress.py \
    -e "--run-stress-tests --ha_stress_config=/abs/path/to/my_testbed.yaml"
```

What you set vs. what is derived:

| Section | Key | Meaning |
| ------- | --- | ------- |
| `direct_link` | `dut_interface` | DUT port cabled to the fanout (same name on each DUT) |
| `direct_link` | `dut_ips` / `dut_gateways` | device side / fanout side of each per-DUT /30 (ordered to match the `-d` DUT list) |
| `fanout` | `ip` / `user` / `password` | SONiC fanout reached over SSH (paramiko) |
| `fanout` | `interfaces` | each fanout port, its /30, and what it `connects_to` (`dut0`, `dut1`, `ixia_tx`, `ixia_rx`) |
| `ixia` | `tx_ip` / `rx_ip` | Ixia L3-emulation IPs (used to bootstrap ARP on the fanout) |
| `addressing` | `appliance_vip` / `pe_pa` | optional overrides; default to `pl.APPLIANCE_VIP` / `pl.PE_PA` |
| `addressing` | `peer_dpu_pa_prefixes` | explicit per-DUT list of each DUT's peer DPU PA /24 (golden-config convention: `20.0.<200+dut_idx>.0/24`) |
| `addressing` | `peer_npu_loopbacks` | `auto` → each DUT's `Loopback0` read from CONFIG_DB, or list to override |
| `stress` | `iterations` / `pre_action_settle_s` / `post_action_settle_s` | HA cycle count and pacing |

Everything else (the fanout routing table, the direct-link steering routes, the
inter-DUT HA steering) is **derived** from the keys above, so a typical new
testbed only edits the `direct_link`, `fanout`, `ixia`, and `addressing`
sections. Each DUT's `Loopback0` is auto-discovered, so you do not have to look
it up by hand.

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

### Route programming summary

Each steered prefix is installed by one or both of: a **fanout** route
(`_configure_fanout_l3`, removed by `_remove_fanout_l3`) and a **per-DUT**
route out the direct link (removed by the matching `_remove_*` helper). The
two halves form one bidirectional steer — the DUT route pushes traffic onto
the direct link toward its fanout gateway (`.1`), and the fanout route forwards
it on to the owning device (`.2`).

| Prefix (role) | Programmed on | Steered to | Function(s) | Purpose |
| ------------- | ------------- | ---------- | ----------- | --- |
| `3.2.1.0/32` (APPLIANCE_VIP) | **Fanout only** | ECMP → DUT1 (.2.2) + DUT2 (.3.2) | `_configure_fanout_l3` | Ingress VxLAN from Ixia TX, ECMP'd to both DUTs. The DUTs terminate the VIP locally in the DASH pipeline, so no DUT-side route is needed. |
| `101.1.2.3/32` (PE_PA) | **Fanout + DUTs** | Ixia 3.2 RX (.4.2) | fanout: `_configure_fanout_l3`; DUT: `_apply_ixia_steering` | Egress GRE/NVGRE return. Each DUT steers it out the direct link (overriding the BGP nexthop via cEOS); the fanout forwards it to the Ixia RX port. |
| `20.0.200.0/24`, `20.0.201.0/24` (peer DPU PA) | **Fanout + DUTs** | peer DUT (.24 → owner DUT) | fanout: `_configure_fanout_l3`; DUT: `_apply_direct_link_ha_steering` | Inter-DUT HA DP/CP flow-sync (UDP/11368 + UDP/11362). Each DUT steers its **peer's** /24 to the fanout; the fanout routes it to the owning DUT. |
| `10.1.0.32/32`, `10.1.0.33/32` (peer NPU Lo0) | **Fanout + DUTs** | peer DUT (.32/.33 → owner DUT) | fanout: `_configure_fanout_l3`; DUT: `_apply_direct_link_ha_steering` | DPU-down VxLAN re-encap toward the peer NPU's Loopback0. Same owner/peer pattern as the DPU PA above. |

> The direct-link interface IPs that these DUT-side routes resolve through are
> applied by `_apply_direct_link_ips` (and the fanout interface IPs by
> `_configure_fanout_l3`); all of the above is set up automatically by the test
> and removed in teardown.

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

> These are MtFuji *reference* values (see the Prerequisites caveat). The MACs
> are informational only — the test is purely L3 and the fanout responds to
> ARP, so no MAC is configured on the DUTs or in static routes.

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

## 2. DUT IP on the direct link

> **Automated by the test.** `_apply_direct_link_ips` brings the direct-link
> interface (`direct_link.dut_interface`, Eth96 on MtFuji) admin-up and adds
> these IPs in setup; `_remove_direct_link_ips` removes them in teardown.

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

## 4. IxNetwork traffic item construction

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
| Outer IPv4    | src      | 25.1.1.1 (VM1_PA)               |
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
| 0x1A   | Outer src IP         | `19010101`     | 25.1.1.1 (VM1_PA)           |
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
  src          25.1.1.1            VM1_PA
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

## 5. Verification

### DPU flow count (pdsctl)

On the DPUs, check the flow table summary via `pdsctl show flow --summary`:

Expected:

- The flow count matches the number of unique flows generated by the UDF
  (e.g. 10M flows for a full UDF sweep — see section 4).
- Both the **primary** and **secondary** DPUs report the same flow count,
  confirming HA flow-sync kept the pair in sync.

### Ixia TX/RX rates and packet counts

In the IxNetwork Statistics view, compare the TX (3.1) and RX (3.2) ports:

Expected:

- TX frame count == RX frame count (no loss across the DASH pipeline).
- TX rate (fps/pps) matches RX rate at steady state.
- Loss = 0% (or within the configured tolerance during HA shutdown/restart).

### NVGRE return capture

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
# --run-stress-tests is required to run the test (otherwise skipped)
# --ha_pause_mode controls interactive pauses: none (default), ends, mid
# --ha_stress_config is optional; omit it to use the bundled default
# (tests/ha/configs/ha_stress_ixia.yaml).
# Extra pytest args (incl. -s for the pause debugger TTY) go in -e.
./run_tests.sh \
    -n vms-kvm-t1-smartswitch-ha \
    -d MtFuji-dut01,MtFuji-dut02 \
    -H MtFuji-dut01-dpu-0,MtFuji-dut02-dpu-0 \
    -t t1-smartswitch-ha \
    -c ha/test_ha_planned_shutdown_stress.py \
    -f testbed.yaml \
    -i veos_vtb \
    -e "--run-stress-tests --ha_stress_config configs/ha_stress_ixia.yaml --ha_pause_mode mid -s"
```

> **Stress-test gating:** the test is decorated with `@pytest.mark.stress_test`
> and is skipped unless `--run-stress-tests` is passed (enforced in
> `tests/conftest.py`). This keeps it from running during normal full-suite
> runs; you must pass `--run-stress-tests` (via `-e`) to execute it.

**Pause modes (`--ha_pause_mode` option):**

| Mode   | Behavior                                                                 |
| ------ | ------------------------------------------------------------------------ |
| `none` | No pauses; test never blocks (default).                                  |
| `ends` | Pause before Ixia start + after all iterations                           |
| `mid`  | `ends` + once after primary-dead and once after secondary-dead (iter 1)  |

Pauses (when `--ha_pause_mode != none`):
1. **Pause #1** — after all DUT/DPU programming and steering is
   complete. Start IxNetwork traffic (TX on 3.1, capture on 3.2), then `c`.
2. **Pause #2** — after all HA iterations complete (HA still active).
   Stop traffic, record TX/RX counts, then `c` to proceed to cleanup.

If an iteration fails, the debugger fires with live state preserved
for debugging (only when `--ha_pause_mode != none`).

> **Note on Ixia vs PTF:** the route steering exists because Ixia only sees
> ports 3.1/3.2, so the NVGRE return must be routed through the fanout to the
> RX port. PTF (veth into every DUT port) captured the return on any egress
> port without steering. This is a measurement constraint, not a datapath
> difference.

---

## Test Matrix

Tests with known issues list them under an **Issues** line — add notes,
links, or bug references there as you run them.

For each test, use corresponding stream in the IXNetwork config file: `TBD`.

### Test 1 — `--ha_pause_mode=none`, UDP low
Start low-rate UDP traffic manually, then run the test with no pauses;
verify it runs successfully to completion.

### Test 2 — `--ha_pause_mode=none`, UDP high (10 Mpps, 10M flows)
Start high-rate UDP traffic manually, then run the test with no pauses;
verify it runs successfully to completion.
- **Issues:**
  - https://github.com/sonic-net/sonic-mgmt/pull/25058#pullrequestreview-4492341205

### Test 3 — `--ha_pause_mode=ends`, UDP low
At pause #1 (HA established): start UDP low stream, clear stats,
continue. At pause #2: verify RX count matches TX count. Ensure test
passes.

### Test 4 — `--ha_pause_mode=ends`, UDP high (10 Mpps, 10M flows)
Same as (3) but with high-rate UDP traffic.

### Test 5 — `--ha_pause_mode=ends`, TCP SYN (1 Mpps, 10M flows) + ACK (10 Mpps, 10M flows)
At pause #1: send TCP SYN stream to establish sessions at 1Mcps;
verify `flows -summary` shows 10M flows on each primary and secondary. Start TCP
ACK stream, clear stats, continue. At pause #2: verify RX matches TX.
Ensure test passes.
- **Issues:**
  - Occasionally, some sessions are not created after SYN stream.
    Requires lower rate or sending the same stream twice to get full 10M flows.
  - Occasionally, some sessions are not synced to the secondary.

### Test 6 — `--ha_pause_mode=ends`, TCP SYN (1 Mpps, 10M flows) + RST (1 Mpps, 10M flows)
Same as (5), but after ACK stream, send TCP RST stream to clear sessions;
verify sessions are cleared.

### Test 7 — `--ha_pause_mode=ends`, TCP SYN (1 Mpps, 10M flows) + FIN-ACK (1 Mpps, 10M flows)
Same as (6), but use TCP FIN-ACK to clear sessions instead of RST.
- **Issues:**
  - Does not work to clear sessions.
    TBD how to properly clear TCP sessions (we are only sending one side of traffic).

### Test 8 — `--ha_pause_mode=mid`, TCP SYN (1 Mpps, 20M flows) + ACK (20 Mpps, 20M flows)
Same as (5) for initial 10M flows. During first mid pause (primary
down): add another 10M flows on secondary for 20M total. Continue test;
verify all 20M flows sync to primary with no drops.
- **Issues:**
  - Same issues as in Test (5)

### Test 9 — `--ha_pause_mode=ends`, uplink-down (single-DUT path)
Simulate an uplink failure by collapsing the APPLIANCE_VIP ECMP route into
a single next-hop so all ingress traffic lands on one DUT. On the fanout,
replace the ECMP route with a single path to DUT1 (or DUT2):
```bash
# fanout: ECMP → single next-hop (simulates the other uplink being down)
sudo ip route replace 3.2.1.0/32 via 10.99.2.2     # all traffic → DUT1 only
# restore ECMP afterwards:
sudo ip route replace 3.2.1.0/32 nexthop via 10.99.2.2 nexthop via 10.99.3.2
```
At pause #1: start traffic, confirm all flows land on the single
chosen DUT, clear stats, continue. Run HA cycles; verify flows stay on
(and sync from) the active DUT with no drops. At pause #2: verify RX
matches TX, then restore the ECMP route.

### TBD additional tests
