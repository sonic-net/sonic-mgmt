# CoPP IPv6 Test Plan

## Table of Contents

- [Overview](#overview)
  - [Scope](#scope)
  - [Related Documents](#related-documents)
- [Background](#background)
- [Testbed](#testbed)
- [Setup Configuration](#setup-configuration)
- [IPv6 CoPP Trap Groups](#ipv6-copp-trap-groups)
- [Test Cases](#test-cases)
  - [TC-01: BGPv6 Policer](#tc-01-bgpv6-policer)
  - [TC-02: NDP Policer (Neighbor Solicitation)](#tc-02-ndp-policer-neighbor-solicitation)
  - [TC-03: NDP Policer (Neighbor Advertisement)](#tc-03-ndp-policer-neighbor-advertisement)
  - [TC-04: NDP Policer (Router Solicitation)](#tc-04-ndp-policer-router-solicitation)
  - [TC-05: NDP Policer (Router Advertisement)](#tc-05-ndp-policer-router-advertisement)
  - [TC-06: DHCPv6 Policer (ToR)](#tc-06-dhcpv6-policer-tor)
  - [TC-07: DHCPv6 Not Punted (T1 Topology)](#tc-07-dhcpv6-not-punted-t1-topology)
  - [TC-08: IP2MEv6 Policer](#tc-08-ip2mev6-policer)
  - [TC-09: BGPv6 Trap Add/Remove Lifecycle](#tc-09-bgpv6-trap-addremove-lifecycle)
  - [TC-10: NDP Trap Always-Enabled Verification](#tc-10-ndp-trap-always-enabled-verification)
  - [TC-11: IPv6 CoPP Config Persistence After Reboot](#tc-11-ipv6-copp-config-persistence-after-reboot)
  - [TC-12: CoPP CLI Shows IPv6 Trap Entries](#tc-12-copp-cli-shows-ipv6-trap-entries)
- [Pass/Fail Criteria](#passfail-criteria)

---

## Overview

### Scope

This test plan covers CoPP (Control Plane Policing) validation for IPv6 protocol traps in SONiC.
The existing `test_copp.py` suite covers IPv4 and dual-stack protocols (ARP, BGP, DHCP, IP2ME, LACP,
LLDP, UDLD, and Default). This plan extends coverage to protocols that are exclusively or primarily
IPv6: BGPv6, NDP (Neighbor Discovery), ICMPv6, MLD (Multicast Listener Discovery), DHCPv6 (extended
validation), IPv6 Hop-by-Hop, and IP2MEv6.

### Related Documents

- [SONiC CoPP HLD](https://github.com/sonic-net/SONiC/blob/master/doc/copp/copp_hld.md)
- [Existing CoPP tests](https://github.com/sonic-net/sonic-mgmt/tree/master/tests/copp)
- GitHub Issue [#22844](https://github.com/sonic-net/sonic-mgmt/issues/22844) — IPv6-only management
  interface support for COPP tests

---

## Background

SONiC implements CoPP via `copp_cfg.json` / `copp_cfg.j2` which defines trap groups with policers
(CIR/CBS in PPS) for each protocol trap. When a trap's policer is configured, control-plane packets
exceeding the CIR are dropped by the ASIC before they reach the kernel.

IPv6-specific traps currently present in the default SONiC CoPP configuration:

| Trap ID              | Trap Group           | Default CIR (PPS) | Description                                   |
|----------------------|----------------------|-------------------|-----------------------------------------------|
| `bgpv6`              | `queue4_group1`      | 10000             | BGP over IPv6 (TCP/179)                       |
| `neigh_discovery`    | `queue4_group2`      | 10000             | NDP: NS/NA/RS/RA/Redirect (ICMPv6 133–137)   |
| `icmpv6`             | `queue4_group2`      | 10000             | ICMPv6 Echo Request/Reply (type 128/129)      |
| `mld_v1_v2`          | `queue4_group3`      | 300               | MLD Query/Report/Done (ICMPv6 130–132, 143)   |
| `dhcpv6`             | `queue8_group1`      | 100               | DHCPv6 Relay (UDP 546→547)                    |
| `ipv6_hop_by_hop`    | `queue1_group1`      | 600               | IPv6 extension header: hop-by-hop             |
| `ip2me` (IPv6)       | `queue4_group2`      | 600               | Packets destined to DUT's own IPv6 address    |

> **Note**: `bgp` and `bgpv6` share `queue4_group1` in most configurations.
> `neigh_discovery` covers all NDP sub-types (NS, NA, RS, RA, Redirect).

---

## Testbed

- **Topology**: `t0`, `t1`, `t2`, `m0`, `mx`, `m1`, `lt2`, `ft2`
- **DUT**: Any SONiC switch with IPv6 data-plane peers configured in minigraph
- **PTF host**: Connected to DUT on data-plane ports
- **Syncd image**: RPC syncd (or `--copp_swap_syncd`) for NN agent communication
- **Rate limit override**: Tests set all policers to 600 PPS (via `copp_utils.limit_policer`)
  to ensure PTF can trigger the policer within the test window

---

## Setup Configuration

The test reuses the `copp_testbed` fixture from `tests/copp/test_copp.py`:

1. Select a random upstream BGP peer port (the NN target port)
2. Gather IPv4/IPv6 peer addresses (`myip6`, `peerip6`) from minigraph facts
3. Limit all COPP policers to 600 PPS (or 625 on Marvell)
4. Shut down BGP upstream neighbors to prevent background traffic consuming COPP bandwidth
5. Configure syncd RPC on the target port
6. Configure PTF NN agent

**Teardown** restores policers, restarts BGP sessions, and restores syncd.

---

## IPv6 CoPP Trap Groups

All policer tests send traffic from the PTF at a rate higher than the configured CIR, then measure
the received PPS at the NN agent and assert it falls within `[CIR × 0.9, CIR × 1.3]`.

---

## Test Cases

### TC-01: BGPv6 Policer

Objective: Verify that BGPv6 traffic (IPv6 TCP destination port 179) is rate-limited by the CoPP policer.

Trap ID: `bgpv6`
Configured CIR: 600 PPS (overridden for test; default is 10000 PPS)

Steps
1. Verify that the `bgpv6` trap exists in STATE_DB.
2. From the PTF host, transmit IPv6 TCP packets with:
   - `tcp_dport = 179`
   - destination IP = `peerip6` (DUT IPv6 BGP peer address)
   - at a rate greater than 600 PPS.
3. Measure the packet receive rate at the NN agent via the RPC syncd socket.
4. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The CoPP policer limits BGPv6 packets to approximately the configured CIR of 600 PPS.

---

### TC-02: NDP Policer (Neighbor Solicitation)

Objective: Verify that NDP Neighbor Solicitation traffic (ICMPv6 type 135) is rate-limited by the CoPP policer.

Trap ID: `neigh_discovery`
Configured CIR: 600 PPS (overridden for test; default is 10000 PPS)

Steps
1. Verify that the `neigh_discovery` trap exists in STATE_DB.
2. From the PTF host, transmit ICMPv6 Neighbor Solicitation packets with:
   - ICMPv6 type 135
   - destination IP = solicited-node multicast address (`ff02::1:ff<last-24-bits>`)
   - target address = `peerip6`
   - at a rate greater than 600 PPS.
3. Measure the packet receive rate at the NN agent via the RPC syncd socket.
4. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The CoPP policer limits NDP Neighbor Solicitation packets to approximately the configured CIR of 600 PPS.

---

### TC-03: NDP Policer (Neighbor Advertisement)

Objective: Verify that NDP Neighbor Advertisement traffic (ICMPv6 type 136) is rate-limited by the CoPP policer.

Trap ID: `neigh_discovery`
Configured CIR: 600 PPS (overridden for test; default is 10000 PPS)

Steps
1. Verify that the `neigh_discovery` trap exists in STATE_DB.
2. From the PTF host, transmit ICMPv6 Neighbor Advertisement packets with:
   - ICMPv6 type 136
   - destination IP = `peerip6` (unicast to DUT)
   - source address = `myip6`
   - at a rate greater than 600 PPS.
3. Measure the packet receive rate at the NN agent via the RPC syncd socket.
4. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The CoPP policer limits NDP Neighbor Advertisement packets to approximately the configured CIR of 600 PPS.

---

### TC-04: NDP Policer (Router Solicitation)

Objective: Verify that NDP Router Solicitation traffic (ICMPv6 type 133) is rate-limited by the CoPP policer.

Trap ID: `neigh_discovery`
Configured CIR: 600 PPS (overridden for test; default is 10000 PPS)

Steps
1. Verify that the `neigh_discovery` trap exists in STATE_DB.
2. From the PTF host, transmit ICMPv6 Router Solicitation packets with:
   - ICMPv6 type 133
   - destination IP = `ff02::2` (all-routers multicast)
   - source address = `myip6`
   - at a rate greater than 600 PPS.
3. Measure the packet receive rate at the NN agent via the RPC syncd socket.
4. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The CoPP policer limits NDP Router Solicitation packets to approximately the configured CIR of 600 PPS.

---

### TC-05: NDP Policer (Router Advertisement)

Objective: Verify that NDP Router Advertisement traffic (ICMPv6 type 134) is rate-limited by the CoPP policer.

Trap ID: `neigh_discovery`
Configured CIR: 600 PPS (overridden for test; default is 10000 PPS)

Steps
1. Verify that the `neigh_discovery` trap exists in STATE_DB.
2. From the PTF host, transmit ICMPv6 Router Advertisement packets with:
   - ICMPv6 type 134
   - destination IP = `ff02::1` (all-nodes multicast)
   - source address = `myip6`
   - at a rate greater than 600 PPS.
3. Measure the packet receive rate at the NN agent via the RPC syncd socket.
4. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The CoPP policer limits NDP Router Advertisement packets to approximately the configured CIR of 600 PPS.

---

### TC-06: DHCPv6 Policer (ToR)

Objective: Verify that DHCPv6 relay traffic is rate-limited by the CoPP policer on ToR (T0) topology.

Trap ID: `dhcpv6`
Configured CIR: 100 PPS on T0; 300 PPS on M0/MX (overridden to 600 PPS for test)

Steps
1. Verify that the `dhcpv6` trap exists in STATE_DB.
2. Confirm topology is T0/M0/MX (skip T1/T2).
3. From the PTF host, transmit DHCPv6 relay packets with:
   - IPv6 UDP, source port 546, destination port 547
   - destination IP = `ff02::1:2` (all-DHCP-servers multicast)
   - source address = `myip6`
   - at a rate greater than the configured CIR.
4. Measure the packet receive rate at the NN agent via the RPC syncd socket.
5. Verify that the observed receive rate is within:
   - [CIR × 0.9, CIR × 1.3] PPS

Pass Criteria

The CoPP policer limits DHCPv6 relay packets to approximately the configured CIR on ToR topology.

---

### TC-07: DHCPv6 Not Punted (T1 Topology)

Objective: Verify that DHCPv6 packets are NOT forwarded to the CPU on T1/T2 topology.

Trap ID: `dhcpv6`
Configured CIR: N/A (trap not active on T1)

Steps
1. Confirm topology is T1 or T2 (skip T0/M0).
2. From the PTF host, transmit DHCPv6 relay packets with:
   - IPv6 UDP, source port 546, destination port 547
   - destination IP = `ff02::1:2`
   - source address = `myip6`.
3. Measure the packet receive count at the NN agent.
4. Verify that the observed receive count equals 0 (no packets punted to CPU).

Pass Criteria

Zero DHCPv6 packets are received by the CPU on T1/T2 topology.

---

### TC-08: IP2MEv6 Policer

Objective: Verify that IPv6 packets destined to the DUT's own IPv6 address (non-BGP, non-NDP) are rate-limited via the ip2me trap.

Trap ID: `ip2me`
Configured CIR: 600 PPS (overridden for test; default is 600 PPS)

Steps
1. Verify that the `ip2me` trap exists in STATE_DB.
2. From the PTF host, transmit IPv6 UDP packets with:
   - destination IP = `peerip6` (DUT's own IPv6 interface address)
   - source address = `myip6`
   - `udp_dport = 9999` (non-standard port to avoid BGP/SNMP classification)
   - at a rate greater than 600 PPS.
3. Measure the packet receive rate at the NN agent via the RPC syncd socket.
4. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The CoPP policer limits IP2MEv6 packets to approximately the configured CIR of 600 PPS.

---

### TC-09: BGPv6 Trap Add/Remove Lifecycle

Objective: Verify that the BGPv6 trap can be dynamically installed and removed, and that the CoPP policer is enforced only when the trap is installed.

Trap ID: `bgpv6`
Configured CIR: 600 PPS (when installed)

Steps
1. Verify that `bgpv6` is a separate COPP entry on this platform (skip if combined with `bgp`).
2. Uninstall the `bgpv6` trap by setting `always_enabled = false` and disabling the `bgp` feature.
3. Verify via STATE_DB that the `bgpv6` trap is not installed.
4. From the PTF host, send BGPv6 traffic at a rate greater than 600 PPS.
5. Verify that the observed receive rate exceeds 600 PPS (traffic is NOT rate-limited).
6. Set `always_enabled = true` for `bgpv6` in CONFIG_DB.
7. Verify via STATE_DB that the `bgpv6` trap is installed.
8. From the PTF host, send BGPv6 traffic again at a rate greater than 600 PPS.
9. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

BGPv6 traffic is not rate-limited when the trap is uninstalled, and is rate-limited to the configured CIR of 600 PPS when the trap is re-installed.

---

### TC-10: NDP Trap Always-Enabled Verification

Objective: Verify that the `neigh_discovery` trap has `always_enabled = true` in CONFIG_DB and is permanently installed in STATE_DB, since NDP is critical for IPv6 forwarding.

Trap ID: `neigh_discovery`

Steps
1. Read the `COPP_TRAP|neigh_discovery` entry from CONFIG_DB.
2. Verify that `always_enabled = true` is set.
3. Read `COPP_TRAP_TABLE|neigh_discovery` from STATE_DB.
4. Verify that `hw_status = installed`.

Pass Criteria

The `neigh_discovery` trap has `always_enabled = true` in CONFIG_DB and `hw_status = installed` in STATE_DB.

---

### TC-11: IPv6 CoPP Config Persistence After Reboot

Objective: Verify that IPv6 CoPP trap configuration (specifically `always_enabled = true` for `bgpv6`) persists across a device reboot and that the policer is enforced after the DUT comes back up.

Trap ID: `bgpv6`
Configured CIR: 600 PPS (overridden for test; default is 10000 PPS)
Parameters: `--copp_reboot_type` in [`reboot`, `warm-reboot`, `fast-reboot`]

Steps
1. Verify that `bgpv6` is a separate COPP entry on this platform (skip if combined with `bgp`).
2. Set `always_enabled = true` for `bgpv6` in CONFIG_DB.
3. Run `sudo config save -y` to persist the configuration.
4. Reboot the DUT using the specified reboot type.
5. Wait 180 seconds for services to stabilise after boot.
6. Verify that `always_enabled = true` is still set for `bgpv6` in CONFIG_DB.
7. Verify that the `bgpv6` trap is installed in STATE_DB.
8. From the PTF host, send BGPv6 traffic at a rate greater than 600 PPS.
9. Verify that the observed receive rate is within:
   - [540, 780] PPS
   - equivalently: 600 × [0.9, 1.3]

Pass Criteria

The `bgpv6` trap configuration persists across reboot and the CoPP policer is enforced after the DUT comes back up.

---

### TC-12: CoPP CLI Shows IPv6 Trap Entries

Objective: Verify that `show copp configuration` displays all expected IPv6-specific trap entries with correct fields, and that the `hw_status` column is consistent with STATE_DB.

Steps
1. Run `show copp configuration` on the DUT.
2. Verify that the command succeeds (rc = 0) and produces output (skip if CLI unavailable).
3. Parse the output and verify the following trap IDs are present:
   - `bgpv6`, `neigh_discovery`, `icmpv6`, `dhcpv6`
4. For each trap, verify that the following fields are non-empty:
   - `trap_group`, `trap_action`, `cir`, `cbs`
5. For each trap, verify that the `hw_status` column matches the value in STATE_DB
   (`COPP_TRAP_TABLE|<trap_id>`).

Pass Criteria

All required IPv6 trap entries are present in `show copp configuration` output with correct fields, and `hw_status` is consistent with STATE_DB.

---

## Pass/Fail Criteria

| Criterion                                 | Requirement                                          |
|-------------------------------------------|------------------------------------------------------|
| Policer rate enforcement                  | Received PPS ∈ [CIR × 0.9, CIR × 1.3]              |
| No-trap traffic rate (when trap removed)  | Received PPS > CIR × 1.4 OR == 0 (platform-specific)|
| Trap install/uninstall (STATE\_DB)        | Matches expected install state                       |
| always\_enabled NDP                       | `always_enabled = true` and `hw_status = installed`  |
| Config save + reboot persistence          | Trap config and policer survive reboot               |
| CLI output                                | `bgpv6`, `neigh_discovery`, `dhcpv6` present with correct fields |
| DHCPv6 on T1                              | 0 packets punted to CPU                              |
