# VXLAN QoS Test Suite - DSCP-to-TC Classification with LAG Ingress

## Overview

This test suite validates DSCP-to-TC (Differentiated Services Code Point to Traffic Class) classification across VXLAN tunnels in a leaf0-style EVPN fabric configuration. The tests mirror real-world deployment scenarios used in production EVPN fabrics.

**Test File**: `test_dscp_to_tc_portchannel_smoke_leaf0.py`

**Test Coverage**:
- **L3VNI** (Layer 3 VXLAN Network Identifier): Routed overlay traffic
- **L2VNI** (Layer 2 VXLAN Network Identifier): Bridged overlay traffic (Unicast and BUM)
- **Traffic Classes**: TC0-TC7 with corresponding DSCP values
- **Address Families**: IPv4 and IPv6
- **Total Test Instances**: 48 (16 per test class × 3 classes)

---

## Test Topology

### Physical Topology

```
┌─────────────────┐                  ┌─────────────────┐
│                 │                  │                 │
│  Ixia Port 1/9  │                  │  Ixia Port 1/12 │
│   (TX/Ingress)  │                  │   (RX/Egress)   │
│                 │                  │                 │
└────────┬────────┘                  └────────▲────────┘
         │                                    │
         │ Ethernet1_49 (breakout)            │ Ethernet1_49 (breakout)
         │ or Ethernet1 (non-breakout)        │ or Ethernet1 (non-breakout)
         │                                    │
┌────────▼─────────────────────┐    ┌────────┴─────────────────────┐
│                              │    │                              │
│         DUT1 (Leaf0)         │    │         DUT2 (Peer)          │
│  Cisco N9K-C93108TC-FX3      │    │  Cisco N9K-C93108TC-FX3      │
│                              │    │                              │
│  • PortChannel0001           │    │  • PortChannel0001           │
│    (L3VNI ingress, LACP)     │    │    (L3VNI egress, LACP)      │
│  • PortChannel0002           │    │                              │
│    (L2VNI ingress, LACP)     │    │                              │
│  • VTEP IP: 10.0.0.1         │    │  • VTEP IP: 10.0.0.2         │
│  • BGP AS: 65001             │    │  • BGP AS: 65002             │
│                              │    │                              │
└──────────────┬───────────────┘    └───────────────┬──────────────┘
               │                                    │
               │      Ethernet1_54_1 (breakout)     │
               │           or Ethernet54            │
               └────────────────┬───────────────────┘
                                │
                        Underlay Transit
                        (BGP-EVPN Peering)
```

### Logical Topology (L3VNI)

```
L3VNI Path

Ixia 1/9 (Tagged)
  │
  └──> PortChannel0001 (DUT1)
        │
        └──> Vlan100 (Tagged SVI)
              │
              └──> VrfQoS
                    │
                    └──> L3 Lookup (EVPN Type-5 Route)
                          │
                          └──> VXLAN Encap (VNI 30000)
                                │
                           Underlay Tunnel
                                │
                          VXLAN Decap (DUT2)
                                │
                                └──> VrfQoS
                                      │
                                      └──> Vlan100 SVI
                                            │
                                            └──> PortChannel0001
                                                  │
                                           Ixia 1/12 (Capture)
```

### Logical Topology (L2VNI)

```
L2VNI Path

Ixia 1/9 (Untagged)
  │
  └──> PortChannel0002 (DUT1)
        │
        └──> Vlan<X> (Untagged Access)
              │
              └──> L2 Bridging
                    │
                    ├──> BUM: Flood to all ports
                    │
                    └──> Unicast: EVPN Type-2 MAC
                          │
                          └──> VXLAN Encap (L2VNI)
                                │
                           Underlay Tunnel
                                │
                          VXLAN Decap (DUT2)
                                │
                                └──> Vlan<X> Flood/Forward
                                      │
                               Ixia 1/12 (Capture)
```

---

## PortChannel Configuration

### L3VNI PortChannel (PortChannel0001)

**Purpose**: Single-member LACP PortChannel for L3VNI tagged-SVI ingress/egress

**Configuration**:
```bash
# DUT1 (Ingress)
config portchannel add PortChannel0001 --fallback=true
config portchannel member add PortChannel0001 Ethernet1_49  # or Ethernet1 in non-breakout

# Tagged VLAN membership
config vlan member add 100 PortChannel0001 --tagged

# SVI in VRF
config interface ip add Vlan100 10.10.10.1/24
config interface ipv6 add Vlan100 2001:db8:10::1/64
config interface vrf bind Vlan100 VrfQoS

# QoS map binding
redis-cli HSET PORT_QOS_MAP|PortChannel0001 dscp_to_tc_map AZURE
```

**Key Properties**:
- **Mode**: LACP with fallback enabled
- **Members**: Single member (Ethernet1_49 or Ethernet1)
- **VLAN**: 100 (tagged)
- **VRF**: VrfQoS
- **L3VNI**: 30000
- **Fallback Behavior**: Admits lone member after LACP timeout (~3s) even without partner LACPDUs

### L2VNI PortChannel (PortChannel0002)

**Purpose**: Single-member LACP PortChannel for L2VNI access ingress

**Configuration**:
```bash
# DUT1 (Ingress)
config portchannel add PortChannel0002 --fallback=true
config portchannel member add PortChannel0002 Ethernet1_50  # ingress_b port

# Untagged VLAN membership (access port)
config vlan member add <L2VNI_VLAN> PortChannel0002 --untagged

# QoS map binding
redis-cli HSET PORT_QOS_MAP|PortChannel0002 dscp_to_tc_map AZURE
```

**Key Properties**:
- **Mode**: LACP with fallback enabled
- **Members**: Single member (Ethernet1_50)
- **VLAN**: L2VNI VLAN (untagged access)
- **L2VNI**: Variable per test

---

## VXLAN Configuration

### L3VNI Configuration

**VRF**: VrfQoS  
**L3VNI**: 30000  
**VLAN**: 100 (tagged SVI)

```bash
# VRF creation
config vrf add VrfQoS

# VXLAN tunnel
config vxlan add vtep VTEP_1
config vxlan evpn_nvo add nvo1 VTEP_1
config vxlan map add vtep VTEP_1 30000 100

# EVPN VRF
config vrf add_vrf_vni_map VrfQoS 30000

# BGP EVPN configuration
vtysh -c "configure terminal" \
      -c "router bgp 65001 vrf VrfQoS" \
      -c "address-family ipv4 unicast" \
      -c "advertise ipv4 unicast" \
      -c "address-family ipv6 unicast" \
      -c "advertise ipv6 unicast"
```

### L2VNI Configuration

**L2VNI**: Variable (test-specific)  
**VLAN**: Variable (untagged access)

```bash
# VXLAN L2VNI mapping
config vxlan map add vtep VTEP_1 <L2VNI> <L2_VLAN>

# EVPN EVI
config bgp evpn advertise-vni <L2VNI>
```

---

## Leaf0-Style BGP Configuration

### BGP Policy Knobs (Both DUTs)

```bash
vtysh -c "configure terminal" \
      -c "router bgp <AS>" \
      -c "bgp disable-ebgp-connected-route-check" \
      -c "bgp bestpath as-path multipath-relax"
```

**Purpose**:
- **disable-ebgp-connected-route-check**: Allows eBGP peering without requiring directly connected networks
- **bestpath multipath-relax**: Enables ECMP across paths with different AS_PATH lengths

### Tunnel Counter Polling (Both DUTs)

```bash
counterpoll tunnel enable
```

**Purpose**: Enables tunnel statistics collection for monitoring and troubleshooting

---

## Test Classes and Use Cases

### 1. TestSmokeL3VNIPortChannelLeaf0

**Test Method**: `test_dscp_to_tc_smoke_l3vni_leaf0_ucast`

**Traffic Type**: L3VNI Unicast (Routed Overlay)

**Test Instances**: 16 (8 TC-DSCP pairs × 2 address families)

**Traffic Flow**:
1. Ixia TX → PortChannel0001 (tagged Vlan100)
2. L3 lookup in VrfQoS
3. EVPN Type-5 route match
4. VXLAN encapsulation (L3VNI 30000)
5. Underlay forwarding
6. VXLAN decapsulation (DUT2)
7. L3 forwarding in VrfQoS
8. Egress via PortChannel0001 → Ixia RX

**Validations**:
- ✅ L3 address family preserved (IPv4/IPv6)
- ✅ DSCP value preserved through encap+decap
- ✅ TTL decremented by 2 (SVI L3 hop + egress L3 hop)
- ✅ VXLAN header removed on RX
- ✅ UDP destination port = 5000 + DSCP
- ✅ 802.1Q tag on TX side, untagged on RX (asymmetric)
- ✅ Traffic classified to correct TC queue

---

### 2. TestSmokeL2VNIPortChannelLeaf0Bum

**Test Method**: `test_dscp_to_tc_smoke_l2vni_leaf0_bum`

**Traffic Type**: L2VNI BUM (Broadcast/Unknown-unicast/Multicast)

**Test Instances**: 16 (8 TC-DSCP pairs × 2 address families)

**Traffic Flow**:
1. Ixia TX → PortChannel0002 (untagged access)
2. L2 bridging (dst_mac=ff:ff:ff:ff:ff:ff)
3. VXLAN encapsulation (L2VNI)
4. Underlay forwarding
5. VXLAN decapsulation (DUT2)
6. BUM flood on L2VNI VLAN
7. Egress via multicast queue → Ixia RX

**Validations**:
- ✅ L3 address family preserved (IPv4/IPv6)
- ✅ DSCP value preserved through encap+decap
- ✅ TTL unchanged (L2 bridging, no TTL decrement)
- ✅ VXLAN header removed on RX
- ✅ UDP destination port = 5000 + DSCP
- ✅ DCHAL multicast queue counters show traffic
- ✅ BUM flood successful

---

### 3. TestSmokeL2VNIPortChannelLeaf0Ucast

**Test Method**: `test_dscp_to_tc_smoke_l2vni_leaf0_ucast`

**Traffic Type**: L2VNI Unicast (EVPN-MAC Learned)

**Test Instances**: 16 (8 TC-DSCP pairs × 2 address families)

**Traffic Flow**:
1. Ixia TX → PortChannel0002 (untagged access)
2. L2 bridging (unicast MAC lookup)
3. EVPN Type-2 MAC route learned
4. VXLAN encapsulation (L2VNI)
5. Underlay forwarding
6. VXLAN decapsulation (DUT2)
7. L2 unicast forwarding
8. Egress via PortChannel member → Ixia RX

**Validations**:
- ✅ L3 address family preserved (IPv4/IPv6)
- ✅ DSCP value preserved through encap+decap
- ✅ TTL unchanged (L2 bridging, no TTL decrement)
- ✅ VXLAN header removed on RX
- ✅ UDP destination port = 5000 + DSCP
- ✅ DUT2 egress queue counters validate TC
- ✅ EVPN-MAC convergence verified (unconverged = test skipped)

---

## TC-DSCP Mapping Matrix

| Test ID      | Traffic Class (TC) | DSCP Value | DSCP Name        | Binary | Priority Level |
|--------------|:------------------:|-----------:|:-----------------|:------:|:---------------|
| tc0-dscp0    | TC0                |          0 | BE (Best Effort) | 000000 | Low            |
| tc1-dscp4    | TC1                |          4 | -                | 000100 | -              |
| tc2-dscp8    | TC2                |          8 | CS1              | 001000 | -              |
| tc3-dscp16   | TC3                |         16 | CS2              | 010000 | -              |
| tc4-dscp24   | TC4                |         24 | CS3              | 011000 | Medium         |
| tc5-dscp32   | TC5                |         32 | CS4              | 100000 | High           |
| tc6-dscp40   | TC6                |         40 | CS5              | 101000 | Higher         |
| tc7-dscp48   | TC7                |         48 | CS6              | 110000 | Highest        |

**Note**: Each TC-DSCP pair is tested with both IPv4 and IPv6, resulting in 16 test instances per test class.

---

## Test Execution Guide

### Environment Variables

```bash
# Packet burst size
export QOS_SMOKE_PKTS_PER_BURST=1000

# Skip DCHAL validation (optional - recommended for LAG ports)
export QOS_SKIP_DCHAL=1

# DUT2 SAI queue counter fallback (recommended for LAG egress)
export SMOKE_DUT2_SAI_QC_FALLBACK=force

# PortChannel features (defaults)
export VXLAN_LEAF0_LAG_INGRESS=1        # Enable LAG ingress wrap
export VXLAN_LEAF0_EGRESS_SVI_LAG=1     # Enable DUT2 egress LAG wrap
```

### Testbed Files

**Breakout Mode**: `testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml`
- Uses breakout ports (e.g., Ethernet1_54_1, Ethernet1_49)
- Static breakout configuration

**Non-Breakout Mode**: `testbeds/fx3/fx3_qos_vxlan_testbed.yaml`
- Uses standard ports (e.g., Ethernet54, Ethernet1)
- No breakout configuration

### Base Command Template

```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file <TESTBED_FILE> \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode <MODE> \
  --logs-path run_logs/ \
  '<TEST_PATH>::<TEST_CLASS>::<TEST_METHOD>[<PARAMS>]'" \
  2>&1 | tee <LOG_FILE>
```

---

## Example Test Commands

### L3VNI Tests

#### Single Test - IPv4, TC0/DSCP0, Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL3VNIPortChannelLeaf0::test_dscp_to_tc_smoke_l3vni_leaf0_ucast[ipv4-tc0-dscp0]'" \
  2>&1 | tee l3vni_ucast_ipv4_tc0_breakout.log
```

#### All L3VNI IPv4 Tests - Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL3VNIPortChannelLeaf0::test_dscp_to_tc_smoke_l3vni_leaf0_ucast' \
  -k 'ipv4'" \
  2>&1 | tee l3vni_ucast_ipv4_all_breakout.log
```

#### All L3VNI Tests (Both IPv4 and IPv6) - Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL3VNIPortChannelLeaf0'" \
  2>&1 | tee l3vni_all_breakout.log
```

### L2VNI Unicast Tests

#### Single Test - IPv4, TC4/DSCP24, Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL2VNIPortChannelLeaf0Ucast::test_dscp_to_tc_smoke_l2vni_leaf0_ucast[ipv4-tc4-dscp24]'" \
  2>&1 | tee l2vni_ucast_ipv4_tc4_breakout.log
```

#### All L2VNI Unicast Tests - Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL2VNIPortChannelLeaf0Ucast'" \
  2>&1 | tee l2vni_ucast_all_breakout.log
```

### L2VNI BUM Tests

#### Single Test - IPv4, TC4/DSCP24, Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL2VNIPortChannelLeaf0Bum::test_dscp_to_tc_smoke_l2vni_leaf0_bum[ipv4-tc4-dscp24]'" \
  2>&1 | tee l2vni_bum_ipv4_tc4_breakout.log
```

#### All L2VNI BUM Tests - Breakout
```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL2VNIPortChannelLeaf0Bum'" \
  2>&1 | tee l2vni_bum_all_breakout.log
```

### Run Entire Test Suite

```bash
podman exec -it qos-spytest bash -c "cd /data/sonic-mgmt/spytest && \
  QOS_SMOKE_PKTS_PER_BURST=1000 QOS_SKIP_DCHAL=1 \
  ./bin/spytest \
  --testbed-file testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode static \
  --logs-path run_logs/ \
  'cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py'" \
  2>&1 | tee all_vxlan_qos_tests.log
```

---

## Test Parameterization Guide

### Test Path Pattern

```
cisco/fx3/qos/qos_map/test_dscp_to_tc_portchannel_smoke_leaf0.py::
  <TEST_CLASS>::<TEST_METHOD>[<ADDRESS_FAMILY>-<TC_DSCP_PAIR>]
```

### Available Parameters

**Test Classes**:
- `TestSmokeL3VNIPortChannelLeaf0` - L3VNI unicast
- `TestSmokeL2VNIPortChannelLeaf0Ucast` - L2VNI unicast
- `TestSmokeL2VNIPortChannelLeaf0Bum` - L2VNI BUM

**Address Families**:
- `ipv4` - IPv4 test
- `ipv6` - IPv6 test

**TC-DSCP Pairs**:
- `tc0-dscp0`, `tc1-dscp4`, `tc2-dscp8`, `tc3-dscp16`
- `tc4-dscp24`, `tc5-dscp32`, `tc6-dscp40`, `tc7-dscp48`

### Filter Examples

**Run only IPv4 tests**:
```bash
-k 'ipv4'
```

**Run only IPv6 tests**:
```bash
-k 'ipv6'
```

**Run only TC4 tests**:
```bash
-k 'tc4-dscp24'
```

**Run only L2VNI tests**:
```bash
-k 'L2VNI'
```

**Run L3VNI IPv4 TC0 and TC7**:
```bash
'...::TestSmokeL3VNIPortChannelLeaf0::test_dscp_to_tc_smoke_l3vni_leaf0_ucast[ipv4-tc0-dscp0]'
'...::TestSmokeL3VNIPortChannelLeaf0::test_dscp_to_tc_smoke_l3vni_leaf0_ucast[ipv4-tc7-dscp48]'
```

---

## Test Execution Matrix

| Traffic Type          | Mode          | AF   | TC Count | Total Tests |
|:----------------------|:--------------|:----:|---------:|------------:|
| **L3VNI Unicast**     | Breakout      | IPv4 |        8 |           8 |
| **L3VNI Unicast**     | Breakout      | IPv6 |        8 |           8 |
| **L3VNI Unicast**     | Non-Breakout  | IPv4 |        8 |           8 |
| **L3VNI Unicast**     | Non-Breakout  | IPv6 |        8 |           8 |
| **L2VNI Unicast**     | Breakout      | IPv4 |        8 |           8 |
| **L2VNI Unicast**     | Breakout      | IPv6 |        8 |           8 |
| **L2VNI Unicast**     | Non-Breakout  | IPv4 |        8 |           8 |
| **L2VNI Unicast**     | Non-Breakout  | IPv6 |        8 |           8 |
| **L2VNI BUM**         | Breakout      | IPv4 |        8 |           8 |
| **L2VNI BUM**         | Breakout      | IPv6 |        8 |           8 |
| **L2VNI BUM**         | Non-Breakout  | IPv4 |        8 |           8 |
| **L2VNI BUM**         | Non-Breakout  | IPv6 |        8 |           8 |
| **GRAND TOTAL**       |               |      |          |      **96** |

---

## Troubleshooting

### Common Issues

#### 1. ARP Resolution Failures
**Symptom**: Preflight ping fails with "Destination Host Unreachable"  
**Cause**: VLAN tag mismatch between DUT and Ixia  
**Solution**: Verify tagged/untagged configuration matches on both sides

#### 2. EVPN Route Convergence
**Symptom**: L2VNI Unicast test skipped (EVPN-MAC not converged)  
**Cause**: BGP EVPN session not established or MAC not advertised  
**Solution**: Check BGP session status and EVPN route advertisement

#### 3. Queue Counter Mismatches
**Symptom**: DCHAL shows 0 packets but SAI shows traffic  
**Cause**: DCHAL not reading LAG-RIF queue counters  
**Solution**: Use `SMOKE_DUT2_SAI_QC_FALLBACK=force`

#### 4. Breakout Port Issues
**Symptom**: Ports not coming up in breakout mode  
**Cause**: Breakout configuration not applied  
**Solution**: Verify `config interface breakout` and check port status

### Debug Commands

#### Verify PortChannel Status
```bash
show interfaces portchannel
show portchannel summary
redis-cli HGETALL "PORTCHANNEL|PortChannel0001"
```

#### Verify VXLAN Configuration
```bash
show vxlan tunnel
show vxlan vni
show vxlan remotevtep
```

#### Verify BGP EVPN
```bash
show bgp l2vpn evpn summary
show bgp l2vpn evpn route
show bgp vrf VrfQoS ipv4 unicast
```

#### Verify Queue Counters
```bash
show queue counters PortChannel0001
show queue counters Ethernet1_49
```

#### Check EVPN MAC Learning
```bash
show mac
show evpn mac vni <VNI>
show bgp l2vpn evpn route type macip
```

---

## Performance Metrics

### Expected Test Duration

- **Single test instance**: ~2-5 minutes
- **Single test class (16 instances)**: ~30-80 minutes
- **Full test suite (48 instances)**: ~2-4 hours

### Traffic Burst Parameters

- **Packets per burst**: 1000 (configurable via `QOS_SMOKE_PKTS_PER_BURST`)
- **Frame rate**: Wire-speed (limited by Ixia and DUT capabilities)
- **Frame size**: 64 bytes (default DSCP smoke)

---

## Key Differences from Non-LAG Tests

| Aspect              | LAG Test                    | Non-LAG Test                |
|:--------------------|:----------------------------|:----------------------------|
| **Ingress Port**    | PortChannel0001/0002        | Physical port (Ethernet1_49)|
| **LACP**            | Enabled with fallback       | Not used                    |
| **Queue Counters**  | LAG-RIF counters            | Physical port counters      |
| **SAI Fallback**    | Recommended (`force`)       | Optional                    |
| **DCHAL Support**   | Limited (LAG-RIF blind)     | Full support                |
| **Deployment Match**| Production-like             | Test-only                   |

---

## References

**Related Test Files**:
- `test_dscp_to_tc_overlay.py` - Non-LAG VXLAN QoS tests
- `vxlan_helper.py` - VXLAN setup helpers
- `qos_helpers.py` - QoS test framework

**Configuration References**:
- `cisco/tortuga/solution/validated_configs/base_l3vni/l3vni_leaf0.cfg`
- EVPN VXLAN best practices guide
- SONiC QoS configuration guide
