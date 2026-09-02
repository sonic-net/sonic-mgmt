# BGP Outbound Route Convergence Tests - Unified T2 Topology Support

## Overview

This document describes the unified T2 topology abstraction layer implemented for BGP outbound route convergence tests. The implementation supports both **T2 Chassis** (multi-DUT) and **T2 Pizzabox** (single-DUT multi-ASIC) topologies using a single, unified configuration model in `variables.py`.

**Original Test Plan:** [Convergence measurement in data center networks](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/Convergence%20measurement%20in%20data%20center%20networks.md)

---

## Supported Topologies

### T2 Chassis (Multi-DUT)

```
                         ┌─────────────────┐
                         │   Supervisor    │
                         │   (duthost3)    │
                         └───┬─────────┬───┘
                             │         │
              ┌──────────────┘         └──────────────┐
              │                                       │
     ┌────────▼────────┐                     ┌────────▼────────┐
     │  T2 Uplink LC   │                     │  T2 Downlink LC │
     │   (duthost1)    │                     │   (duthost2)    │
     └────────┬────────┘                     └────────┬────────┘
              │                                       │
     ┌────────▼────────┐                     ┌────────▼────────┐
     │     Fanout      │                     │   Lower Tier    │
     └────────┬────────┘                     │     (T1)        │
              │                              └────────┬────────┘
     ┌────────▼────────┐                     ┌────────▼────────┐
     │   Snappi/Ixia   │                     │   Snappi/Ixia   │
     │    (Uplink)     │                     │   (Downlink)    │
     └─────────────────┘                     └─────────────────┘
```

### T2 Pizzabox (Single-DUT Multi-ASIC)

```
                    ┌─────────────────────────────────┐
                    │         T2 Pizzabox             │
                    │     (Single DUT Multi-ASIC)     │
                    │                                 │
                    │  ┌──────────┐   ┌──────────┐   │
                    │  │  Uplink  │   │ Downlink │   │
                    │  │  Ports   │   │  Ports   │   │
                    │  │ (asic0)  │   │ (asic1)  │   │
                    └──┴─────┬────┴───┴─────┬────┴───┘
                             │              │
                      ┌──────▼──────┐  ┌────▼────────┐
                      │   Fanout    │  │ Lower Tier  │
                      └──────┬──────┘  │    (Lt2)    │
                             │         └─────┬───────┘
                      ┌──────▼──────┐  ┌─────▼───────┐
                      │  Snappi/Ixia│  │ Snappi/Ixia │
                      │  (Uplink)   │  │ (Downlink)  │
                      └─────────────┘  └─────────────┘
```

### Key Differences

| Aspect | T2 Chassis | T2 Pizzabox |
|--------|------------|-------------|
| DUT Count | 3 (Uplink LC, Downlink LC, Supervisor) | 1 (multi-ASIC) |
| Uplink Path | Uplink LC → Fanout → Ixia | Pizzabox uplink ports → Fanout → Ixia |
| Downlink Path | Downlink LC → Lower Tier → Ixia | Pizzabox downlink ports → Lower Tier → Ixia |
| Lower Tier Device | T1 Router | Lt2 Router |
| Supervisor | Present | Not applicable |
| Device Hostnames | [lower_tier, uplink_lc, downlink_lc, supervisor] | [lower_tier, dut] |

---

## Implementation

### Unified Configuration Model

All topology configurations are stored in a single `TOPOLOGY_CONFIG` dictionary in `variables.py`, organized by topology type and vendor:

```
TOPOLOGY_CONFIG
├── TOPOLOGY_T2_CHASSIS
│   ├── VENDOR_1
│   ├── VENDOR_2
│   └── VENDOR_3
└── TOPOLOGY_T2_PIZZABOX
    ├── VENDOR_1
    ├── VENDOR_2
    └── VENDOR_3
```

### Topology Type Constants

```python
TOPOLOGY_T2_CHASSIS = 'T2_CHASSIS'    # Multi-DUT chassis topology
TOPOLOGY_T2_PIZZABOX = 'T2_PIZZABOX'  # Single-DUT pizzabox topology
```

### AS Number Configuration

Unified AS numbers used across all topologies:

| Constant | Value | Description |
|----------|-------|-------------|
| `T2_DUT_AS_NUM` | 65100 | T2 DUT under test |
| `UPPER_TIER_SNAPPI_AS_NUM` | 65400 | T3/Spine devices emulated via Snappi (uplink) |
| `BACKUP_T2_SNAPPI_AS_NUM` | 65300 | Backup T2 DUTs emulated via Snappi |
| `LOWER_TIER_DUT_AS_NUM` | 65200 | Lower tier DUT (T1/Lt2) |

### Vendor Configuration Structure

Each vendor configuration under a topology type contains:

```python
'VENDOR_NAME': {
    # Device hostnames list
    'device_hostnames': [...],  # Order differs by topology type
    
    # Lower tier device info
    'lower_tier_info': {
        'dut_ip': '...',           # Management IP
        'ports': [...],            # Snappi-connected ports
        'interconnect_port': '...', # Port connecting to DUT
    },
    
    # Snappi ports connected to lower tier
    'lower_tier_snappi_ports': [...],
    
    # Fanout configuration for uplink
    'uplink_fanout': {
        'fanout_ip': '...',
        'port_mapping': [...]
    },
    
    # Portchannel members by ASIC
    'uplink_portchannel_members': {
        'asic0': {...},
        'asic1': {...},  # or None for single-ASIC
    },
    
    # DUT-side interconnect port
    'dut_interconnect_port': {'port_name': '...', 'asic_value': '...'},
}
```

---

## Accessor Functions

The following functions provide a clean API for accessing topology configuration:

### Core Functions

| Function | Description |
|----------|-------------|
| `detect_topology_and_vendor(hostnames)` | Auto-detect topology type and vendor from DUT hostnames |
| `get_topology_config(topology_type, vendor, key, default)` | Get configuration value for topology/vendor |
| `get_device_hostnames(topology_type, vendor)` | Get device hostname list |

### Data Access Functions

| Function | Description |
|----------|-------------|
| `get_lower_tier_info(topology_type, vendor)` | Get lower tier device info (IP, ports, interconnect) |
| `get_lower_tier_snappi_ports(topology_type, vendor)` | Get Snappi ports connected to lower tier |
| `get_uplink_fanout_info(topology_type, vendor)` | Get fanout configuration for uplinks |
| `get_uplink_portchannel_members(topology_type, vendor)` | Get portchannel members by ASIC |
| `get_dut_interconnect_port(topology_type, vendor)` | Get DUT-side interconnect port info |
| `get_as_numbers()` | Get AS number mappings dictionary |

### IP Generation Functions

| Function | Description |
|----------|-------------|
| `get_routed_port_count(topology_type, vendor)` | Calculate routed port count |
| `get_portchannel_count(topology_type, vendor)` | Calculate portchannel count |
| `generate_ips_for_bgp(ipv4_subnet, ipv6_subnet, total_count)` | Generate IP address lists for BGP |
| `get_bgp_ips_for_topology(topology_type, vendor)` | Get complete BGP IP configuration |

---

## Test File Integration

### Topology Detection Pattern

Test files use automatic topology detection:

```python
from tests.snappi_tests.variables import (
    detect_topology_and_vendor,
    get_device_hostnames,
    get_lower_tier_info,
    get_lower_tier_snappi_ports,
    get_uplink_fanout_info,
    TOPOLOGY_T2_CHASSIS,
    TOPOLOGY_T2_PIZZABOX,
)

# In test or fixture
hostnames = [dut.hostname for dut in duthosts]
topo_type, vendor = detect_topology_and_vendor(hostnames)

if topo_type == TOPOLOGY_T2_PIZZABOX:
    # Single DUT - same device handles uplink and downlink
    ...
elif topo_type == TOPOLOGY_T2_CHASSIS:
    # Multi-DUT - separate linecards for uplink/downlink
    ...
```

### DUT Resolution

| Concept | T2 Chassis | T2 Pizzabox |
|---------|------------|-------------|
| Uplink DUT | `device_hostnames[1]` (Uplink LC) | `device_hostnames[1]` (same DUT) |
| Downlink DUT | `device_hostnames[2]` (Downlink LC) | `device_hostnames[1]` (same DUT) |
| Supervisor DUT | `device_hostnames[3]` | N/A (skip test) |
| Lower Tier | `device_hostnames[0]` (T1) | `device_hostnames[0]` (Lt2) |

---

## Test Case Behavior

### Tests That Run on Both Topologies

| Test | T2 Chassis Behavior | T2 Pizzabox Behavior |
|------|---------------------|----------------------|
| `test_bgp_outbound_uplink_po_flap` | Flap PO on Uplink LC | Flap uplink PO on Pizzabox |
| `test_bgp_outbound_uplink_multi_po_flap` | Flap multiple POs on Uplink LC | Flap multiple uplink POs on Pizzabox |
| `test_bgp_outbound_uplink_po_member_flap` | Flap PO member on Uplink LC | Flap uplink PO member on Pizzabox |
| `test_bgp_outbound_downlink_port_flap` | Flap port on Downlink LC | Flap downlink port on Pizzabox |
| `test_bgp_outbound_uplink_process_crash` | Kill process on Uplink LC | Kill process on Pizzabox |
| `test_bgp_outbound_downlink_process_crash` | Kill process on Downlink LC | Kill process on Pizzabox |
| `test_bgp_outbound_tsa` | TSA/TSB on LC | TSA/TSB on Pizzabox |
| `test_bgp_outbound_ungraceful_restart` | Restart LC | Restart Pizzabox |

### Tests Skipped on T2 Pizzabox

| Test | Skip Reason |
|------|-------------|
| Supervisor TSA | No supervisor in pizzabox topology |
| Supervisor ungraceful restart | No supervisor in pizzabox topology |

---

## Configuration Files

### Topology Files

| Topology | Topology File |
|----------|---------------|
| T2 Chassis (multi-ASIC) | `topo_tgen_t2_2lc_masic_route_conv.yml` |
| T2 Chassis (single-ASIC) | `topo_tgen_t2_2lc_route_conv.yml` |
| T2 Pizzabox (multi-ASIC) | `topo_tgen_t2_pizzabox_masic_route_conv.yml` |

### Device Configuration Files

Located in `tests/snappi_tests/bgp/configs/`:

| Device | Topology | File Pattern |
|--------|----------|--------------|
| Lower Tier (T1) | T2 Chassis | `config_db.json.lower_tier.chassis.<VENDOR>` |
| Lower Tier (Lt2) | T2 Pizzabox | `config_db.json.lower_tier.pizzabox.<VENDOR>` |
| Fanout | T2 Chassis | `config_db.json.fanout.chassis.<VENDOR>` |
| Fanout | T2 Pizzabox | `config_db.json.fanout.pizzabox.<VENDOR>` |

---

## Adding New Vendor/Topology Support

### Step 1: Add Configuration to `TOPOLOGY_CONFIG`

```python
TOPOLOGY_CONFIG = {
    TOPOLOGY_T2_PIZZABOX: {
        'VENDOR_X': {
            'device_hostnames': ["lower-tier-hostname", "dut-hostname"],
            'lower_tier_info': {
                'dut_ip': '10.x.x.x',
                'ports': ['EthernetX', 'EthernetY'],
                'interconnect_port': 'EthernetZ',
            },
            'lower_tier_snappi_ports': [...],
            'uplink_fanout': {...},
            'uplink_portchannel_members': {...},
            'dut_interconnect_port': {...},
        },
    },
}
```

### Step 2: Add Device Configuration Files

Create appropriate `config_db.json.*` files for the new vendor's lower tier and fanout devices.

### Step 3: Verify Topology Detection

The `detect_topology_and_vendor()` function automatically detects the topology based on DUT hostnames in the configuration.

---

## Files Modified

| File | Changes |
|------|---------|
| `tests/snappi_tests/variables.py` | Unified `TOPOLOGY_CONFIG`, accessor functions, AS number constants |
| `tests/snappi_tests/bgp/conftest.py` | Updated to use new accessor functions and topology detection |
| `tests/snappi_tests/bgp/files/bgp_outbound_helper.py` | Updated imports and function calls |
| `tests/snappi_tests/bgp/test_bgp_outbound_*.py` | Updated to use new accessor functions |

---

## Benefits

| Benefit | Description |
|---------|-------------|
| **Single Source of Truth** | All topology configurations in one `TOPOLOGY_CONFIG` dictionary |
| **Easy Extensibility** | Add new vendors/topologies by extending the config dictionary |
| **Automatic Detection** | Topology and vendor auto-detected from DUT hostnames |
| **Code Reuse** | Same test files work for all supported topologies |
| **Type Safety** | Topology type constants prevent typos |
| **Maintainability** | Centralized configuration reduces duplication |
| **Clear API** | Well-named accessor functions abstract configuration details |
