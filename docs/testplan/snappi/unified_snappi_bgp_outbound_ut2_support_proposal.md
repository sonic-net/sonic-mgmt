# BGP Outbound Tests - UT2 Pizzabox Support

## Overview

This proposal extends the existing BGP outbound convergence tests to support **Pizzabox UT2** topology in addition to the current **T2 Chassis** topology. The same test files will work on both topologies through a topology abstraction layer.

**Original Test Plan:** [Convergence measurement in data center networks](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/Convergence%20measurement%20in%20data%20center%20networks.md)

## Topology Comparison

### T2 Chassis (Multi-DUT) - Current

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
     │     Fanout      │                     │       T1        │
     └────────┬────────┘                     │     Router      │
              │                              └────────┬────────┘
     ┌────────▼────────┐                     ┌────────▼────────┐
     │   Snappi/Ixia   │                     │   Snappi/Ixia   │
     │    (Uplink)     │                     │   (Downlink)    │
     └─────────────────┘                     └─────────────────┘
```

### UT2 Pizzabox (Single DUT) - New

```
                    ┌─────────────────────────────────┐
                    │         UT2 Pizzabox            │
                    │        (Single DUT)             │
                    │                                 │
                    │  ┌──────────┐   ┌──────────┐   │
                    │  │  Uplink  │   │ Downlink │   │
                    │  │  Ports   │   │  Ports   │   │
                    └──┴─────┬────┴───┴─────┬────┴───┘
                             │              │
                      ┌──────▼──────┐  ┌────▼────────┐
                      │   Fanout    │  │     Lt2     │
                      └──────┬──────┘  └─────┬───────┘
                             │               │
                      ┌──────▼──────┐  ┌─────▼───────┐
                      │    Ixia     │  │    Ixia     │
                      │  (Uplink)   │  │ (Downlink)  │
                      └─────────────┘  └─────────────┘
```

### Key Differences

| Aspect | T2 Chassis | UT2 Pizzabox |
|--------|------------|--------------|
| DUT Count | 3 (Uplink LC, Downlink LC, Supervisor) | 1 |
| Uplink Path | Uplink LC → Fanout → Ixia | UT2 uplink ports → Fanout → Ixia |
| Downlink Path | Downlink LC → T1 → Ixia | UT2 downlink ports → Lt2 → Ixia |
| Supervisor | Present | Not applicable |

---

## Proposed Solution

### Topology Abstraction Layer

Add functions to `bgp_outbound_helper.py` that abstract topology differences:

```python
def get_topology_type(duthosts):
    """
    Detect topology type based on number of DUTs.
    
    Returns:
        str: 'chassis' for T2 multi-DUT, 'pizzabox' for single DUT
    """
    if len(duthosts) == 1:
        return 'pizzabox'
    return 'chassis'


def get_target_dut(duthosts, target_type, hw_platform=None):
    """
    Get the appropriate DUT for the target type.
    
    Args:
        duthosts: List of DUT hosts
        target_type: 'uplink', 'downlink', or 'supervisor'
        hw_platform: Hardware platform identifier
    
    Returns:
        duthost object or pytest.skip() if not applicable
    """
    topology = get_topology_type(duthosts)
    
    if topology == 'pizzabox':
        if target_type == 'supervisor':
            pytest.skip("Supervisor tests not applicable for pizzabox topology")
        return duthosts[0]  # Same DUT for uplink/downlink
    else:
        # T2 Chassis - existing logic
        from tests.snappi_tests.variables import t1_t2_device_hostnames
        
        if target_type == 'uplink':
            target_hostname = t1_t2_device_hostnames[hw_platform][1]
        elif target_type == 'downlink':
            target_hostname = t1_t2_device_hostnames[hw_platform][2]
        elif target_type == 'supervisor':
            target_hostname = t1_t2_device_hostnames[hw_platform][3]
        
        for duthost in duthosts:
            if target_hostname in duthost.hostname:
                return duthost
        
        pytest.fail(f"Could not find DUT for {target_type}")


def get_uplink_ports(duthosts, snappi_extra_params):
    """Get uplink ports based on topology."""
    topology = get_topology_type(duthosts)
    duthost = get_target_dut(duthosts, 'uplink')
    
    if topology == 'pizzabox':
        return snappi_extra_params.uplink_interface or 'PortChannel0'
    else:
        return snappi_extra_params.multi_dut_params.flap_details


def get_downlink_ports(duthosts, snappi_extra_params):
    """Get downlink ports based on topology."""
    topology = get_topology_type(duthosts)
    duthost = get_target_dut(duthosts, 'downlink')
    
    if topology == 'pizzabox':
        return snappi_extra_params.downlink_interface or 'PortChannel100'
    else:
        return snappi_extra_params.multi_dut_params.flap_details
```

### DUT Resolution Mapping

| Concept | T2 Chassis | Pizzabox UT2 |
|---------|------------|--------------|
| Uplink DUT | duthost1 (Uplink LC) | duthost (UT2) |
| Downlink DUT | duthost2 (Downlink LC) | duthost (UT2) |
| Supervisor DUT | duthost3 (Supervisor) | N/A (skip test) |
| Uplink Ports | Ports on Uplink LC | Uplink-facing ports on UT2 |
| Downlink Ports | Ports on Downlink LC | Downlink-facing ports on UT2 |

---

## Test Case Behavior

### Tests That Run on Both Topologies

| Test | T2 Chassis Behavior | Pizzabox UT2 Behavior |
|------|---------------------|----------------------|
| `test_bgp_outbound_uplink_po_flap` | Flap PO on Uplink LC | Flap uplink PO on UT2 |
| `test_bgp_outbound_uplink_multi_po_flap` | Flap multiple POs on Uplink LC | Flap multiple uplink POs on UT2 |
| `test_bgp_outbound_uplink_po_member_flap` | Flap PO member on Uplink LC | Flap uplink PO member on UT2 |
| `test_bgp_outbound_uplink_complete_blackout` | 100% PO flap on Uplink LC | 100% uplink PO flap on UT2 |
| `test_bgp_outbound_uplink_partial_blackout` | 50% PO flap on Uplink LC | 50% uplink PO flap on UT2 |
| `test_bgp_outbound_downlink_port_flap` | Flap port on Downlink LC | Flap downlink port on UT2 |
| `test_bgp_outbound_uplink_process_crash` | Kill process on Uplink LC | Kill process on UT2 |
| `test_bgp_outbound_downlink_process_crash` | Kill process on Downlink LC | Kill process on UT2 |
| `test_bgp_outbound_uplink_tsa` | TSA/TSB on Uplink LC | TSA/TSB on UT2 |
| `test_bgp_outbound_uplink_ungraceful_restart` | Restart Uplink LC | Restart UT2 |

### Tests Skipped on Pizzabox UT2

| Test | Skip Reason |
|------|-------------|
| `test_bgp_outbound_supervisor_tsa` | No supervisor in pizzabox |
| `test_bgp_outbound_supervisor_ungraceful_restart` | No supervisor in pizzabox |
| `test_bgp_outbound_downlink_tsa` | Covered by `uplink_tsa` (same DUT) |
| `test_bgp_outbound_downlink_ungraceful_restart` | Covered by `uplink_ungraceful_restart` (same DUT) |

---

## Configuration Model

The configuration follows the same pattern as T2 Chassis:

| Component | T2 Chassis | UT2 Pizzabox |
|-----------|------------|--------------|
| **DUT Topology** | `topo_tgen_t2_2lc_route_conv.yml` | `topo_tgen_ut2_route_conv.yml` |
| **Neighbor Config** | `conftest.py` → T1 + Fanout | `conftest.py` → Lt2 + Fanout |
| **Device Variables** | `variables.py` | `variables.py` (extended) |
| **Config Files** | `config_db.json.t1.*`, `config_db.json.fanout.*` | `config_db.json.lt2.*`, `config_db.json.fanout.*` |

### Topology-Aware Initial Setup

The `initial_setup` fixture in `conftest.py` will detect topology and configure accordingly:

```python
@pytest.fixture(scope="session", autouse=True)
def initial_setup(duthosts, creds, tbinfo):
    """Perform initial DUT configurations for convergence tests."""
    if 'route_conv' not in tbinfo['topo']['name']:
        yield
        return

    topology = get_topology_type(duthosts)
    
    if topology == 'pizzabox':
        # Configure Lt2 and Fanout for UT2
        configure_ut2_dut(hw_platform, creds, "lt2", context=context)
        if fanout_presence:
            configure_ut2_dut(hw_platform, creds, "fanout")
    else:
        # Configure T1 and Fanout for T2 Chassis (existing logic)
        configure_dut(hw_platform, creds, "t1", context=context)
        if fanout_presence:
            configure_dut(hw_platform, creds, "fanout")

    for duthost in duthosts:
        apply_tsb(duthost)

    yield
    # Cleanup...
```

---

## Required Changes

### New Files

| File | Description |
|------|-------------|
| `ansible/vars/topo_tgen_ut2_route_conv.yml` | UT2 topology definition |
| `tests/snappi_tests/bgp/configs/config_db.json.lt2.<PLATFORM>` | Lt2 device configuration |
| `tests/snappi_tests/bgp/configs/config_db.json.fanout.<PLATFORM>` | Fanout configuration for UT2 |

### Files to Modify

| File | Changes |
|------|---------|
| `tests/snappi_tests/bgp/files/bgp_outbound_helper.py` | Add `get_topology_type()`, `get_target_dut()`, `get_uplink_ports()`, `get_downlink_ports()` |
| `tests/snappi_tests/bgp/conftest.py` | Add `apply_lt2_config_on_dut()`, `configure_ut2_dut()`, update `initial_setup()` |
| `tests/snappi_tests/variables.py` | Add `ut2_device_hostnames`, `lt2_dut_info`, `ut2_uplink_fanout_info`, `lt2_snappi_ports`, `ut2_uplink_portchannel_members`, `ut2_downlink_portchannel_members` |

### Test Files to Modify

All test files need minimal changes:

1. **Update topology marker** to support both:
   ```python
   pytestmark = [pytest.mark.topology('tgen', 'multidut-tgen')]
   ```

2. **Add topology detection** in test functions:
   ```python
   topology = get_topology_type(duthosts)
   if topology == 'pizzabox':
       # Pizzabox-specific setup
   else:
       # Existing T2 Chassis logic
   ```

3. **Add skip logic** for redundant/non-applicable tests:
   ```python
   if topology == 'pizzabox':
       pytest.skip("Covered by uplink test on pizzabox")
   ```

| Test File | Modification |
|-----------|-------------|
| `test_bgp_outbound_uplink_po_flap.py` | Add topology detection |
| `test_bgp_outbound_uplink_multi_po_flap.py` | Add topology detection |
| `test_bgp_outbound_uplink_po_member_flap.py` | Add topology detection |
| `test_bgp_outbound_downlink_port_flap.py` | Add topology detection |
| `test_bgp_outbound_uplink_process_crash.py` | Add topology detection |
| `test_bgp_outbound_downlink_process_crash.py` | Add topology detection |
| `test_bgp_outbound_tsa.py` | Add topology detection + skip downlink/supervisor on pizzabox |
| `test_bgp_outbound_ungraceful_restart.py` | Add topology detection + skip downlink/supervisor on pizzabox |

---

## Variables Configuration

### New Variables for UT2

```python
# UT2 device hostnames [Lt2, UT2]
ut2_device_hostnames = {
    'HW_PLATFORM_UT2': ["sonic-lt2", "sonic-ut2"],
}

# Lt2 device info
lt2_dut_info = {
    'HW_PLATFORM_UT2': {
        'dut_ip': '10.64.246.20',
    },
}

# Fanout info for UT2
ut2_uplink_fanout_info = {
    'HW_PLATFORM_UT2': {
        'fanout_ip': '10.3.146.15',
        'port_mapping': [
            {'fanout_port': 'Ethernet0', 'uplink_port': 'Ethernet0'},
            {'fanout_port': 'Ethernet4', 'uplink_port': 'Ethernet4'},
        ]
    },
}

# Uplink portchannel members on UT2
ut2_uplink_portchannel_members = {
    'HW_PLATFORM_UT2': {
        'sonic-ut2': {
            None: {
                'PortChannel0': ['Ethernet0', 'Ethernet4'],
                'PortChannel1': ['Ethernet8', 'Ethernet12'],
            }
        }
    },
}

# Downlink portchannel members on UT2
ut2_downlink_portchannel_members = {
    'HW_PLATFORM_UT2': {
        'sonic-ut2': {
            None: {
                'PortChannel100': ['Ethernet120', 'Ethernet124'],
                'PortChannel101': ['Ethernet128', 'Ethernet132'],
            }
        }
    },
}

# Lt2 Snappi ports
lt2_snappi_ports = {
    'HW_PLATFORM_UT2': [
        {'ip': '10.1.1.1', 'port_id': '12.1', 'peer_port': 'Ethernet0', 
         'peer_device': 'sonic-lt2', 'speed': 'speed_100_gbps'},
    ],
}
```

---

## Benefits

| Benefit | Description |
|---------|-------------|
| **Code Reuse** | Same test files for both topologies |
| **Maintainability** | Bug fixes apply to both topologies |
| **Consistent Reporting** | Same test names in reports |
| **CI/CD Simplicity** | Same test collection, different testbed |
| **Clear Abstraction** | Topology differences isolated in helper layer |
