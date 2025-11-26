# BGP Sentinel Testing Fixtures

This document describes how to use the reusable BGP Sentinel fixtures for testing.

## Overview

This module provides **two fixtures** and **helper functions** for BGP Sentinel testing:

### **Fixtures** (Setup/Teardown Infrastructure)
1. **`enable_bgp_sentinel`** - Enables BGP Sentinel feature on DUT (configuration only)
2. **`bgp_sentinel_with_exabgp`** - Adds ExaBGP peers and establishes iBGP sessions (for route testing)

### **Helper Functions** (Used by Tests)
- `is_bgp_sentinel_supported()` - Check if feature is available
- `get_sentinel_community()` - Get sentinel community value
- `is_bgp_sentinel_session_established()` - Verify BGP sessions are up

### **What Tests Can Do** (Using the Fixtures)
- Test BGP Sentinel configuration and schema
- Announce and withdraw routes via ExaBGP HTTP API
- Verify route filtering, propagation, and BGP behavior
- Test BGP community handling

## Available Fixtures

### 1. `enable_bgp_sentinel` (Module Scope)

**Purpose**: Enables BGP Sentinel feature on DUT with basic configuration.

**What it does**:
- Reads DUT loopback addresses
- Derives listen ranges from topology
- Configures BGP_SENTINELS in CONFIG_DB
- Sets up IPv6 NHT resolution
- Cleans up configuration after tests

**Returns**: Dictionary with:
```python
{
    'duthost': <duthost object>,
    'lo_ipv4': '10.1.0.32',
    'lo_ipv6': 'fc00:1::32',
    'ipv4_subnet': '100.1.0.0/24',
    'ipv6_subnet': '2064:100::/59',
    'ptf_bp_v4': '10.0.0.1',
    'ptf_bp_v6': 'fc00::1',
    'config_file': '/tmp/bgp_sentinel_config.json',
    'is_enabled': True
}
```

**Usage Example**:
```python
def test_basic_config(enable_bgp_sentinel):
    config = enable_bgp_sentinel
    assert config['is_enabled'], 'BGP Sentinel should be enabled'

    duthost = config['duthost']
    # Your test logic here
```

---

### 2. `bgp_sentinel_with_exabgp` (Module Scope)

**Purpose**: Full setup including ExaBGP peers and iBGP session establishment.

**What it does**:
- All setup from `enable_bgp_sentinel`
- Starts ExaBGP processes on PTF (IPv4 and IPv6)
- Establishes routing between PTF and DUT loopback
- Waits for iBGP sessions to establish
- Cleans up ExaBGP and routes after tests

**Returns**: Extended dictionary with all fields from `enable_bgp_sentinel` plus:
```python
{
    # ... all fields from enable_bgp_sentinel ...
    'ibgp_sessions': ['10.0.0.1', 'fc00::1'],
    'ptfip': '192.168.1.100',
    'exabgp_ports': {
        'v4': 5000,
        'v6': 5001
    },
    'ipv4_nh': '10.0.0.1',  # Next hop that worked for IPv4
    'ipv6_nh': 'fc00::1'    # Next hop that worked for IPv6
}
```

**Usage Example**:
```python
def test_route_announcement(bgp_sentinel_with_exabgp):
    config = bgp_sentinel_with_exabgp

    # Check sessions are established
    duthost = config['duthost']
    assert is_bgp_sentinel_session_established(duthost, config['ibgp_sessions'])

    # Announce routes via ExaBGP
    announce_route(
        config['ptfip'],
        config['lo_ipv4'],
        '192.168.100.0/24',
        config['ptf_bp_v4'],
        config['exabgp_ports']['v4'],
        'sentinel_community_value'
    )
```

---

## Helper Functions

### `is_bgp_sentinel_supported(duthost)`
Check if BGP Sentinel is configured on DUT.

```python
if is_bgp_sentinel_supported(duthost):
    # BGP Sentinel is available
    pass
```

### `is_bgp_monv6_supported(duthost)`
Check if BGP Monitor V6 is configured on DUT.

### `get_sentinel_community(duthost, constants_file='/etc/sonic/constants.yml')`
Get the sentinel community value from DUT.

```python
community = get_sentinel_community(duthost)
# Returns: "1111:1111" or None
```

### `is_bgp_sentinel_session_established(duthost, ibgp_sessions)`
Check if BGP sessions are established.

```python
sessions = ['10.0.0.1', 'fc00::1']
if is_bgp_sentinel_session_established(duthost, sessions):
    # All sessions are up
    pass
```

---

## Usage Patterns

### Pattern 1: Simple Configuration Test
Test that just needs BGP Sentinel configured:

```python
def test_config_applied(enable_bgp_sentinel):
    config = enable_bgp_sentinel
    assert config['is_enabled']
    # Verify configuration details
```

### Pattern 2: Session Establishment Test
Test that needs active iBGP sessions:

```python
def test_sessions(bgp_sentinel_with_exabgp):
    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']

    # Verify sessions
    assert is_bgp_sentinel_session_established(
        duthost,
        config['ibgp_sessions']
    )
```

### Pattern 3: Route Announcement Test
Test that announces routes and verifies behavior:

```python
import requests

def test_route_behavior(bgp_sentinel_with_exabgp):
    config = bgp_sentinel_with_exabgp

    # Get configuration
    ptfip = config['ptfip']
    port = config['exabgp_ports']['v4']
    neighbor = config['lo_ipv4']
    nexthop = config['ptf_bp_v4']

    # Announce route
    url = "http://{}:{}".format(ptfip, port)
    data = {
        "command": "neighbor {} announce route {} next-hop {} community [{}]".format(
            neighbor, '192.168.1.0/24', nexthop, 'community'
        )
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200

    # Verify route behavior
    # ... your verification logic ...

    # Withdraw route
    data['command'] = "neighbor {} withdraw route {}".format(
        neighbor, '192.168.1.0/24'
    )
    requests.post(url, data=data)
```

### Pattern 4: Parameterized Tests
Use with pytest parameterization:

```python
@pytest.mark.parametrize('ip_version', ['IPv4', 'IPv6'])
def test_both_versions(bgp_sentinel_with_exabgp, ip_version):
    config = bgp_sentinel_with_exabgp

    if ip_version == 'IPv4':
        if config['ipv4_nh'] is None:
            pytest.skip('IPv4 session not established')
        neighbor = config['lo_ipv4']
        port = config['exabgp_ports']['v4']
    else:
        if config['ipv6_nh'] is None:
            pytest.skip('IPv6 session not established')
        neighbor = config['lo_ipv6']
        port = config['exabgp_ports']['v6']

    # Test logic for both versions
```

### Pattern 5: Class-based Tests
Use fixtures in test classes:

```python
class TestBGPSentinel:
    def test_config(self, enable_bgp_sentinel):
        config = enable_bgp_sentinel
        assert config['is_enabled']

    def test_sessions(self, bgp_sentinel_with_exabgp):
        config = bgp_sentinel_with_exabgp
        assert len(config['ibgp_sessions']) > 0
```

---

## Fixture Dependencies

```
enable_bgp_sentinel
    ├─ Requires: duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo
    └─ Provides: Basic BGP Sentinel configuration

bgp_sentinel_with_exabgp
    ├─ Depends on: enable_bgp_sentinel
    ├─ Requires: ptfhost, tbinfo
    └─ Provides: Full setup with ExaBGP and iBGP sessions
```

---

## Configuration Files

### BGP Sentinel Config Template
Location: `tests/bgp/bgp_sentinel_fixtures.py`

```json
{
    "BGP_SENTINELS": {
        "BGPSentinel": {
            "ip_range": ["100.1.0.0/24", "10.0.0.1/32"],
            "name": "BGPSentinel",
            "src_address": "10.1.0.32"
        },
        "BGPSentinelV6": {
            "ip_range": ["2064:100::/59", "fc00::1/128"],
            "name": "BGPSentinelV6",
            "src_address": "fc00:1::32"
        }
    }
}
```

---

## Topology Requirements

- **Topology**: T1 (required)
- **Device Type**: vs (virtual switch)
- **Required Components**:
  - PTF host with backplane connectivity
  - DUT with Loopback0 configured
  - Spine/ToR topology information

---

## Cleanup

Both fixtures automatically clean up after tests:

**`enable_bgp_sentinel` cleanup**:
- Removes BGP_SENTINELS from CONFIG_DB
- Deletes temporary config file

**`bgp_sentinel_with_exabgp` cleanup**:
- Stops ExaBGP processes
- Removes PTF routes to DUT loopback
- Calls `enable_bgp_sentinel` cleanup

---

## Troubleshooting

### Issue: "BGP Sentinel is not enabled"
**Solution**: Check if BGP Sentinel is supported on the SONiC image:
```python
assert is_bgp_sentinel_supported(duthost)
```

### Issue: "iBGP sessions not establishing"
**Solution**:
1. Verify routing between PTF and DUT loopback:
   ```bash
   # On PTF
   ping <dut_loopback_ip> -I backplane
   ```
2. Check BGP logs on DUT:
   ```bash
   show log | grep bgp
   ```

### Issue: "Sentinel community not found"
**Solution**: Ensure `/etc/sonic/constants.yml` exists and contains:
```yaml
constants:
  bgp:
    sentinel_community: "1111:1111"
```

---

## Example Test File

See `tests/bgp/test_bgp_sentinel_example.py` for complete working examples.

---

## Migration from Old Tests

To migrate existing tests to use these fixtures:

**Before**:
```python
def test_my_feature(duthost, ptfhost, tbinfo):
    # 50 lines of BGP Sentinel setup code
    # Test logic
    # 30 lines of cleanup code
```

**After**:
```python
def test_my_feature(bgp_sentinel_with_exabgp):
    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']
    # Test logic only
```

This reduces code duplication and makes tests more maintainable!
