# BGP Sentinel Fixtures - Migration Guide

## Overview

The BGP Sentinel test code has been refactored to use reusable fixtures. This guide shows how to migrate existing tests or create new tests using these fixtures.

## What's Available Now

### 1. Fixture Files
- **Location**: `tests/common/fixtures/bgp_sentinel_utils.py`
- **Documentation**: `tests/common/fixtures/BGP_SENTINEL_FIXTURES_README.md`
- **Example Tests**: `tests/bgp/test_bgp_sentinel_example.py`

### 2. Auto-imported Fixtures
The following fixtures are automatically available in all tests (no explicit import needed):
- `enable_bgp_sentinel` - Basic BGP Sentinel configuration
- `bgp_sentinel_with_exabgp` - Full setup with ExaBGP peers

### 3. Helper Functions
Available via import from `tests.common.fixtures.bgp_sentinel_utils`:
- `is_bgp_sentinel_supported(duthost)`
- `is_bgp_monv6_supported(duthost)`
- `get_sentinel_community(duthost)`
- `is_bgp_sentinel_session_established(duthost, sessions)`

## Migration Examples

### Example 1: Migrating `test_bgp_sentinel.py`

**Original Code** (simplified):
```python
@pytest.fixture(scope="module")
def dut_setup_teardown(rand_selected_dut, tbinfo, dut_lo_addr, request):
    duthost = rand_selected_dut
    # 50+ lines of setup code
    yield ...
    # 20+ lines of cleanup code

@pytest.fixture(scope="module")
def ptf_setup_teardown(dut_setup_teardown, rand_selected_dut, ptfhost, tbinfo):
    # 40+ lines of setup code
    yield ...
    # 15+ lines of cleanup code

def test_bgp_sentinel(rand_selected_dut, prepare_bgp_sentinel_routes, reset_type):
    duthost = rand_selected_dut
    # Test logic
```

**Migrated Code**:
```python
# Option 1: Import fixtures (they're already auto-imported, but explicit is fine)
from tests.common.fixtures.bgp_sentinel_utils import (
    bgp_sentinel_with_exabgp,
    is_bgp_sentinel_session_established
)

# Option 2: Just use them directly (auto-imported)
def test_bgp_sentinel_new(bgp_sentinel_with_exabgp, reset_type):
    """Simplified test using reusable fixtures."""
    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']

    # All setup is done - just write test logic!
    assert is_bgp_sentinel_session_established(duthost, config['ibgp_sessions'])

    # Test logic here...
```

### Example 2: Creating a New BGP Sentinel Test

**New Test File**: `tests/bgp/test_my_bgp_feature.py`

```python
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs'),
]

def test_my_feature_basic(enable_bgp_sentinel):
    """
    Test basic BGP Sentinel configuration.
    Use this when you just need BGP Sentinel configured.
    """
    config = enable_bgp_sentinel

    # Verify feature is enabled
    pytest_assert(config['is_enabled'], 'BGP Sentinel should be enabled')

    duthost = config['duthost']
    # Your test logic here


def test_my_feature_with_routes(bgp_sentinel_with_exabgp):
    """
    Test route behavior with active iBGP sessions.
    Use this when you need to announce/withdraw routes.
    """
    import requests
    from tests.common.fixtures.bgp_sentinel_utils import get_sentinel_community

    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']

    # Get sentinel community
    community = get_sentinel_community(duthost)

    # Announce a test route
    url = "http://{}:{}".format(config['ptfip'], config['exabgp_ports']['v4'])
    data = {
        "command": "neighbor {} announce route 192.168.100.0/24 next-hop {} community [{}]".format(
            config['lo_ipv4'],
            config['ptf_bp_v4'],
            community
        )
    }
    response = requests.post(url, data=data)
    pytest_assert(response.status_code == 200, 'Route announcement should succeed')

    # Your verification logic here
```

### Example 3: Parameterized Test

```python
@pytest.mark.parametrize('ip_version,expected_sessions', [
    ('IPv4', 1),
    ('IPv6', 1),
    ('Both', 2)
])
def test_sessions_by_version(bgp_sentinel_with_exabgp, ip_version, expected_sessions):
    """Test BGP sessions for different IP versions."""
    config = bgp_sentinel_with_exabgp

    if ip_version == 'IPv4' and config['ipv4_nh'] is None:
        pytest.skip('IPv4 session not available')
    elif ip_version == 'IPv6' and config['ipv6_nh'] is None:
        pytest.skip('IPv6 session not available')

    # Test logic
    actual_sessions = len(config['ibgp_sessions'])
    # Assertions...
```

## Benefits of Migration

### Before Migration
```python
# test_old.py (200 lines)
- 80 lines of fixture setup code
- 40 lines of test logic
- 30 lines of cleanup code
- 50 lines of helper functions
```

### After Migration
```python
# test_new.py (50 lines)
- 0 lines of fixture setup (reused)
- 40 lines of test logic
- 0 lines of cleanup (automatic)
- 10 lines of imports
```

**Result**: 75% code reduction, better maintainability!

## Step-by-Step Migration Process

### Step 1: Identify Test Requirements
Determine what your test needs:
- [ ] Just BGP Sentinel configured? → Use `enable_bgp_sentinel`
- [ ] Active iBGP sessions? → Use `bgp_sentinel_with_exabgp`
- [ ] Route announcements? → Use `bgp_sentinel_with_exabgp` + helper functions

### Step 2: Replace Fixtures
**Before**:
```python
@pytest.fixture(scope="module")
def my_custom_bgp_setup(duthost, ptfhost, tbinfo):
    # Custom setup code
    yield config
    # Custom cleanup
```

**After**:
```python
# Remove custom fixture, use built-in
def test_my_feature(bgp_sentinel_with_exabgp):
    config = bgp_sentinel_with_exabgp
    # config contains everything you need
```

### Step 3: Update Test Function Signatures
**Before**:
```python
def test_feature(rand_selected_dut, my_custom_bgp_setup, ptfhost):
    duthost = rand_selected_dut
    # ...
```

**After**:
```python
def test_feature(bgp_sentinel_with_exabgp):
    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']
    # ...
```

### Step 4: Use Helper Functions
**Before**:
```python
def check_if_sessions_up(duthost, sessions):
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    # 10 lines of checking logic
    return result
```

**After**:
```python
from tests.common.fixtures.bgp_sentinel_utils import is_bgp_sentinel_session_established

# Just call the helper
is_up = is_bgp_sentinel_session_established(duthost, sessions)
```

### Step 5: Test Your Changes
```bash
# Run your migrated test
pytest tests/bgp/test_my_feature.py -v

# Run with markers
pytest tests/bgp/test_my_feature.py -m "topology('t1')" -v
```

## Common Patterns

### Pattern 1: Simple Configuration Check
```python
def test_config(enable_bgp_sentinel):
    config = enable_bgp_sentinel
    assert config['is_enabled']
```

### Pattern 2: Session Verification
```python
def test_sessions(bgp_sentinel_with_exabgp):
    from tests.common.fixtures.bgp_sentinel_utils import is_bgp_sentinel_session_established

    config = bgp_sentinel_with_exabgp
    assert is_bgp_sentinel_session_established(
        config['duthost'],
        config['ibgp_sessions']
    )
```

### Pattern 3: Route Announcement
```python
def test_routes(bgp_sentinel_with_exabgp):
    import requests

    config = bgp_sentinel_with_exabgp
    url = "http://{}:{}".format(config['ptfip'], config['exabgp_ports']['v4'])

    # Announce
    data = {"command": "neighbor ... announce route ..."}
    requests.post(url, data=data)

    # Verify
    # ...

    # Withdraw
    data = {"command": "neighbor ... withdraw route ..."}
    requests.post(url, data=data)
```

## Troubleshooting

### Issue: Fixture not found
```python
# Error: fixture 'enable_bgp_sentinel' not found
```
**Solution**: The fixtures are auto-imported via `tests/common/fixtures/__init__.py`. If they're not found:
1. Verify the file exists: `tests/common/fixtures/bgp_sentinel_utils.py`
2. Check `tests/common/fixtures/__init__.py` imports it
3. Restart your test environment

### Issue: Import errors
```python
# Error: cannot import name 'BGP_SENTINEL_PORT_V4' from 'tests.bgp.bgp_helpers'
```
**Solution**: The fixture file has fallback values. If you see this error, the constants are missing from bgp_helpers.py. The fixture will use defaults.

### Issue: Test skipped
```
SKIPPED [1] ... BGP Sentinel is not enabled
```
**Solution**: BGP Sentinel may not be supported on your test image. Check:
```python
from tests.common.fixtures.bgp_sentinel_utils import is_bgp_sentinel_supported
assert is_bgp_sentinel_supported(duthost)
```

## Additional Resources

- **Full Documentation**: `tests/common/fixtures/BGP_SENTINEL_FIXTURES_README.md`
- **Example Tests**: `tests/bgp/test_bgp_sentinel_example.py`
- **Original Test**: `tests/bgp/test_bgp_sentinel.py` (for comparison)
- **Fixture Source**: `tests/common/fixtures/bgp_sentinel_utils.py`

## Support

For questions or issues with the fixtures:
1. Check the BGP_SENTINEL_FIXTURES_README.md
2. Review test_bgp_sentinel_example.py for working examples
3. File an issue with test framework team

---

**Migration Status**: ✅ Fixtures implemented and ready to use!
