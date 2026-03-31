# Copilot Instructions for sonic-mgmt

## Project Overview

sonic-mgmt is the test infrastructure and management automation repository for SONiC. It contains thousands of test cases for functional, performance, and regression testing of SONiC switches. Tests run against physical testbeds and virtual switch (VS) topologies. This repo is essential for validating all changes across the SONiC ecosystem.

## Architecture

```
sonic-mgmt/
├── tests/               # Main test suite (pytest-based)
│   ├── common/          # Shared test utilities and helpers
│   ├── bgp/             # BGP protocol tests
│   ├── acl/             # ACL tests
│   ├── platform_tests/  # Platform-specific tests
│   ├── vlan/            # VLAN tests
│   ├── ecmp/            # ECMP tests
│   ├── crm/             # CRM tests
│   ├── conftest.py      # Shared pytest fixtures
│   └── ...              # Many more test modules
├── ansible/             # Ansible playbooks for testbed management
│   ├── roles/           # Ansible roles
│   ├── vars/            # Variable files
│   ├── testbed.yaml     # Testbed topology definitions
│   └── ...
├── spytest/             # SPyTest framework (alternative test framework)
├── sdn_tests/           # SDN-specific tests
├── test_reporting/      # Test result reporting tools
├── docs/                # Documentation
│   └── README.md        # Detailed docs index
└── .azure-pipelines/    # CI pipeline definitions
```

### Key Concepts
- **Testbed topologies**: Tests run on defined topologies (t0, t1, t2, dualtor, etc.)
- **DUT (Device Under Test)**: The SONiC switch being tested
- **PTF (Packet Test Framework)**: Used for data-plane testing via packet injection
- **Ansible**: Used to deploy and manage testbed infrastructure
- **Fixtures**: Pytest fixtures provide testbed access, DUT connections, and topology info

## Language & Style

- **Primary language**: Python 3
- **Framework**: pytest (with custom plugins and fixtures)
- **Indentation**: 4 spaces
- **Naming conventions**:
  - Test files: `test_*.py`
  - Test functions: `test_*`
  - Test classes: `Test*`
  - Fixtures: `snake_case`, descriptive names
  - Variables: `snake_case`
- **Docstrings**: Required for test functions — describe what is being tested
- **Ansible**: YAML files with 2-space indentation

## Build Instructions

```bash
# No build needed — this is a test/automation repo
# Clone the repo
git clone https://github.com/sonic-net/sonic-mgmt.git
cd sonic-mgmt

# Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# For VS testing, use the sonic-mgmt Docker container
# See docs/README.md for testbed setup instructions
```

## Testing

### Running Tests
```bash
# Run a specific test against a testbed
cd tests
pytest test_feature.py -v --testbed=vms-kvm-t0 --inventory=../ansible/veos_vtb

# Run with markers
pytest -m "topology_t0" test_bgp.py

# Run VS (virtual switch) tests
pytest --testbed_type=vs test_feature.py
```

### Test Structure
- Each test file tests a specific feature or protocol
- Tests use fixtures from `conftest.py` at various directory levels
- `tests/common/` contains shared utilities (duthost, ptfhost, etc.)
- Tests are marked with topology decorators: `@pytest.mark.topology('t0')`
- Data-plane tests use PTF for packet generation/verification

### Writing Tests
```python
import pytest
from tests.common.helpers.assertions import pytest_assert

@pytest.mark.topology('t0')
def test_my_feature(duthosts, rand_one_dut_hostname, tbinfo):
    """Test that my feature works correctly."""
    duthost = duthosts[rand_one_dut_hostname]
    
    # Configure via CLI
    duthost.shell('config my_feature enable')
    
    # Verify state
    output = duthost.show_and_parse('show my_feature status')
    pytest_assert(output[0]['status'] == 'enabled', 
                  "Feature should be enabled")
```

## PR Guidelines

- **Commit format**: `[component/test]: Description`
- **Signed-off-by**: REQUIRED (`git commit -s`)
- **CLA**: Sign Linux Foundation EasyCLA
- **Test validation**: New tests should be validated on at least VS topology
- **Topology markers**: Always mark tests with appropriate topology
- **Idempotency**: Tests should be idempotent — clean up after themselves
- **No hardcoded values**: Use fixtures and testbed info instead of hardcoded IPs/ports

## Common Patterns

### DUT Host Operations
```python
# Run CLI command
duthost.shell('show interfaces status')

# Run command and parse output
result = duthost.show_and_parse('show vlan brief')

# Check service status
duthost.is_service_running('swss')

# Config reload
duthost.shell('config reload -y')
```

### PTF Data-Plane Testing
```python
# Send and verify packets
ptf_runner(duthost, ptfhost, 'my_ptf_test',
           platform_dir='ptftests',
           params={'router_mac': router_mac})
```

### Test Fixtures
- `duthosts` — access to all DUTs in testbed
- `tbinfo` — testbed topology information
- `ptfhost` — PTF container for packet testing
- `rand_one_dut_hostname` — random DUT selection
- `enum_frontend_dut_hostname` — iterate over frontend DUTs

## Dependencies

- **pytest**: Test framework
- **Ansible**: Testbed management
- **PTF**: Packet Test Framework
- **sonic-buildimage**: VS images for virtual testing
- **Jinja2**: Template rendering for test configurations
- **paramiko/netmiko**: SSH connectivity to DUTs

## Gotchas

- **Topology requirements**: Tests marked for `t1` won't work on `t0` testbeds
- **Test isolation**: Tests may affect each other if they modify persistent config — always restore state
- **Fixture scope**: Be aware of fixture scope (session, module, function) — session-scoped fixtures persist
- **Timing**: Network state changes take time — use `wait_until` helpers, not `time.sleep`
- **Multi-ASIC**: Tests must work on multi-ASIC platforms — use appropriate fixtures
- **Flaky tests**: Add retries with `@pytest.mark.flaky(reruns=3)` for inherently flaky network tests
- **VS limitations**: VS doesn't support all features — check VS compatibility before expecting tests to pass
- **Ansible inventory**: Tests need correct inventory files matching the testbed topology
