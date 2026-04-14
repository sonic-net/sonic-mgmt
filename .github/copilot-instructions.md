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
│   ├── smartswitch/     # SmartSwitch / DPU tests
│   │   ├── common/      # Shared DPU utilities (device_utils_dpu.py, reboot.py)
│   │   ├── conftest.py  # SmartSwitch fixtures (gNOI certs, ptf_gnoi)
│   │   └── platform_tests/  # DPU platform tests (reboot, health, temperature)
│   ├── conftest.py      # Shared pytest fixtures
│   └── ...              # Many more test modules
├── ansible/             # Ansible playbooks for testbed management
│   ├── roles/           # Ansible roles
│   ├── vars/            # Variable files
│   ├── testbed.yaml     # Testbed topology definitions
│   ├── golden_config_db/  # Golden config DB JSON files applied to DUTs
│   └── ...
├── spytest/             # SPyTest framework (alternative test framework)
├── sdn_tests/           # SDN-specific tests
├── test_reporting/      # Test result reporting tools
├── docs/                # Documentation
│   └── README.md        # Detailed docs index
└── .azure-pipelines/    # CI pipeline definitions
```

### Key Concepts
- **Testbed topologies**: Tests run on defined topologies (t0, t1, t2, dualtor, smartswitch, etc.)
- **DUT (Device Under Test)**: The SONiC switch being tested
- **PTF (Packet Test Framework)**: Used for data-plane testing via packet injection
- **Ansible**: Used to deploy and manage testbed infrastructure
- **Fixtures**: Pytest fixtures provide testbed access, DUT connections, and topology info

### SmartSwitch / DPU Concepts
- **SmartSwitch**: A SONiC switch with one or more on-board DPU (Data Processing Unit) modules
- **DPU (Data Processing Unit)**: An independent SONiC instance running on a SmartSwitch module; accessed via midplane IP
- **NPU**: The main switch CPU on a SmartSwitch (runs SONiC, manages DPUs via `config chassis modules`)
- **Midplane**: Internal network connecting NPU to DPUs; DPUs are reachable via midplane IP addresses
- **Dark mode**: All DPUs are administratively shut down (`CHASSIS_MODULE` admin-status = down)
- **Lit mode**: DPUs are administratively up and running; tests can interact with them via midplane IPs using SSH port forwarding
- **`duthost`**: Handle to the NPU (switch); **`dpuhosts`**: list of handles to individual DPU SONiC instances


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

## Setup

### Clone the Repository

```bash
git clone https://github.com/sonic-net/sonic-mgmt.git
cd sonic-mgmt
# Checkout the target branch, e.g. master
git checkout master
```

No build step is needed — this is a test/automation repo. Tests run inside a sonic-mgmt Docker container.

### VS (Virtual Switch) Testbed Setup

The VS testbed allows running tests locally against a virtual SONiC switch. All steps below assume:
- A Linux VM (Ubuntu 22.04 recommended) with Docker installed
- The sonic-mgmt repo cloned (e.g., to `/data/code/sonic-mgmt`)

#### 1. Create the sonic-mgmt Container

```bash
cd /data/code/sonic-mgmt
./setup-container.sh -n <container-name> -d /data/code -v
```

Replace `<container-name>` with a name for your container (e.g., `sonic-mgmt-<your-username>`).
This creates a Docker container with the sonic-mgmt environment and configures SSH key-based access to the host VM.

#### 2. Set Up the Management Network

```bash
cd /data/code/sonic-mgmt/ansible
sudo ./setup-management-network.sh
```

This creates the `br1` bridge used for management connectivity.

#### 3. Update Ansible Inventory

Edit `ansible/veos_vtb` and update `ansible_user` and `vm_host_user` to match your Linux VM username:

```yaml
vm_host_1:
  hosts:
    STR-ACS-VSERV-01:
      ansible_host: 172.17.0.1
      ansible_user: <your-username>
      vm_host_user: <your-username>
```

#### 4. Prepare Images

**cEOS Image (for neighbor VMs):**

Download the cEOS lab image from the [Arista software download page](https://www.arista.com/en/support/software-download) (requires an Arista account). The image file is named like `cEOS64-lab-4.32.5M.tar`. Place it under `~/veos-vm/images/`. The testbed automation will load it automatically.

**SONiC VS Image:**

Download the sonic-vs image from the [SONiC build pipeline artifacts](https://dev.azure.com/mssonic/build/_build?definitionId=142). Place it at `~/sonic-vm/images/sonic-vs.img`.

#### 5. Enter the Container

```bash
docker exec -it --user $USER <container-name> /bin/bash
```

All subsequent steps are executed **inside the sonic-mgmt container**.

#### 6. Export Environment Variables

```bash
BASE_PATH="/data/code/sonic-mgmt"
export ANSIBLE_CONFIG=${BASE_PATH}/ansible
export ANSIBLE_HOME=${BASE_PATH}/ansible
export ANSIBLE_LIBRARY=${BASE_PATH}/ansible/library/
export ANSIBLE_MODULE_UTILS=${BASE_PATH}/ansible/module_utils
export ANSIBLE_ACTION_PLUGINS=${BASE_PATH}/ansible/plugins/action
export ANSIBLE_CONNECTION_PLUGINS=${BASE_PATH}/ansible/plugins/connection
export ANSIBLE_CLICONF_PLUGINS=${BASE_PATH}/ansible/cliconf_plugins
export ANSIBLE_TERMINAL_PLUGINS=${BASE_PATH}/ansible/terminal_plugins
```

#### 7. Deploy the Testbed Topology

```bash
cd /data/code/sonic-mgmt/ansible
echo "abc" > password.txt   # Ansible needs a non-empty password file
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos add-topo vms-kvm-t0 password.txt -vv
```

#### 8. Deploy Minigraph (Push Configuration to DUT)

```bash
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos deploy-mg vms-kvm-t0 veos_vtb password.txt -vv
```

#### 9. Teardown (Optional)

To remove the testbed topology when no longer needed:

```bash
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos remove-topo vms-kvm-t0 password.txt -vv
```

The testbed can be kept running for iterative test development and debugging.

## Testing

### Running Tests

Tests are run from the `tests/` directory **inside the sonic-mgmt container**.

```bash
cd /data/code/sonic-mgmt/tests

# Run a specific test against the VS testbed
pytest bgp/test_bgp_fact.py \
    --inventory ../ansible/veos_vtb \
    --host-pattern all \
    --testbed_file vtestbed.yaml \
    --testbed vms-kvm-t0 \
    --log-cli-level debug \
    --showlocals \
    --assert plain \
    --show-capture no \
    -rav

# Speed up testing by skipping sanity checks and disabling the log analyzer
pytest bgp/test_bgp_fact.py \
    --inventory ../ansible/veos_vtb \
    --host-pattern all \
    --testbed_file vtestbed.yaml \
    --testbed vms-kvm-t0 \
    --log-cli-level debug \
    --showlocals \
    --assert plain \
    --show-capture no \
    -rav \
    --skip_sanity \
    --disable_loganalyzer
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

### PR Description Template

When creating a PR, always use `.github/PULL_REQUEST_TEMPLATE.md` as the body. Fill in every section; do not omit or reorder them:

```
### Description of PR
Summary:
Fixes # (issue)

### Type of change
- [ ] Bug fix
- [ ] Testbed and Framework(new/improvement)
- [ ] New Test case
    - [ ] Skipped for non-supported platforms
- [ ] Test case improvement

### Back port request
- [ ] 202205
- [ ] 202305
- [ ] 202311
- [ ] 202405
- [ ] 202411
- [ ] 202505
- [ ] 202511

### Approach
#### What is the motivation for this PR?

#### How did you do it?

#### How did you verify/test it?

#### Any platform specific information?

#### Supported testbed topology if it's a new test case?

### Documentation
```

Mark the appropriate `[ ]` checkbox(es) with `[x]` based on the change type and target branches.

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
