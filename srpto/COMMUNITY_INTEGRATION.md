# SRPTO — Community Framework Integration Guide

This document explains how SRPTO integrates with the **sonic-mgmt community**
pytest/ansible framework at `sonic-net/sonic-mgmt`.

---

## Files Added to sonic-mgmt

```
sonic-mgmt/
├── srpto/                              ← SRPTO core package
│   ├── __init__.py
│   ├── lock_manager/dut_lock.py        ← DUTPool (Eka acquire_duts port)
│   ├── resource_tagger/tagger.py       ← Resource requirement parser
│   ├── scheduler/engine.py             ← ParallelScheduler
│   ├── scheduler/conflict.py           ← Pre-flight conflict detection
│   ├── cli/srpto_run.py               ← CLI entry point
│   ├── tests/test_dut_lock.py         ← Unit tests (7/7 ✅)
│   └── docs/resource_map_example.yaml
│
├── tests/
│   ├── conftest_srpto.py              ← pytest plugin (srpto_duts fixture)
│   ├── common/helpers/
│   │   └── srpto_scheduler.py         ← SRPTOScheduler (community wrapper)
│   └── pytest.ini                     ← srpto_resources marker registered
│
├── run_srpto.sh                       ← Shell runner (replaces run_tests.sh loops)
└── srpto_resources.yaml               ← Default community resource map
```

---

## Quick Start

### Option 1 — Shell runner (simplest)

```bash
# Run BGP + ACL + SNMP in parallel on a 4-DUT topology
./run_srpto.sh \
    --testbed-file ansible/testbed.yaml \
    --testbed-name vms-kvm-t0 \
    --resource-map srpto_resources.yaml \
    tests/bgp/test_bgp_gr.py \
    tests/acl/test_acl.py \
    tests/snmp/test_snmp_walk.py
```

### Option 2 — pytest plugin

```bash
# Add to tests/conftest.py:
pytest_plugins = ['tests.conftest_srpto']

# Then run:
pytest tests/bgp/ tests/acl/ tests/snmp/ \
    --srpto-testbed-file ansible/testbed.yaml \
    --srpto-testbed-name vms-kvm-t0 \
    --srpto-resource-map srpto_resources.yaml \
    --srpto-run-parallel
```

### Option 3 — Inline marker (zero-config)

```python
# tests/bgp/test_bgp_gr.py
import pytest

@pytest.mark.srpto_resources(dut_count=2, min_topology=["D1D2:2"])
def test_bgp_gr(srpto_duts, duthosts, tbinfo):
    dut1_name, dut2_name = srpto_duts
    # SRPTO automatically allocated 2 DUTs with ≥2 links between them
    dut1 = duthosts[dut1_name]
    ...
```

### Option 4 — Python API (CI/CD integration)

```python
from tests.common.helpers.srpto_scheduler import SRPTOScheduler

scheduler = SRPTOScheduler(
    testbed_file="ansible/testbed.yaml",
    testbed_name="vms-kvm-t0",
    resource_map="srpto_resources.yaml",
)
results = scheduler.run_scripts_parallel([
    "tests/bgp/test_bgp_gr.py",
    "tests/acl/test_acl.py",
    "tests/snmp/test_snmp_walk.py",
])
```

---

## Resource Map (srpto_resources.yaml)

```yaml
test_bgp_gr.py:
  dut_count: 2
  min_topology: ["D1D2:2"]   # needs ≥2 links between DUT1 and DUT2

test_acl.py:
  dut_count: 1
  shared_resources: ["vlan:100"]   # serialized with other vlan:100 users

test_warm_reboot.py:
  dut_count: 1
  topology_exclusive: true    # no other tests run during reboot
```

**Auto-generate** from your existing scripts:
```bash
./run_srpto.sh --generate-map srpto_resources.yaml tests/**/*.py
```

---

## How It Works (Eka Execute Tab → Community)

| Eka Execute Tab | Community SRPTO | File |
|---|---|---|
| `acquire_duts()` pool lock | `DUTPool.acquire()` | `srpto/lock_manager/dut_lock.py` |
| `release_duts()` | `DUTPool.release()` | same |
| Topology canvas links | `testbed.yaml` topology | `srpto_scheduler.py` parser |
| WebSocket queue state | JSON stdout stream | `SRPTOScheduler._emit_status()` |
| Job-level conflict check | `ConflictDetector` | `srpto/scheduler/conflict.py` |
| `run_one_script()` thread | `_run_one_script()` | `srpto_scheduler.py` |

---

## Lock Tiers

| Tier | When | Effect |
|---|---|---|
| Device (default) | Every test | Other tests on same DUT wait |
| PTF exclusive | `ptf_required: true` | Serializes all PTF tests |
| Topology exclusive | `topology_exclusive: true` | Reboot/config-reload: all others wait |
| Shared resource | `shared_resources: [vlan:100]` | Serializes VLAN-conflicting tests |
