# CsonicHost: Test Framework Access to cSONiC Neighbors

This document describes how to use `CsonicHost` to interact with cSONiC neighbor containers from sonic-mgmt tests.

## Overview

`CsonicHost` provides test access to cSONiC (docker-sonic-vs) neighbor containers via `docker exec`, similar to how `EosHost` provides access to cEOS neighbors via eAPI/SSH. No SSH daemon, admin user, or management IP is needed inside the containers.

## Usage

### Running Tests with cSONiC Neighbors

Pass `--neighbor_type csonic` when running tests:

```bash
cd /data/sonic-mgmt/tests
pytest bgp/test_bgp_fact.py \
  --neighbor_type csonic \
  --inventory ../ansible/veos_vtb \
  --host-pattern vlab-01 \
  --module-path ../ansible/library \
  --testbed vms-kvm-t0-csonic \
  --testbed_file ../ansible/vtestbed.yaml
```

### nbrhosts Fixture

When `--neighbor_type csonic` is passed, the `nbrhosts` fixture returns `CsonicHost` instances instead of `EosHost`:

```python
def test_example(nbrhosts):
    for name, host in nbrhosts.items():
        # host is a CsonicHost instance
        result = host.command("show ip bgp summary")
        print(result["stdout"])
```

## CsonicHost API

Located at `tests/common/devices/csonic.py`.

### Container Naming

Containers follow the pattern `csonic_{group-name}_{vm_name}`:
- `csonic_vms6-1_VM0100` → ARISTA01T1
- `csonic_vms6-1_VM0101` → ARISTA02T1

### Methods

| Method | Description |
|---|---|
| `command(cmd)` | Run a command inside the container via `docker exec` |
| `shell(cmd)` | Run a shell command (same as `command` but with shell=True) |
| `shutdown(interface)` | Shut down an interface (`ip link set <intf> down`) |
| `no_shutdown(interface)` | Bring up an interface (`ip link set <intf> up`) |
| `get_route(prefix)` | Get routing table entry via `vtysh -c "show ip route <prefix>"` |
| `get_port_channel_status(pc)` | Get PortChannel status via `teamdctl <pc> state` |
| `config(cmd)` | Apply FRR config via `vtysh -c "configure terminal" -c "<cmd>"` |

### Implementation

CsonicHost uses `subprocess.run()` to execute `docker exec` commands on the host machine. This avoids the need for:
- SSH daemon inside the container
- Admin user account
- Management IP assignment
- SSH key distribution

The trade-off is that tests must run on the same host as the cSONiC containers (or have Docker socket access).
