# IPv6-Only Management Network Configuration for Virtual Testbed

This document explains how to use the `--ipv6-only-mgmt` flag to configure virtual testbeds with IPv6-only management networks.

## Overview

The `--ipv6-only-mgmt` flag allows you to configure a virtual DUT (Device Under Test) with IPv6-only management network settings, including:

- IPv6 management IP address (using an IPv6 primary or `ansible_hostv6` from inventory)
- IPv6 NTP servers
- IPv6 DNS servers
- IPv6 TACACS servers (using PTF container's IPv6 address)
- IPv6 syslog servers
- IPv6 SNMP servers
- IPv6 management routes

## Usage

### Basic Usage

To deploy a virtual testbed with IPv6-only management configuration:

**Generate Minigraph**

Generate minigraph for IPv6 only management address is only required for Virtual testbed.

```bash
./testbed-cli.sh [-t testbed-file] [-m inventory] gen-mg <testbed-name> <inventory> <vault-password-file> --ipv6-only-mgmt
```

**Deploy Minigraph**
```bash
./testbed-cli.sh deploy-mg <testbed-name> <inventory> <vault-password-file> --ipv6-only-mgmt
```

### Examples

1. **Deploy minigraph with IPv6-only management:**
   ```bash
   ./testbed-cli.sh deploy-mg vms-sn2700-t0 lab ~/.password --ipv6-only-mgmt
   ```

2. **Generate and deploy minigraph with IPv6-only management for virtual testbed:**
   ```bash
   # generate minigraph
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb gen-mg vms-kvm-t0 veos_vtb ~/.password --ipv6-only-mgmt
   # deploy minigraph
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-t0 veos_vtb ~/.password --ipv6-only-mgmt
   ```

3. **Test minigraph with IPv6-only management:**
   ```bash
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb test-mg vms-kvm-t0 veos_vtb ~/.password --ipv6-only-mgmt
   ```

## Prerequisites

### 1. Testbed Configuration

The testbed must have `ptf_ipv6` defined in the testbed.yaml file:

```yaml
- conf-name: vms-sn2700-t0
  group-name: vms1-3
  topo: t0
  ptf_image_name: docker-ptf
  ptf: ptf_vms1-3
  ptf_ip: 10.255.0.180/24
  ptf_ipv6: 2001:db8:1::10/64    # Required for IPv6-only management
  server: server_1
  vm_base: VM0100
  dut:
    - str-msn2700-01
  inv_name: lab
```

### 2. Inventory Configuration

`ansible_host` is the supplied primary management address, not an IPv4-only
field. The deployment inventory contract is:

| Supplied addresses | Inventory fields |
|---|---|
| IPv4 only | IPv4 in `ansible_host` |
| IPv6 only | IPv6 in `ansible_host` |
| IPv4 and IPv6 | IPv4 in `ansible_host`, IPv6 in `ansible_hostv6` |

If only `ansible_hostv6` is supplied, deployment fills the missing
`ansible_host` from that value in the first controller-side task, before connecting.
An explicitly supplied primary is never overwritten, and an IPv6 primary
does not cause a missing `ansible_hostv6` to be populated. This repair is
local to the playbook invocation; it does not rewrite the inventory file.

For example, a dual-stack inventory entry is:

```yaml
str-msn2700-01:
  ansible_host: 10.250.0.101
  ansible_hostv6: fc00:2::101
  mgmt_subnet_mask_length: 24
```

An IPv6-primary entry can instead supply `ansible_host: fc00:2::101` without
`ansible_hostv6`. An IPv6-only deployment requires an IPv6 address to be
supplied; it does not invent one when only IPv4 is provided.

These values describe the supplied configuration inputs, not the DUT's
current addresses or which endpoint happens to be reachable. SSH fallback
does not rewrite them. Only `--ipv6-only-mgmt` selects IPv6-only deployment;
an IPv6 primary or an IPv4 connection failure does not implicitly enable
that mode.

The normal multi-DUT play handles each selected ToR independently. For a
partial deployment, `dual_tor_facts` applies the same missing-primary fallback
when reading an unselected peer, without writing facts onto that peer. Its
output remains family-specific: optional IPv4 `ip` and IPv6 `ip_v6` fields.

### 3. IPv6 Configuration Files

IPv6 service configurations are defined in:
- `group_vars/lab/ipv6.yml` - For lab inventory
- `group_vars/sonic/ipv6.yml` - For lab inventory (depending on the inventory group)
- `group_vars/vm_host/ipv6.yml` - For vm_host inventory

## Virtual Testbed IPv6 Addressing Scheme

For virtual testbeds, we use the following IPv6 addressing:

| Network Purpose | IPv6 Prefix | Notes |
|----------------|-------------|-------|
| Management Network | `fc00:2::/64` | ULA prefix for DUT management |
| PTF Backplane | `fc0a::/64` | Defined in vm_host/main.yml |
| Local Server | `fc00:1::/64` | ULA for syslog, SNMP |
| Google DNS | `2001:4860:4860::/64` | Public DNS servers |

## Configuration Details

### IPv6 Service Addresses

When `--ipv6-only-mgmt` is used, the following services use IPv6:

| Service | IPv6 Address | Notes |
|---------|-------------|-------|
| NTP | `fec0::ffff:afa:2` | Local testbed NTP server (primary) |
| NTP | `2001:4860:4806::` | Google IPv6 NTP (fallback) |
| TACACS | PTF's `ptf_ipv6` | From testbed.yaml |
| Syslog | `fec0::1` | Testbed gateway |
| SNMP | `fec0::1` | Testbed gateway |

### Management IP Configuration

- An IPv6 primary is used directly; otherwise IPv6-only deployment uses `ansible_hostv6`
- IPv6-only deployment omits the IPv4 management interface and IPv4 management metadata
- Normal dual-stack deployment records both supplied management addresses in their matching metadata fields
- The IPv6 prefix length uses `mgmt_subnet_v6_mask_length`, defaulting to `/64`
- IPv6 management routes are configured for proper connectivity

### TACACS Integration

When using PTF TACACS servers (default behavior):
- IPv4 mode: Uses testbed's `ptf_ip`
- IPv6 mode: Uses testbed's `ptf_ipv6` (with CIDR notation stripped)

The TACACS server runs on the PTF container, which must have IPv6 connectivity to the DUT.

## Setting Up IPv6 on the PTF Container

Ensure the PTF container has IPv6 configured:

1. The `ptf_ipv6` address from testbed.yaml or vtestbed.yaml is assigned to the PTF container
2. The TACACS server on PTF must listen on the IPv6 address
3. Verify IPv6 connectivity between DUT and PTF

## Setting Up Local NTP Server

For IPv6-only management networks, external NTP servers may not be reachable. A local NTP server running on the testbed host provides reliable time synchronization.

### Deploying the NTP Server

The NTP server runs as a Docker container connected to the management bridge (br1):

```bash
cd ansible/
./setup-ntp-server.sh start
```

This will:
1. Build the Chrony NTP server Docker image
2. Create a macvlan network attached to br1
3. Start the container with both IPv4 and IPv6 addresses

### NTP Server Addresses

| Protocol | Address | Notes |
|----------|---------|-------|
| IPv4 | `10.250.0.2` | For IPv4 management networks |
| IPv6 | `fec0::ffff:afa:2` | For IPv6-only management networks |

### Managing the NTP Server

```bash
# Check status
./setup-ntp-server.sh status

# Stop the server
./setup-ntp-server.sh stop

# Restart the server
./setup-ntp-server.sh restart

# Test connectivity
./setup-ntp-server.sh test

# Full cleanup (remove container, network, and image)
./setup-ntp-server.sh clean
```

### Verifying NTP Synchronization

On the DUT, verify NTP is working:

```bash
# Check NTP status
show ntp

# Or using chronyc
chronyc sources
chronyc tracking
```

### Configuration Files

The local NTP server is configured as the primary NTP source in:
- `group_vars/sonic/ipv6.yml` - For DUTs
- `group_vars/lab/ipv6.yml` - For lab devices
- `group_vars/vm_host/ipv6.yml` - For VM hosts
- `host_vars/STR-ACS-VSERV-01.yml` - Server-specific config

## Troubleshooting

### Missing ptf_ipv6

**Error:** `IPv6-only management mode requested but ptf_ipv6 is not configured in testbed file`

**Solution:** Add `ptf_ipv6` to your testbed entry in testbed.yaml

### No supplied IPv6 address

**Error:** `IPv6-only deployment requested but no IPv6 management address is supplied for <dut>`

**Solution:** Supply an IPv6 `ansible_host` for an IPv6-primary inventory, or
add `ansible_hostv6` alongside the IPv4 primary. Do not change inventory
addresses merely because the DUT is temporarily unreachable over IPv4.

### DUT Not Reachable After IPv6 Transition

**Issue:** Playbook fails waiting for DUT after loading minigraph

**Solution:**
1. Verify IPv6 routing is configured on the management network
2. Check that the server/PTF can reach the DUT's IPv6 management address
3. Ensure the management switch/bridge supports IPv6

### IPv6 Services Not Working

**Issue:** NTP or other services fail after IPv6 transition

**Solution:**
1. Verify the IPv6 service addresses are reachable from the DUT
2. Check firewall rules allow IPv6 traffic
3. Ensure forced management routes include necessary IPv6 prefixes

### NTP Server Not Reachable

**Issue:** DUT cannot sync time with local NTP server

**Solution:**
1. Verify the NTP server is running:
   ```bash
   ./setup-ntp-server.sh status
   ```
2. Check network connectivity from DUT:
   ```bash
   # On DUT
   ping6 fec0::ffff:afa:2
   ```
3. Verify the macvlan network is attached to br1:
   ```bash
   docker network inspect sonic-mgmt-ntp-net
   ```
4. Check chrony configuration inside container:
   ```bash
   docker exec sonic-mgmt-ntp chronyc tracking
   ```

## Running Tests in IPv6-Only Management Mode

When running tests against a DUT configured with IPv6-only management, you must tell the test framework to use IPv6 addresses.

### Using run_tests.sh

Use the `-6` flag to enable IPv6-only management mode:

```bash
./run_tests.sh -6 -n vms-kvm-t0 -d vlab-01 -c bgp/test_bgp_fact.py -f vtestbed.yaml -i ../ansible/veos_vtb
```

### Using pytest directly

Use the `--ipv6_only_mgmt` option:

```bash
pytest --ipv6_only_mgmt --testbed vms-kvm-t0 --testbed_file vtestbed.yaml --inventory ../ansible/veos_vtb --host-pattern vlab-01 bgp/test_bgp_fact.py
```

### What the IPv6-only flag does

When enabled, the test framework will:
- Use `ansible_hostv6` as the DUT management IP instead of `ansible_host`
- Skip IPv4 management connectivity sanity checks
- Use `ping6` for management reachability tests

### Important notes

- The `--ipv6_only_mgmt` / `-6` flag only affects test execution, not deployment
- The DUT must already be configured with IPv6 management (via `deploy-mg --ipv6-only-mgmt`)
- This test-execution option still requires `ansible_hostv6` for all DUTs; accepting an IPv6 primary for deployment does not change the test runner's separate address-selection option

## Reverting to IPv4 Management

To switch back to IPv4 management, simply run `deploy-mg` without the `--ipv6-only-mgmt` flag:

```bash
./testbed-cli.sh deploy-mg vms-sn2700-t0 lab ~/.password
```

This regenerates normal management configuration from the supplied inventory.
When both IPv4 and IPv6 are supplied, it restores dual-stack management.
It cannot restore an IPv4 address that is not supplied in inventory.
