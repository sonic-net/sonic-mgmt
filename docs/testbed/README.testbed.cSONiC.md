# cSONiC Testbed: Using docker-sonic-vs as Neighbor Devices

This document describes how to deploy and manage a SONiC testbed using **cSONiC** (docker-sonic-vs) containers as neighbor devices instead of cEOS or vEOS, enabling a SONiC-to-SONiC test environment.

## Overview

cSONiC neighbors run the same SONiC software stack as the DUT, configured via CONFIG_DB and bgpcfgd — matching the production SONiC configuration path. This provides a more realistic test environment compared to Arista cEOS neighbors.

### Key Differences from cEOS

| Aspect | cEOS | cSONiC |
|---|---|---|
| Image | `ceosimage:X.Y.Z` (Arista) | `docker-sonic-vs:latest` (built from sonic-buildimage) |
| Import | `docker import` | `docker load` from `.gz` |
| Flag | `-k ceos` (default) | `-k csonic` |
| Config | EOS CLI via eAPI | CONFIG_DB + bgpcfgd → FRR (same as production SONiC) |
| Topology | Standard `topo_t0.yml` | Same standard `topo_t0.yml` (shared with cEOS) |
| Network plugin | `ceos_network.py` | `csonic_network.py` |
| Containers per VM | 1 cEOS | 2 (net base + csonic) |
| Test access | SSH via EosHost | `docker exec` via CsonicHost (see [CsonicHost PR](https://github.com/sonic-net/sonic-mgmt/pull/22748)) |

## Prerequisites

### Build or Download docker-sonic-vs Image

The cSONiC testbed uses the `docker-sonic-vs` image as neighbor devices.

> **IMPORTANT — the stock/upstream `docker-sonic-vs` image is NOT sufficient.**
> A cSONiC neighbor must establish BGP and advertise LLDP exactly like a real
> SONiC device. This requires a `docker-sonic-vs` image that composes the
> control-plane features the neighbor depends on — at minimum **`bgpcfgd`**
> (from `docker-fpm-frr`, so BGP_NEIGHBOR entries in CONFIG_DB are translated
> into FRR config) and **`lldpd`/`lldpmgrd`** (from `docker-lldp`). The default
> upstream `docker-sonic-vs` (a swss+syncd test image) ships **without**
> `bgpcfgd` and `lldpd`, and its `start.sh` does not load `/var/sonic/config_db.json`
> or auto-start services under supervisord — so neighbors come up with no BGP
> sessions and no LLDP. Symptoms of using the wrong image:
> `sonic-db-cli CONFIG_DB PING` returns *"Connection refused / Cannot assign
> requested address"*, `start.sh` shows `FATAL Exited too quickly`, and
> `vtysh -c "show running-config"` has no `router bgp` stanza.
>
> Build the neighbor image from a `docker-sonic-vs` that includes the cSONiC
> feature composition (`_INCLUDE_DOCKER` for `docker-fpm-frr`, `docker-lldp`,
> `docker-teamd`, etc.) plus the `start.sh`/`supervisord` `dependent_startup`
> changes. See the `sonic-csonic-testbed` skill ("`_INCLUDE_DOCKER` — Feature
> Composition" and "Known Issues") for the full conversion checklist.

**Option 1: Download from Azure Pipelines**
1. Go to [SONiC Azure Pipelines](https://sonic-build.azurewebsites.net/ui/sonic/pipelines)
2. Find a recent successful build of `Azure.sonic-buildimage.official.vs`
3. Download the `sonic-vs.tar.gz` artifact

**Option 2: Build locally**
```bash
cd sonic-buildimage
make target/docker-sonic-vs.gz
```

**Load the image:**
```bash
gunzip -c docker-sonic-vs.gz | docker load
docker images | grep docker-sonic-vs
```

The image should appear as `docker-sonic-vs:latest`.

### PortChannels / LACP on the host kernel

cSONiC neighbors are **containers that share the host kernel**, so neighbor
PortChannels are realized by the *host* kernel — not by a private neighbor
kernel as with vSONiC (a KVM VM) or cEOS (Arista's own LAG implementation).

#### Automatic native-team selection with userspace-OVS fallback

The default `auto` backend tries to use stock SONiC teamd. During `add-topo`,
sonic-mgmt:

1. Loads `team` and `team_mode_loadbalance` when they are already installed.
2. If either module is missing, installs the exact signed
   `linux-modules-extra-$(uname -r)` package when the distro publishes it.
3. If that exact package is unavailable, builds only the missing modules from
   the exact matching distro kernel source and verifies their vermagic and the
   active module-signature policy before installing them.
4. Creates and removes a disposable team/loadbalance device using teamd from
   the selected cSONiC image.
5. Selects the existing userspace-OVS backend if any team-module or probe step
   fails. Converged topologies still require Linux `vrf`; failure to provision
   that independent prerequisite is fatal rather than an OVS fallback.

The requested mode can be forced when diagnosing either path:

```bash
export SONIC_MGMT_CSONIC_LAG_BACKEND=auto           # default
export SONIC_MGMT_CSONIC_LAG_BACKEND=teamd          # require native teamd
export SONIC_MGMT_CSONIC_LAG_BACKEND=userspace_ovs  # force fallback
```

When userspace OVS is selected, sonic-mgmt derives a local image from
`csonic_image` with the OVS userspace packages. For each neighbor, it reads the
`PORTCHANNEL`, `PORTCHANNEL_MEMBER`, and `PORTCHANNEL_INTERFACE` tables, stops
the conflicting teamd processes, and recreates the PortChannels as OVS LACP
bonds. The host-side virtual-wire bridges need no extra flows: the flows
installed when the topology is bound already carry LACP between the DUT and
the neighbor and copy it to the PTF. `deploy-mg` only configures the DUT; LACP
converges once the DUT PortChannels exist. To reapply backend selection, rerun
`add-topo`.

SONiC normally uses `teamd`/libteam, which needs the kernel **`team`** module.
The cSONiC image also retains an image-level bonding fallback for deployments
that bypass sonic-mgmt's selector. Normal `auto` deployment selects userspace
OVS before neighbor creation when native-team provisioning or its probe fails,
so bonding is not the primary sonic-mgmt fallback.

#### Image-level bonding (802.3ad) fallback

When `CSONIC_MODE` is active and the `team` driver cannot be loaded, the image's
`start.sh` builds each CONFIG_DB PortChannel with the `bonding` driver instead
of teamd:

1. `teammgrd`/`teamsyncd` are stopped (they cannot work without `team`).
2. For each `PORTCHANNEL|*` it creates a bond: `ip link add <pc> type bond mode
   802.3ad miimon 100 lacp_rate fast`.
3. Each `PORTCHANNEL_MEMBER|<pc>|<port>` is **deleted from CONFIG_DB** so
   `orchagent`/`saivs` release the member port's carrier (otherwise the port is
   held `DOWN` while the broken teamd LAG stays pending), then the port is
   enslaved to the bond.
4. `PORTCHANNEL` and `PORTCHANNEL_INTERFACE` are **kept** so `bgpcfgd` still sees
   the local address and emits `router bgp`. The bond's IPs come from
   `PORTCHANNEL_INTERFACE`.

Linux bonding 802.3ad speaks standard LACP and bundles with the DUT's `teamd`
LACP. It remains an image-level last resort; **the DUT is unchanged** and sees a
normal `LACP(A)(Up)` PortChannel.

> **Verifying the fallback:** on a neighbor, `ip -d link show PortChannel1`
> reports `bond mode 802.3ad`, `cat /proc/net/bonding/PortChannel1` shows MII
> status `up` with a non-zero partner MAC, and the syslog/`start.sh` log notes
> that the bonding fallback was used. On the DUT, `show interfaces portchannel`
> shows `LACP(A)(Up)` with the member `(S)` (Selected), and BGP reaches
> `Established`.

#### Module provisioning diagnostics

Manual source builds are not required for normal sonic-mgmt deployment. The
`auto` selector reports whether it used an installed module, the exact distro
package, an exact-source build, or userspace OVS. Locally built modules are
stored under `/lib/modules/$(uname -r)/updates/sonic-csonic`; they are tied to
that exact kernel and will be reprovisioned after a kernel change. Source or
vermagic mismatch and module-signature enforcement cause a safe OVS fallback
rather than installing an incompatible module.

Use `SONIC_MGMT_CSONIC_LAG_BACKEND=teamd` only when a failed native-team gate
should abort deployment for diagnosis instead of selecting userspace OVS.

Kernel packages, exact-source build dependencies, successfully installed local
modules, and loaded drivers are intentionally host-persistent. `remove-topo`
removes the per-topology backend selection but does not remove shared host
prerequisites that another cSONiC topology may use. Run `auto` only on dedicated
test VM hosts whose package/module state is managed for sonic-mgmt workloads.
The helper does roll back newly copied `.ko` files if loading them fails.

A backend selection is also persistent for the life of a topology. If a later
`add-topo` run would select a different backend, it stops and requires a clean
`remove-topo` followed by `add-topo`; live containers are never switched in
place.

> **Symptom of a missing `team` module:** `add-topo`/`deploy-mg` succeed, FRR
> comes up and `bgpcfgd` generates `router bgp`, but BGP stays `Active`/`Idle`
> and the DUT's `show interfaces portchannel` shows members `Dw`/`D`
> (deselected). The neighbor's `teammgrd` logs
> `Failed to create team device ... Operation not supported`, the
> `PortChannel1` netdev never appears, and the member port (`Ethernet1`) has no
> carrier. The BGP/LLDP control plane itself is fine — only LAG bundling is
> blocked.

## Testbed Configuration

### vtestbed.yaml

Define a cSONiC testbed entry using standard `topo: t0`:

```yaml
- conf-name: vms-kvm-t0-csonic
  group-name: vms6-1
  topo: t0
  ptf_image_name: docker-ptf
  ptf: ptf_vms6-1
  ptf_ip: 10.250.0.102/24
  ptf_ipv6:
  server: server_1
  vm_base: VM0100
  dut:
    - vlab-01
  comment: cSONiC T0 testbed
```

**Important**: Use standard `topo: t0` (not a custom cSONiC-specific topology). The standard `topo_t0.yml` includes PortChannel/LACP definitions and uses ARISTA names (e.g., ARISTA01T1). The cSONiC ansible roles handle the VM-to-ARISTA name mapping automatically.

### Credential Files

These files need local edits (do NOT commit):

- `group_vars/vm_host/creds.yml`: Set `ansible_user` and `vm_host_user` to your host username
- `group_vars/sonic/variables`: Set `ansible_altpassword` to match your DUT password
- `veos_vtb`: Set `ansible_altpassword`, `ansible_user`, and `vm_host_user`

## Deploying a T0 Topology

All commands must be run from within the `sonic-mgmt` container:

```bash
docker exec -it sonic-mgmt bash
cd /data/sonic-mgmt/ansible

# 1. Add topology — creates cSONiC containers, OVS bridges, network wiring
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k csonic add-topo vms-kvm-t0-csonic password.txt

# 2. Deploy minigraph — configures DUT with BGP, PortChannels, VLANs
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k csonic deploy-mg vms-kvm-t0-csonic veos_vtb password.txt

# 3. Verify
ssh admin@vlab-01 "show ip bgp summary"
ssh admin@vlab-01 "show interfaces portchannel"
```

### Removing Topology

```bash
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k csonic remove-topo vms-kvm-t0-csonic password.txt
```

**Note**: Always use `-k csonic` flag. The `vm_type` field in vtestbed.yaml is NOT read by `testbed-cli.sh` — only the `-k` flag determines the VM type.

## Architecture

### Container Layout

```
Host Machine (KVM + Docker)
├── vlab-01 (KVM VM) — DUT running SONiC
├── csonic_vms6-1_VM0100 (Docker) — cSONiC neighbor ARISTA01T1
├── csonic_vms6-1_VM0101 (Docker) — cSONiC neighbor ARISTA02T1
├── csonic_vms6-1_VM0102 (Docker) — cSONiC neighbor ARISTA03T1
├── csonic_vms6-1_VM0103 (Docker) — cSONiC neighbor ARISTA04T1
├── net_vms6-1_VM01XX (Docker) — net base containers (network namespaces)
├── ptf_vms6-1 (Docker) — PTF test traffic generator + exabgp
├── br1 (Linux bridge) — management network 10.250.0.0/24
├── br-b-vms6-1 (Linux bridge) — backplane 10.10.246.0/24
└── br-VM01XX-N (OVS bridges) — per-VM front-panel links
```

### Network Interfaces (per cSONiC neighbor)

Each cSONiC container has:
- **eth0**: Management (10.250.0.0/24 via br1)
- **eth1**: Front-panel → mapped to Ethernet1 inside container (DUT-facing, PortChannel member)
- **eth2**: Backplane → mapped to Ethernet2 inside container (exabgp-facing)

### PortChannel / LACP

cSONiC neighbors support LACP PortChannels via CONFIG_DB:
- **DUT side**: PortChannel101-104 (from minigraph)
- **Neighbor side**: PortChannel1 per neighbor (Ethernet1 as member)
- `teammgrd` creates PortChannels automatically from CONFIG_DB PORTCHANNEL/PORTCHANNEL_MEMBER entries
- BGP peers over PortChannel interfaces (IPs on PORTCHANNEL_INTERFACE)

## Neighbor Configuration via CONFIG_DB

cSONiC neighbors are configured using CONFIG_DB + bgpcfgd, matching the production SONiC configuration path:

1. **Template**: `csonic_config.yml` selects the CONFIG_DB template with a
   first-found fallback chain so any topology/role is supported:
   `configdb-{topo}-{swrole}.j2` → `configdb-{swrole}.j2` →
   `configdb-csonic.j2`. The generic `configdb-csonic.j2` is role-aware (it
   maps `props.swrole` → DEVICE_METADATA `type`: `leaf`→`LeafRouter`,
   `spine`→`SpineRouter`, `tor`→`ToRRouter`), so T1/T2/dualtor neighbor roles
   render without a bespoke per-role file. Add a `configdb-{topo}-{swrole}.j2`
   only when a role needs config that diverges from the generic template.
2. **Contents**: PORT, DEVICE_METADATA, LOOPBACK_INTERFACE, PORTCHANNEL, PORTCHANNEL_MEMBER, PORTCHANNEL_INTERFACE, INTERFACE, BGP_NEIGHBOR
3. **Deploy flow**:
   - `csonic_config.yml` renders the template and writes to `/var/sonic/config_db.json` (bind-mounted volume)
   - Container `start.sh` copies `/var/sonic/config_db.json` → `/etc/sonic/config_db.json` at boot
   - `bgpcfgd` reads BGP_NEIGHBOR from CONFIG_DB and generates FRR configuration
   - `teammgrd` creates PortChannels from PORTCHANNEL entries
   - `intfmgrd` assigns interface IPs from INTERFACE/PORTCHANNEL_INTERFACE entries

**hwsku**: SONiC-VM (Ethernet1 starts at lanes 25-28)

## Running Tests

Tests can be run with standard sonic-mgmt pytest commands. For neighbor access via the test framework (e.g., `nbrhosts` fixture), see the CsonicHost PR ([#22748](https://github.com/sonic-net/sonic-mgmt/pull/22748)) which adds `--neighbor_type csonic` support.

## Verification Checklist

After `add-topo` + `deploy-mg`:

```bash
# DUT BGP sessions — expect 4 Established
ssh admin@vlab-01 "show ip bgp summary"
ssh admin@vlab-01 "show ipv6 bgp summary"

# DUT PortChannels — expect 4x LACP(A)(Up)
ssh admin@vlab-01 "show interfaces portchannel"

# Neighbor BGP (from host)
for vm in VM0100 VM0101 VM0102 VM0103; do
  docker exec csonic_vms6-1_$vm vtysh -c "show ip bgp summary"
done

# Neighbor PortChannel status
for vm in VM0100 VM0101 VM0102 VM0103; do
  docker exec csonic_vms6-1_$vm teamdctl PortChannel1 state
done

# CPU check — expect <5% per container
docker stats --no-stream --format "{{.Name}}: {{.CPUPerc}}" \
  csonic_vms6-1_VM0100 csonic_vms6-1_VM0101 \
  csonic_vms6-1_VM0102 csonic_vms6-1_VM0103
```

## Implementation Details

### Key Files

| File | Purpose |
|---|---|
| `ansible/roles/vm_set/tasks/add_csonic_list.yml` | Creates cSONiC containers, builds VM→ARISTA name mapping |
| `ansible/roles/vm_set/tasks/add_csonic.yml` | Per-VM container creation and network wiring |
| `ansible/roles/vm_set/library/csonic_network.py` | Network plugin: creates eth0/eth1/eth2 interfaces |
| `ansible/roles/sonic/tasks/csonic.yml` | Neighbor configuration (link up, config load) |
| `ansible/roles/sonic/templates/configdb-t0-leaf.j2` | CONFIG_DB template for cSONiC neighbors |
| `ansible/roles/vm_set/tasks/remove_csonic_list.yml` | Tear down cSONiC containers |
| `tests/common/devices/csonic.py` | CsonicHost class for test framework |
| `tests/conftest.py` | `--neighbor_type csonic` integration |

### ARISTA→VM Name Mapping

Standard `topo_t0.yml` uses ARISTA names (ARISTA01T1, ARISTA02T1, etc.) but the inventory uses VM names (VM0100, VM0101, etc.). The `add_csonic_list.yml` builds a `vm_inv_to_topo` mapping dict using `topology.VMs` and `vm_offset` to translate between them. This allows cSONiC to share the same topology file as cEOS.

### docker-sonic-vs Requirements

The docker-sonic-vs image must include:
- **bgpcfgd**: For CONFIG_DB → FRR configuration (added via sonic-buildimage PR)
- **lldpd**: For LLDP neighbor discovery in tests
- **constants.yml and FRR templates**: Baked into the image (not mounted from host)
- **start.sh**: Must copy `/var/sonic/config_db.json` → `/etc/sonic/` and set `kernel_version` at runtime

See [sonic-buildimage PR #25764](https://github.com/sonic-net/sonic-buildimage/pull/25764) for bgpcfgd addition.
