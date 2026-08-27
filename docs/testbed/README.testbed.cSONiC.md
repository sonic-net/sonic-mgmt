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
SONiC normally uses `teamd`/libteam, which needs the kernel **`team`** module.
The cSONiC image handles both cases automatically:

- **`team` module present on the host** → the neighbor uses stock `teamd`,
  exactly like production SONiC. Nothing extra to do.
- **`team` module absent** (e.g. some cloud kernels such as `*-azure` that ship
  without it, or where Secure Boot blocks loading an out-of-tree `team`) → the
  image **automatically falls back to the in-tree `bonding` driver in 802.3ad
  (LACP) mode**. No host changes, no reboot, no module signing are required.

#### Automatic bonding (802.3ad) fallback — recommended, zero host setup

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
LACP. This is the default, validated path on hosts without `team`; **the DUT is
unchanged** and sees a normal `LACP(A)(Up)` PortChannel. No further action is
needed — just run `add-topo` + `deploy-mg`.

> **Verifying the fallback:** on a neighbor, `ip -d link show PortChannel1`
> reports `bond mode 802.3ad`, `cat /proc/net/bonding/PortChannel1` shows MII
> status `up` with a non-zero partner MAC, and the syslog/`start.sh` log notes
> that the bonding fallback was used. On the DUT, `show interfaces portchannel`
> shows `LACP(A)(Up)` with the member `(S)` (Selected), and BGP reaches
> `Established`.

#### Optional: load the kernel `team` module (use teamd instead of bonding)

If you prefer the neighbor to run stock `teamd` (e.g. to exercise teamd-specific
behavior), load the `team` module on every VM host before deploying. This is
**not required** — the bonding fallback above covers PortChannel/LACP topologies
(T0/T1/T2) without it.

```bash
lsmod | grep team           # already loaded?
sudo modprobe team          # load it
```

If `modprobe team` fails:
- **`Module team not found`** — the running kernel doesn't ship the module.
  Install the matching extra-modules package (e.g.
  `linux-modules-extra-$(uname -r)`), or use a kernel/distro that includes it.
  Some cloud kernels (notably `*-azure`) omit `team` entirely. In that case
  build it out-of-tree against the installed kernel headers (the team driver is
  stable across point releases, so the mainline source for the matching
  major.minor works):

  > **Important:**
  > - Set `B=...linux/v<MAJOR>.<MINOR>` to **your running kernel's
  >   major.minor** (`uname -r`), e.g. a `6.11.x` kernel needs `v6.11`. A
  >   mismatched source tree will fail to build or load.
  > - This copies headers into the distro-managed `linux-headers-$(uname -r)`
  >   tree and drops modules under `/lib/modules/$(uname -r)`. These do **not**
  >   survive a kernel upgrade — after the host moves to a new kernel you must
  >   repeat the build (and the signing step below) for the new `uname -r`.

  ```bash
  K=$(uname -r); mkdir -p /tmp/teambuild && cd /tmp/teambuild
  B=https://raw.githubusercontent.com/torvalds/linux/v6.8   # MUST match your kernel's major.minor (uname -r)
  for f in team team_mode_loadbalance team_mode_activebackup \
           team_mode_roundrobin team_mode_broadcast team_mode_random; do
    curl -sSL -o $f.c "$B/drivers/net/team/$f.c"
  done
  # The team uapi/internal headers are not in the -headers package; fetch them:
  curl -sSL -o if_team.h      "$B/include/linux/if_team.h"
  curl -sSL -o if_team_uapi.h "$B/include/uapi/linux/if_team.h"
  sudo cp if_team.h      /usr/src/linux-headers-$K/include/linux/if_team.h
  sudo cp if_team_uapi.h /usr/src/linux-headers-$K/include/uapi/linux/if_team.h
  printf 'obj-m += team.o team_mode_loadbalance.o team_mode_activebackup.o team_mode_roundrobin.o team_mode_broadcast.o team_mode_random.o\n' > Makefile
  make -C /lib/modules/$K/build M=$PWD modules
  sudo cp *.ko /lib/modules/$K/kernel/drivers/net/team/   # mkdir -p first if needed
  sudo depmod -a $K
  ```

- **`Key was rejected by service`** — **Secure Boot** is enabled and the module
  is unsigned (you'll see this for any locally built/out-of-tree module; check
  with `mokutil --sb-state` and `cat /sys/module/module/parameters/sig_enforce`).
  You must sign the module with a key the firmware trusts, then **reboot once**
  to enroll that key (there is no way to load an unsigned module under Secure
  Boot without a reboot):

  ```bash
  K=$(uname -r); cd /tmp/teambuild
  # 1. Generate a Machine Owner Key (MOK)
  openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER \
    -out MOK.der -nodes -days 3650 -subj "/CN=csonic-team-module-signing/"
  # 2. Sign every module
  SF=/usr/src/linux-headers-$K/scripts/sign-file
  for m in team team_mode_*; do sudo $SF sha256 MOK.priv MOK.der \
    /lib/modules/$K/kernel/drivers/net/team/${m%.ko}.ko; done
  # 3. Stage the key for enrollment (choose a one-time password)
  sudo mokutil --import MOK.der          # prompts for a password
  # 4. Reboot. At boot, shim's blue "MOK Manager" screen appears:
  #    select "Enroll MOK" -> "Continue" -> enter the password above -> reboot.
  # 5. After reboot:
  sudo modprobe team && lsmod | grep team
  ```

  Alternatively, disable Secure Boot entirely (Gen2/Azure VM setting or firmware
  menu) — also a reboot. Once `team` loads, re-run `deploy-mg` so the neighbor
  `teammgrd` can create the PortChannels.

> **Note:** loading `team` is only needed if you specifically want `teamd` on the
> neighbor. If the module is absent the image automatically uses the bonding
> 802.3ad fallback (see above), so PortChannel topologies still work with no host
> changes. The symptoms below describe an **older image without the fallback**;
> the current image instead logs that it switched to bonding and the PortChannel
> bundles normally.

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
