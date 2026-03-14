# Virtual NUT Testbed (vnut-topo)

## 1. Overview

The virtual NUT testbed (`vnut-topo`) allows developers to run sonic-mgmt NUT tests locally on a single host without any physical switches or traffic generators. It provides a fully virtualized alternative to the hardware-based NUT testbed described in [README.testbed.NUT.md](README.testbed.NUT.md).

Key characteristics:

- Uses `docker-sonic-vs` containers as DUTs (Device Under Test) and `debian:bookworm` containers as traffic generators
- Reuses existing testbed YAML/CSV formats, topology definitions (`nut-*`), and `testbed-cli.sh` commands
- All containers share a management bridge network (`br-mgmt`) for SSH and API access
- Enables rapid local development and testing without lab hardware

## 2. Architecture

The virtual NUT testbed creates a containerized network topology on a single host machine. The example below shows a 2-tier topology (`nut-2tiers`) with 3 DUTs and 1 traffic generator:

```
┌─────────────────────────────────────────────────────┐
│                    Host Machine                      │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │vnut-t0-01│  │vnut-t0-02│  │vnut-t1-01│  (DUTs)  │
│  │sonic-vs  │  │sonic-vs  │  │sonic-vs  │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       │veth         │veth         │veth              │
│  ┌────┴─────────────┴─────────────┴─────┐           │
│  │           vnut-tg-01 (TG)            │           │
│  │           debian:bookworm            │           │
│  └──────────────────────────────────────┘           │
│                                                      │
│  ┌──────────────────────────────────────┐           │
│  │    br-mgmt (10.99.0.0/24)           │           │
│  │    Management Network                │           │
│  └──────────────────────────────────────┘           │
└─────────────────────────────────────────────────────┘
```

### Network Planes

- **Management network**: A Linux bridge (`br-mgmt`) on the `10.99.0.0/24` subnet connects all containers for SSH and API access. NAT and IP forwarding are configured to give containers internet connectivity.
- **Data plane**: veth pairs connect DUT ports to TG ports (and DUT-to-DUT links), managed by the custom Ansible module `vnut_network.py`. Each veth pair directly links an interface in one container's network namespace to an interface in another.

### Topology: nut-2tiers

The `nut-2tiers` topology consists of:
- 2× T0 DUTs (`vnut-t0-01`, `vnut-t0-02`)
- 1× T1 DUT (`vnut-t1-01`)
- 1× Traffic Generator (`vnut-tg-01`)

Links:
| Source | Source Port | Destination | Destination Port |
|--------|------------|-------------|-----------------|
| vnut-t0-01 | Ethernet0 | vnut-tg-01 | Ethernet0 |
| vnut-t0-01 | Ethernet4 | vnut-t1-01 | Ethernet0 |
| vnut-t0-02 | Ethernet0 | vnut-tg-01 | Ethernet4 |
| vnut-t0-02 | Ethernet4 | vnut-t1-01 | Ethernet4 |

## 3. Prerequisites

- **Docker** installed on the host
- **`docker-sonic-vs:latest`** image available (pull or build from [sonic-buildimage](https://github.com/sonic-net/sonic-buildimage))
- **sonic-mgmt Docker container** (recommended) launched with the required privileges:
  ```bash
  docker run -it --pid host --network host --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    <sonic-mgmt-image>
  ```
  The `--pid host` and `--network host` flags allow the sonic-mgmt container to manage sibling Docker containers and host networking. The Docker socket mount enables container orchestration.

## 4. Testbed Definition

The virtual NUT testbed reuses the same YAML and CSV formats as the hardware NUT testbed.

### Testbed YAML (`testbed.vnut.yaml`)

```yaml
- name: vnut-2tier-test
  comment: "Virtual NUT 2-tier testbed for local testing"
  inv_name: vnut-lab
  topo: nut-2tiers
  test_tags: []
  duts:
    - vnut-t0-01
    - vnut-t0-02
    - vnut-t1-01
  tgs:
    - vnut-tg-01
  tg_api_server: "10.99.0.20:443"
  auto_recover: 'True'
```

Fields follow the same schema as standard NUT testbed definitions. The `inv_name` points to the `vnut-lab` inventory directory.

### Inventory (`vnut-lab/`)

The inventory directory contains an Ansible hosts file and device/link CSV files.

#### `vnut-lab/hosts`

```yaml
all:
  children:
    lab:
      vars:
        mgmt_subnet_mask_length: 24
        ansible_python_interpreter: /usr/bin/python3
        ansible_user: admin
        ansible_password: YourPaSsWoRd
        ansible_become_password: YourPaSsWoRd
      children:
        sonic:
          hosts:
            vnut-t0-01:
              ansible_host: 10.99.0.10
            vnut-t0-02:
              ansible_host: 10.99.0.11
            vnut-t1-01:
              ansible_host: 10.99.0.12
        ptf:
          hosts:
            vnut-tg-01:
              ansible_host: 10.99.0.20
```

#### `vnut-lab/files/sonic_lab_devices.csv`

```csv
Hostname,ManagementIp,HwSku,Type,Protocol,Os,AuthType
vnut-t0-01,10.99.0.10/24,Force10-S6000,DevSonic,,sonic,
vnut-t0-02,10.99.0.11/24,Force10-S6000,DevSonic,,sonic,
vnut-t1-01,10.99.0.12/24,Force10-S6000,DevSonic,,sonic,
vnut-tg-01,10.99.0.20/24,IxiaChassis,DevIxiaChassis,,ixia,
```

#### `vnut-lab/files/sonic_lab_links.csv`

```csv
StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode,AutoNeg
vnut-t0-01,Ethernet0,vnut-tg-01,Ethernet0,10000,,,
vnut-t0-01,Ethernet4,vnut-t1-01,Ethernet0,10000,,,
vnut-t0-02,Ethernet0,vnut-tg-01,Ethernet4,10000,,,
vnut-t0-02,Ethernet4,vnut-t1-01,Ethernet4,10000,,,
```

## 5. Deployment

Deploy the virtual NUT testbed using `testbed-cli.sh`:

```bash
./testbed-cli.sh -t testbed.vnut.yaml add-vnut-topo <testbed-name> <inventory> <vault-password-file>
```

For example:

```bash
cd ansible
./testbed-cli.sh -t testbed.vnut.yaml add-vnut-topo vnut-2tier-test vnut-lab password.txt
```

### Deployment Steps

The `add-vnut-topo` action executes the following sequence:

1. **Read testbed definition** — Parse `testbed.vnut.yaml` to determine topology, DUTs, TGs, and links.
2. **Create management network** — Create the `br-mgmt` Linux bridge on the `10.99.0.0/24` subnet with NAT and IP forwarding rules.
3. **Launch containers** — Start `docker-sonic-vs` containers for each DUT and a `debian:bookworm` container for the TG. All containers are attached to `br-mgmt` with static IP addresses.
4. **Create veth links** — Use the `vnut_network.py` Ansible module to create veth pairs connecting container interfaces according to the link definitions in `sonic_lab_links.csv`.
5. **Start SONiC services** — Ensure supervisord and SONiC services are running inside each DUT container.
6. **Wait for readiness** — Poll each DUT for SSH availability and service readiness.
7. **Provision admin user** — Create the `admin` user with sudo privileges on each DUT for Ansible access.

## 6. Teardown

Remove the virtual NUT testbed:

```bash
./testbed-cli.sh -t testbed.vnut.yaml remove-vnut-topo <testbed-name> <inventory> <vault-password-file>
```

For example:

```bash
cd ansible
./testbed-cli.sh -t testbed.vnut.yaml remove-vnut-topo vnut-2tier-test vnut-lab password.txt
```

The teardown process cleans up all resources:

- Stops and removes all DUT and TG containers
- Deletes veth pairs between containers
- Removes the `br-mgmt` bridge
- Cleans up iptables NAT and forwarding rules

## 7. Running Tests

Once the testbed is deployed, run tests using `run_tests.sh`:

```bash
cd tests
bash run_tests.sh -f ../ansible/testbed.vnut.yaml -i ../ansible/vnut-lab \
  -n vnut-2tier-test -d all -t nut,any -m individual -a False -u -l debug \
  -e "--skip_sanity --disable_loganalyzer" -c <test_file>
```

Key parameters:
- `-n vnut-2tier-test` — testbed name from the YAML file
- `-d all` — run on all DUTs
- `-t nut,any` — topology tags (NUT topology, any sub-topology)
- `-e "--skip_sanity --disable_loganalyzer"` — extra pytest options (recommended for virtual testbeds)
- `-c <test_file>` — the test file or directory to run

## 8. Implementation Details

### vnut_network.py

A custom Ansible module that manages veth pair creation and deletion between container network namespaces.

- **Hash-based naming**: veth interfaces are named using `vm{md5[:8]}a` and `vm{md5[:8]}b` (where the MD5 hash is derived from the link endpoints) to avoid naming collisions.
- **IFNAMSIZ compliance**: Inside containers, interfaces use the `vl{idx}` naming pattern to stay within the Linux 15-character interface name limit.
- **Operations**: Supports `create` (create a veth pair and move endpoints into container namespaces), `delete` (remove a specific veth pair), and `cleanup` (remove all veth pairs for a testbed).

### Management Network

The deployment creates a `br-mgmt` Linux bridge with:
- Subnet `10.99.0.0/24` with the bridge at `10.99.0.1`
- iptables MASQUERADE rule for NAT (container internet access)
- IP forwarding enabled via `sysctl`

### Container Launch

- **DUT containers**: Run the `docker-sonic-vs` image with `--privileged` and `--network bridge` initially, then attach to `br-mgmt` with a static IP.
- **TG containers**: Run `debian:bookworm` with SSH server installed, attached to `br-mgmt` with a static IP.
- All containers run with `--restart unless-stopped` for resilience.

### Service Readiness

After container launch, the deployment:
1. Waits for SSH to become available on each container
2. Waits for supervisord to report all SONiC services as running
3. Provisions the `admin` user with password authentication and sudo access

## 9. Limitations and Future Work

- **Empty `build_version`**: The `docker-sonic-vs` image may report an empty `build_version` field. The test framework needs graceful handling of this case.
- **Single topology**: Currently supports the `nut-2tiers` topology. The design is extensible to other NUT topologies (e.g., single-tier, 3-tier).
- **Minimal TG**: The traffic generator container (`debian:bookworm`) does not run actual traffic generation software. It serves as a network endpoint for basic connectivity tests.
- **Future: deploy-cfg integration**: Integrate with the `deploy-cfg` testbed-cli action to deploy full BGP configuration on virtual DUTs, enabling end-to-end routing tests.
