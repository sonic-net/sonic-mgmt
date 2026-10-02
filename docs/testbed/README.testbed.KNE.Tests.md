# Running sonic-mgmt Tests on KNE

This guide shows how to configure a KNE topology and run sonic-mgmt's existing tests against it, without changing the tests.

**Prerequisites:**

1. Complete the [one-time host setup for KNE](README.testbed.KNE.Setup.md).
2. Bring up a topology with [SONiC T0, T1, and T1-LAG Topologies on KNE](README.testbed.KNE.Topologies.md), through its management routes step, and confirm every SONiC node is reachable.

---

## Overview

The steps below map to sonic-mgmt's usual `testbed-cli.sh` workflow:

| Step | sonic-mgmt equivalent | When |
|---|---|---|
| [1. Set up the sonic-mgmt container](#1-set-up-the-sonic-mgmt-container) | `setup-container.sh` | Once per host |
| [3.1 Install SSH keys](#31-install-ssh-keys) | — | Each time a topology is created |
| [3.2 Configure the neighbors](#32-configure-the-neighbors) | The neighbor configuration part of `add-topo` | Each time a topology is created |
| [3.3 Deploy the minigraph to the DUT](#33-deploy-the-minigraph-to-the-dut) | `deploy-mg` | Each time a topology is created |
| [4. Run tests](#4-run-tests) | `run_tests.sh` / `pytest` | Any time |

### Testbed names

Each topology has its own testbed name, inventory, and DUT name, defined in the KNE testbed files (see [KNE testbed files](#kne-testbed-files)). The commands in this guide use these shell variables, so set them for the topology you're testing:

| Topology | `TOPO_ID` | `TESTBED` | `INVENTORY` | `DUT` |
|---|---|---|---|---|
| T0 | `100` | `kne-t0` | `kne_vtb` | `vlab-kne-01` |
| T1 | `101` | `kne-t1` | `kne_vtb_t1` | `vlab-kne-t1-01` |
| T1-LAG | `102` | `kne-t1-lag` | `kne_vtb_t1_lag` | `vlab-kne-t1lag-01` |

For example, for T0:

```bash
export TOPO_ID=100 TESTBED=kne-t0 INVENTORY=kne_vtb DUT=vlab-kne-01
```

> **Note:** the KNE testbed files currently describe each topology at its template's default `TOPO_ID`, so use the IDs in this table. Running topologies with other IDs needs testbed files generated for those IDs; see [Known Limitations](#known-limitations).

---

## 1. Set up the sonic-mgmt container

Tests run inside sonic-mgmt's standard `docker-sonic-mgmt` container, as on any sonic-mgmt testbed. This is done once per host.

1. Use the sonic-mgmt clone that contains the KNE files (`ansible/kne/` and the KNE testbed files). This guide assumes it's at `~/sonic-mgmt`.

2. Pull the container image:

   ```bash
   docker pull sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest
   ```

   The image is several gigabytes, so the first pull takes a few minutes.

3. Start the container with **host networking**, with the clone mounted at `/data/sonic-mgmt`:

   ```bash
   docker run -d --name sonic-mgmt --network host --privileged \
     -v ~/sonic-mgmt:/data/sonic-mgmt -w /data/sonic-mgmt \
     sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest \
     /bin/bash -c "while true; do sleep 3600; done"
   ```

   Host networking lets the container reach every node through the host routes that `setup_mgmt_routes.py` adds, so the container needs no routes of its own, and one container serves every topology on the host. The container runs outside the KNE cluster, so creating or deleting topologies doesn't affect it.

4. Confirm the container can reach the DUT and PTF:

   ```bash
   docker exec sonic-mgmt ping -c 3 172.31.$TOPO_ID.2
   docker exec sonic-mgmt ping -c 3 172.31.$TOPO_ID.200
   ```

### KNE testbed files

The KNE testbed is described to sonic-mgmt by these files, alongside sonic-mgmt's other testbed definitions:

| File | Purpose |
|---|---|
| `ansible/kne_testbed.yaml` | Testbed definitions for `kne-t0`, `kne-t1`, and `kne-t1-lag`, using sonic-mgmt's standard `t0`, `t1`, and `t1-lag` topologies. |
| `ansible/kne_vtb`, `kne_vtb_t1`, `kne_vtb_t1_lag` | Ansible inventories: the DUT, PTF, and neighbor management addresses. |
| `ansible/host_vars/KNE-VSERV-01.yml` | Variables for the testbed's server entry. |
| `ansible/files/sonic_kne_vtb*_devices.csv`, `*_links.csv` | Lab graph: devices, and the links between the DUT and its neighbors. |
| `ansible/files/graph_groups.yml` | Registers the three KNE lab graph groups, after the existing groups, so existing testbeds' lookups are unaffected. |

---

## 2. Credentials

No passwords are stored in the testbed files. The inventories read them from two environment variables:

| Variable | Password for |
|---|---|
| `SONIC_MGMT_SONIC_PASSWORD` | The `admin` account on the DUT and neighbors |
| `SONIC_MGMT_PTF_PASSWORD` | The `root` account on PTF |

Set them in the shell you'll run the remaining steps from. Each prompt is hidden, so the passwords don't appear on screen or in your shell history:

```bash
read -rs -p "SONiC admin password: " SONIC_MGMT_SONIC_PASSWORD; echo; export SONIC_MGMT_SONIC_PASSWORD
read -rs -p "PTF root password: " SONIC_MGMT_PTF_PASSWORD; echo; export SONIC_MGMT_PTF_PASSWORD
```

The commands below pass them into the container by name (`docker exec -e SONIC_MGMT_SONIC_PASSWORD ...`), never by value. In CI, supply the same variables from the pipeline's secret store.

---

## 3. Configure the topology

Each topology is created with every node running SONiC VS's default configuration, so these steps run each time a topology is created or recreated.

### 3.1 Install SSH keys

The neighbor configuration step connects to the SONiC nodes with an SSH key, so install the container's key on each node. You're prompted for the `admin` password once, and it's passed to `sshpass` through an environment variable rather than on the command line.

1. Clear SSH host keys from any previous topology. Recreated nodes have new host keys, which SSH would otherwise reject:

   ```bash
   docker exec sonic-mgmt rm -f /root/.ssh/known_hosts
   ```

2. Install the key on every SONiC node. For T0, the nodes are the DUT (`.2`) and the four neighbors (`.250`–`.253`):

   ```bash
   read -rs -p "SONiC admin password: " SSHPASS; echo; export SSHPASS
   docker exec -e SSHPASS -e TOPO_ID sonic-mgmt bash -c '
     [ -f ~/.ssh/id_rsa ] || ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa -q
     for ip in 2 250 251 252 253; do
       sshpass -e ssh-copy-id -o StrictHostKeyChecking=no -o PubkeyAuthentication=no admin@172.31.$TOPO_ID.$ip
     done'
   unset SSHPASS
   ```

   For T1, use `for ip in 2 $(seq 10 41)`, and for T1-LAG, `for ip in 2 $(seq 10 17) $(seq 26 41)`. Each node should report `Number of key(s) added: 1`.

3. Confirm key login works on every node, without a password:

   ```bash
   for ip in 2 250 251 252 253; do
     docker exec sonic-mgmt ssh -o BatchMode=yes admin@172.31.$TOPO_ID.$ip hostname
   done
   ```

   Each node prints its hostname. The `Debian GNU/Linux` line before each one is SONiC's pre-login banner.

### 3.2 Configure the neighbors

Each neighbor boots with SONiC VS's default configuration, which uses the same BGP AS as the DUT and puts an address on every port. The neighbor scripts replace it with the configuration sonic-mgmt's topology expects: a PortChannel on the link to the DUT, the topology's addresses and loopback, and BGP peering with the DUT. Run them from `ansible/kne`, with the rendered topology file where the script takes one.

**T0:**

```bash
cd ~/sonic-mgmt/ansible/kne
TOPO_ID=$TOPO_ID ./topologies/t0/configure_neighbors.sh
```

For each of the four neighbors, the script clears the default configuration, creates `PortChannel1` on `Ethernet0`, assigns the addresses, sets BGP AS 64600 with the DUT (AS 65100) as its peer, and saves. It then checks the result, and ends with a summary such as `DONE ok=4 fail=0`.

**T1** (not yet validated):

```bash
cd ~/sonic-mgmt/ansible/kne
python3 topologies/t1/configure_neighbors.py /tmp/kne-rendered/t1-$TOPO_ID.pb.txt
```

**T1-LAG:** neighbor configuration isn't available yet. The T2 neighbors need a two-member PortChannel on `Ethernet0` and `Ethernet4`, and the data for every neighbor is in `topologies/t1-lag/neighbors.json`.

### 3.3 Deploy the minigraph to the DUT

This is sonic-mgmt's **deploy minigraph** step, the same playbook `testbed-cli.sh deploy-mg` runs. It generates a minigraph from the testbed and topology definitions, loads it onto the DUT, brings up BGP, and saves the configuration.

```bash
docker exec -e SONIC_MGMT_SONIC_PASSWORD -e SONIC_MGMT_PTF_PASSWORD -e TESTBED -e INVENTORY -e DUT sonic-mgmt bash -c \
  'cd /data/sonic-mgmt/ansible && ansible-playbook -i $INVENTORY config_sonic_basedon_testbed.yml -l $DUT \
   -e testbed_name=$TESTBED -e testbed_file=kne_testbed.yaml -e deploy=true -e save=true'
```

It takes several minutes. A successful run ends with a `PLAY RECAP` showing `unreachable=0` and `failed=0`, for example:

```
vlab-kne-01                : ok=98   changed=23   unreachable=0    failed=0    skipped=116  rescued=0    ignored=2
```

The `ignored` tasks are expected: the playbook's clock synchronization and PTF TACACS tasks are allowed to fail. During the `config load_minigraph` task, the DUT's management interface restarts, so it stops answering for a few seconds, then recovers.

### 3.4 Verify

Check from the DUT that the PortChannels and BGP sessions are up:

```bash
docker exec sonic-mgmt ssh admin@172.31.$TOPO_ID.2 "show interfaces portchannel; show ip bgp summary; show ipv6 bgp summary"
```

For T0, all 4 PortChannels show `LACP(A)(Up)` with their member selected (`(S)`), and all 8 BGP sessions (4 IPv4 and 4 IPv6) show a prefix count under `State/PfxRcd`. A session showing `Active` means the DUT is waiting for that neighbor; check that the neighbor was configured in step 3.2.

---

## 4. Run tests

Run tests from the `tests/` directory inside the container, passing the KNE inventory, testbed, and DUT. For example, `bgp/test_bgp_fact.py`:

```bash
docker exec -e SONIC_MGMT_SONIC_PASSWORD -e SONIC_MGMT_PTF_PASSWORD -e TESTBED -e INVENTORY -e DUT sonic-mgmt bash -c '
  cd /data/sonic-mgmt/tests && \
  ANSIBLE_LIBRARY=/data/sonic-mgmt/ansible/library \
  ANSIBLE_MODULE_UTILS=/data/sonic-mgmt/ansible/module_utils \
  python -m pytest bgp/test_bgp_fact.py -v \
    --inventory /data/sonic-mgmt/ansible/$INVENTORY \
    --host-pattern $DUT \
    --testbed $TESTBED \
    --testbed_file /data/sonic-mgmt/ansible/kne_testbed.yaml \
    --disable_loganalyzer --skip_sanity --skip_post_check \
    --allow_recover --disable_memory_utilization --skip_yang \
    -p no:test_completeness --tb=line'
```

On T0, this ends with `1 passed` in about 30–40 seconds. To run a different test, replace `bgp/test_bgp_fact.py` with its path under `tests/`.

What the options do:

| Option | Purpose |
|---|---|
| `ANSIBLE_LIBRARY`, `ANSIBLE_MODULE_UTILS` | Point Ansible at sonic-mgmt's own modules. |
| `--inventory`, `--host-pattern`, `--testbed`, `--testbed_file` | Select the KNE testbed and DUT. Use absolute paths. |
| `--skip_sanity`, `--skip_post_check` | Skip sonic-mgmt's pre-test sanity checks and post-test checks, which expect parts of the KVM testbed (such as a full connection graph) that the KNE testbed doesn't provide yet. Skipping the post-check also avoids a config reload after each test. |
| `--disable_loganalyzer`, `--disable_memory_utilization`, `--skip_yang` | Skip log analysis, memory checks, and YANG validation. |
| `--allow_recover` | Lets sonic-mgmt try to recover the DUT if a check fails. |
| `-p no:test_completeness` | Disables the test completeness plugin. |

To limit a run to tests marked for a topology, add `--topology t0,any` (for T0). sonic-mgmt also keeps a list of tests it deliberately skips on certain platforms, including virtual switches; those skips apply on KNE too, which keeps results comparable with sonic-mgmt's own virtual testbeds.

---

## When to Redo the Steps

| Event | Redo |
|---|---|
| A topology is created or recreated | 3.1 (SSH keys, after clearing `known_hosts`), 3.2, and 3.3 |
| The `sonic-mgmt` container is recreated | 1 (from step 3), then 3.1 |
| A new shell | The credential variables in 2, and the testbed variables |

The topology steps from the topologies guide (management routes and PTF management) come first in every case.

---

## Troubleshooting

**`pytest` reports `unrecognized arguments`**
It isn't running from the `tests/` directory, so sonic-mgmt's `conftest.py`, which defines those options, isn't loaded. Make sure the command starts with `cd /data/sonic-mgmt/tests`.

**Ansible fails to log in to the DUT or PTF**
The credential variables aren't set, or weren't passed into the container. Check them without revealing their values with `[ -n "$SONIC_MGMT_SONIC_PASSWORD" ] && [ -n "$SONIC_MGMT_PTF_PASSWORD" ] && echo set`, and make sure the `docker exec` command includes `-e SONIC_MGMT_SONIC_PASSWORD -e SONIC_MGMT_PTF_PASSWORD`.

**SSH reports `REMOTE HOST IDENTIFICATION HAS CHANGED`**
The topology was recreated, so its nodes have new host keys. Run `docker exec sonic-mgmt rm -f /root/.ssh/known_hosts`, then reinstall the SSH keys (step 3.1).

**Deploy minigraph fails with `UNREACHABLE` during `config load_minigraph`**
The DUT lost its management route when the minigraph was loaded. SONiC sets the management gateway to the first address of the management subnet, so the pod bridge must be at `.1` and the DUT elsewhere. Check that the topology template gives the DUT `SWITCH_ID` 2, and that the inventory's DUT address matches (`172.31.<TOPO_ID>.2`).

**BGP sessions stay `Active`**
The neighbors aren't configured, or a neighbor pod restarted and its VM booted with the default configuration again. Rerun step 3.2.

**`pytest` warns `Unable to parse .../tests/ansible/<inventory> as an inventory source`**
Harmless: pytest's Ansible plugin first looks for the inventory relative to `tests/`, then sonic-mgmt loads it from the absolute path.

---

## Known Limitations

- **Default topology IDs only:** the KNE testbed files hardcode each topology's management addresses at its default `TOPO_ID` (100, 101, and 102). Running copies with other IDs, for example in parallel CI runs, needs these files generated from the rendered topology file.
- **PTF services:** KNE starts the PTF container with its own placeholder command instead of the PTF image's entrypoint, so PTF's services (such as its SSH and TACACS servers) don't run. Tests that rely on PTF aren't supported yet. Deploy minigraph still configures the DUT to use a TACACS server on PTF; logins with the container's SSH key are unaffected.
- **Validation status:** T0 has been validated end to end. T1 and T1-LAG have not, and T1-LAG neighbor configuration isn't available yet.
- **Neighbor configuration** uses KNE scripts rather than sonic-mgmt's `add-topo`, whose neighbor configuration is specific to KVM testbeds today.
