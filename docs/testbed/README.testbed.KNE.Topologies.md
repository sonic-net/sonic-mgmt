# SONiC T0, T1, and T1-LAG Topologies on KNE

This guide shows how to bring up sonic-mgmt's standard **T0**, **T1**, and **T1-LAG** topologies on [KNE (Kubernetes Network Emulation)](https://github.com/openconfig/kne), using SONiC Virtual Switch (VS) for the DUT and all neighbors, plus a PTF container for packet tests. All three topologies have been validated end to end, from bring-up through running sonic-mgmt tests.

**Prerequisite:** complete the [one-time host setup for KNE](README.testbed.KNE.Setup.md) first. You should have a running `kne` cluster before continuing.

---

## How It Works

Each SONiC node (DUT or neighbor) runs in its own KNE pod. Inside the pod, `startup.sh` boots SONiC VS as a QEMU virtual machine and wires it to the topology:

```
             KNE pod (one per SONiC node)
  ┌──────────────────────────────────────────────────┐
  │                                                  │
  │  eth0 ── br<TOPO_ID> ── tap0 ──┐                 │
  │  (pod network)  (DHCP via      │                 │
  │                  dnsmasq)      │   ┌───────────┐ │
  │                                ├──▶│ SONiC VS  │ │
  │  eth1 ◀── tc redirect ──▶ tap1 ┤   │ (QEMU VM) │ │
  │  eth2 ◀── tc redirect ──▶ tap2 ┤   └───────────┘ │
  │  ...                           │                 │
  │  ethN ◀── tc redirect ──▶ tapN ┘                 │
  │  (meshnet links)                                 │
  └──────────────────────────────────────────────────┘
```

- **Data plane:** meshnet creates the topology links as pod interfaces (`eth1` to `ethN`). `tc` redirect rules pass traffic between each `ethN` and a matching QEMU tap device (`tapN`), so the VM sees one NIC per link.
- **Management:** a bridge (`br<TOPO_ID>`) connects the VM's management NIC to the pod, and dnsmasq hands the VM a fixed management IP over DHCP.
- **Disk:** each VM boots from a copy-on-write overlay of the SONiC VS image. The image itself is only read, so all pods share the single copy inside the container image, and each pod stores only its own VM's changes.
- **PTF mirroring (experimental):** when `MIRROR_ENABLED=1`, uplink ports also get `tc` mirror rules. A copy of each packet crossing an uplink goes to an extra mirror interface linked to PTF, and PTF can inject packets back into the DUT through the same interface. The VM is unaware of the mirror ports.

> **Experimental:** PTF mirroring has not been fully validated. The mirror links are part of all three topologies, but don't rely on PTF tests that sniff or inject on uplink ports until this is validated. Topology bring-up, management access, and BGP don't depend on it.

### Topology file format

Each topology is a KNE topology file (`.pb.txt`) with three parts: a `name`, one `nodes` block per node, and one `links` entry per connection. Here's the DUT node and one of its links from the T0 template:

```
name: "100"

nodes: {
  name: "dut"
  vendor: HOST
  config: {
    image: "sonic-vs:community"
    command: "/startup.sh"
    env: { key: "SWITCH_ID"      value: "1" }
    env: { key: "TOPO_ID"        value: "100" }
    env: { key: "QEMU_RAM"       value: "4G" }
    env: { key: "SERVER_PORTS"   value: "28" }
    env: { key: "UPLINK_PORTS"   value: "4" }
    env: { key: "MIRROR_ENABLED" value: "1" }
  }
}

links: { a_node: "dut" a_int: "eth29" z_node: "t1-1" z_int: "eth1" }
```

The three parts:

- **`name`** becomes the topology's Kubernetes **namespace**. All of the topology's pods live in that namespace, which is what lets several topologies run in parallel: each copy gets a unique name, so their pods never collide. The name must match the `TOPO_ID` on every node, which is why both change together when a template is rendered (see [Topology files are templates](#topology-files-are-templates)).
- **`nodes`**: each SONiC node uses the `sonic-vs:community` image with `/startup.sh` as its command, and the `env` entries configure how `startup.sh` sets up that node. This is your **DUT image**: it packages whichever SONiC VS build you put in it (see [Build and Load the Images](#1-build-and-load-the-images)), so it's the software under test. For these examples, the DUT and the neighbors use the same image. The PTF node is the exception: it uses the `docker-ptf:latest` image and doesn't run `startup.sh`.
- **`links`**: each entry connects one interface on one node to one interface on another. This one connects the DUT's first uplink to neighbor `t1-1`.

A single command deploys everything the file describes. For example, with `TOPO_ID` set to the topology's ID, this creates the T0 topology: its namespace, one pod per node, and all of the links between them:

```bash
kne create /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
```

After that, you can see the topology's pods in its namespace with `kubectl get pods -n $TOPO_ID`. Section 2 walks through the full T0 deployment, including rendering the file and setting up management access. For a complete topology file, see any of the templates, such as `topologies/t0/t0.pb.txt`.

### Node settings

`startup.sh` reads its settings from each node's `env` entries.

**Required on every SONiC node:**

| Variable | Meaning |
|---|---|
| `TOPO_ID` | Topology ID. Must match the topology `name`, be 1–234, and be unique among running topologies. Sets the management subnet and console ports. |
| `SWITCH_ID` | Node ID. Must be 2–254 (`.1` is the gateway) and unique within the topology. Sets the node's management IP, console port, and MAC addresses. |

**Optional VM sizing:**

| Variable | Default | Meaning |
|---|---|---|
| `QEMU_RAM` | `4G` | VM memory. |
| `QEMU_SMP` | `2` | VM CPU count. |

Each DUT also sets its port layout with `SERVER_PORTS`, `UPLINK_PORTS`, and `MIRROR_ENABLED`. Each topology section below lists its DUT's values. Neighbors don't need these settings: `startup.sh` wires whichever interfaces exist, up to `SERVER_PORTS + UPLINK_PORTS` (32 with the defaults), and ignores any beyond that.

### Boot timing

To avoid every VM booting at once, `startup.sh` delays each node's VM start by `(SWITCH_ID % 14) × 20` seconds, so delays range from 0 to 260 seconds. SONiC then needs a few more minutes to boot inside the VM. As a result, nodes become reachable in an order set by their `SWITCH_ID`, not their role, and some neighbors come up several minutes after the DUT. A node that isn't reachable yet is usually still booting; check its stagger delay before troubleshooting.

### Management addressing

Every node's management addresses are derived from its `TOPO_ID` and `SWITCH_ID`:

| | Address |
|---|---|
| Subnet | `172.31.<TOPO_ID>.0/24` |
| Gateway (pod bridge) | `172.31.<TOPO_ID>.1` |
| VM management IP | `172.31.<TOPO_ID>.<SWITCH_ID>` |
| Serial console port | `4321 + TOPO_ID × 256 + SWITCH_ID` |

The gateway is the first address in the subnet because that's what SONiC expects: when a minigraph is deployed to the DUT, SONiC sets the management gateway to the first address of the management subnet. It's also the convention sonic-mgmt's KVM testbeds use.

### Management routes

Each VM's management IP lives on a bridge inside its own pod, so the host can't reach it until routes are added. `setup_mgmt_routes.py` adds them in three hops:

1. **Host → kind node:** one route for the topology's subnet, `172.31.<TOPO_ID>.0/24`, via the `kne-control-plane` container.
2. **Kind node → pod:** one `/32` route per VM, sending its management IP to its pod.
3. **Pod → VM:** the pod's `br<TOPO_ID>` bridge, which `startup.sh` creates. The script also re-applies the bridge's gateway address and NAT rule in case they're missing.

Usage:

```
python3 setup_mgmt_routes.py <rendered-topology-file>
```

| Argument | Meaning |
|---|---|
| `<rendered-topology-file>` | The rendered topology file passed to `kne create`, such as `/tmp/kne-rendered/t0-$TOPO_ID.pb.txt`. Not the template; see [Topology files are templates](#topology-files-are-templates). |

For example:

```bash
python3 setup_mgmt_routes.py /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
```

The script only processes SONiC nodes. It skips PTF, which has no management bridge and is set up by [`setup_ptf_mgmt.sh`](#ptf-management) instead. It needs `docker`, `kubectl`, and `sudo` access, because the host route is a system change. It prints each node's pod IP and management IP as it goes, then a summary line (`Routes configured: <n>/<total>`) and a table of every node's management IP with its SSH command. It exits with an error if any node fails.

Routes don't persist: rerun the script after a pod restarts, since its pod IP changes, and after a host reboot. See [When to Rerun the Scripts](#when-to-rerun-the-scripts).

### PTF management

PTF doesn't run `startup.sh`, so it has no management bridge or DHCP. `setup_ptf_mgmt.sh` gives it a management IP that follows the same rule as every other node, `172.31.<TOPO_ID>.<SWITCH_ID>` (`.200` in all three topologies):

1. It assigns the IP to the PTF pod's `eth0` as a `/32`, alongside the pod's own IP. Using `/32` means PTF keeps using its default route for everything else.
2. It routes that IP from the kind node to the PTF pod.

Usage:

```
./setup_ptf_mgmt.sh <rendered-topology-file> [ptf-node-name]
```

| Argument | Meaning |
|---|---|
| `<rendered-topology-file>` | The rendered topology file passed to `kne create`. The script reads the namespace and PTF's `SWITCH_ID` from it. |
| `[ptf-node-name]` | The PTF node's name in the topology. Defaults to `ptf`. |

The script waits for the PTF pod to be ready, checks that both changes took effect, and exits with an error if they didn't. It's safe to rerun. It needs `kubectl` and `docker`. The host's route to the management subnet comes from `setup_mgmt_routes.py`, so PTF is reachable from the host once both scripts have run.

> **Note:** this gives the host access to PTF. The VMs can't reach PTF over the management network, because each VM's pod treats the whole management subnet as local to its own bridge.

### Topology files are templates

The topology files are templates. Each one ships with a default ID (`100` for T0, `101` for T1, and `102` for T1-LAG). Before deploying, you render a copy of the template with the `TOPO_ID` you want to use. Because the ID determines the namespace, management subnet, and console ports, copies with different IDs can run side by side without colliding.

How the ID is chosen depends on how you deploy:

- **Manually:** you choose the ID yourself, and it's up to you to make sure no running topology on the host already uses it. Since each topology's namespace is its ID, `kubectl get namespaces` shows which IDs are taken.
- **With automation, such as a CI/CD pipeline:** the automation can pick a unique ID, for example one per pull request, and render the template with it.

The commands in this guide use a `TOPO_ID` shell variable. Each topology's deploy steps start by setting it and rendering the template, which changes the topology `name` and every node's `TOPO_ID` to that value:

```bash
export TOPO_ID=123
mkdir -p /tmp/kne-rendered
sed -E "s/^name: \"[0-9]+\"/name: \"$TOPO_ID\"/; s/(key: \"TOPO_ID\" +value: \")[0-9]+\"/\1$TOPO_ID\"/" \
  topologies/t0/t0.pb.txt > /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
```

After rendering, use the rendered file everywhere a topology file is needed: `kne create`, `setup_ptf_mgmt.sh`, `setup_mgmt_routes.py`, `configure_neighbors.py`, and `kne delete`. The scripts read the namespace and IDs from the file they're given, so they need no other changes. But passing any of them the template instead of the rendered file would point it at the template's default namespace and subnet, which may belong to a different running topology. The examples below set `TOPO_ID` to each template's default, but any unused ID works.

Each `TOPO_ID` must be between 1 and 234, and unique among the topologies running on the host. In practice, host resources limit how many topologies can run at once long before IDs run out. Rendered files go in `/tmp/kne-rendered/`, named by topology and ID (for example, `/tmp/kne-rendered/t0-123.pb.txt`). Keeping them outside the repo means they can't be committed by accident. `/tmp` is usually cleared on reboot, which is harmless: rendering is repeatable, so running the same render command again recreates the identical file, for example to tear down a topology.

---

## Requirements

Each SONiC node is a full VM, so resource needs grow quickly with topology size:

| Topology | SONiC VMs | Guest RAM (4 GB each) | Guest vCPUs (2 each) |
|---|---|---|---|
| T0 | 5 | 20 GB | 10 |
| T1 | 33 | 132 GB | 66 |
| T1-LAG | 25 | 100 GB | 50 |

QEMU allocates guest memory as it's used and KVM can oversubscribe CPUs, so actual usage may be lower than these figures. Plan for them anyway, and reduce `QEMU_RAM` if you're short on memory.

Large topologies start dozens of pods at once, which can exhaust the host's default inotify limits and cause pods to fail during deploy. Before deploying T1 or T1-LAG, raise them:

```bash
sudo sysctl fs.inotify.max_user_watches=655360
sudo sysctl fs.inotify.max_user_instances=512
```

To keep these settings after a reboot, add both lines (without `sudo sysctl`) to a file in `/etc/sysctl.d/`.

Plan for about **50 GB of free disk** before building the images. The two images take about 40 GB together, counting the copies in Docker and in the cluster, and each running VM adds only its own changes on top, typically well under 1 GB while booting.

The host must also support **KVM** (`/dev/kvm` must exist). Without it, QEMU falls back to software emulation, which is too slow to be practical. If the host is itself a VM, it needs nested virtualization enabled.

---

## Files

All files live in `ansible/kne/`, and every command in this guide runs from that directory:

```bash
cd ansible/kne
```

| File | Purpose |
|---|---|
| `Dockerfile` | Builds the `sonic-vs:community` pod image (QEMU, networking tools, and the SONiC VS disk image). |
| `startup.sh` | Pod entrypoint: management bridge, DHCP, `tc` wiring, and QEMU launch. |
| `setup_mgmt_routes.py` | Adds routes so the host can reach every VM's management IP. |
| `setup_ptf_mgmt.sh` | Gives the PTF container a management IP and routes it from the kind node. |
| `topologies/t0/t0.pb.txt` | T0 topology template. |
| `topologies/t0/configure_neighbors.sh` | Configures IP addresses, PortChannels, and BGP on the four T0 neighbors. |
| `topologies/t1/t1.pb.txt` | T1 topology template. |
| `topologies/t1/neighbors.json` | Addressing and BGP data for the 32 T1 neighbors. |
| `topologies/t1/configure_neighbors.py` | Configures IP addresses and BGP on the T1 neighbors. |
| `topologies/t1-lag/t1-lag.pb.txt` | T1-LAG topology template. |
| `topologies/t1-lag/neighbors.json` | Addressing, LAG membership, and BGP data for the 24 T1-LAG neighbors. |

---

## 1. Build and Load the Images

Both topologies use the same two images. Build them once, then load them into the KNE cluster.

1. Download the SONiC VS disk image. This is the same public build artifact sonic-mgmt's [virtual switch setup](README.testbed.VsSetup.md) uses. Run this in the directory containing the `Dockerfile`:

   ```bash
   wget "https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&platform=vs&target=target/sonic-vs.img.gz" -O sonic-vs.img.gz
   gzip -d sonic-vs.img.gz
   ```

   The Dockerfile expects the file to be named exactly `sonic-vs.img`. If you use an image with a versioned filename (for example, one you built yourself), rename it: `mv <your-image>.img sonic-vs.img`.

2. Build the SONiC VS pod image:

   ```bash
   docker build -t sonic-vs:community .
   ```

   The first build takes about 15 minutes, most of it in the `exporting layers` stage, which writes the multi-gigabyte disk image into the image and prints nothing while it works. Later builds reuse the cached layers and finish in seconds unless the disk image or `startup.sh` changes.

3. Pull the PTF image and give it the tag the topology files expect:

   ```bash
   docker pull sonicdev-microsoft.azurecr.io:443/docker-ptf:latest
   docker tag sonicdev-microsoft.azurecr.io:443/docker-ptf:latest docker-ptf:latest
   ```

4. Load both images into the KNE cluster:

   ```bash
   kind load docker-image sonic-vs:community --name kne
   kind load docker-image docker-ptf:latest --name kne
   ```

   The topology files reference these images by local tag, so skipping this step causes `ImagePullBackOff` errors. Repeat it whenever you rebuild an image.

5. Verify both images are available inside the cluster:

   ```bash
   docker exec kne-control-plane crictl images | grep -E "sonic-vs|docker-ptf"
   ```

   You should see one line for each image.

> **Rebuilding the image:** to test a different SONiC build, replace `sonic-vs.img`, then repeat steps 2, 4, and 5. Docker detects that the disk image (or `startup.sh`) changed and rebuilds from that point, so `--no-cache` isn't needed. Use `docker build --no-cache` only when you also want to refresh the OS packages inside the image.
>
> Running topologies keep the image they were created with, even after you load a new one. Delete and recreate a topology (`kne delete`, then `kne create`) to run it on the new image.

---

## 2. T0 Topology

T0 models a top-of-rack (ToR) switch: one DUT with servers below it and four T1 spine neighbors above it.

```
        t1-1      t1-2      t1-3      t1-4
          │         │         │         │
        eth29     eth30     eth31     eth32
          └─────────┴────┬────┴─────────┘
                       DUT ────── eth33–eth36 ──▶ PTF eth29–eth32 (uplink mirrors, experimental)
                        │
                   eth1–eth28
                        │
                  PTF eth1–eth28 (server-facing ports)
```

| Node | Role | `SWITCH_ID` | Management IP |
|---|---|---|---|
| `dut` | DUT (ToR) | 2 | `172.31.<TOPO_ID>.2` |
| `t1-1` | T1 neighbor | 251 | `172.31.<TOPO_ID>.251` |
| `t1-2` | T1 neighbor | 252 | `172.31.<TOPO_ID>.252` |
| `t1-3` | T1 neighbor | 253 | `172.31.<TOPO_ID>.253` |
| `t1-4` | T1 neighbor | 250 | `172.31.<TOPO_ID>.250` |
| `ptf` | PTF | — | — |

**DUT port settings:**

| Variable | Value | Effect |
|---|---|---|
| `SERVER_PORTS` | `28` | eth1–eth28 are server-facing ports, connected to PTF. |
| `UPLINK_PORTS` | `4` | eth29–eth32 are uplinks to the T1 neighbors. |
| `MIRROR_ENABLED` | `1` | The 4 uplinks are mirrored to PTF on eth33–eth36 (experimental). |

The template's default `TOPO_ID` is **100**. Addresses below are shown as `172.31.<TOPO_ID>.x`, and the commands use the `TOPO_ID` variable you set in step 1.

### Deploy

1. Set the topology ID and render the template. Use the default shown here, or any unused ID:

   ```bash
   export TOPO_ID=100
   mkdir -p /tmp/kne-rendered
   sed -E "s/^name: \"[0-9]+\"/name: \"$TOPO_ID\"/; s/(key: \"TOPO_ID\" +value: \")[0-9]+\"/\1$TOPO_ID\"/" \
     topologies/t0/t0.pb.txt > /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
   ```

2. Create the topology:

   ```bash
   kne create /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
   ```

3. Wait for the pods, then the VMs. Watch the pods (press Ctrl+C to stop watching):

   ```bash
   kubectl get pods -n $TOPO_ID -w
   ```

   All six pods should reach `Running` within a minute. The SONiC VMs inside them take longer, because their starts are staggered (see [Boot timing](#boot-timing)). Allow **5–10 minutes**, and check which nodes are reachable with:

   ```bash
   for ip in 2 250 251 252 253; do
     ping -c1 -W2 172.31.$TOPO_ID.$ip >/dev/null && echo "172.31.$TOPO_ID.$ip up" || echo "172.31.$TOPO_ID.$ip down"
   done
   ```

   Run this after steps 4 and 5 below, which add the routes it relies on. Nodes come up in this order:

   | Node | `SWITCH_ID` | Stagger delay |
   |---|---|---|
   | `t1-2` | 252 | 0 s |
   | `t1-3` | 253 | 20 s |
   | `dut` | 2 | 40 s |
   | `t1-4` | 250 | 240 s |
   | `t1-1` | 251 | 260 s |

   So `t1-4` and `t1-1` typically come up several minutes after the others. Steps 4 and 5 only need the pods running, so you can run them while the VMs boot.

4. Set up PTF management:

   ```bash
   ./setup_ptf_mgmt.sh /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
   ```

   It ends with `Done: 172.31.<TOPO_ID>.200 is assigned in pod ptf`.

5. Set up management routes:

   ```bash
   python3 setup_mgmt_routes.py /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
   ```

   The script ends with a table of management IPs. Confirm it reports `Routes configured: 5/5`. Then confirm PTF is reachable from the host with `ping -c 3 172.31.$TOPO_ID.200`.

6. Configure the topology and run tests. Configuring the neighbors, deploying the minigraph to the DUT, and running sonic-mgmt tests are covered in [Running sonic-mgmt Tests on KNE](README.testbed.KNE.Tests.md).

### Verify

Confirm you can log in to the DUT over SSH, and check which SONiC build it's running. SSH prompts for the `admin` password, which is the SONiC VS image's default unless you've changed it:

```bash
ssh admin@172.31.$TOPO_ID.2
show version
```

The first connection asks you to confirm the DUT's host key; answer `yes`. `show version` should report the SONiC build you put in the image, with platform `x86_64-kvm_x86_64-r0`, HwSKU `Force10-S6000`, and ASIC `vs`.

Configuring and checking topology features, such as BGP neighbors, is done by the sonic-mgmt tests.

---

## 3. T1 Topology

T1 models a leaf/spine switch with the full upstream sonic-mgmt T1 layout: 16 T2 neighbors upstream, 16 T0 neighbors downstream, and PTF mirroring on all 32 neighbor links (experimental).

```
             t2-1 ... t2-16
                  │
              eth1–eth16
                  │
                 DUT ────── eth33–eth64 ──▶ PTF eth1–eth32 (mirrors, experimental)
                  │
              eth17–eth32
                  │
             t0-1 ... t0-16
```

| Nodes | Role | `SWITCH_ID` | Management IPs | Neighbor names | ASN |
|---|---|---|---|---|---|
| `dut` | DUT | 2 | `172.31.<TOPO_ID>.2` | — | 65100 |
| `t2-1` to `t2-16` | T2 neighbors | 10–25 | `172.31.<TOPO_ID>.10` – `.25` | `ARISTA01T2` – `ARISTA16T2` | 65200 |
| `t0-1` to `t0-16` | T0 neighbors | 26–41 | `172.31.<TOPO_ID>.26` – `.41` | `ARISTA01T0` – `ARISTA16T0` | 64001–64016 |
| `ptf` | PTF | — | — | — | — |

**DUT port settings:**

| Variable | Value | Effect |
|---|---|---|
| `SERVER_PORTS` | `0` | No server-facing ports. |
| `UPLINK_PORTS` | `32` | eth1–eth32 all connect to neighbors: eth1–eth16 to the T2s and eth17–eth32 to the T0s. |
| `MIRROR_ENABLED` | `1` | All 32 neighbor links are mirrored to PTF on eth33–eth64 (experimental). |

The template's default `TOPO_ID` is **101**. Addresses below are shown as `172.31.<TOPO_ID>.x`, and the commands use the `TOPO_ID` variable you set in step 1. It can run alongside T0 if the host has enough resources.

> **Note:** the `ARISTAxxTx` names and `VMxxxx` identifiers in `neighbors.json` follow sonic-mgmt's upstream T1 topology conventions, which sonic-mgmt tests and generated minigraphs expect. In this setup, every neighbor is actually a SONiC VS instance, not an Arista device.

### Deploy

1. Set the topology ID and render the template. Use the default shown here, or any unused ID:

   ```bash
   export TOPO_ID=101
   mkdir -p /tmp/kne-rendered
   sed -E "s/^name: \"[0-9]+\"/name: \"$TOPO_ID\"/; s/(key: \"TOPO_ID\" +value: \")[0-9]+\"/\1$TOPO_ID\"/" \
     topologies/t1/t1.pb.txt > /tmp/kne-rendered/t1-$TOPO_ID.pb.txt
   ```

2. Create the topology:

   ```bash
   kne create /tmp/kne-rendered/t1-$TOPO_ID.pb.txt
   ```

3. Wait for all 34 pods to reach `Running`, then allow time for the VMs to boot. Boots are staggered (see [Boot timing](#boot-timing)), and with 33 VMs starting, allow **10–15 minutes** before expecting every node to be reachable.

   ```bash
   kubectl get pods -n $TOPO_ID -w
   ```

   After steps 4 and 5, which add the routes it relies on, check which nodes are reachable (the DUT plus `SWITCH_ID`s 10–41):

   ```bash
   for ip in 2 $(seq 10 41); do
     ping -c1 -W2 172.31.$TOPO_ID.$ip >/dev/null && echo "172.31.$TOPO_ID.$ip up" || echo "172.31.$TOPO_ID.$ip down"
   done
   ```

4. Set up PTF management:

   ```bash
   ./setup_ptf_mgmt.sh /tmp/kne-rendered/t1-$TOPO_ID.pb.txt
   ```

   It ends with `Done: 172.31.<TOPO_ID>.200 is assigned in pod ptf`.

5. Set up management routes:

   ```bash
   python3 setup_mgmt_routes.py /tmp/kne-rendered/t1-$TOPO_ID.pb.txt
   ```

   Confirm it reports `Routes configured: 33/33`. Then confirm PTF is reachable from the host with `ping -c 3 172.31.$TOPO_ID.200`.

6. Configure the topology and run tests. Configuring the neighbors, deploying the minigraph to the DUT, and running sonic-mgmt tests are covered in [Running sonic-mgmt Tests on KNE](README.testbed.KNE.Tests.md).

### Verify

Confirm you can log in to the DUT over SSH, and check which SONiC build it's running. SSH prompts for the `admin` password, which is the SONiC VS image's default unless you've changed it:

```bash
ssh admin@172.31.$TOPO_ID.2
show version
```

The first connection asks you to confirm the DUT's host key; answer `yes`. `show version` should report the SONiC build you put in the image, with platform `x86_64-kvm_x86_64-r0`, HwSKU `Force10-S6000`, and ASIC `vs`.

Configuring and checking topology features, such as BGP neighbors, is done by the sonic-mgmt tests.

---

## 4. T1-LAG Topology

T1-LAG is the T1 layout with link aggregation on the upstream side: 8 T2 neighbors each connect to the DUT over a 2-link LACP PortChannel, while 16 T0 neighbors connect over single links. It matches sonic-mgmt's upstream T1-LAG topology.

```
     t2-1      t2-2    ...    t2-8          (each: 2 links → 1 PortChannel)
     ║ ║       ║ ║            ║ ║
  eth1 eth2 eth3 eth4  ... eth15 eth16
         └──────────┬──────────┘
                   DUT ────── eth33–eth64 ──▶ PTF eth1–eth32 (mirrors, experimental)
                    │
               eth17–eth32
                    │
              t0-1 ... t0-16                (each: 1 link)
```

| Nodes | Role | `SWITCH_ID` | Management IPs | Neighbor names | ASN | DUT ports |
|---|---|---|---|---|---|---|
| `dut` | DUT | 2 | `172.31.<TOPO_ID>.2` | — | 65100 | — |
| `t2-1` to `t2-8` | T2 neighbors | 10–17 | `172.31.<TOPO_ID>.10` – `.17` | `ARISTA01T2`, `ARISTA03T2`, … `ARISTA15T2` | 65200 | 2 each: eth1–eth2, eth3–eth4, … eth15–eth16 |
| `t0-1` to `t0-16` | T0 neighbors | 26–41 | `172.31.<TOPO_ID>.26` – `.41` | `ARISTA01T0` – `ARISTA16T0` | 64001–64016 | 1 each: eth17–eth32 |
| `ptf` | PTF | — | — | — | — | — |

**DUT port settings:**

| Variable | Value | Effect |
|---|---|---|
| `SERVER_PORTS` | `0` | No server-facing ports. |
| `UPLINK_PORTS` | `32` | eth1–eth32 all connect to neighbors: eth1–eth16 to the T2s (2 links each) and eth17–eth32 to the T0s. |
| `MIRROR_ENABLED` | `1` | All 32 neighbor links are mirrored to PTF on eth33–eth64 (experimental). |

The template's default `TOPO_ID` is **102**. Addresses below are shown as `172.31.<TOPO_ID>.x`, and the commands use the `TOPO_ID` variable you set in step 1. It can run alongside T0 and T1 if the host has enough resources. The odd-numbered T2 names (`ARISTA01T2`, `ARISTA03T2`, and so on) follow sonic-mgmt's upstream T1-LAG naming.

### Deploy

1. Set the topology ID and render the template. Use the default shown here, or any unused ID:

   ```bash
   export TOPO_ID=102
   mkdir -p /tmp/kne-rendered
   sed -E "s/^name: \"[0-9]+\"/name: \"$TOPO_ID\"/; s/(key: \"TOPO_ID\" +value: \")[0-9]+\"/\1$TOPO_ID\"/" \
     topologies/t1-lag/t1-lag.pb.txt > /tmp/kne-rendered/t1-lag-$TOPO_ID.pb.txt
   ```

2. Create the topology:

   ```bash
   kne create /tmp/kne-rendered/t1-lag-$TOPO_ID.pb.txt
   ```

3. Wait for all 26 pods to reach `Running`, then allow **10–15 minutes** for the 25 VMs to boot (see [Boot timing](#boot-timing)).

   ```bash
   kubectl get pods -n $TOPO_ID -w
   ```

   After steps 4 and 5, which add the routes it relies on, check which nodes are reachable (the DUT plus `SWITCH_ID`s 10–17 and 26–41):

   ```bash
   for ip in 2 $(seq 10 17) $(seq 26 41); do
     ping -c1 -W2 172.31.$TOPO_ID.$ip >/dev/null && echo "172.31.$TOPO_ID.$ip up" || echo "172.31.$TOPO_ID.$ip down"
   done
   ```

4. Set up PTF management:

   ```bash
   ./setup_ptf_mgmt.sh /tmp/kne-rendered/t1-lag-$TOPO_ID.pb.txt
   ```

   It ends with `Done: 172.31.<TOPO_ID>.200 is assigned in pod ptf`.

5. Set up management routes:

   ```bash
   python3 setup_mgmt_routes.py /tmp/kne-rendered/t1-lag-$TOPO_ID.pb.txt
   ```

   Confirm it reports `Routes configured: 25/25`. Then confirm PTF is reachable from the host with `ping -c 3 172.31.$TOPO_ID.200`.

6. Configure the topology and run tests. Configuring the neighbors, deploying the minigraph to the DUT, and running sonic-mgmt tests are covered in [Running sonic-mgmt Tests on KNE](README.testbed.KNE.Tests.md).

### Verify

Confirm you can log in to the DUT over SSH, and check which SONiC build it's running. SSH prompts for the `admin` password, which is the SONiC VS image's default unless you've changed it:

```bash
ssh admin@172.31.$TOPO_ID.2
show version
```

The first connection asks you to confirm the DUT's host key; answer `yes`. `show version` should report the SONiC build you put in the image, with platform `x86_64-kvm_x86_64-r0`, HwSKU `Force10-S6000`, and ASIC `vs`.

Configuring and checking topology features, such as BGP neighbors, is done by the sonic-mgmt tests.

---

## Accessing Nodes

**SSH**, after `setup_mgmt_routes.py` has run and the VM has its DHCP lease:

```bash
ssh admin@172.31.<TOPO_ID>.<SWITCH_ID>
```

Log in as `admin`. SSH prompts for the password, which is the SONiC VS image's default `admin` password unless you've changed it.

**PTF** is at `172.31.<TOPO_ID>.200` once `setup_ptf_mgmt.sh` and `setup_mgmt_routes.py` have run. For a shell inside the PTF container:

```bash
kubectl exec -it -n $TOPO_ID ptf -- bash
```

**Serial console**, useful while a VM is still booting or if SSH isn't working. The port is `4321 + TOPO_ID × 256 + SWITCH_ID`, which the shell can calculate for you. For example, for the DUT (`SWITCH_ID` 2):

```bash
kubectl exec -it -n $TOPO_ID dut -- telnet localhost $((4321 + TOPO_ID * 256 + 2))
```

To open a shell inside a node's pod (not the VM), for example to inspect its `tc` rules or bridge:

```bash
kubectl exec -it -n $TOPO_ID dut -- /bin/bash
```

To see a node's boot progress and port wiring, check its pod logs:

```bash
kubectl logs -n $TOPO_ID dut
```

---

## When to Rerun the Scripts

None of the management setup or neighbor configuration persists on its own:

| Event | Rerun |
|---|---|
| Topology created (`kne create`) | `setup_ptf_mgmt.sh` and `setup_mgmt_routes.py`, then neighbor configuration |
| A SONiC pod restarts | `setup_mgmt_routes.py` (the pod's IP changes), then neighbor configuration for that node (its VM boots from a clean image) |
| The PTF pod restarts | `setup_ptf_mgmt.sh` (the pod's IP changes, and its management IP is lost) |
| Host reboots | Everything, as for a newly created topology. The cluster's pods restart along with the host. |

---

## Teardown

For each topology you created, set `TOPO_ID` to its ID, then delete the topology using the same rendered file:

```bash
export TOPO_ID=100
kne delete /tmp/kne-rendered/t0-$TOPO_ID.pb.txt
```

Confirm its pods are gone. This should report `No resources found`:

```bash
kubectl get pods -n $TOPO_ID
```

Then remove its host management route:

```bash
sudo ip route del 172.31.$TOPO_ID.0/24
```

The `kne` cluster itself stays up, so you can create topologies again without repeating the host setup.

---

## Troubleshooting

**Pods stuck in `ImagePullBackOff`**
The images weren't loaded into the cluster. Run the `kind load docker-image` commands from step 1.

**Pod logs show `WARNING: /dev/kvm not found`**
QEMU is running without hardware acceleration and will be extremely slow. Check that the host supports KVM, and enable nested virtualization if the host is a VM.

**A pod restarts, and its previous log shows `No space left on device`**
The host's disk is full. Check with `df -h /`, and see `kubectl logs -n $TOPO_ID <pod> --previous` for the failed container's log. Free space by deleting topologies you no longer need, or removing unused images with `docker image prune`.

**A VM never becomes reachable over SSH**
Check the pod log for errors, then connect to the serial console to watch the boot. Confirm the node's `SWITCH_ID` is between 2 and 254 and unique within the topology. Rerun `setup_mgmt_routes.py` if the pod has restarted.

**BGP sessions don't come up after configuring neighbors**
`configure_neighbors.py` reports `OK` even if individual commands fail. Log into an affected neighbor and check its configuration with `show ip interfaces`, `show ipv6 interfaces`, and `show running-config bgp`. Leftover default addresses or a pre-existing BGP instance on the neighbor are the most likely causes.

---

## Known Limitations

- **PTF mirroring:** experimental and not yet fully validated. See [How It Works](#how-it-works).
- **Address range:** management subnets use `172.31.0.0/16`, which is also part of Docker's default address pools. On a host with many Docker networks, Docker could eventually assign an overlapping range.
