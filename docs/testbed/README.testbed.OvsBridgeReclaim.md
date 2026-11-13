# Reclaiming orphaned OVS bridges

## Why this exists

A testbed deployment creates OVS bridges named after the VM or the vm_set that
owns them. `VMTopology.destroy_bridges()` only removes the bridges belonging to
the `vm_names` it was invoked with, which are derived from the `vm_base` of the
topology currently being removed:

```python
def destroy_bridges(self):
    for vm in self.vm_names:
        for fp_num in range(self.max_fp_num):
            fp_br_name = adaptive_name(OVS_FP_BRIDGE_TEMPLATE, vm, fp_num)
            self.destroy_ovs_bridge(fp_br_name)
```

Bridges are therefore stranded whenever a topology is re-deployed under a
different `vm_base`, or whenever `remove-topo` does not complete. Nothing
enumerates the leftovers again — the only `ovs-vsctl list-br` in
`vm_topology.py` is inside `wait_for_bridges_cleanup()`, which just confirms
that the bridges it already deleted are gone.

The one existing cleanup path is `cleanup-vmhost`, which runs
`roles/vm_set/templates/cleanup.sh.j2`:

```bash
test -z "$(ovs-vsctl list-br)" || ovs-vsctl list-br | xargs -I % ovs-vsctl del-br %
test -z "$(docker ps -a -q)"   || docker rm -f $(docker ps -a -q)
test -z "$(docker images -q)"  || docker rmi -f $(docker images -q|uniq)
```

That deletes every bridge, VM, container and image on the machine. It is correct
for a server being rebuilt and unusable on a server shared by several testbeds,
so in practice hosts are left to accumulate instead. This script is the missing
middle ground: it removes only what it can prove is unowned.

## Where bridges are created and destroyed

Useful context for interpreting the output, because most testbed operations do
not touch bridges at all:

| testbed-cli action | creates bridges | destroys bridges |
|---|---|---|
| `start-vms` | yes (`start.yml`, `cmd=create`) | no |
| `stop-vms` | no | yes (`stop.yml`, `cmd=destroy`) |
| `add-topo` | yes (`add_ceos_list.yml`, `cmd=create`) | no, there is no pre-clean |
| `remove-topo` | no | yes, the current `VM_targets` only |
| `redeploy-topo` | yes | best effort — `remove_topo "$@" \|\| true` |
| `restart-ptf` | no | no — `renumber_topo.yml` only unbinds and re-binds |
| `deploy-mg` | no | no — it runs against the DUT, not the vm_host |

Steady-state nightly runs that only use `restart-ptf` and `deploy-mg` neither
create nor reclaim anything, so leftovers are never revisited. Creation is
unconditional while destruction is scoped to the caller's own targets, and that
asymmetry is what accumulates.

## How ownership is decided

The script uses only information available on the server, so it does not need
`testbed.yaml`:

* live VM names come from the `ceos_<vm_set>_<vm>` and `net_<vm_set>_<vm>`
  containers and from libvirt domains matching `VM<digits>`;
* live vm_set names come from the `ptf_<vm_set>`, `ceos_*` and `net_*`
  containers.

Bridges are matched to owners by **reconstruction**, not by pattern matching.
`adaptive_name()` truncates the leading characters of a template to fit the
15-byte interface name limit, so `mbr-` can legitimately appear as `mb-` or
`m-`:

```python
MAX_LEN = 15
host_index_str = '-%s-%d' % (host, index)
leading_len = MAX_LEN - len(host_index_str)
leading_characters = template.split('-')[0][:leading_len]
```

A regex over prefixes would misclassify those. Instead the script generates
every name each live owner could produce — across `br-%s-%d`, `mbr-%s-%d`,
`baa-%s-%d`, `br-b-%s`, `br-%s-inb` and `br-%s-mid` — and treats that set as
protected. A bridge is only considered for removal when it is **absent from the
protected set** *and* decomposes to an owner that is **known to be gone**. A
bridge that cannot be attributed is reported as unattributed and never touched.

This ordering matters. `br-b-vms93-4` decomposes ambiguously: it is the back
bridge of vm_set `vms93-4`, but it also reconstructs exactly as a front-panel
bridge of a host called `b-vms93` at index 4. Building the protected set from
live owners first means the live interpretation always wins.

## Safety properties

* Dry run by default. `--apply` is required before anything is deleted.
* Aborts if the container runtime cannot be queried, or reports no live vm_set.
  Without the container list every bridge would look orphaned, so failing to
  read it must never be treated as "nothing is deployed".
* Aborts the removal step while `ansible-playbook`, `testbed-cli.sh` or
  `vm_topology` is running on the host.
* Only removes bridges older than `--min-age-days` (default 7), using the
  `/sys/class/net/<bridge>` mtime.
* Only removes bridges that were seen as orphaned on `--confirmations`
  consecutive runs (default 2), tracked in a state file. A transient container
  runtime failure cannot cause a deletion.
* Refuses to remove more than `--max-delete` bridges in one run (default 100).
* Prints the reason for every decision, including the ones it held back.

With the defaults, a bridge must be unowned for at least seven days *and*
observed twice before it is removed.

## Usage

```bash
# Report only. Safe to run at any time.
sudo python3 ovs_bridge_reclaim.py

# Machine-readable, for health checks and dashboards.
sudo python3 ovs_bridge_reclaim.py --json

# Remove the confirmed orphans.
sudo python3 ovs_bridge_reclaim.py --apply

# More conservative: only bridges unowned for a month, confirmed three times.
sudo python3 ovs_bridge_reclaim.py --apply --min-age-days 30 --confirmations 3
```

Sample output from a server running four testbeds:

```
bridges=2104  attributed_in_use=2028  orphaned=76  unattributed=0
live vm_sets=4  live VMs=283  containers=477

orphaned bridges (owner no longer present on this host):
  br-VM93163-0         vm      owner=VM93163          age=143.0d  ELIGIBLE
  br-VM93163-1         vm      owner=VM93163          age=143.0d  ELIGIBLE
  ...
```

Every bridge on that host was attributed, including the `mbr-` and `baa-`
bridges of the dualtor testbed, and 76 bridges from 19 VMs that were removed in
May were identified as orphans.

## Scheduling

`ovs-bridge-reclaim.service` and `ovs-bridge-reclaim.timer` are provided
alongside the script. They are not installed automatically, so that adopting
this is an explicit per-fleet decision.

```bash
sudo install -D -m 0755 ovs_bridge_reclaim.py /opt/sonic-testbed/ovs_bridge_reclaim.py
sudo install -m 0644 ovs-bridge-reclaim.service /etc/systemd/system/
sudo install -m 0644 ovs-bridge-reclaim.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ovs-bridge-reclaim.timer

systemctl list-timers ovs-bridge-reclaim.timer
journalctl -u ovs-bridge-reclaim.service -n 50
```

The unit ships in reporting mode. Review a few days of output on the host, then
add `--apply` to `ExecStart` when the list of orphans looks right.

## What this does not fix

On the server measured above, the orphans are 76 of 2104 bridges — about 3.6 %.
The other 2028 belong to 283 neighbour VMs that are genuinely deployed, because
that one host carries four topologies at once. Reclaiming orphans keeps the
growth bounded and is worth doing, but on a host that is simply carrying too
many topologies it will not meaningfully reduce `ovs-vswitchd` load. That needs
the topologies to be spread across more servers.

See #28198 for the measurements behind this.
