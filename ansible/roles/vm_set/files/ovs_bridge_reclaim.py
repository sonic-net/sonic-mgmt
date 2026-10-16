#!/usr/bin/env python3
"""Report and optionally reclaim orphaned OVS bridges on a testbed server.

A testbed deployment creates OVS bridges named after the VM or the vm_set that
owns them.  ``VMTopology.destroy_bridges()`` only removes the bridges belonging
to the vm_names it was invoked with, so bridges are stranded whenever a topology
is re-deployed under a different vm_base, or whenever ``remove-topo`` does not
complete.  Nothing enumerates the leftovers again, and the only existing cleanup
(``cleanup.sh``) deletes every bridge, VM and container on the host, which is
unusable on a server shared by several testbeds.

This script fills that gap.  It determines which bridges still have an owner and
reports the rest.  It is read-only unless ``--apply`` is passed.

Ownership is established from the host itself, without needing testbed.yaml:

  * live VM names come from the ``ceos_<vm_set>_<vm>`` and ``net_<vm_set>_<vm>``
    containers and from libvirt domains;
  * live vm_set names come from the ``ptf_<vm_set>``, ``ceos_*`` and ``net_*``
    containers.

Bridges are matched to owners by reconstruction rather than by pattern matching.
``adaptive_name()`` truncates the leading characters of a template to fit the
15-byte interface name limit, so ``mbr-`` can appear as ``mb-`` or ``m-``; a
regex over prefixes would misclassify those.  Instead every name a live owner
could possibly produce is generated up front, and a bridge is only ever
considered for removal when it is absent from that set *and* decomposes to an
owner that is known to be gone.  A bridge that cannot be attributed is reported
as unknown and never touched.

Safety properties:

  * dry run by default; ``--apply`` is required to delete anything;
  * aborts if the container runtime cannot be queried, or reports no live
    vm_set, because that would make every bridge look like an orphan;
  * aborts while a deployment is running on the host;
  * only removes bridges older than ``--min-age-days``;
  * only removes bridges seen as orphaned on ``--confirmations`` consecutive
    runs, recorded in a state file, so a transient failure cannot cause a
    deletion;
  * refuses to remove more than ``--max-delete`` bridges in one run;
  * prints the reason for every decision.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

MAX_IF_NAME_LEN = 15

# Mirrors ansible/roles/vm_set/library/vm_topology.py
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
MUXY_BRIDGE_TEMPLATE = 'mbr-%s-%d'
ACTIVE_ACTIVE_BRIDGE_TEMPLATE = 'baa-%s-%d'
ROOT_BACK_BR_TEMPLATE = 'br-b-%s'
VS_CHASSIS_INBAND_BRIDGE_NAME_TEMPLATE = 'br-%s-inb'
VS_CHASSIS_MIDPLANE_BRIDGE_NAME_TEMPLATE = 'br-%s-mid'

INDEXED_TEMPLATES = (
    OVS_FP_BRIDGE_TEMPLATE,
    MUXY_BRIDGE_TEMPLATE,
    ACTIVE_ACTIVE_BRIDGE_TEMPLATE,
)

VM_NAME_RE = re.compile(r'^VM\d+$')
DEPLOY_IN_FLIGHT_RE = re.compile(r'(ansible-playbook|testbed-cli\.sh|vm_topology)')

DEFAULT_STATE_FILE = '/var/lib/sonic-testbed/ovs_bridge_reclaim.json'


def adaptive_name(template, host, index):
    """Reproduce vm_topology.adaptive_name so generated names match exactly."""
    host_index_str = '-%s-%d' % (host, index)
    leading_len = MAX_IF_NAME_LEN - len(host_index_str)
    leading_characters = template.split('-')[0][:leading_len]
    return leading_characters + host_index_str


def run(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.returncode, proc.stdout.decode('utf-8', 'replace'), proc.stderr.decode('utf-8', 'replace')


def run_lines(cmd):
    rc, out, err = run(cmd)
    if rc != 0:
        raise RuntimeError('%s failed (rc=%d): %s' % (' '.join(cmd), rc, err.strip()))
    return [line.strip() for line in out.splitlines() if line.strip()]


class Inventory(object):
    """What is currently deployed on this host."""

    def __init__(self, live_vms, live_sets, container_count):
        self.live_vms = live_vms
        self.live_sets = live_sets
        self.container_count = container_count


def discover_inventory(docker):
    try:
        names = run_lines([docker, 'ps', '-a', '--format', '{{.Names}}'])
    except (RuntimeError, OSError) as exc:
        raise RuntimeError(
            'cannot enumerate containers (%s); refusing to run, because '
            'without the container list every bridge would look orphaned' % exc)

    live_vms = set()
    live_sets = set()
    for name in names:
        for prefix in ('ceos_', 'net_'):
            if name.startswith(prefix):
                rest = name[len(prefix):]
                # <vm_set>_<VM name>; vm_set may itself contain underscores
                head, sep, tail = rest.rpartition('_')
                if sep and VM_NAME_RE.match(tail):
                    live_sets.add(head)
                    live_vms.add(tail)
                else:
                    live_sets.add(rest)
        if name.startswith('ptf_'):
            live_sets.add(name[len('ptf_'):])

    try:
        for domain in run_lines(['virsh', 'list', '--all', '--name']):
            if VM_NAME_RE.match(domain):
                live_vms.add(domain)
    except (RuntimeError, OSError):
        # libvirt is absent on cEOS-only hosts; containers already cover those.
        pass

    return Inventory(live_vms, live_sets, len(names))


def build_protected(inventory, max_index):
    """Every bridge name a live owner could produce."""
    protected = set()
    indices = range(max_index + 1)
    for vm in inventory.live_vms:
        for i in indices:
            protected.add(adaptive_name(OVS_FP_BRIDGE_TEMPLATE, vm, i))
    for vm_set in inventory.live_sets:
        protected.add(ROOT_BACK_BR_TEMPLATE % vm_set)
        protected.add(VS_CHASSIS_INBAND_BRIDGE_NAME_TEMPLATE % vm_set)
        protected.add(VS_CHASSIS_MIDPLANE_BRIDGE_NAME_TEMPLATE % vm_set)
        for i in indices:
            protected.add(adaptive_name(MUXY_BRIDGE_TEMPLATE, vm_set, i))
            protected.add(adaptive_name(ACTIVE_ACTIVE_BRIDGE_TEMPLATE, vm_set, i))
    return protected


def decompose(name):
    """Return (owner_kind, owner) for a bridge we can attribute, else None.

    owner_kind is 'vm' for front-panel bridges and 'vm_set' for the mux,
    active-active and back-panel bridges.
    """
    if name.startswith('br-b-'):
        owner = name[len('br-b-'):]
        return ('vm_set', owner) if owner else None

    parts = name.split('-')
    if len(parts) < 3:
        return None
    index_str = parts[-1]
    if not index_str.isdigit():
        return None
    owner = '-'.join(parts[1:-1])
    if not owner:
        return None
    index = int(index_str)

    for template in INDEXED_TEMPLATES:
        if adaptive_name(template, owner, index) == name:
            return ('vm', owner) if VM_NAME_RE.match(owner) else ('vm_set', owner)
    return None


def bridge_age_days(name, now):
    path = '/sys/class/net/%s' % name
    try:
        return (now - os.stat(path).st_mtime) / 86400.0
    except OSError:
        return None


def deploy_in_flight():
    rc, out, _ = run(['ps', '-eo', 'args', '--no-headers'])
    if rc != 0:
        return ['unable to read the process table']
    hits = []
    for line in out.splitlines():
        if DEPLOY_IN_FLIGHT_RE.search(line) and 'ovs_bridge_reclaim' not in line:
            hits.append(line.strip()[:120])
    return hits


def load_state(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
            return data.get('orphan_streak', {})
    except (IOError, OSError, ValueError):
        return {}


def save_state(path, streak):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except OSError as exc:
            print('warning: cannot create %s: %s' % (directory, exc))
            return
    tmp = '%s.tmp' % path
    try:
        with open(tmp, 'w') as handle:
            json.dump({'updated': int(time.time()), 'orphan_streak': streak}, handle, indent=1, sort_keys=True)
        os.rename(tmp, path)
    except (IOError, OSError) as exc:
        print('warning: cannot write %s: %s' % (path, exc))


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Report and optionally reclaim orphaned OVS bridges.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--apply', action='store_true',
                        help='delete the confirmed orphans; without this nothing is changed')
    parser.add_argument('--min-age-days', type=float, default=7.0,
                        help='never remove a bridge younger than this')
    parser.add_argument('--confirmations', type=int, default=2,
                        help='consecutive runs a bridge must be seen orphaned before removal')
    parser.add_argument('--max-delete', type=int, default=100,
                        help='refuse to remove more than this many bridges in one run')
    parser.add_argument('--state-file', default=DEFAULT_STATE_FILE,
                        help='where the per-run confirmation counters are kept')
    parser.add_argument('--docker', default='docker', help='container runtime executable')
    parser.add_argument('--json', action='store_true', help='emit a machine-readable summary')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    now = time.time()

    try:
        bridges = run_lines(['ovs-vsctl', 'list-br'])
    except (RuntimeError, OSError) as exc:
        print('error: %s' % exc)
        return 2

    try:
        inventory = discover_inventory(args.docker)
    except RuntimeError as exc:
        print('error: %s' % exc)
        return 2

    if not inventory.live_sets:
        print('error: no live vm_set found among %d containers; refusing to run, '
              'because that would classify every bridge as an orphan'
              % inventory.container_count)
        return 2

    in_flight = deploy_in_flight()
    if in_flight:
        print('a deployment appears to be running; not removing anything:')
        for line in in_flight:
            print('  %s' % line)

    protected = build_protected(inventory, max_index=255)

    orphans = []
    unknown = []
    in_use = []
    for name in bridges:
        if name in protected:
            in_use.append(name)
            continue
        attribution = decompose(name)
        if attribution is None:
            unknown.append(name)
            continue
        kind, owner = attribution
        live = inventory.live_vms if kind == 'vm' else inventory.live_sets
        if owner in live:
            in_use.append(name)
        else:
            orphans.append((name, kind, owner))

    streak = load_state(args.state_file)
    orphan_names = set(name for name, _, _ in orphans)
    new_streak = {name: streak.get(name, 0) + 1 for name in orphan_names}

    deletable = []
    held = []
    for name, kind, owner in sorted(orphans):
        age = bridge_age_days(name, now)
        seen = new_streak[name]
        if age is None:
            held.append((name, 'age unavailable'))
        elif age < args.min_age_days:
            held.append((name, 'age %.1fd < %.1fd' % (age, args.min_age_days)))
        elif seen < args.confirmations:
            held.append((name, 'confirmed %d/%d runs' % (seen, args.confirmations)))
        else:
            deletable.append((name, kind, owner, age))

    print('bridges=%d  attributed_in_use=%d  orphaned=%d  unattributed=%d'
          % (len(bridges), len(in_use), len(orphans), len(unknown)))
    print('live vm_sets=%d  live VMs=%d  containers=%d'
          % (len(inventory.live_sets), len(inventory.live_vms), inventory.container_count))

    if orphans:
        print('\norphaned bridges (owner no longer present on this host):')
        for name, kind, owner, age in deletable:
            print('  %-20s %-7s owner=%-16s age=%5.1fd  ELIGIBLE' % (name, kind, owner, age))
        for name, reason in held:
            print('  %-20s %-7s %s  HELD' % (name, '', reason))

    if unknown:
        print('\nunattributed bridges, left untouched (%d):' % len(unknown))
        for name in sorted(unknown)[:20]:
            print('  %s' % name)
        if len(unknown) > 20:
            print('  ... and %d more' % (len(unknown) - 20))

    removed = []
    blocked = None
    if args.apply and deletable and not in_flight:
        if len(deletable) > args.max_delete:
            blocked = ('%d bridges are eligible, which exceeds --max-delete=%d; '
                       'nothing removed' % (len(deletable), args.max_delete))
            print('\n%s' % blocked)
        else:
            print('\nremoving %d bridges:' % len(deletable))
            for name, _, owner, _ in deletable:
                rc, _, err = run(['ovs-vsctl', '--if-exists', 'del-br', name])
                if rc == 0:
                    removed.append(name)
                    new_streak.pop(name, None)
                    print('  removed %s (owner %s)' % (name, owner))
                else:
                    print('  FAILED  %s: %s' % (name, err.strip()))
    elif deletable:
        print('\n%d bridges are eligible for removal; re-run with --apply to remove them'
              % len(deletable))

    save_state(args.state_file, new_streak)

    if args.json:
        print(json.dumps({
            'bridges': len(bridges),
            'in_use': len(in_use),
            'orphaned': len(orphans),
            'unattributed': len(unknown),
            'eligible': [name for name, _, _, _ in deletable],
            'removed': removed,
            'blocked': blocked,
            'live_vm_sets': sorted(inventory.live_sets),
        }, indent=1, sort_keys=True))

    return 0


if __name__ == '__main__':
    sys.exit(main())
