#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import jinja2  # nosemgrep: direct-use-of-jinja2
import glob
import hashlib
import json
import multiprocessing
import os
import re
import sys
import tempfile
import traceback
import time

DOCUMENTATION = '''
---
module: gobgp
version_added: "1.0"
short_description: manage the gobgp-backed PTF BGP speaker (drop-in for exabgp)
description:
    - Start/stop the GoBGP PTF speaker. Each neighbor gets a dedicated gobgpd
      holding exactly that one BGP session, so a route POSTed to a neighbor's
      port advertises only over that session, the same semantics exabgp
      provides. In front of them sits a pool of HTTP shim processes
      (ansible/roles/vm_set/files/gobgp) that accept the ExaBGP HTTP grammar and
      translate it into gobgpd gRPC AddPath/DeletePath.
    - The shim pool is sized min(cores, ports), each member owning a disjoint
      shard of the neighbor ports per gobgp.shardmap. That module is imported
      rather than reimplemented, so the manager and the shims cannot disagree
      about which shim owns which port.
    - Configuration is two-phase, because the pool spans the whole topology.
      state=configure runs once per neighbor and only writes files, then
      state=pool (or started) runs once to merge every neighbor's contribution
      and render the pool. The pool phase is idempotent and may be re-run after
      more neighbors are configured.
    - The deployed package must sit at <GOBGP_PKG_DIR>/gobgp/, which is both
      this module's import root and the shims' PYTHONPATH.
options:
    name:
        description:
            - Instance name, per neighbor and family (ARISTA01T1, ARISTA01T1-v6).
        required: true
    state:
        description:
            - configure, present, absent and status act on one neighbor.
            - pool, started, restarted and stopped act on the whole speaker.
        required: true
        choices: [configure, pool, started, restarted, stopped, present, absent, status]
    router_id:
        description:
            - BGP router id for this neighbor's daemon.
        required: false
    local_ip:
        description:
            - Local transport address; shared by every PTF speaker.
        required: false
    peer_ip:
        description:
            - Neighbor address this daemon connects out to.
        required: false
    local_asn:
        description:
            - Local AS number.
        required: false
    peer_asn:
        description:
            - Peer AS number.
        required: false
    port:
        description:
            - HTTP port the shim serves this neighbor on; also derives the
              gRPC port.
        required: false
        default: 5000
    passive:
        description:
            - Accepted for exabgp parity and rejected. gobgpd listens only when
              the global port is positive, and it is fixed at -1 here.
        required: false
        default: false
    debug:
        description:
            - Raise gobgpd log level to debug.
        required: false
        default: false
'''

EXAMPLES = '''
# Phase 1 -- once per neighbor, writes config only
- name: configure gobgp speaker
  gobgp:
    name: ARISTA01T1
    state: configure
    router_id: 10.0.0.0
    local_ip: 10.0.0.0
    peer_ip: 10.0.0.1
    local_asn: 65534
    peer_asn: 65535
    port: 5000

# Phase 2 -- once, after every neighbor is configured
- name: start the gobgp speaker
  gobgp:
    name: pool
    state: started

- name: stop the gobgp speaker
  gobgp:
    name: pool
    state: stopped
'''

DEFAULT_BGP_LISTEN_PORT = 179
# gRPC port derived deterministically from the HTTP port so it never collides:
#   v4 http 5000+off -> grpc 61000+off ;  v6 http 6000+off -> grpc 62000+off
# The offset also places the band above net.ipv4.ip_local_port_range, whose
# per-netns kernel default is 32768-60999, and inside the 16-bit port space. The
# shims hold one loopback gRPC channel per neighbor, so an ephemeral source port
# could otherwise take the API port a restarting gobgpd must re-bind.
GRPC_PORT_OFFSET = 56000

GOBGP_BIN = "/usr/local/bin/gobgpd"
GOBGP_CLI = "/usr/local/bin/gobgp"
# Directory holding the deployed `gobgp` python package (shim + shardmap).
GOBGP_PKG_DIR = os.environ.get("GOBGP_PKG_DIR", "/usr/share/gobgp")
GOBGP_CONF_DIR = "/etc/gobgp"
# One file per neighbor, merged into the topology-wide portmap by the pool
# phase. A spool directory rather than an accumulating single file so that a
# re-run of `configure` for one neighbor cannot corrupt the others' entries.
PORTMAP_SPOOL_DIR = os.path.join(GOBGP_CONF_DIR, "portmap.d")
PORTMAP_PATH = os.path.join(GOBGP_CONF_DIR, "portmap.json")
SUPERVISOR_CONF_DIR = "/etc/supervisor/conf.d"

V4_GROUP = "gobgpv4"
V6_GROUP = "gobgpv6"
SHIM_GROUP = "gobgpshim"
# The shim pool is sharded by port, and shardmap deliberately round-robins over
# the sorted port list so one shard fronts both families. The pool therefore
# cannot be split into v4/v6 groups the way the gobgpd programs are.
ALL_GROUPS = (V4_GROUP, V6_GROUP, SHIM_GROUP)

# Bounds of the shim HTTP band the manager is given ports from (filters.py port
# math), and the basis of the derived gRPC band.
SHIM_PORT_MIN = 5000
SHIM_PORT_MAX = 6999

# These templates render config files from internal identifiers and paths.
# autoescape stays on at every render site so they are clear of the XSS sink
# pattern; the rendered output is unchanged either way.
#
# gobgpd TOML config: a single neighbor. gobgpd does not listen (port = -1) and
# connects out to peer_ip, because all PTF speakers share one local_ip and
# multiple listening daemons would collide on <local_ip>:179. Passive mode is
# rejected in setup_gobgp_conf for the same reason.
gobgpd_config_template = '''\
[global.config]
  as = {{ local_asn }}
  router-id = "{{ router_id }}"
  port = -1
  local-address-list = ["{{ local_ip }}"]

[[neighbors]]
  [neighbors.config]
    neighbor-address = "{{ peer_ip }}"
    peer-as = {{ peer_asn }}
  [neighbors.transport.config]
    local-address = "{{ local_ip }}"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-unicast"
'''

# supervisord program for one gobgpd. Both HTTP flags are required: pprof and
# prometheus metrics share a single listener that starts unless both are off,
# and its 127.0.0.1:6060 default is the v6 shim port at offset 60.
gobgpd_supervisord_tmpl = '''\
[program:gobgpd-{{ name }}]
command={{ gobgpd }} -f {{ conf_dir }}/{{ name }}.toml -t toml \
--api-hosts 127.0.0.1:{{ grpc_port }} --pprof-disable --metrics-path ""\
{% if debug %} --log-level debug{% endif %}
stdout_logfile=/tmp/gobgpd-{{ name }}.out.log
stderr_logfile=/tmp/gobgpd-{{ name }}.err.log
stdout_logfile_maxbytes=10000000
stdout_logfile_backups=2
stderr_logfile_maxbytes=10000000
stderr_logfile_backups=2
redirect_stderr=false
autostart=false
autorestart=true
startsecs=1
numprocs=1
priority=100
'''

# One program per shard. `-m gobgp.shim` runs the deployed package; PYTHONPATH
# points at its parent so the import works without installing it.
#
# GOBGP_PORTMAP_DIGEST makes a portmap content change a program *configuration*
# change. The shim reads portmap.json once at startup, and `supervisorctl update`
# restarts only programs whose configuration changed -- it does not watch data
# files. Without the digest, a later pool run that adds ports without changing
# the shard count renders an identical block, and the added ports never bind.
gobgp_shim_supervisord_tmpl = '''\
[program:gobgp-shim-{{ index }}]
command=/usr/bin/env python3 -m gobgp.shim --portmap {{ portmap }} \
--shard {{ index }}/{{ shards }}{% if debug %} --debug{% endif %}
environment=PYTHONPATH="{{ pkg_dir }}",GOBGP_PORTMAP_DIGEST="{{ digest }}"
stdout_logfile=/tmp/gobgp-shim-{{ index }}.out.log
stderr_logfile=/tmp/gobgp-shim-{{ index }}.err.log
stdout_logfile_maxbytes=10000000
stdout_logfile_backups=2
stderr_logfile_maxbytes=10000000
stderr_logfile_backups=2
redirect_stderr=false
autostart=false
autorestart=true
startsecs=1
numprocs=1
priority=200
'''

group_supervisord_tmpl = '''\
[group:{{ group }}]
programs={{ programs }}
'''


def load_shardmap():
    """Import the deployed ``gobgp.shardmap``.

    Imported, never reimplemented: the shim resolves its own shard with these
    same helpers, so a second copy of the port-split logic here would be a
    silent-divergence bug waiting to happen.
    """
    if GOBGP_PKG_DIR not in sys.path:
        sys.path.insert(0, GOBGP_PKG_DIR)
    try:
        from gobgp import shardmap
    except ImportError as exc:
        # GOBGP_PKG_DIR is both the import root here and the shims' PYTHONPATH,
        # so it must be the package's parent. The bare ImportError does not say so.
        raise ImportError(
            "cannot import gobgp.shardmap from %s (%s). GOBGP_PKG_DIR must be "
            "the PARENT of the deployed package: the package itself has to be "
            "%s/gobgp/ containing __init__.py, shardmap.py and shim/. A flat "
            "layout that copies those files directly into %s will fail here "
            "and in every shim, which receives the same path as PYTHONPATH."
            % (GOBGP_PKG_DIR, exc, GOBGP_PKG_DIR, GOBGP_PKG_DIR))
    return shardmap


def grpc_port_for(port):
    return int(port) + GRPC_PORT_OFFSET


def family_for(port):
    # v6 speakers use the 6000+ HTTP port range (see filters.py port math)
    return "v6" if int(port) >= 6000 else "v4"


def exec_command(module, cmd, ignore_error=False, msg="executing command"):
    rc, out, err = module.run_command(cmd)
    if not ignore_error and rc != 0:
        module.fail_json(msg="Failed %s: rc=%d, out=%s, err=%s" %
                         (msg, rc, out, err))
    return out


def _write(path, data):
    """Write via a temp file and rename.

    The shim reloads its portmap on restart, and supervisord restarts it
    automatically, so a crash landing in the middle of a pool re-render could
    otherwise read a half-written file.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.rename(tmp, path)
    except Exception:
        _remove(tmp)
        raise


def _remove(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def refresh_supervisord(module):
    exec_command(module, cmd="supervisorctl reread", ignore_error=True)
    exec_command(module, cmd="supervisorctl update", ignore_error=True)


def _status_lines(output):
    """``supervisorctl status`` output -> {program: state}."""
    states = {}
    for line in output.splitlines():
        m = re.match(r'^(\S+)\s+(\w+)', line.strip())
        if m:
            states[m.group(1)] = m.group(2)
    return states


def get_gobgp_status(module, name):
    output = exec_command(module, cmd="supervisorctl status gobgpd-%s" % name,
                          ignore_error=True)
    return _status_lines(output).get("gobgpd-%s" % name, "UNKNOWN")


def wait_groups_running(module, groups, timeout=300):
    """Poll whole groups until every member is RUNNING.

    Polling the group in one call rather than each program in turn matters at
    fleet scale: a per-program wait serializes hundreds of timeouts, and a
    single slow bind under load would blow the play's budget on its own.
    """
    deadline = time.monotonic() + timeout
    pending = {}
    while time.monotonic() < deadline:
        pending = {}
        for group in groups:
            out = exec_command(module, cmd="supervisorctl status %s:" % group,
                               ignore_error=True)
            states = _status_lines(out)
            if not states:
                # No output also means an unreachable supervisord or an
                # unloaded group, so it cannot count as ready.
                pending["%s:" % group] = "UNKNOWN"
                continue
            for program, state in states.items():
                if state != "RUNNING":
                    pending[program] = state
        if not pending:
            return
        time.sleep(2)
    module.fail_json(msg="gobgp speaker not ready after %ds; pending=%s"
                         % (timeout, pending))


def setup_gobgp_conf(name, router_id, local_ip, peer_ip, local_asn, peer_asn,
                     port, passive=False, debug=False):
    """Phase 1: everything that concerns exactly one neighbor."""
    if passive:
        # port = -1 leaves gobgpd without a listener, and passive suppresses the
        # outbound connect, so the session has no way to establish.
        raise ValueError(
            "passive=True is unsupported by the gobgp speaker: gobgpd listens "
            "only when the global port is positive, and it is fixed at -1 so "
            "every neighbor's daemon can share one local_ip. Passive mode "
            "suppresses the outbound connect, leaving no way to establish.")

    os.makedirs(GOBGP_CONF_DIR, 0o755, exist_ok=True)
    os.makedirs(PORTMAP_SPOOL_DIR, 0o755, exist_ok=True)

    data = jinja2.Template(gobgpd_config_template, autoescape=True).render(  # nosemgrep: direct-use-of-jinja2
        local_asn=local_asn, router_id=router_id, local_ip=local_ip,
        peer_ip=peer_ip, peer_asn=peer_asn)
    _write("%s/%s.toml" % (GOBGP_CONF_DIR, name), data)

    block = jinja2.Template(gobgpd_supervisord_tmpl, autoescape=True).render(  # nosemgrep: direct-use-of-jinja2
        name=name, gobgpd=GOBGP_BIN, conf_dir=GOBGP_CONF_DIR,
        grpc_port=grpc_port_for(port), debug=debug)
    _write("%s/gobgpd-%s.conf" % (SUPERVISOR_CONF_DIR, name), block)

    # This neighbor's contribution to the topology-wide portmap.
    entry = {
        str(port): {
            "grpc": "127.0.0.1:%d" % grpc_port_for(port),
            "family": family_for(port),
            "name": name,
            "peer": peer_ip,
            "self_nexthop": local_ip,
        }
    }
    _write("%s/%s.json" % (PORTMAP_SPOOL_DIR, name), json.dumps(entry))


def collect_portmap():
    """Merge every neighbor's spool entry into the topology-wide portmap."""
    portmap = {}
    for path in sorted(glob.glob("%s/*.json" % PORTMAP_SPOOL_DIR)):
        with open(path) as f:
            portmap.update(json.load(f))
    return portmap


def render_pool(portmap, core_count=None, debug=False):
    """Phase 2: render the portmap, the shim shard programs and the groups.

    Returns the rendered shard count. Idempotent -- every file it owns is
    rewritten from the current spool, and all shard programs live in one file so
    a shrinking pool cannot leave orphaned per-shard files behind.

    Convergence covers the running processes too: the portmap digest is embedded
    in each shim program, so a changed portmap is a changed configuration and
    ``supervisorctl update`` restarts the pool onto the new map.
    """
    shardmap = load_shardmap()
    os.makedirs(GOBGP_CONF_DIR, 0o755, exist_ok=True)
    serialized = json.dumps(portmap, indent=2, sort_keys=True)
    _write(PORTMAP_PATH, serialized)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]

    if core_count is None:
        core_count = multiprocessing.cpu_count()
    k = shardmap.num_shards(core_count, len(portmap))
    # num_shards caps at the port count, but partition() additionally clamps to
    # a non-empty split; render exactly what it yields, or a shim launched with
    # an out-of-range index would exit on IndexError.
    shards = shardmap.partition(portmap, k)
    k = len(shards)

    blocks = [
        jinja2.Template(gobgp_shim_supervisord_tmpl, autoescape=True).render(  # nosemgrep: direct-use-of-jinja2
            index=i, shards=k, portmap=PORTMAP_PATH, pkg_dir=GOBGP_PKG_DIR,
            digest=digest, debug=debug)
        for i in range(k)
    ]
    blocks.append(jinja2.Template(group_supervisord_tmpl, autoescape=True).render(  # nosemgrep: direct-use-of-jinja2
        group=SHIM_GROUP,
        programs=",".join("gobgp-shim-%d" % i for i in range(k))))
    _write("%s/%s.conf" % (SUPERVISOR_CONF_DIR, SHIM_GROUP), "\n".join(blocks))

    for group, family in ((V4_GROUP, "v4"), (V6_GROUP, "v6")):
        names = [spec["name"] for _, spec in sorted(portmap.items(), key=lambda kv: int(kv[0]))
                 if spec.get("family") == family]
        path = "%s/%s.conf" % (SUPERVISOR_CONF_DIR, group)
        if not names:
            # An empty `programs=` is a supervisord config error, so a topology
            # with only one family must not leave a stale group file behind.
            _remove(path)
            continue
        _write(path, jinja2.Template(group_supervisord_tmpl, autoescape=True).render(  # nosemgrep: direct-use-of-jinja2
            group=group, programs=",".join("gobgpd-%s" % n for n in names)))

    return k


def existing_groups():
    return [g for g in ALL_GROUPS
            if os.path.exists("%s/%s.conf" % (SUPERVISOR_CONF_DIR, g))]


def start_gobgp(module, groups):
    """Start gobgpd first, then the shims.

    Ordering is deliberate: the shims dial the gRPC endpoints, and starting them
    second means a shard's first request does not race a daemon that has not yet
    opened its API socket.
    """
    for group in groups:
        exec_command(module, cmd="supervisorctl start %s:" % group,
                     ignore_error=True)
    wait_groups_running(module, groups)


def stop_gobgp(module, groups):
    # Reverse of start: drop the front end before the daemons behind it.
    for group in reversed(groups):
        exec_command(module, cmd="supervisorctl stop %s:" % group,
                     ignore_error=True)


def remove_gobgp_conf(name):
    for path in ("%s/%s.toml" % (GOBGP_CONF_DIR, name),
                 "%s/%s.json" % (PORTMAP_SPOOL_DIR, name),
                 "%s/gobgpd-%s.conf" % (SUPERVISOR_CONF_DIR, name)):
        _remove(path)


def remove_neighbor(module, name, debug=False):
    """Drop one neighbor and reconverge the pool around it.

    Only this neighbor's daemon is stopped; the rest of the fleet keeps serving.
    """
    exec_command(module, cmd="supervisorctl stop gobgpd-%s" % name,
                 ignore_error=True)
    remove_gobgp_conf(name)
    # The group files still name this neighbor's program, and supervisord fails
    # to load a group whose `programs=` references a missing section, wedging
    # the family rather than the one neighbor.
    render_pool(collect_portmap(), debug=debug)
    refresh_supervisord(module)


def fail_with_traceback(module, exc):
    """Fail with the exception message and a real traceback.

    Failures here name a missing package or an unwritable path, so the frame is
    the diagnostic.
    """
    module.fail_json(msg="Error: %s" % exc, traceback=traceback.format_exc())


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True, type='str'),
            state=dict(required=True, choices=[
                'configure', 'pool', 'started', 'restarted', 'stopped',
                'present', 'absent', 'status'], type='str'),
            router_id=dict(required=False, type='str'),
            local_ip=dict(required=False, type='str'),
            peer_ip=dict(required=False, type='str'),
            local_asn=dict(required=False, type='int'),
            peer_asn=dict(required=False, type='int'),
            port=dict(required=False, type='int', default=5000),
            passive=dict(required=False, type='bool', default=False),
            debug=dict(required=False, type='bool', default=False),
        ),
        supports_check_mode=False)

    p = module.params
    name = p['name']
    state = p['state']

    result = {}
    try:
        if state in ('configure', 'present'):
            setup_gobgp_conf(name, p['router_id'], p['local_ip'], p['peer_ip'],
                             p['local_asn'], p['peer_asn'], p['port'],
                             passive=p['passive'], debug=p['debug'])
            if state == 'present':
                refresh_supervisord(module)
        elif state in ('pool', 'started', 'restarted'):
            portmap = collect_portmap()
            shards = render_pool(portmap, debug=p['debug'])
            result = {'shards': shards, 'ports': len(portmap)}
            refresh_supervisord(module)
            groups = existing_groups()
            if state == 'restarted':
                stop_gobgp(module, groups)
            if state in ('started', 'restarted'):
                start_gobgp(module, groups)
        elif state == 'stopped':
            stop_gobgp(module, existing_groups())
        elif state == 'absent':
            remove_neighbor(module, name, debug=p['debug'])
        elif state == 'status':
            result = {'status': get_gobgp_status(module, name)}
    except Exception as exc:
        fail_with_traceback(module, exc)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
