"""Unit tests for the ``gobgp`` ansible module (the speaker manager).

The manager renders config; it never talks to a DUT, so everything here runs
against a temporary directory tree with ``supervisorctl`` faked out.

The invariant worth most of these tests is that the manager and the shim agree
about the port split. The manager is required to *import* ``gobgp.shardmap``
rather than reimplement it, so the tests assert the rendered artifacts against
``shardmap.partition`` directly -- if the manager ever grows its own copy of the
math, these fail.
"""
import ast
import hashlib
import itertools
import json
import os
import sys
import types

import pytest
import yaml

from gobgp import shardmap


def _load_manager():
    """Import ``ansible/library/gobgp.py`` without a real ansible install.

    Ansible is absent here, and the module is a stand-alone library file rather
    than an importable package, so stub the one ansible symbol it needs and load
    it by path.
    """
    if 'ansible' not in sys.modules:
        ansible = types.ModuleType('ansible')
        module_utils = types.ModuleType('ansible.module_utils')
        basic = types.ModuleType('ansible.module_utils.basic')
        basic.AnsibleModule = object
        ansible.module_utils = module_utils
        module_utils.basic = basic
        sys.modules['ansible'] = ansible
        sys.modules['ansible.module_utils'] = module_utils
        sys.modules['ansible.module_utils.basic'] = basic

    here = os.path.dirname(os.path.abspath(__file__))
    library = os.path.abspath(
        os.path.join(here, os.pardir, os.pardir, os.pardir, os.pardir,
                     os.pardir, 'library'))
    path = os.path.join(library, 'gobgp.py')
    if not os.path.exists(path):
        pytest.skip("ansible/library/gobgp.py not found at %s" % path)

    if sys.version_info[0] >= 3:
        import importlib.util
        spec = importlib.util.spec_from_file_location("gobgp_manager", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    else:  # pragma: no cover - repo is py3, kept so the import cannot silently pass
        import imp
        mod = imp.load_source("gobgp_manager", path)
    return mod


mgr = _load_manager()


class FakeModule(object):
    """Records ``supervisorctl`` invocations and replays canned status output."""

    def __init__(self, statuses=None, failing=()):
        self.commands = []
        # {group: [output, output, ...]} consumed in order, last one repeats.
        self.statuses = statuses or {}
        # command prefixes that exit non-zero, e.g. "supervisorctl reread".
        self.failing = tuple(failing)
        self.failed = None
        self.fail_kwargs = {}
        self.logs = []

    def log(self, msg):
        self.logs.append(msg)

    def run_command(self, cmd):
        self.commands.append(cmd)
        for prefix in self.failing:
            if cmd.startswith(prefix):
                return 1, "", "%s: ERROR" % prefix
        if cmd.startswith("supervisorctl status "):
            target = cmd.split()[-1].rstrip(':')
            outputs = self.statuses.get(target)
            if outputs:
                out = outputs[0] if len(outputs) == 1 else outputs.pop(0)
                return 0, out, ""
            return 0, "", ""
        return 0, "", ""

    def fail_json(self, msg=None, **kw):
        self.failed = msg
        self.fail_kwargs = kw
        raise AssertionError(msg)

    @property
    def supervisor_actions(self):
        return [c for c in self.commands
                if c.startswith("supervisorctl start")
                or c.startswith("supervisorctl stop")]


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """Point every path the manager writes to at a temp tree."""
    conf = tmp_path / "gobgp"
    spool = conf / "portmap.d"
    supervisor = tmp_path / "conf.d"
    pkg = tmp_path / "pkg"
    for d in (conf, spool, supervisor, pkg):
        d.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(mgr, "GOBGP_CONF_DIR", str(conf))
    monkeypatch.setattr(mgr, "PORTMAP_SPOOL_DIR", str(spool))
    monkeypatch.setattr(mgr, "PORTMAP_PATH", str(conf / "portmap.json"))
    monkeypatch.setattr(mgr, "SUPERVISOR_CONF_DIR", str(supervisor))
    monkeypatch.setattr(mgr, "GOBGP_PKG_DIR", str(pkg))
    return types.SimpleNamespace(conf=conf, spool=spool, supervisor=supervisor,
                                 pkg=pkg)


def configure(n, family="v4", base_port=5000):
    """Configure ``n`` neighbors of one family, returning their names."""
    names = []
    for off in range(n):
        name = "ARISTA%02dT1" % (off + 1)
        if family == "v6":
            name += "-v6"
        mgr.setup_gobgp_conf(
            name=name, router_id="10.10.246.254", local_ip="10.10.246.254",
            peer_ip="10.0.0.%d" % (off + 1), local_asn=65534, peer_asn=65535,
            port=base_port + off)
        names.append(name)
    return names


def read(path):
    with open(str(path)) as f:
        return f.read()


# --- phase 1: per-neighbor configure -----------------------------------------

def test_configure_writes_toml_program_and_spool_entry(tree):
    configure(1)

    toml = read(tree.conf / "ARISTA01T1.toml")
    # gobgpd must not listen: every PTF speaker shares one local_ip, so a
    # listening daemon would collide on <local_ip>:179 with its siblings.
    assert "port = -1" in toml
    assert 'neighbor-address = "10.0.0.1"' in toml
    assert 'local-address = "10.10.246.254"' in toml
    assert "passive-mode" not in toml

    program = read(tree.supervisor / "gobgpd-ARISTA01T1.conf")
    assert "[program:gobgpd-ARISTA01T1]" in program
    # The pool phase owns startup ordering, so programs must not self-start.
    assert "autostart=false" in program

    entry = json.loads(read(tree.spool / "ARISTA01T1.json"))
    assert entry == {
        "5000": {
            "grpc": "127.0.0.1:61000",
            "family": "v4",
            "name": "ARISTA01T1",
            "peer": "10.0.0.1",
            "self_nexthop": "10.10.246.254",
        }
    }


def test_configure_rejects_passive(tree):
    """port = -1 leaves gobgpd without a listener and passive suppresses the
    outbound connect, so the pair renders a config that starts and never
    establishes.
    """
    with pytest.raises(ValueError) as excinfo:
        mgr.setup_gobgp_conf("N", "10.0.0.0", "10.0.0.0", "10.0.0.1", 1, 2,
                             5000, passive=True)
    assert "passive" in str(excinfo.value).lower()
    assert not (tree.conf / "N.toml").exists()


def test_gobgpd_http_listener_is_disabled(tree):
    """gobgpd serves pprof and prometheus metrics from one HTTP listener.

    Disabling either alone leaves it bound, and its default port 6060 is the v6
    shim HTTP port at offset 60. Both flags are required to remove it.
    """
    configure(1)
    program = read(tree.supervisor / "gobgpd-ARISTA01T1.conf")
    assert "--pprof-disable" in program
    assert '--metrics-path ""' in program
    assert "--pprof-host" not in program
    assert ":6060" not in program


def test_family_derives_from_the_port_range():
    assert mgr.family_for(5000) == "v4"
    assert mgr.family_for(5071) == "v4"
    assert mgr.family_for(6000) == "v6"
    assert mgr.family_for(6071) == "v6"


# --- phase 2: pool render -----------------------------------------------------

def test_collect_portmap_merges_every_neighbor(tree):
    configure(4)
    configure(4, family="v6", base_port=6000)
    portmap = mgr.collect_portmap()
    assert len(portmap) == 8
    assert set(portmap) == {"5000", "5001", "5002", "5003",
                            "6000", "6001", "6002", "6003"}


def test_pool_render_matches_shardmap_exactly(tree):
    """The rendered pool must be the one shardmap describes.

    Covering + disjoint + the right cardinality: this is the contract the shims
    rely on to serve their slice without coordinating with each other.
    """
    configure(4)
    configure(4, family="v6", base_port=6000)
    portmap = mgr.collect_portmap()

    k = mgr.render_pool(portmap, core_count=4)
    expected = shardmap.partition(portmap, shardmap.num_shards(4, len(portmap)))
    assert k == len(expected)

    written = json.loads(read(tree.conf / "portmap.json"))
    assert written == portmap

    union = {}
    for shard in expected:
        assert not set(union) & set(shard)   # disjoint
        union.update(shard)
    assert union == portmap                  # covering

    conf = read(tree.supervisor / "gobgpshim.conf")
    for i in range(k):
        assert "[program:gobgp-shim-%d]" % i in conf
    assert "[program:gobgp-shim-%d]" % k not in conf


def test_shim_command_uses_the_slash_shard_form(tree):
    """``--shard`` is one ``i/k`` argument, not two positional values."""
    configure(4)
    k = mgr.render_pool(mgr.collect_portmap(), core_count=2)
    conf = read(tree.supervisor / "gobgpshim.conf")
    for i in range(k):
        assert "--shard %d/%d" % (i, k) in conf
    assert "-m gobgp.shim" in conf
    assert 'PYTHONPATH="%s"' % tree.pkg in conf
    assert str(tree.conf / "portmap.json") in conf


def test_fleet_pool_is_sized_by_cores_not_sessions(tree):
    """The whole point of the pool: process count tracks cores, not neighbors.

    A shim-per-session deploy at this scale costs ~11.5 GB of interpreter
    overhead; a core-sized pool costs ~640 MB at measured performance parity.
    """
    portmap = {}
    for off in range(144):
        for base, family in ((5000, "v4"), (6000, "v6")):
            portmap[str(base + off)] = {
                "grpc": "127.0.0.1:%d" % mgr.grpc_port_for(base + off),
                "family": family, "name": "ARISTA%03dT1" % (off + 1),
            }
    assert len(portmap) == 288

    # The bounds are kept apart so a pool that ignored core_count and tracked
    # only the ceiling would show up here.
    k = mgr.render_pool(portmap, core_count=12, pool_max=16)
    assert k == 12

    conf = read(tree.supervisor / "gobgpshim.conf")
    assert conf.count("[program:gobgp-shim-") == 12

    # Every port still served, exactly once, by some shard.
    served = {}
    for i in range(k):
        shard = shardmap.shard_for(portmap, k, i)
        assert not set(served) & set(shard)
        served.update(shard)
    assert served == portmap

    # A shard fronts both families, which is why the pool cannot be split into
    # v4/v6 groups the way the gobgpd programs are.
    families = {spec["family"] for spec in shardmap.shard_for(portmap, k, 0).values()}
    assert families == {"v4", "v6"}


def test_shard_count_never_exceeds_the_port_count(tree):
    """More cores than ports must not spawn shims that own nothing.

    ``partition`` clamps the split, so a manager that rendered the raw
    ``min(cores, ports)`` would launch a shim whose index is out of range and it
    would exit on IndexError.
    """
    configure(2)
    portmap = mgr.collect_portmap()
    k = mgr.render_pool(portmap, core_count=64)
    assert k == 2
    conf = read(tree.supervisor / "gobgpshim.conf")
    assert "[program:gobgp-shim-2]" not in conf
    for i in range(k):
        assert shardmap.shard_for(portmap, k, i)   # no empty shard


def test_shim_group_lists_every_shard(tree):
    configure(4)
    k = mgr.render_pool(mgr.collect_portmap(), core_count=4)
    conf = read(tree.supervisor / "gobgpshim.conf")
    assert "[group:gobgpshim]" in conf
    programs = conf.split("programs=")[-1].strip()
    assert programs.split(",") == ["gobgp-shim-%d" % i for i in range(k)]


def test_gobgpd_groups_split_by_family(tree):
    configure(3)
    configure(3, family="v6", base_port=6000)
    mgr.render_pool(mgr.collect_portmap(), core_count=4)

    v4 = read(tree.supervisor / "gobgpv4.conf")
    v6 = read(tree.supervisor / "gobgpv6.conf")
    assert "[group:gobgpv4]" in v4
    assert "programs=gobgpd-ARISTA01T1,gobgpd-ARISTA02T1,gobgpd-ARISTA03T1" in v4
    assert "programs=gobgpd-ARISTA01T1-v6,gobgpd-ARISTA02T1-v6,gobgpd-ARISTA03T1-v6" in v6


def test_single_family_topology_leaves_no_stale_group_file(tree):
    """An empty ``programs=`` is a supervisord config error.

    A v4-only topology (v6 route generation disabled) must not inherit a v6
    group file from an earlier run.
    """
    stale = tree.supervisor / "gobgpv6.conf"
    stale.write_text("[group:gobgpv6]\nprograms=gobgpd-GONE-v6\n")

    configure(2)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)

    assert (tree.supervisor / "gobgpv4.conf").exists()
    assert not stale.exists()


def test_pool_render_is_idempotent_and_prunes_a_shrinking_pool(tree):
    """Re-running the pool phase converges instead of accumulating.

    announce_routes configures v4 for every neighbor and then v6 for every
    neighbor, so the pool phase can legitimately run more than once with a
    growing portmap; a torn-down topology shrinks it again.
    """
    configure(8)
    first = mgr.render_pool(mgr.collect_portmap(), core_count=8)
    assert first == 8

    again = mgr.render_pool(mgr.collect_portmap(), core_count=8)
    assert again == first

    for name in configure(8)[2:]:
        mgr.remove_gobgp_conf(name)
    shrunk = mgr.render_pool(mgr.collect_portmap(), core_count=8)
    assert shrunk == 2

    # All shard programs share one file precisely so a shrink cannot orphan one.
    conf = read(tree.supervisor / "gobgpshim.conf")
    assert "[program:gobgp-shim-2]" not in conf
    assert len(list(tree.supervisor.glob("gobgp-shim-*.conf"))) == 0


# --- lifecycle ----------------------------------------------------------------

RUNNING = "gobgpd-ARISTA01T1   RUNNING   pid 100, uptime 0:00:05"


def test_start_brings_up_daemons_before_shims(tree):
    """A shim must not dial a gRPC socket its daemon has not opened yet."""
    configure(2)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)
    module = FakeModule(statuses={g: [RUNNING] for g in ("gobgpv4", "gobgpshim")})

    mgr.start_gobgp(module, mgr.existing_groups())

    starts = [c for c in module.supervisor_actions if c.startswith("supervisorctl start")]
    assert starts == ["supervisorctl start gobgpv4:",
                      "supervisorctl start gobgpshim:"]


def test_stop_tears_down_in_reverse(tree):
    configure(2)
    configure(2, family="v6", base_port=6000)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)
    module = FakeModule()

    mgr.stop_gobgp(module, mgr.existing_groups())

    assert module.supervisor_actions == ["supervisorctl stop gobgpshim:",
                                         "supervisorctl stop gobgpv6:",
                                         "supervisorctl stop gobgpv4:"]


def test_existing_groups_skips_groups_that_were_never_rendered(tree):
    configure(2)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)
    # v6 was never configured, so starting `gobgpv6:` would just error.
    assert mgr.existing_groups() == ["gobgpv4", "gobgpshim"]


def test_wait_returns_once_the_whole_group_is_running(tree, monkeypatch):
    monkeypatch.setattr(mgr.time, "sleep", lambda _s: None)
    module = FakeModule(statuses={"gobgpv4": [
        "gobgpd-ARISTA01T1   STARTING",
        "gobgpd-ARISTA01T1   RUNNING   pid 1, uptime 0:00:02",
    ]})
    mgr.wait_groups_running(module, ["gobgpv4"], timeout=30)


def test_wait_reports_the_programs_still_pending(tree, monkeypatch):
    """A fleet-scale failure must name what is stuck, not just time out."""
    monkeypatch.setattr(mgr.time, "sleep", lambda _s: None)
    module = FakeModule(statuses={"gobgpshim": ["gobgp-shim-3   FATAL"]})

    with pytest.raises(AssertionError):
        mgr.wait_groups_running(module, ["gobgpshim"], timeout=1)
    assert "gobgp-shim-3" in module.failed
    assert "FATAL" in module.failed


def test_wait_treats_a_silent_group_as_pending(tree, monkeypatch):
    """An unreachable supervisord or an unloaded group yields no status lines,
    which must not read as ready.
    """
    monkeypatch.setattr(mgr.time, "sleep", lambda _s: None)
    module = FakeModule()

    with pytest.raises(AssertionError):
        mgr.wait_groups_running(module, ["gobgpv4"], timeout=1)
    assert "UNKNOWN" in module.failed


def test_wait_deadline_survives_a_wall_clock_jump(tree, monkeypatch):
    """Bring-up takes minutes, and an NTP step must not end the wait early."""
    monkeypatch.setattr(mgr.time, "sleep", lambda _s: None)
    jumped = itertools.count(0, 3600)
    monkeypatch.setattr(mgr.time, "time", lambda: 1e9 + next(jumped))
    module = FakeModule(statuses={"gobgpv4": ["gobgpd-ARISTA01T1   STARTING", RUNNING]})
    mgr.wait_groups_running(module, ["gobgpv4"], timeout=30)


def test_wait_polls_the_group_not_each_program(tree, monkeypatch):
    """Per-program waits serialize hundreds of timeouts at fleet scale."""
    monkeypatch.setattr(mgr.time, "sleep", lambda _s: None)
    module = FakeModule(statuses={"gobgpv4": [RUNNING]})
    mgr.wait_groups_running(module, ["gobgpv4"], timeout=30)

    status_cmds = [c for c in module.commands if c.startswith("supervisorctl status")]
    assert status_cmds == ["supervisorctl status gobgpv4:"]


# --- regression: portmap digest and group integrity ---------------------------

def test_growing_the_portmap_restarts_the_pool_even_when_k_is_saturated(tree):
    """A changed portmap must be a changed shim *configuration*.

    The shim reads portmap.json once at startup, and ``supervisorctl update``
    restarts only programs whose config changed. announce_routes runs the pool
    phase twice -- v4 then v6 -- so once k saturates at the core count the
    second render would otherwise be byte-identical, leaving every v6 port
    unbound while every process reports RUNNING.
    """
    def portmap_for(families):
        out = {}
        for off in range(72):
            for base, family in families:
                out[str(base + off)] = {
                    "grpc": "127.0.0.1:%d" % mgr.grpc_port_for(base + off),
                    "family": family, "name": "ARISTA%02dT1" % off,
                }
        return out

    conf = tree.supervisor / "gobgpshim.conf"

    cap = shardmap.DEFAULT_POOL_MAX

    v4_only = portmap_for([(5000, "v4")])
    assert mgr.render_pool(v4_only, core_count=16) == cap
    first = read(conf)

    both = portmap_for([(5000, "v4"), (6000, "v6")])
    assert mgr.render_pool(both, core_count=16) == cap     # k is saturated
    second = read(conf)

    assert first != second, \
        "shim config unchanged after the portmap grew: supervisorctl update " \
        "would not restart the pool and the added ports would never bind"

    # Re-rendering the same map must still be a no-op, or every pool run would
    # bounce the speaker.
    mgr.render_pool(both, core_count=16)
    assert read(conf) == second


def test_shim_program_carries_the_portmap_digest(tree):
    configure(4)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)
    expected = hashlib.sha256(
        read(tree.conf / "portmap.json").encode("utf-8")).hexdigest()[:16]
    assert ('GOBGP_PORTMAP_DIGEST="%s"' % expected
            in read(tree.supervisor / "gobgpshim.conf"))


def test_absent_leaves_no_group_pointing_at_a_deleted_program(tree):
    """supervisord fails to load a group naming a section that is gone.

    That wedges the whole family group, not just the removed neighbor, so the
    group files have to be re-rendered when a neighbor is dropped.
    """
    names = configure(3)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)
    assert "gobgpd-%s" % names[1] in read(tree.supervisor / "gobgpv4.conf")

    mgr.remove_gobgp_conf(names[1])
    mgr.render_pool(mgr.collect_portmap(), core_count=2)

    group = read(tree.supervisor / "gobgpv4.conf")
    assert "gobgpd-%s" % names[1] not in group
    programs = group.split("programs=")[-1].strip().splitlines()[0].split(",")
    for program in programs:
        assert (tree.supervisor / ("%s.conf" % program.strip())).exists(), \
            "group references %s but its program file is gone" % program


# --- derived listener ports ---------------------------------------------------

def test_derived_grpc_ports_avoid_the_ephemeral_range(tree):
    """The gRPC band must sit outside net.ipv4.ip_local_port_range.

    Its per-netns kernel default is 32768-60999. A fixed port inside that window
    can be held by a loopback ephemeral socket when a daemon restarts, so the
    band is placed above it.
    """
    EPHEMERAL_LO, EPHEMERAL_HI = 32768, 60999

    for port in range(mgr.SHIM_PORT_MIN, mgr.SHIM_PORT_MAX + 1):
        listener = mgr.grpc_port_for(port)
        assert not EPHEMERAL_LO <= listener <= EPHEMERAL_HI
        assert listener <= 65535


def test_shim_and_grpc_bands_are_disjoint(tree):
    """A derived gRPC port must never land on another neighbor's shim port."""
    shim = set(range(mgr.SHIM_PORT_MIN, mgr.SHIM_PORT_MAX + 1))
    grpc = {mgr.grpc_port_for(port) for port in shim}
    assert not shim & grpc


# --- filesystem helpers -------------------------------------------------------

def test_remove_is_silent_only_for_a_missing_file(tmp_path):
    """Callers delete paths that may be absent, so only that case is absorbed.

    Anything else -- an unwritable directory, a path component that is a file --
    would otherwise leave a supervisord program file behind while teardown
    reported success.
    """
    mgr._remove(str(tmp_path / "never-written.conf"))

    with pytest.raises(IsADirectoryError):
        mgr._remove(str(tmp_path))


# --- deployed-package layout ---------------------------------------------------

def test_missing_package_names_the_expected_layout(tree, tmp_path, monkeypatch):
    """GOBGP_PKG_DIR is the shims' PYTHONPATH as well as the manager's import
    root, so it must be the package's parent. A flat deploy is the predecessor
    layout and the likeliest mistake; the bare ImportError does not say so.
    """
    # Block at the import system so the result holds for any checkout path.
    class _BlockGobgp(object):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "gobgp" or fullname.startswith("gobgp."):
                raise ImportError("blocked by test")
            return None

    monkeypatch.setattr(mgr, "GOBGP_PKG_DIR", str(tmp_path / "nothing-here"))
    monkeypatch.delitem(sys.modules, "gobgp", raising=False)
    monkeypatch.delitem(sys.modules, "gobgp.shardmap", raising=False)
    monkeypatch.setattr(sys, "meta_path", [_BlockGobgp()] + list(sys.meta_path))

    with pytest.raises(ImportError) as excinfo:
        mgr.load_shardmap()

    message = str(excinfo.value)
    assert "PARENT" in message
    assert "/gobgp/" in message


def test_failure_reports_the_frame_not_the_traceback_repr():
    """`str(sys.exc_info())` -- the inherited idiom -- renders the traceback
    object's repr, so the operator gets `<traceback object at 0x...>` instead of
    the frames. The layout ImportError above is raised inside main()'s try, so
    that idiom would deliver this module's clearest error wrapped in noise.
    """
    module = FakeModule()

    def raise_layout_error():
        raise ImportError("cannot import shardmap; expected the PARENT of /gobgp/")

    try:
        raise_layout_error()
    except Exception as exc:
        with pytest.raises(AssertionError):
            mgr.fail_with_traceback(module, exc)

    assert module.failed == "Error: cannot import shardmap; expected the PARENT of /gobgp/"
    assert "<traceback object at" not in module.failed
    assert "raise_layout_error" in module.fail_kwargs["traceback"]
    assert "ImportError" in module.fail_kwargs["traceback"]


# --- teardown -----------------------------------------------------------------

def test_absent_stops_only_the_removed_neighbor(tree):
    """`absent` is a per-neighbor state, so the surviving daemons and the shim
    pool keep serving while the removed one is dropped.
    """
    names = configure(3)
    mgr.render_pool(mgr.collect_portmap(), core_count=2)
    module = FakeModule()

    mgr.remove_neighbor(module, names[1])

    stops = [c for c in module.supervisor_actions
             if c.startswith("supervisorctl stop")]
    # Group-qualified: supervisord reads a bare `gobgpd-X` as a *group* of that
    # name, finds none loaded, and fails with BAD_NAME having stopped nothing.
    assert stops == ["supervisorctl stop gobgpv4:gobgpd-ARISTA02T1"]
    assert set(mgr.collect_portmap()) == {"5000", "5002"}
    groups = read(tree.supervisor / "gobgpv4.conf")
    assert "gobgpd-ARISTA02T1" not in groups
    assert "gobgpd-ARISTA01T1" in groups


def test_absent_removes_the_neighbor_from_the_next_portmap(tree):
    names = configure(3)
    mgr.remove_gobgp_conf(names[1])

    assert not (tree.conf / "ARISTA02T1.toml").exists()
    assert not (tree.supervisor / "gobgpd-ARISTA02T1.conf").exists()
    assert set(mgr.collect_portmap()) == {"5000", "5002"}


# --- module documentation -----------------------------------------------------

def _argument_spec_keys():
    """Parameter names from the module's AnsibleModule argument_spec."""
    with open(mgr.__file__) as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg == "argument_spec" and isinstance(kw.value, ast.Call):
                return {k.arg for k in kw.value.keywords}
    raise AssertionError("argument_spec not found")


def test_documentation_is_valid_ansible_yaml():
    """ansible-doc parses DOCUMENTATION as YAML and reads `options` as a
    mapping of parameter names, so a plain-scalar description or a capitalised
    key leaves the module undocumented.
    """
    doc = yaml.safe_load(mgr.DOCUMENTATION)

    assert doc["module"] == "gobgp"
    assert isinstance(doc["options"], dict)
    assert set(doc["options"]) == _argument_spec_keys()
    for name, spec in doc["options"].items():
        assert spec.get("description"), "%s has no description" % name


def test_examples_are_valid_yaml():
    tasks = yaml.safe_load(mgr.EXAMPLES)
    assert isinstance(tasks, list) and tasks


# --- pool ceiling -----------------------------------------------------------

def test_the_smallest_of_cores_sessions_and_the_cap_sizes_the_pool():
    """cpu_count() reports the host, not this container's share of it.

    A PTF container sits alongside other containers and other testbeds' PTFs, so
    a pool sized purely by host cores oversubscribes a busy server. The cap
    bounds that without displacing the two bounds that were already there.
    """
    assert shardmap.num_shards(64, 512) == shardmap.DEFAULT_POOL_MAX  # cap wins
    assert shardmap.num_shards(2, 512) == 2                           # cores win
    assert shardmap.num_shards(64, 3) == 3                            # sessions win


def test_pool_max_override_widens_and_narrows_the_pool():
    assert shardmap.num_shards(64, 512, pool_max=32) == 32
    assert shardmap.num_shards(64, 512, pool_max=1) == 1


def test_pool_max_never_yields_an_empty_pool():
    assert shardmap.num_shards(64, 512, pool_max=0) == 1


def test_render_pool_passes_the_operator_pool_max_through(tree):
    portmap = {
        str(5000 + off): {
            "grpc": "127.0.0.1:%d" % mgr.grpc_port_for(5000 + off),
            "family": "v4", "name": "ARISTA%02dT1" % off,
        }
        for off in range(64)
    }

    assert mgr.render_pool(portmap, core_count=64) == shardmap.DEFAULT_POOL_MAX
    assert mgr.render_pool(portmap, core_count=64, pool_max=20) == 20

    conf = read(tree.supervisor / "gobgpshim.conf")
    assert conf.count("[program:gobgp-shim-") == 20


# --- supervisorctl error propagation ----------------------------------------

def test_a_failed_reread_is_reported(tree):
    """A rejected shim block means the pool was never installed.

    Swallowed here it reappears 300s later as a readiness timeout, with
    supervisord's own diagnosis discarded.
    """
    module = FakeModule(failing=["supervisorctl reread"])
    with pytest.raises(AssertionError):
        mgr.refresh_supervisord(module)
    assert "supervisorctl reread" in module.failed


def test_a_failed_update_is_reported(tree):
    module = FakeModule(failing=["supervisorctl update"])
    with pytest.raises(AssertionError):
        mgr.refresh_supervisord(module)


def test_teardown_tolerates_a_failed_update(tree):
    """`update` applies the parsed result to running groups, so a teardown can
    legitimately race a group that is already going away.
    """
    module = FakeModule(failing=["supervisorctl update"])
    mgr.refresh_supervisord(module, strict=False)
    assert module.failed is None


def test_teardown_still_reports_a_failed_reread(tree):
    """`reread` parses the files this module just wrote and says nothing about
    group state, so a rejection there is a malformed render on every path.
    """
    module = FakeModule(failing=["supervisorctl reread"])
    with pytest.raises(AssertionError):
        mgr.refresh_supervisord(module, strict=False)


def test_a_failed_start_is_reported(tree):
    """`supervisorctl start` exits 0 for an already-running group, so a non-zero
    exit means a missing group or a process that could not spawn.
    """
    module = FakeModule(failing=["supervisorctl start"])
    with pytest.raises(AssertionError):
        mgr.start_gobgp(module, ["gobgpv4"])
    assert "supervisorctl start" in module.failed


def test_remove_neighbor_tolerates_a_failed_update_and_stop(tree):
    """Teardown races a group supervisord may already be tearing down, so both
    the per-neighbor stop and the reload that follows it stay tolerant.
    """
    mgr.setup_gobgp_conf("ARISTA01T1", "10.0.0.0", "10.0.0.0", "10.0.0.1",
                         65534, 65535, 5000)
    module = FakeModule(failing=["supervisorctl update", "supervisorctl stop"])
    mgr.remove_neighbor(module, "ARISTA01T1")
    assert module.failed is None


def test_stop_still_tolerates_a_missing_group(tree):
    module = FakeModule(failing=["supervisorctl stop"])
    mgr.stop_gobgp(module, ["gobgpv4"])
    assert module.failed is None


# --- fleet reset ------------------------------------------------------------

def _spool_neighbors(names):
    for i, name in enumerate(names):
        mgr.setup_gobgp_conf(name, "10.0.0.0", "10.0.0.0", "10.0.0.1",
                             65534, 65535, 5000 + i)
    return list(names)


def test_reset_drops_the_neighbors_the_topology_no_longer_has(tree):
    """The spool is the only record of group membership, so a redeploy into a
    container that already served a topology would otherwise start the previous
    numbering's daemons alongside the new one.
    """
    _spool_neighbors(["ARISTA01T1", "ARISTA02T1", "ARISTA03T1"])
    mgr.render_pool(mgr.collect_portmap())

    module = FakeModule()
    removed = mgr.reset_fleet(module, keep=["ARISTA02T1"])

    assert removed == ["ARISTA01T1", "ARISTA03T1"]
    assert set(mgr.collect_portmap()) == {"5001"}
    conf = read(tree.supervisor / "gobgpv4.conf")
    assert "gobgpd-ARISTA02T1" in conf
    for stale in ("ARISTA01T1", "ARISTA03T1"):
        assert "gobgpd-%s" % stale not in conf


@pytest.mark.parametrize("name,local_ip,peer_ip,port,group", [
    ("ARISTA01T1", "10.0.0.0", "10.0.0.1", 5000, "gobgpv4"),
    ("ARISTA01T1-v6", "fc0a::ff", "fc0a::1", 6000, "gobgpv6"),
])
def test_reset_stops_each_stale_daemon_through_its_own_group(
        tree, name, local_ip, peer_ip, port, group):
    """supervisord resolves an unqualified name as a group of that name, so an
    unqualified stop matches nothing and reports BAD_NAME having done nothing.
    """
    mgr.setup_gobgp_conf(name, "10.0.0.0", local_ip, peer_ip, 65534, 65535, port)
    mgr.render_pool(mgr.collect_portmap())

    module = FakeModule()
    mgr.reset_fleet(module)

    stops = [c for c in module.commands if c.startswith("supervisorctl stop")]
    assert stops == ["supervisorctl stop %s:gobgpd-%s" % (group, name)]


def test_reset_is_idempotent_on_a_container_that_never_ran_gobgp(tree):
    module = FakeModule()
    assert mgr.reset_fleet(module) == []
    assert module.failed is None


def test_reset_touches_nothing_when_the_topology_is_unchanged(tree):
    """A repeat announce re-enters this path against a live fleet. Rewriting
    the pool there would drop and re-establish every BGP session.
    """
    names = _spool_neighbors(["ARISTA01T1", "ARISTA02T1"])
    mgr.render_pool(mgr.collect_portmap())
    before = read(tree.supervisor / "gobgpshim.conf")

    module = FakeModule()
    assert mgr.reset_fleet(module, keep=names) == []

    assert read(tree.supervisor / "gobgpshim.conf") == before
    assert module.supervisor_actions == []


def test_reset_leaves_the_container_marked_as_running_gobgp(tree):
    """The playbook reads the shim group's conf to decide which speaker a
    container runs, so a reset that removed it would revert the next run to
    ExaBGP.
    """
    _spool_neighbors(["ARISTA01T1", "ARISTA02T1"])
    mgr.render_pool(mgr.collect_portmap())

    mgr.reset_fleet(FakeModule(), keep=["ARISTA01T1"])

    assert (tree.supervisor / "gobgpshim.conf").exists()


# --- pool_max reaches every re-render ---------------------------------------

def test_removing_a_neighbor_keeps_the_operator_pool_max(tree, monkeypatch):
    """`partition` is round-robin over the sorted port list, so a changed k
    reassigns every port and bounces the whole front end. Dropping one neighbor
    holds the ceiling it was deployed with.

    `core_count` needs no such care: every render reads it from the same host.
    """
    monkeypatch.setattr(mgr.multiprocessing, "cpu_count", lambda: 64)
    _spool_neighbors(["ARISTA%02dT1" % i for i in range(1, 41)])
    mgr.render_pool(mgr.collect_portmap(), pool_max=32)
    before = read(tree.supervisor / "gobgpshim.conf")
    assert before.count("[program:gobgp-shim-") == 32

    module = FakeModule()
    mgr.remove_neighbor(module, "ARISTA40T1", pool_max=32)

    after = read(tree.supervisor / "gobgpshim.conf")
    assert after.count("[program:gobgp-shim-") == 32


# --- the playbook branch ----------------------------------------------------

def _announce_routes_tasks():
    """Every task in announce_routes.yml, flattened out of its blocks."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.abspath(os.path.join(
        here, os.pardir, os.pardir, os.pardir, 'tasks', 'announce_routes.yml'))
    if not os.path.exists(path):
        pytest.skip("announce_routes.yml not found at %s" % path)

    with open(path) as f:
        tree = yaml.safe_load(f)

    def walk(tasks, inherited, scope):
        for task in tasks:
            own = task.get('when', [])
            own = [own] if isinstance(own, str) else list(own)
            conditions = inherited + own
            if 'block' in task:
                nested = dict(scope)
                nested.update(task.get('vars') or {})
                for found in walk(task['block'], conditions, nested):
                    yield found
            else:
                yield task, conditions, scope

    return [(task, conditions) for task, conditions, _ in walk(tree, [], {})]


def _announce_routes_tasks_with_vars():
    """Every task paired with the vars its enclosing blocks put in scope."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.abspath(os.path.join(
        here, os.pardir, os.pardir, os.pardir, 'tasks', 'announce_routes.yml'))
    if not os.path.exists(path):
        pytest.skip("announce_routes.yml not found at %s" % path)

    with open(path) as f:
        tree = yaml.safe_load(f)

    def walk(tasks, scope):
        for task in tasks:
            if 'block' in task:
                nested = dict(scope)
                nested.update(task.get('vars') or {})
                for found in walk(task['block'], nested):
                    yield found
            else:
                yield task, scope

    return list(walk(tree, {}))


SPEAKER_MODULES = ('exabgp', 'gobgp')


def test_every_speaker_task_is_guarded_by_the_speaker_it_drives():
    """The branch is the whole point of the wiring: an unguarded speaker task
    runs both speakers against the same neighbor ports.
    """
    seen = {'exabgp': 0, 'gobgp': 0}
    for task, conditions in _announce_routes_tasks():
        for speaker in SPEAKER_MODULES:
            if speaker not in task:
                continue
            seen[speaker] += 1
            guard = "ptf_bgp_speaker == '%s'" % speaker
            assert any(guard in c.replace('"', "'") for c in conditions), \
                "task %r invokes %s without %s" % (
                    task.get('name'), speaker, guard)

    assert seen['exabgp'] >= 2, seen
    assert seen['gobgp'] >= 2, seen


# Parameters one manager accepts and the other rejects. `gobgp` raises on
# `passive` because gobgpd listens only when the global port is positive, and it
# is fixed at -1 there.
SPEAKER_ONLY_PARAMS = {'exabgp': {'passive'}, 'gobgp': {'pool_max'}}


def _resolve_speaker_args(args, scope):
    """Module args as a dict, following a ``"{{ var }}"`` reference into scope."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        name = args.strip().strip('{} ').strip()
        resolved = scope.get(name)
        if isinstance(resolved, dict):
            return resolved
    return None


def test_the_exabgp_and_gobgp_branches_cover_the_same_neighbor_parameters():
    """The manager is an API drop-in, so a parameter added to one branch and
    missed on the other silently changes the session the shim opens.
    """
    by_speaker = {'exabgp': [], 'gobgp': []}
    for task, scope in _announce_routes_tasks_with_vars():
        for speaker in SPEAKER_MODULES:
            if speaker not in task:
                continue
            args = _resolve_speaker_args(task[speaker], scope)
            assert args is not None, \
                "task %r passes %s args this test cannot resolve" % (
                    task.get('name'), speaker)
            if args.get('state') == 'configure':
                by_speaker[speaker].append(args)

    assert len(by_speaker['exabgp']) == len(by_speaker['gobgp']) == 2
    exempt = SPEAKER_ONLY_PARAMS['exabgp'] | SPEAKER_ONLY_PARAMS['gobgp']
    for exa, go in zip(by_speaker['exabgp'], by_speaker['gobgp']):
        for key in (set(exa) | set(go)) - exempt:
            assert exa.get(key) == go.get(key), \
                "configure parameter %r diverges: %r vs %r" % (
                    key, exa.get(key), go.get(key))


def test_the_speaker_default_is_taken_from_the_container():
    """A re-entry that omits the extra-var must not start the other speaker."""
    for task, _ in _announce_routes_tasks():
        fact = task.get('set_fact', {})
        if 'ptf_bgp_speaker' in fact:
            assert task.get('when') == 'ptf_bgp_speaker is not defined'
            assert 'ptf_gobgp_installed' in fact['ptf_bgp_speaker']
            break
    else:
        raise AssertionError("nothing defaults ptf_bgp_speaker")

    guards = [task for task, _ in _announce_routes_tasks() if 'fail' in task]
    conditions = " ".join(str(t.get('when', '')) for t in guards)
    for marker in ('ptf_gobgp_installed', 'ptf_exabgp_installed'):
        assert marker in conditions, \
            "no guard covers a container already running the other speaker (%s)" % marker


@pytest.mark.parametrize("name,local_ip,peer_ip,port,group,state", [
    ("ARISTA01T1", "10.0.0.0", "10.0.0.1", 5000, "gobgpv4", "RUNNING"),
    ("ARISTA01T1-v6", "fc0a::ff", "fc0a::1", 6000, "gobgpv6", "FATAL"),
])
def test_status_reads_the_namespec_supervisord_prints(
        tree, name, local_ip, peer_ip, port, group, state):
    """supervisorctl labels a grouped process `group:program`, so the reply is
    keyed the way the query was phrased.
    """
    mgr.setup_gobgp_conf(name, "10.0.0.0", local_ip, peer_ip, 65534, 65535, port)
    namespec = "%s:gobgpd-%s" % (group, name)
    module = FakeModule(statuses={namespec: ["%s  %s  pid 42" % (namespec, state)]})

    assert mgr.get_gobgp_status(module, name) == state
    assert module.commands == ["supervisorctl status %s" % namespec]
