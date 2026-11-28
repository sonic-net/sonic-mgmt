# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Spanning tree with a PortChannel as the STP port, PVST and MSTP.

Three VLAN member ports, the first test port among them, leave the VLAN and
become the members of a new static PortChannel, and the PortChannel takes
their place in the VLAN. On the PTF the matching ports go into a static
balance-xor bond, so neither side runs LACP. The second test port stays a
plain port.

Each mode checks the same things: the PortChannel gets a role and a state and
the DUT sends BPDUs out of it, port cost and priority apply to it, BPDU guard
and root guard work on it, a topology change arriving on it flushes the other
port, it stays in the tree while a member is removed and added back, and it
comes back into the tree with its settings after its members go down and come
back up.
"""
import json
import logging

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.stp import stp_utils
from tests.stp.conftest import CANDIDATE_PORTCHANNEL
from tests.stp.stp_base import StpTestBase, PVST, MST

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    # Guard trips and superior BPDUs log at error level on purpose.
    pytest.mark.disable_loganalyzer,
]

CIST = 0
PROBE_MAC_PREFIX = "00:11:22:33:55"

# MST neighbours, as in test_mstp.py: a foreign bridge that beats any real
# switch on the MAC tiebreak, and one that loses to everything.
FOREIGN_BRIDGE_MAC = "00:00:00:00:00:01"
SUPERIOR_PRIORITY = 0
INFERIOR_PRIORITY = 0xF000
INFERIOR_BRIDGE_MAC = "02:ff:ff:ff:ff:ff"
CIST_FLAGS_DESIGNATED = 0x7E
CIST_FLAGS_QUIET_DESIGNATED = 0x0C

# Costs for the root port election: the plain port gets a fixed middle cost,
# and the PortChannel goes above it and then below it.
PLAIN_PORT_COST = 500
HIGH_COST = 2000
LOW_COST = 100
RECOVERY_COST = 1234
PORT_PRIORITY = 64


def _lag_oper(duthost, pc):
    return duthost.shell("redis-cli -n 0 hget 'LAG_TABLE:{}' oper_status".format(pc),
                         module_ignore_errors=True).get("stdout", "").strip()


def _run(duthost, cmd):
    res = duthost.shell(cmd, module_ignore_errors=True)
    if res.get("rc", 0) != 0:
        logger.warning("%s -> rc %s: %s", cmd, res.get("rc"), res.get("stderr", "").strip())
    return res


def _unbind_acls(duthost, ports):
    """Drop `ports` from every ACL table's port list; return {table: old list}."""
    saved = {}
    tables = duthost.shell("redis-cli -n 4 keys 'ACL_TABLE|*'",
                           module_ignore_errors=True).get("stdout_lines", [])
    for table in (t.strip() for t in tables if t.strip()):
        bound = duthost.shell("redis-cli -n 4 hget '{}' ports@".format(table),
                              module_ignore_errors=True).get("stdout", "").strip()
        members = bound.split(",") if bound else []
        if any(p in members for p in ports):
            saved[table] = bound
            kept = ",".join(p for p in members if p not in ports)
            _run(duthost, "redis-cli -n 4 hset '{}' ports@ '{}'".format(table, kept))
    return saved


def _restore_acls(duthost, saved):
    for table, ports in saved.items():
        _run(duthost, "redis-cli -n 4 hset '{}' ports@ '{}'".format(table, ports))


# Static lag set up the way tests/pc/test_lag_member.py sets up its PTF bond,
# so neither side runs LACP.
PTF_BOND = "bond990"
PTF_BOND_MAC = "00:11:22:33:44:99"
MEMBER_COUNT = 3
# Longer than LACP's 30 second slow periodic interval.
LACPDU_CAPTURE_SECONDS = 35


def _lag_runner(duthost, pc):
    try:
        return duthost.get_port_channel_status(pc)["setup"]["runner_name"]
    except Exception:   # noqa: BLE001 -- teamd is restarting or the lag is not there yet
        return ""


def _make_static(duthost, pc):
    """`config portchannel add` has no lag type here, so set it in CONFIG_DB;
    teammgrd restarts the lag's teamd on the change."""
    _run(duthost, 'sonic-db-cli CONFIG_DB HSET "PORTCHANNEL|{}" lag_type STATIC'.format(pc))
    return wait_until(60, 2, 0, lambda: _lag_runner(duthost, pc) == "loadbalance")


def _ptf_bond_up(ptfhost, ptf_ports):
    ptfhost.command("ip link add {} type bond".format(PTF_BOND))
    ptfhost.command("ip link set {} type bond miimon 100 mode balance-xor".format(PTF_BOND))
    for ptf_port in ptf_ports:
        ptfhost.add_intf_to_lag(PTF_BOND, "eth{}".format(ptf_port))
    # A fixed MAC, as tests/pc does: the bond would otherwise take the first
    # member's, and the fanout drops frames from a MAC it sees on two ports.
    ptfhost.shell("ip link set {} address {}".format(PTF_BOND, PTF_BOND_MAC))
    ptfhost.startup_lag(PTF_BOND)
    ptfhost.ptf_nn_agent()


def _ptf_bond_down(ptfhost, ptf_ports):
    for ptf_port in ptf_ports:
        port = "eth{}".format(ptf_port)
        ptfhost.shell("ip link set {} nomaster".format(port), module_ignore_errors=True)
        ptfhost.set_dev_up_or_down(port, True)
    ptfhost.shell("ip link del {}".format(PTF_BOND), module_ignore_errors=True)
    ptfhost.ptf_nn_agent()


def _lag_candidates(duthost, tbinfo, data):
    """The VLAN's member ports in port order, the second test port left out,
    with their PTF ports: the first test port first, then the spares."""
    mg = duthost.get_extended_minigraph_facts(tbinfo)
    _, vlan = list(mg["minigraph_vlans"].items())[0]
    ptf_of = mg["minigraph_ptf_indices"]
    plain = data["dut_ports"]["dut_port_2"]
    members = sorted((p for p in vlan["members"] if p.startswith("Ethernet") and p != plain and p in ptf_of),
                     key=lambda x: int(x.replace("Ethernet", "")))
    return members, [ptf_of[p] for p in members]


def _members_enabled(duthost, pc):
    """The PortChannel's members teamd has enabled, from APPL_DB."""
    keys = duthost.shell("redis-cli -n 0 keys 'LAG_MEMBER_TABLE:{}:*'".format(pc),
                         module_ignore_errors=True).get("stdout_lines", [])
    enabled = set()
    for key in (k.strip() for k in keys if k.strip()):
        status = duthost.shell("redis-cli -n 0 hget '{}' status".format(key),
                               module_ignore_errors=True).get("stdout", "").strip()
        if status == "enabled":
            enabled.add(key.rsplit(":", 1)[1])
    return enabled


def _in_vlan(duthost, vlan_id, port):
    return duthost.shell("redis-cli -n 0 exists 'VLAN_MEMBER_TABLE:Vlan{}:{}'".format(vlan_id, port),
                         module_ignore_errors=True).get("stdout", "").strip() == "1"


def _lacpdus_sent(duthost, port):
    """tcpdump exit status: 124 when the DUT sent no LACPDU on `port` in the window."""
    return duthost.shell("timeout {} tcpdump -nni {} -Q out -c 1 ether proto 0x8809 >/dev/null 2>&1; echo $?"
                         .format(LACPDU_CAPTURE_SECONDS, port), module_ignore_errors=True)["stdout"].strip()


def _stp_keys_for(duthost, pc):
    keys = []
    for pattern in ("STP_PORT|{}", "STP_VLAN_PORT|*|{}", "STP_MST_PORT|*|{}"):
        out = duthost.shell("redis-cli -n 4 keys '{}'".format(pattern.format(pc)),
                            module_ignore_errors=True).get("stdout_lines", [])
        keys += [k.strip() for k in out if k.strip()]
    return keys


class _PortChannelStp(StpTestBase):
    """The cases, written once. A subclass sets STP_MODE and the mode hooks."""

    BLOCK_STATE = None

    # ------------------------------------------------------------ mode hooks
    def scope(self, data):
        raise NotImplementedError

    def superior_params(self, data, send_ptf_ports, **overrides):
        raise NotImplementedError

    def send_tc(self, ptfhost, duthost, data, ptf_port):
        raise NotImplementedError

    def make_non_edge(self, ptfhost, duthost, data, ptf_port):
        """MSTP treats a port that never heard a BPDU as an edge port and a
        topology change leaves its entries alone. PVST has no such rule."""

    def requiesce(self, duthost, data):
        self.bounce_stp(duthost)

    def root_guard_tripped(self, duthost, scope, port):
        raise NotImplementedError

    def capture_own_bpdu(self, ptfhost, duthost, data, ptf_port):
        raise NotImplementedError

    # -------------------------------------------------------------- fixtures
    @pytest.fixture(scope="class")
    def lag(self, duthosts, rand_one_dut_hostname, ptfhost, tbinfo, setup_stp_test_data,
            enable_stp_and_verify):
        """Move three VLAN member ports, the first test port among them, into a
        new static PortChannel, bond the matching PTF ports, and put the
        PortChannel in the VLAN in their place; undo all of it afterwards."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        vlan_id = d["vlan"]["id"]
        members, ptf_ports = _lag_candidates(duthost, tbinfo, d)
        if len(members) < MEMBER_COUNT:
            pytest.skip("need {} VLAN member ports with PTF ports besides {}, have {}".format(
                MEMBER_COUNT, d["dut_ports"]["dut_port_2"], members))
        members, ptf_ports = members[:MEMBER_COUNT], ptf_ports[:MEMBER_COUNT]
        taken = duthost.shell("redis-cli -n 4 keys 'PORTCHANNEL|*'",
                              module_ignore_errors=True).get("stdout", "")
        pc = next((p for p in CANDIDATE_PORTCHANNEL if "PORTCHANNEL|{}".format(p) not in taken), None)
        if pc is None:
            pytest.skip("no spare PortChannel name on {}".format(duthost.hostname))

        # A port bound to an ACL table cannot join a PortChannel, so take the
        # members out of every table's port list and put the lists back after.
        acl_ports = _unbind_acls(duthost, members)
        for member in members:
            _run(duthost, "config vlan member del {} {}".format(vlan_id, member))
        _run(duthost, "config portchannel add {}".format(pc))
        try:
            if not _make_static(duthost, pc):
                pytest.skip("teamd does not run the loadbalance runner; image lacks static lag support")
            _ptf_bond_up(ptfhost, ptf_ports)
            for member in members:
                _run(duthost, "config portchannel member add {} {}".format(pc, member))
            _run(duthost, "config vlan member add {} {} --untagged".format(vlan_id, pc))
            pytest_assert(wait_until(120, 3, 0, lambda: _lag_oper(duthost, pc) == "up"),
                          "static {} with members {} did not come up".format(pc, members))
            pytest_assert(wait_until(60, 3, 0, lambda: _members_enabled(duthost, pc) == set(members)),
                          "{} did not enable all of {}: {}".format(pc, members, _members_enabled(duthost, pc)))
            scope = self.scope(d)
            pytest_assert(self.wait_enrolled(duthost, scope, pc),
                          "{} did not join the spanning tree".format(pc))
            yield {"pc": pc, "members": list(members), "ptf_ports": list(ptf_ports)}
        finally:
            _run(duthost, "config vlan member del {} {}".format(vlan_id, pc))
            for member in members:
                _run(duthost, "config portchannel member del {} {}".format(pc, member))
            _run(duthost, "config portchannel del {}".format(pc))
            _ptf_bond_down(ptfhost, ptf_ports)
            for key in _stp_keys_for(duthost, pc):
                _run(duthost, "redis-cli -n 4 del '{}'".format(key))
            for member in members:
                _run(duthost, "config interface startup {}".format(member))
            _restore_acls(duthost, acl_ports)
            for member in members:
                _run(duthost, "config vlan member add {} {} --untagged".format(vlan_id, member))
            wait_until(30, 2, 0, lambda: all(_in_vlan(duthost, vlan_id, m) for m in members))

    @pytest.fixture(autouse=True)
    def quiesced(self, duthosts, rand_one_dut_hostname, setup_stp_test_data, lag):
        """Every case starts with the lone DUT as root and the PortChannel up
        with all of its members."""
        duthost = duthosts[rand_one_dut_hostname]
        scope = self.scope(setup_stp_test_data)
        for member in lag["members"]:
            _run(duthost, "config interface startup {}".format(member))
        if not wait_until(60, 3, 0, lambda: self.is_self_root(duthost, scope)):
            self.requiesce(duthost, setup_stp_test_data)
            pytest_assert(wait_until(60, 3, 0, lambda: self.is_self_root(duthost, scope)),
                          "DUT did not return to root before the test started")
        pytest_assert(wait_until(60, 3, 0, lambda: _lag_oper(duthost, lag["pc"]) == "up"),
                      "{} is not up before the test started".format(lag["pc"]))
        pytest_assert(wait_until(60, 3, 0, lambda: _members_enabled(duthost, lag["pc"]) == set(lag["members"])),
                      "{} does not have all of {} before the test started: {}".format(
                          lag["pc"], lag["members"], _members_enabled(duthost, lag["pc"])))
        yield

    def capture_own_bpdu_on_lag(self, ptfhost, duthost, data, pc, ptf_ports):
        """The loadbalance runner sends the DUT's BPDUs out of whichever member
        its hash picks, so look on each member's PTF port until one carries
        them. Returns that PTF port."""
        misses = []
        for ptf_port in ptf_ports:
            try:
                self.capture_own_bpdu(ptfhost, duthost, data, ptf_port)
                return ptf_port
            except Exception as err:   # noqa: BLE001 -- not this member; try the next
                misses.append("eth{}: {}".format(ptf_port, str(err).splitlines()[0][:160]))
        pytest.fail("no member of {} carried the DUT's BPDUs: {}".format(pc, "; ".join(misses)))

    # ================================================================= cases
    def test_portchannel_is_static(self, duthosts, rand_one_dut_hostname, lag):
        """The PortChannel runs the loadbalance runner and sends no LACPDUs."""
        duthost = duthosts[rand_one_dut_hostname]
        pc, member = lag["pc"], lag["members"][0]
        pytest_assert(_lag_runner(duthost, pc) == "loadbalance",
                      "{} runs {!r}, not the static loadbalance runner".format(pc, _lag_runner(duthost, pc)))
        status = _lacpdus_sent(duthost, member)
        pytest_assert(status == "124",
                      "static {} sent an LACPDU on {} or the capture failed (tcpdump {})".format(
                          pc, member, status))

    def test_portchannel_has_role_and_state(self, duthosts, rand_one_dut_hostname, ptfhost,
                                            setup_stp_test_data, lag):
        """With the DUT as root the PortChannel is a forwarding designated port,
        and the DUT's BPDUs leave through one of its members."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc = self.scope(d), lag["pc"]

        self.verify_stp_state(duthost, scope, [pc], "FORWARDING")
        row = stp_utils.get_port_data(duthost, self.STP_MODE, scope, pc)
        role = row.get("role", "")
        if role:
            pytest_assert(role.upper().startswith("DESIG"),
                          "{} has role {!r} with the DUT as root, not designated".format(pc, role))
        self.capture_own_bpdu_on_lag(ptfhost, duthost, d, pc, lag["ptf_ports"])

    def test_portchannel_cost_and_priority_apply(self, duthosts, rand_one_dut_hostname, ptfhost,
                                                 setup_stp_test_data, lag):
        """The PortChannel's port cost decides the root port against the plain
        port, and its port priority reaches the daemon."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc = self.scope(d), lag["pc"]
        plain = d["dut_ports"]["dut_port_2"]
        ptf_1, ptf_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        plain_cost = self.get_port_cost(duthost, scope, plain)

        try:
            self.set_port_priority(duthost, scope, pc, PORT_PRIORITY)
            pytest_assert(
                wait_until(30, 2, 0, lambda: stp_utils.get_port_data(
                    duthost, self.STP_MODE, scope, pc).get("priority") == str(PORT_PRIORITY)),
                "port priority {} on {} did not reach the daemon: {}".format(
                    PORT_PRIORITY, pc, stp_utils.get_port_data(duthost, self.STP_MODE, scope, pc)))

            self.set_port_cost(duthost, scope, plain, PLAIN_PORT_COST)
            self.set_port_cost(duthost, scope, pc, HIGH_COST)
            with self.periodic_superior_sender(ptfhost, duthost,
                                               self.superior_params(d, [ptf_1, ptf_2]),
                                               "/tmp/stp_pc_cost_periodic.log"):
                pytest_assert(wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, scope)),
                              "DUT did not accept the superior neighbour as root")
                pytest_assert(self.get_port_cost(duthost, scope, pc) == HIGH_COST,
                              "{} cost is {}, not {}".format(pc, self.get_port_cost(duthost, scope, pc),
                                                             HIGH_COST))
                pytest_assert(self.wait_root_port(duthost, scope, plain),
                              "root port is not {} while {} costs {}".format(plain, pc, HIGH_COST))
                self.verify_stp_state(duthost, scope, [pc], self.BLOCK_STATE)

                self.set_port_cost(duthost, scope, pc, LOW_COST)
                pytest_assert(self.wait_root_port(duthost, scope, pc),
                              "root port did not move to {} when its cost dropped to {}".format(
                                  pc, LOW_COST))
                self.verify_stp_state(duthost, scope, [pc], "FORWARDING")
                self.verify_stp_state(duthost, scope, [plain], self.BLOCK_STATE)
        finally:
            self.set_port_cost(duthost, scope, plain, plain_cost)

    def test_portchannel_bpdu_guard(self, duthosts, rand_one_dut_hostname, ptfhost,
                                    setup_stp_test_data, lag):
        """A BPDU on a PortChannel with bpdu-guard --shutdown trips it; with
        the guard off it comes back and stays up under more BPDUs."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc = self.scope(d), lag["pc"]
        ptf_1 = d["dut_ports"]["ptf_port_1"]

        def _tripped():
            state = stp_utils.get_port_data(duthost, self.STP_MODE, scope, pc).get("port_state", "")
            return state in ("BPDU-DIS", "DISCARDING", "BLOCKING") or _lag_oper(duthost, pc) == "down"

        try:
            _run(duthost, "config spanning-tree interface bpdu-guard enable {} --shutdown".format(pc))
            self.run_bpdu(ptfhost, duthost, "config", self.superior_params(d, [ptf_1]),
                          "/tmp/stp_pc_bpdu_guard.log")
            pytest_assert(wait_until(30, 2, 0, _tripped),
                          "{} did not trip on a BPDU; state={!r}, oper={!r}".format(
                              pc, stp_utils.get_port_data(duthost, self.STP_MODE, scope, pc).get("port_state"),
                              _lag_oper(duthost, pc)))

            _run(duthost, "config spanning-tree interface bpdu-guard disable {}".format(pc))
            _run(duthost, "config interface shutdown {}".format(pc))
            _run(duthost, "config interface startup {}".format(pc))
            pytest_assert(wait_until(60, 2, 0, lambda: _lag_oper(duthost, pc) == "up"),
                          "{} did not come back up after the guard was disabled".format(pc))
            self.run_bpdu(ptfhost, duthost, "config", self.superior_params(d, [ptf_1]),
                          "/tmp/stp_pc_bpdu_guard_off.log")
            pytest_assert(not wait_until(6, 2, 0, lambda: _lag_oper(duthost, pc) == "down"),
                          "{} went down with the guard disabled".format(pc))
        finally:
            _run(duthost, "config spanning-tree interface bpdu-guard disable {}".format(pc))
            _run(duthost, "config interface startup {}".format(pc))

    def test_portchannel_root_guard(self, duthosts, rand_one_dut_hostname, ptfhost,
                                    setup_stp_test_data, lag):
        """With root guard on the PortChannel, a superior BPDU on it blocks the
        PortChannel instead of taking the root."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc = self.scope(d), lag["pc"]
        ptf_1 = d["dut_ports"]["ptf_port_1"]

        try:
            _run(duthost, "config spanning-tree interface root_guard enable {}".format(pc))
            with self.periodic_superior_sender(ptfhost, duthost, self.superior_params(d, [ptf_1]),
                                               "/tmp/stp_pc_root_guard.log"):
                pytest_assert(wait_until(60, 2, 0, lambda: self.root_guard_tripped(duthost, scope, pc)),
                              "{} was not blocked by root guard; state={!r}".format(
                                  pc, stp_utils.get_port_data(duthost, self.STP_MODE, scope, pc)
                                  .get("port_state")))
                pytest_assert(self.is_self_root(duthost, scope),
                              "the neighbour on root-guarded {} took the root".format(pc))
        finally:
            _run(duthost, "config spanning-tree interface root_guard disable {}".format(pc))

    def test_portchannel_topology_change_flushes(self, duthosts, rand_one_dut_hostname, ptfhost,
                                                 setup_stp_test_data, lag):
        """A topology change that arrives on the PortChannel flushes the MACs
        learned on the plain port. The probe that learns them is forwarded to
        the PortChannel, so it is counted over every member's PTF port."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc = self.scope(d), lag["pc"]
        plain = d["dut_ports"]["dut_port_2"]
        ptf_1, ptf_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        self.verify_stp_state(duthost, scope, [pc, plain], "FORWARDING")
        self.make_non_edge(ptfhost, duthost, d, ptf_2)
        if self.STP_MODE == PVST:
            # The flush row is published once per change window; start from a closed one.
            key = "STP_FASTAGEING_FLUSH_TABLE:Vlan{}".format(vlan_id)
            pytest_assert(wait_until(90, 3, 0, lambda: duthost.shell(
                "redis-cli -n 0 exists {0} _{0}".format(key)).get("stdout", "0").strip() == "0"),
                "a topology change window was still open on Vlan{}".format(vlan_id))

        def _mac_count():
            lines = duthost.shell("show mac").get("stdout_lines", [])
            return sum(1 for ln in lines if plain in ln and PROBE_MAC_PREFIX in ln.lower())

        before = _mac_count()
        self.run_bpdu(ptfhost, duthost, "validate_l2_packet",
                      {"send_port": ptf_2, "receive_port": lag["ptf_ports"], "vlan_id": vlan_id,
                       "verify_packet": True},
                      "/tmp/stp_pc_flush_l2.log")
        learned = _mac_count()
        pytest_assert(learned > before,
                      "no MAC learned on {} (before {}, after {})".format(plain, before, learned))

        self.send_tc(ptfhost, duthost, d, ptf_1)
        pytest_assert(wait_until(60, 2, 0, lambda: _mac_count() < learned),
                      "a topology change on {} did not flush {} (still {})".format(
                          pc, plain, _mac_count()))

    def test_portchannel_keeps_the_tree_through_member_churn(self, duthosts, rand_one_dut_hostname,
                                                             ptfhost, setup_stp_test_data, lag):
        """With one of the three members removed the PortChannel stays up and
        forwarding with its cost, the DUT's BPDUs still leave through it and a
        superior neighbour on it is still heard; with the member added back
        all three members are enabled and the tree is as before."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc = self.scope(d), lag["pc"]
        members, ptf_ports = lag["members"], lag["ptf_ports"]
        leaving, staying, staying_ptf = members[-1], members[:-1], ptf_ports[:-1]

        self.set_port_cost(duthost, scope, pc, RECOVERY_COST)
        pytest_assert(wait_until(30, 2, 0, lambda: self.get_port_cost(duthost, scope, pc) == RECOVERY_COST),
                      "{} cost did not become {}".format(pc, RECOVERY_COST))
        try:
            _run(duthost, "config portchannel member del {} {}".format(pc, leaving))
            pytest_assert(wait_until(60, 2, 0, lambda: _members_enabled(duthost, pc) == set(staying)),
                          "{} still lists {} after its removal: {}".format(
                              pc, leaving, _members_enabled(duthost, pc)))
            pytest_assert(_lag_oper(duthost, pc) == "up", "{} went down when {} left".format(pc, leaving))
            self.verify_stp_state(duthost, scope, [pc], "FORWARDING")
            pytest_assert(self.is_self_root(duthost, scope),
                          "the DUT lost the root when {} left {}".format(leaving, pc))
            pytest_assert(self.get_port_cost(duthost, scope, pc) == RECOVERY_COST,
                          "{} cost is {} after {} left, not {}".format(
                              pc, self.get_port_cost(duthost, scope, pc), leaving, RECOVERY_COST))
            self.capture_own_bpdu_on_lag(ptfhost, duthost, d, pc, staying_ptf)
            with self.periodic_superior_sender(ptfhost, duthost, self.superior_params(d, [staying_ptf[0]]),
                                               "/tmp/stp_pc_churn_superior.log"):
                pytest_assert(wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, scope)),
                              "a superior neighbour on {} was not heard with {} removed".format(pc, leaving))
                pytest_assert(self.wait_root_port(duthost, scope, pc),
                              "root port is not {} with the superior neighbour on it".format(pc))
            pytest_assert(wait_until(90, 3, 0, lambda: self.is_self_root(duthost, scope)),
                          "the DUT did not take the root back when the neighbour went quiet")

            _run(duthost, "config portchannel member add {} {}".format(pc, leaving))
            pytest_assert(wait_until(90, 3, 0, lambda: _members_enabled(duthost, pc) == set(members)),
                          "{} did not enable {} again: {}".format(pc, leaving, _members_enabled(duthost, pc)))
            self.verify_stp_state(duthost, scope, [pc], "FORWARDING")
            pytest_assert(self.is_self_root(duthost, scope),
                          "the DUT lost the root when {} rejoined {}".format(leaving, pc))
            pytest_assert(self.get_port_cost(duthost, scope, pc) == RECOVERY_COST,
                          "{} cost is {} after {} rejoined, not {}".format(
                              pc, self.get_port_cost(duthost, scope, pc), leaving, RECOVERY_COST))
            self.capture_own_bpdu_on_lag(ptfhost, duthost, d, pc, ptf_ports)
        finally:
            if leaving not in _members_enabled(duthost, pc):
                _run(duthost, "config portchannel member add {} {}".format(pc, leaving))

    def test_portchannel_returns_with_its_settings(self, duthosts, rand_one_dut_hostname, ptfhost,
                                                   setup_stp_test_data, lag):
        """When the PortChannel loses all of its members it leaves forwarding;
        when they come back it rejoins the tree with its port cost intact."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        scope, pc, members = self.scope(d), lag["pc"], lag["members"]

        self.set_port_cost(duthost, scope, pc, RECOVERY_COST)
        pytest_assert(wait_until(30, 2, 0, lambda: self.get_port_cost(duthost, scope, pc) == RECOVERY_COST),
                      "{} cost did not become {}".format(pc, RECOVERY_COST))
        try:
            for member in members:
                _run(duthost, "config interface shutdown {}".format(member))
            pytest_assert(wait_until(60, 2, 0, lambda: _lag_oper(duthost, pc) == "down"),
                          "{} stayed up with every member shut".format(pc))
            pytest_assert(
                wait_until(60, 2, 0, lambda: stp_utils.get_port_data(
                    duthost, self.STP_MODE, scope, pc).get("port_state", "DISABLED") != "FORWARDING"),
                "{} still reads FORWARDING with no member up".format(pc))

            for member in members:
                _run(duthost, "config interface startup {}".format(member))
            pytest_assert(wait_until(120, 3, 0, lambda: _lag_oper(duthost, pc) == "up"),
                          "{} did not come back with its members".format(pc))
            pytest_assert(wait_until(60, 3, 0, lambda: _members_enabled(duthost, pc) == set(members)),
                          "{} came back without all of {}: {}".format(
                              pc, members, _members_enabled(duthost, pc)))
            self.verify_stp_state(duthost, scope, [pc], "FORWARDING")
            pytest_assert(self.get_port_cost(duthost, scope, pc) == RECOVERY_COST,
                          "{} came back with cost {}, not {}".format(
                              pc, self.get_port_cost(duthost, scope, pc), RECOVERY_COST))
        finally:
            for member in members:
                _run(duthost, "config interface startup {}".format(member))


class TestPvstPortChannel(_PortChannelStp):

    STP_MODE = PVST
    BLOCK_STATE = "BLOCKING"

    def scope(self, data):
        return data["vlan"]["id"]

    def superior_params(self, data, send_ptf_ports, **overrides):
        params = {"vlan_id": data["vlan"]["id"], "send_port": list(send_ptf_ports)}
        params.update(overrides)
        return params

    def send_tc(self, ptfhost, duthost, data, ptf_port):
        self.run_bpdu(ptfhost, duthost, "tcn",
                      {"vlan_id": data["vlan"]["id"], "send_port": [ptf_port]},
                      "/tmp/stp_pc_tcn.log")

    def root_guard_tripped(self, duthost, scope, port):
        return self.get_port_state(duthost, scope, port) == "ROOT-INC"

    def capture_own_bpdu(self, ptfhost, duthost, data, ptf_port):
        vlan_id = data["vlan"]["id"]
        prio = int(stp_utils._hgetall(duthost, "STP_VLAN|Vlan{}".format(vlan_id), dbnum=4)
                   .get("priority", "32768"))
        self.run_bpdu(ptfhost, duthost, "validate_root_bridge_id",
                      {"vlan_id": vlan_id,
                       "expected_bridge_mac": data["dut_ports"]["mac"],
                       "expected_bridge_priority": prio + vlan_id,
                       "capture_port": ptf_port, "capture_duration": self.PKT_CAPTURE_DURATION},
                      "/tmp/stp_pc_own_bpdu.log")


class TestMstpPortChannel(_PortChannelStp):

    STP_MODE = MST
    BLOCK_STATE = "DISCARDING"

    def scope(self, data):
        return CIST

    def _region(self, data):
        mst = data["mst"]
        return {"region_name": mst["region_name"], "revision": mst["revision"],
                "vid_to_mstid": json.dumps(mst["vid_to_mstid"])}

    def superior_params(self, data, send_ptf_ports, **overrides):
        params = dict(self._region(data), send_port=list(send_ptf_ports),
                      cist_flags=CIST_FLAGS_DESIGNATED,
                      cist_root_priority=SUPERIOR_PRIORITY, cist_root_mac=FOREIGN_BRIDGE_MAC,
                      cist_bridge_priority=SUPERIOR_PRIORITY, cist_bridge_mac=FOREIGN_BRIDGE_MAC)
        params.update(overrides)
        return params

    def send_tc(self, ptfhost, duthost, data, ptf_port):
        self.run_bpdu(ptfhost, duthost, "tcn", self.superior_params(data, [ptf_port]),
                      "/tmp/stp_pc_tcn.log")

    def make_non_edge(self, ptfhost, duthost, data, ptf_port):
        self.run_bpdu(ptfhost, duthost, "send_cist",
                      self.superior_params(data, [ptf_port],
                                           cist_flags=CIST_FLAGS_QUIET_DESIGNATED,
                                           cist_root_priority=INFERIOR_PRIORITY,
                                           cist_root_mac=INFERIOR_BRIDGE_MAC,
                                           cist_bridge_priority=INFERIOR_PRIORITY,
                                           cist_bridge_mac=INFERIOR_BRIDGE_MAC),
                      "/tmp/stp_pc_neighbour.log")

    def requiesce(self, duthost, data):
        # A disable drops the region, so put it back after the bounce.
        self.bounce_stp(duthost)
        mst = data["mst"]
        self.setup_region(duthost, mst["region_name"], mst["revision"], mst["instance_vlan_map"])

    def root_guard_tripped(self, duthost, scope, port):
        return self.get_port_state(duthost, scope, port) in ("DISCARDING", "ROOT-INC", "BLOCKING")

    def capture_own_bpdu(self, ptfhost, duthost, data, ptf_port):
        self.run_bpdu(ptfhost, duthost, "validate_bpdu_packet",
                      dict(self._region(data), expected_max_age=20, capture_port=ptf_port,
                           capture_duration=self.PKT_CAPTURE_DURATION),
                      "/tmp/stp_pc_own_bpdu.log")
