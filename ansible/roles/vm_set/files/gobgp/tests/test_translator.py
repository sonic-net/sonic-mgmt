"""U2 translation correctness, U3 as-path guard, U4 batching, U5 targeting.

All against :class:`FakeStub` -- no gobgpd. U2 asserts N parsed prefixes become
N gb.Path messages with the right family/next-hop encoding. U4 asserts a POST of
N routes issues ONE AddPathStream (chunked), never a unary call per route
(guards the batched-gRPC design, HLD R6/U4). U5 asserts a route applied to one
neighbor's client never touches another neighbor's stub.
"""
import pytest

pytest.importorskip("gobgp.shim._gbapi",
                    reason="gobgp gRPC stubs are generated into the PTF image")

from gobgp.shim import parser  # noqa: E402
from gobgp.shim.translator import (  # noqa: E402
    NeighborClient, build_path, stream_requests, _STREAM_CHUNK)
from gobgp.shim._gbapi import gb, common  # noqa: E402
from gobgp.tests.fakes import FakeStub  # noqa: E402


def _client(family="v4", stub=None, self_nh="10.10.246.254"):
    return NeighborClient("127.0.0.1:50052", family, "ARISTA01T1",
                          self_nexthop=self_nh, stub=stub or FakeStub())


def _attrs(path, field):
    """Return the sub-messages of the given oneof kind carried in path.pattrs.

    Path attributes are a typed ``oneof`` on ``Attribute``, so selecting e.g.
    every NEXT_HOP is ``HasField('next_hop')``.
    """
    return [getattr(a, field) for a in path.pattrs if a.HasField(field)]


# --------------------------------------------------------------------------- #
# U2 -- translation correctness
# --------------------------------------------------------------------------- #
def test_u2_v4_path_family_and_nexthop():
    p = build_path("10.0.0.0/24", "v4", nexthop="1.1.1.1")
    assert p.family.afi == common.Family.AFI_IP
    assert p.family.safi == common.Family.SAFI_UNICAST
    ipp = p.nlri.prefix  # typed NLRI oneof -> IPAddressPrefix
    assert ipp.prefix == "10.0.0.0" and ipp.prefix_len == 24
    nhs = [nh.next_hop for nh in _attrs(p, "next_hop")]
    assert nhs == ["1.1.1.1"]


def test_u2_v6_nexthop_in_mpreach():
    p = build_path("2001:db8::/48", "v6", nexthop="fe80::1")
    assert p.family.afi == common.Family.AFI_IP6
    # v6 next hop rides in MpReachNLRI, not a bare NextHopAttribute
    assert not _attrs(p, "next_hop")
    mpr = _attrs(p, "mp_reach")
    assert mpr and list(mpr[0].next_hops) == ["fe80::1"]


def test_u2_build_paths_count_matches_prefixes():
    cmds = [parser.parse_command(
        "announce route 10.0.%d.0/24 next-hop self" % i) for i in range(50)]
    add, dele, errors = _client().build_paths(cmds)
    assert len(add) == 50 and dele == [] and errors == []


def test_u2_nexthop_self_resolves_to_local_ip():
    c = _client(self_nh="10.10.246.254")
    add, _, _ = c.build_paths([parser.parse_command(
        "announce route 10.0.0.0/24 next-hop self")])
    nh = [x.next_hop for x in _attrs(add[0], "next_hop")]
    assert nh == ["10.10.246.254"]


def test_u2_withdraw_flag_set():
    add, dele, _ = _client().build_paths([parser.parse_command(
        "withdraw route 10.0.0.0/24 next-hop self")])
    assert add == [] and len(dele) == 1 and dele[0].is_withdraw is True


def test_u2_v6_withdraw_flag_set():
    add, dele, _ = _client(family="v6").build_paths([parser.parse_command(
        "withdraw route 2001:db8::/48 next-hop self")])
    assert add == [] and len(dele) == 1 and dele[0].is_withdraw is True


# --------------------------------------------------------------------------- #
# U3 -- as-path guard (translate half)
# --------------------------------------------------------------------------- #
def test_u3_aspath_over_255_rejected():
    with pytest.raises(ValueError):
        build_path("10.0.0.0/24", "v4", nexthop="1.1.1.1",
                   aspath=[65000] * 256)


def test_u3_aspath_255_ok():
    p = build_path("10.0.0.0/24", "v4", nexthop="1.1.1.1", aspath=[65000] * 255)
    assert _attrs(p, "as_path")


def test_u3_prefix_len_out_of_range_rejected():
    # An out-of-range length passes isdigit() but would build a Path that
    # poisons the batched AddPathStream -- reject it before it is built.
    for prefix, family in (("10.0.0.0/33", "v4"), ("2001:db8::/129", "v6")):
        with pytest.raises(ValueError):
            build_path(prefix, family, nexthop="1.1.1.1")


def test_u3_announce_without_nexthop_rejected():
    # 'next-hop self' with no self_nexthop resolves to None -> an announce with
    # no NEXT_HOP; fail fast rather than stream an invalid UPDATE.
    with pytest.raises(ValueError):
        build_path("10.0.0.0/24", "v4", nexthop=None)
    with pytest.raises(ValueError):
        build_path("2001:db8::/48", "v6", nexthop=None)
    # withdraw carries no next-hop -> must NOT raise
    build_path("10.0.0.0/24", "v4", nexthop=None, is_withdraw=True)


def test_u3_nexthop_self_unset_is_per_route_error():
    # self_nexthop=None + 'next-hop self' announce -> isolated per-route error;
    # a sibling route with an explicit next-hop still applies.
    c = _client(self_nh=None)
    add, dele, errors = c.build_paths([
        parser.parse_command("announce route 10.0.0.0/24 next-hop self"),
        parser.parse_command("announce route 10.0.1.0/24 next-hop 1.1.1.1"),
    ])
    assert len(add) == 1 and len(errors) == 1


def test_u3_bare_announce_no_nexthop_is_per_route_error():
    # A bare 'announce route X' (no next-hop clause) must NOT be silently
    # coalesced to self_nexthop; build_path rejects it as a per-route error.
    c = _client(self_nh="10.10.246.254")
    add, dele, errors = c.build_paths(
        [parser.parse_command("announce route 10.0.0.0/24")])
    assert add == [] and len(errors) == 1


def test_u3_bare_withdraw_carries_no_nexthop():
    # A bare 'withdraw route X' (no next-hop clause) is applied and its Path
    # carries no NEXT_HOP attribute.
    c = _client(self_nh="10.10.246.254")
    add, dele, errors = c.build_paths(
        [parser.parse_command("withdraw route 10.0.0.0/24")])
    assert errors == [] and len(dele) == 1
    assert not _attrs(dele[0], "next_hop")


# --------------------------------------------------------------------------- #
# U4 -- batching: N routes -> ONE stream, ceil(N/chunk) messages
# --------------------------------------------------------------------------- #
def test_u4_stream_requests_chunking():
    paths = [build_path("10.%d.%d.0/24" % (i // 256, i % 256), "v4",
                        nexthop="1.1.1.1") for i in range(2500)]
    reqs = list(stream_requests(paths))
    assert len(reqs) == 3  # ceil(2500/1000)
    assert sum(len(r.paths) for r in reqs) == 2500
    assert all(r.table_type == gb.TABLE_TYPE_GLOBAL for r in reqs)


def test_u4_apply_many_single_stream_call_not_per_route():
    stub = FakeStub()
    c = _client(stub=stub)
    cmds = [parser.parse_command(
        "announce route 10.%d.%d.0/24 next-hop self" % (i // 256, i % 256))
        for i in range(2500)]
    c.apply_many(cmds)
    assert stub.call_count == 1          # ONE AddPathStream, not 2500 unary
    assert stub.request_messages == 3    # chunked at _STREAM_CHUNK
    assert stub.total_paths == 2500
    assert _STREAM_CHUNK == 1000


def test_u4_withdraw_uses_same_stream_api():
    stub = FakeStub()
    c = _client(stub=stub)
    cmds = [parser.parse_command(
        "withdraw route 10.0.%d.0/24 next-hop self" % i) for i in range(10)]
    c.apply_many(cmds)
    assert stub.call_count == 1
    assert stub.withdraw_flags() == [True] * 10


def test_u4_empty_batch_no_call():
    stub = FakeStub()
    _client(stub=stub).apply_many([parser.parse_command("")])
    assert stub.call_count == 0


# --------------------------------------------------------------------------- #
# W1 -- one bad route never drops the whole batch (best-effort apply)
# --------------------------------------------------------------------------- #
def test_w1_bad_route_isolated_good_routes_still_applied():
    stub = FakeStub()
    c = _client(stub=stub)
    cmds = [
        parser.parse_command("announce route 10.0.0.0/24 next-hop self"),
        parser.parse_command("announce route NOTAPREFIX next-hop self"),
        parser.parse_command("announce route 10.0.1.0/24 next-hop self"),
    ]
    errors = c.apply_many(cmds)
    assert stub.total_paths == 2          # both good routes applied
    assert len(errors) == 1 and "NOTAPREFIX" in errors[0]


def test_w1_long_aspath_isolated_not_batch_fatal():
    stub = FakeStub()
    c = _client(stub=stub)
    good = parser.parse_command("announce route 10.0.0.0/24 next-hop self")
    bad = dict(op="announce", is_withdraw=False, prefixes=["10.0.9.0/24"],
               nexthop="self", aspath=[65000] * 300)
    errors = c.apply_many([good, bad])
    assert stub.total_paths == 1
    assert len(errors) == 1 and "as-path too long" in errors[0]


def test_w1_clean_batch_returns_no_errors():
    stub = FakeStub()
    assert _client(stub=stub).apply_many(
        [parser.parse_command("announce route 10.0.0.0/24 next-hop self")]) == []


# --------------------------------------------------------------------------- #
# U5 -- per-neighbor targeting
# --------------------------------------------------------------------------- #
def test_u5_route_on_one_client_never_touches_another():
    stub_a, stub_b = FakeStub(), FakeStub()
    ca = _client(stub=stub_a)
    _client(stub=stub_b)  # neighbor B's client exists but is never driven
    ca.apply_many([parser.parse_command(
        "announce route 10.0.0.0/24 next-hop self")])
    assert stub_a.total_paths == 1
    assert stub_b.call_count == 0 and stub_b.total_paths == 0
