"""U6 -- structured receive endpoint returns ADJ_IN prefixes per neighbor.

The shim's ``/adj-in`` replaces ExaBGP's text dump. Here the FakeStub replays a
neighbor advertising a known prefix set; the receive path must return exactly
that set for the requested family, sourced from the ADJ_IN table.
"""
import pytest

pytest.importorskip("gobgp.shim._gbapi",
                    reason="gobgp gRPC stubs are generated into the PTF image")

from gobgp.shim import receive  # noqa: E402
from gobgp.shim.translator import NeighborClient  # noqa: E402
from gobgp.shim._gbapi import common  # noqa: E402
from gobgp.tests.fakes import FakeStub  # noqa: E402


def test_u6_adj_in_prefixes_match_advertisement():
    stub = FakeStub(peers=["10.0.0.57"],
                    adj_in={"10.0.0.57": ["100.0.0.0/24", "100.0.1.0/24"]})
    assert receive.adj_in_prefixes(stub, "v4") == ["100.0.0.0/24", "100.0.1.0/24"]


def test_u6_adj_in_empty_when_no_peer():
    assert receive.adj_in_prefixes(FakeStub(), "v4") == []


def test_u6_adj_in_uses_correct_family_afi():
    seen = {}
    stub = FakeStub(peers=["fc00::1"], adj_in={"fc00::1": ["2064:100::/64"]})
    orig = stub.ListPath

    def spy(req):
        seen["afi"] = req.family.afi
        return orig(req)

    stub.ListPath = spy
    out = receive.adj_in_prefixes(stub, "v6")
    assert out == ["2064:100::/64"]
    assert seen["afi"] == common.Family.AFI_IP6


def test_u6_neighborclient_delegates_to_receive():
    stub = FakeStub(peers=["10.0.0.57"], adj_in={"10.0.0.57": ["100.0.0.0/24"]})
    c = NeighborClient("127.0.0.1:50052", "v4", "ARISTA01T1", stub=stub)
    assert c.adj_in_prefixes() == ["100.0.0.0/24"]
