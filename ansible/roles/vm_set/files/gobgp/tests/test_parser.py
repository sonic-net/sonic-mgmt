"""U1 grammar parity + U3 negative parsing -- pure parser, no gRPC.

U1: every ExaBGP command form sonic-mgmt emits parses into the expected
structured dict. U3 (parse half): malformed / unknown / empty inputs degrade to
a safe no-op instead of raising, so a bad line never takes the shim down.
"""
from gobgp.shim import parser


# --------------------------------------------------------------------------- #
# U1 -- grammar parity
# --------------------------------------------------------------------------- #
def test_u1_announce_route_full_attrs():
    d = parser.parse_command(
        "announce route 10.0.0.0/24 next-hop 1.1.1.1 as-path [ 65000 65001 ] "
        "community [ 65000:1 no-export ] local-preference 200 med 5 origin igp")
    assert d["op"] == "announce" and d["is_withdraw"] is False
    assert d["prefixes"] == ["10.0.0.0/24"]
    assert d["nexthop"] == "1.1.1.1"
    assert d["aspath"] == [65000, 65001]
    assert d["communities"] == [(65000 << 16) | 1, 0xFFFFFF01]
    assert d["local_pref"] == 200 and d["med"] == 5 and d["origin"] == 0


def test_u1_withdraw_route():
    d = parser.parse_command("withdraw route 2001:db8::/48 next-hop fe80::1")
    assert d["op"] == "withdraw" and d["is_withdraw"] is True
    assert d["prefixes"] == ["2001:db8::/48"] and d["nexthop"] == "fe80::1"


def test_u1_announce_attributes_multi_nlri():
    d = parser.parse_command(
        "announce attributes next-hop 1.1.1.1 origin egp "
        "nlri 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24")
    assert d["prefixes"] == ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
    assert d["nexthop"] == "1.1.1.1" and d["origin"] == 1


def test_u1_large_and_ext_community():
    d = parser.parse_command(
        "announce route 10.0.0.0/24 next-hop 1.1.1.1 "
        "large-community [ 65000:1:2 ] extended-community [ target:65000:100 ]")
    assert d["large_communities"] == [(65000, 1, 2)]
    assert d["ext_communities"] == [(65000, 100)]


def test_u1_bare_unbracketed_community():
    d = parser.parse_command(
        "announce route 10.0.0.0/24 next-hop 1.1.1.1 community 65000:7")
    assert d["communities"] == [(65000 << 16) | 7]


def test_u1_origin_variants_and_localpref_alias():
    assert parser.parse_command(
        "announce route 10.0.0.0/24 origin incomplete")["origin"] == 2
    assert parser.parse_command(
        "announce route 10.0.0.0/24 local-pref 150")["local_pref"] == 150


def test_u1_commands_from_body_forms():
    assert parser.commands_from_body("command=announce+route+10.0.0.0%2F24") == \
        ["announce route 10.0.0.0/24"]
    assert parser.commands_from_body("commands=a+1;b+2") == ["a 1", "b 2"]
    assert parser.commands_from_body("announce route 10.0.0.0/24") == \
        ["announce route 10.0.0.0/24"]


# --------------------------------------------------------------------------- #
# U3 -- negative parsing (never raises)
# --------------------------------------------------------------------------- #
def test_u3_unknown_verb_is_noop():
    assert parser.parse_command("frobnicate route 1.2.3.0/24")["op"] == "noop"


def test_u3_empty_and_blank():
    assert parser.parse_command("")["op"] == "noop"
    assert parser.parse_command("   ")["op"] == "noop"
    assert parser.commands_from_body("") == []


def test_u3_unknown_attr_token_skipped():
    d = parser.parse_command(
        "announce route 10.0.0.0/24 next-hop 1.1.1.1 wat 9 origin igp")
    assert d["nexthop"] == "1.1.1.1" and d["origin"] == 0


def test_u3_truncated_commands_are_noop_not_raise():
    # W3: partial lines must degrade to a safe no-op, never raise IndexError.
    for cmd in ("announce route",
                "announce",
                "withdraw route",
                "announce route 10.0.0.0/24 next-hop",
                "announce route 10.0.0.0/24 med",
                "announce route 10.0.0.0/24 local-pref",
                "announce route 10.0.0.0/24 origin"):
        d = parser.parse_command(cmd)
        assert d.get("op") in ("announce", "withdraw", "noop")
        # trailing-valueless attr keyword just yields a None attr, never a crash
        if d.get("op") != "noop":
            assert d["prefixes"] == ["10.0.0.0/24"]


def test_u3_truncated_route_no_prefix_is_noop():
    assert parser.parse_command("announce route")["op"] == "noop"
    assert parser.parse_command("withdraw route")["op"] == "noop"


def test_u3_malformed_scalar_is_noop():
    # W3: non-integer med/local-pref (untrusted body) degrade to noop, never raise.
    for cmd in ("announce route 10.0.0.0/24 med abc",
                "announce route 10.0.0.0/24 local-pref xyz",
                "announce route 10.0.0.0/24 local-preference NaN"):
        assert parser.parse_command(cmd)["op"] == "noop"
