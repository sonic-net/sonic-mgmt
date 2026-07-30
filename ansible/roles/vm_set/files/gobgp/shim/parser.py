"""ExaBGP text-command grammar parser.

Pure functions, **no gRPC/protobuf imports**, so the grammar can be unit-tested
(U1/U3) without a gobgpd or the generated stubs. Translates the exact ExaBGP
command grammar that ``announce_routes.py`` and the test helpers emit into
plain structured dicts; :mod:`gobgp.shim.translator` turns those into gRPC paths.

Grammar handled (superset of what sonic-mgmt emits)::

    announce route <prefix> next-hop <nh> [as-path [ <asns> ]]
        [community [ <c> ]] [large-community [ <c> ]] [extended-community [ <c> ]]
        [local-preference <n>] [med <n>] [origin igp|egp|incomplete]
    withdraw route <prefix> [next-hop <nh>] ...
    announce attributes <same attrs> nlri <p1> <p2> ...
    withdraw attributes ... nlri <p1> <p2> ...
"""
from __future__ import print_function

ORIGIN_MAP = {"igp": 0, "egp": 1, "incomplete": 2}

_WELL_KNOWN_COMMUNITIES = {
    "no-export": 0xFFFFFF01,
    "no-advertise": 0xFFFFFF02,
    "no-export-subconfed": 0xFFFFFF03,
    "local-as": 0xFFFFFF03,
}


def _bracket_list(tokens, i):
    """Parse ``[ a b c ]`` starting at ``tokens[i] == '['``.

    Returns ``(items, next_i)``. Also tolerates a single bare token, because
    ExaBGP allows the un-bracketed form (e.g. ``community 65000:1``).
    """
    if i >= len(tokens):
        return [], i
    if tokens[i] == "[":
        items = []
        i += 1
        while i < len(tokens) and tokens[i] != "]":
            items.append(tokens[i])
            i += 1
        i += 1  # skip ']'
        return items, i
    return [tokens[i]], i + 1


def parse_community(tok):
    """``'65000:100'`` -> packed 32-bit community int; well-known names mapped."""
    if tok in _WELL_KNOWN_COMMUNITIES:
        return _WELL_KNOWN_COMMUNITIES[tok]
    if ":" in tok:
        hi, lo = tok.split(":")
        return (int(hi) << 16) | int(lo)
    return int(tok)


def parse_large_community(tok):
    """``'a:b:c'`` -> ``(a, b, c)`` tuple of ints."""
    a, b, c = tok.split(":")
    return (int(a), int(b), int(c))


def parse_ext_community(tok):
    """``'target:65000:100'`` or ``'65000:100'`` -> ``(as_num, local_admin)``."""
    t = tok.split(":")
    if len(t) == 3:
        _, a, b = t
    else:
        a, b = t
    return (int(a), int(b))


def parse_attrs(tokens, i):
    """Parse the shared attribute tail (next-hop/as-path/community/...).

    Returns ``(attrs_dict, next_i)``. Stops at the ``nlri`` keyword or end of
    input. Truncated (value-less) and unknown tokens are skipped defensively; a
    malformed scalar value (e.g. a non-integer ``med``) raises ``ValueError``,
    which ``parse_command`` catches to keep the U3 no-op contract.
    """
    a = {"nexthop": None, "aspath": None, "communities": None,
         "large_communities": None, "ext_communities": None,
         "local_pref": None, "med": None, "origin": None}
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t == "nlri":
            break
        elif t == "next-hop":
            if i + 1 >= n:
                break
            a["nexthop"] = tokens[i + 1]
            i += 2
        elif t == "as-path":
            items, i = _bracket_list(tokens, i + 1)
            a["aspath"] = [int(x) for x in items]
        elif t == "community":
            items, i = _bracket_list(tokens, i + 1)
            a["communities"] = [parse_community(x) for x in items]
        elif t == "large-community":
            items, i = _bracket_list(tokens, i + 1)
            a["large_communities"] = [parse_large_community(x) for x in items]
        elif t == "extended-community":
            items, i = _bracket_list(tokens, i + 1)
            a["ext_communities"] = [parse_ext_community(x) for x in items]
        elif t in ("local-preference", "local-pref"):
            if i + 1 >= n:
                break
            a["local_pref"] = int(tokens[i + 1])
            i += 2
        elif t == "med":
            if i + 1 >= n:
                break
            a["med"] = int(tokens[i + 1])
            i += 2
        elif t == "origin":
            if i + 1 >= n:
                break
            a["origin"] = ORIGIN_MAP.get(tokens[i + 1], 0)
            i += 2
        else:
            i += 1
    return a, i


def parse_command(cmd):
    """Parse one ExaBGP command line into an operation dict.

    Returns ``{op, is_withdraw, prefixes: [...], **attrs}`` for announce/withdraw
    of ``route``/``attributes`` forms, or ``{"op": "noop"}`` for commands we
    intentionally ignore (route-refresh, session-level teardown, blanks),
    truncated commands (e.g. ``announce route`` with no prefix), and commands
    whose attribute values are malformed (e.g. a non-integer ``med``), so a bad
    line from an untrusted body degrades to a no-op instead of raising.
    """
    tokens = cmd.strip().split()
    if not tokens:
        return {"op": "noop"}
    op = tokens[0]
    if op not in ("announce", "withdraw"):
        return {"op": "noop", "raw": cmd}
    is_withdraw = (op == "withdraw")

    kind = tokens[1] if len(tokens) > 1 else ""
    try:
        if kind == "route":
            if len(tokens) < 3:  # 'announce route' with no prefix
                return {"op": "noop", "raw": cmd}
            prefix = tokens[2]
            attrs, _ = parse_attrs(tokens, 3)
            return dict(op=op, is_withdraw=is_withdraw, prefixes=[prefix], **attrs)
        elif kind == "attributes":
            attrs, i = parse_attrs(tokens, 2)
            prefixes = tokens[i + 1:] if i < len(tokens) else []  # tokens[i] == 'nlri'
            return dict(op=op, is_withdraw=is_withdraw, prefixes=prefixes, **attrs)
    except ValueError:  # malformed attribute value -> safe no-op
        return {"op": "noop", "raw": cmd}
    return {"op": "noop", "raw": cmd}


def commands_from_body(body):
    """Split an HTTP POST body into individual command strings.

    Accepts ExaBGP form-encoding (``command=`` / ``commands=`` where the latter
    is ``;``-separated) **and** raw text (one command or ``;``-separated), so
    every existing caller works unchanged.
    """
    from urllib.parse import parse_qs

    cmds = []
    if "command=" in body or "commands=" in body:
        form = parse_qs(body, keep_blank_values=True)
        for c in form.get("command", []):
            cmds.append(c)
        for blob in form.get("commands", []):
            cmds.extend(blob.split(";"))
    else:
        cmds.extend(body.split(";"))
    return [c.strip() for c in cmds if c.strip()]
