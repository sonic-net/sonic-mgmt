"""Command-dict -> gobgp gRPC translation and the per-neighbor client.

This module owns the two things that turn parsed commands into BGP state:

* :func:`build_path` -- one parsed prefix + attributes -> a ``gb.Path`` protobuf
  (typed-oneof NLRI + path attributes), and
* :class:`NeighborClient` -- batches every prefix from one HTTP POST into a
  **single** ``AddPathStream`` (chunked), never a unary call per route. That
  batching is the whole point of R6 and is guarded by unit test U4.

Withdrawals reuse the same stream: gobgp has no ``DeletePathStream``, but
``AddPathStream`` honours each ``Path.is_withdraw`` flag, so a bulk withdraw is
one streamed call exactly like a bulk announce.

The gRPC stub is injectable (``NeighborClient(..., stub=...)``) so U2/U4/U5 can
drive the batching logic with a fake stub and no real gobgpd.
"""
import threading

from ._gbapi import gb, gbg, attr, nlri, extcom, grpc, family_msg
from . import receive

ORIGIN_DEFAULT = 0
_AS_SEGMENT_MAX = 255  # one AS_PATH segment length field is a single octet
_STREAM_CHUNK = 1000   # paths per AddPathStreamRequest message


def _nlri(prefix_len, prefix):
    return nlri.NLRI(prefix=nlri.IPAddressPrefix(prefix_len=prefix_len,
                                                 prefix=prefix))


def build_path(prefix, family, nexthop=None, aspath=None, communities=None,
               large_communities=None, ext_communities=None, local_pref=None,
               med=None, origin=None, is_withdraw=False):
    """Build one ``gb.Path`` from parsed command fields.

    ``family`` is ``"v4"`` or ``"v6"``; for v6 the next hop is carried in an
    ``MpReachNLRIAttribute`` rather than a plain ``NextHopAttribute``.
    """
    fam = family_msg(family)
    if not is_withdraw and not nexthop:
        raise ValueError("announce %s has no next-hop "
                         "('next-hop self' needs self_nexthop in the port spec)"
                         % prefix)
    if "/" not in prefix:
        raise ValueError("malformed prefix %r (expected addr/len)" % prefix)
    addr, plen = prefix.split("/", 1)
    if not plen.isdigit():
        raise ValueError("malformed prefix %r (bad length)" % prefix)
    plen_i = int(plen)
    max_plen = 32 if family == "v4" else 128
    if plen_i > max_plen:
        raise ValueError("prefix %r length exceeds /%d max for %s"
                         % (prefix, max_plen, family))
    route = _nlri(plen_i, addr)

    pattrs = [attr.Attribute(origin=attr.OriginAttribute(
        origin=origin if origin is not None else ORIGIN_DEFAULT))]

    if aspath:
        # >255 ASNs overflow gobgpd's one-octet segment length and panic the
        # backend; reject with a clear error instead.
        if len(aspath) > _AS_SEGMENT_MAX:
            raise ValueError(
                "as-path too long (%d ASNs > %d per-segment limit) for %s"
                % (len(aspath), _AS_SEGMENT_MAX, prefix))
        seg = attr.AsSegment(type=attr.AsSegment.TYPE_AS_SEQUENCE, numbers=aspath)
        pattrs.append(attr.Attribute(as_path=attr.AsPathAttribute(segments=[seg])))

    if local_pref is not None:
        pattrs.append(attr.Attribute(
            local_pref=attr.LocalPrefAttribute(local_pref=local_pref)))
    if med is not None:
        pattrs.append(attr.Attribute(
            multi_exit_disc=attr.MultiExitDiscAttribute(med=med)))
    if communities:
        pattrs.append(attr.Attribute(
            communities=attr.CommunitiesAttribute(communities=communities)))
    if large_communities:
        lcs = [attr.LargeCommunity(global_admin=g, local_data1=d1, local_data2=d2)
               for (g, d1, d2) in large_communities]
        pattrs.append(attr.Attribute(
            large_communities=attr.LargeCommunitiesAttribute(communities=lcs)))
    if ext_communities:
        exts = [
            extcom.ExtendedCommunity(
                two_octet_as_specific=extcom.TwoOctetAsSpecificExtended(
                    is_transitive=True, sub_type=2, asn=as_num,
                    local_admin=local_admin))
            for (as_num, local_admin) in ext_communities]
        pattrs.append(attr.Attribute(
            extended_communities=attr.ExtendedCommunitiesAttribute(communities=exts)))

    if family == "v4":
        if nexthop:
            pattrs.append(attr.Attribute(
                next_hop=attr.NextHopAttribute(next_hop=nexthop)))
    else:
        nh = [nexthop] if nexthop else []
        pattrs.append(attr.Attribute(mp_reach=attr.MpReachNLRIAttribute(
            family=fam, next_hops=nh, nlris=[route])))

    return gb.Path(nlri=route, pattrs=pattrs, family=fam, is_withdraw=is_withdraw)


def stream_requests(paths, chunk=_STREAM_CHUNK):
    """Yield ``AddPathStreamRequest`` messages carrying ``paths`` in ``chunk``-sized
    batches against the GLOBAL table.

    Factored out of :class:`NeighborClient` so U4 can assert that N prefixes
    produce ``ceil(N/chunk)`` stream messages (i.e. batched, not per-route).
    """
    for j in range(0, len(paths), chunk):
        yield gb.AddPathStreamRequest(table_type=gb.TABLE_TYPE_GLOBAL,
                                      paths=paths[j:j + chunk])


class NeighborClient(object):
    """gRPC client for one (neighbor, family) gobgpd behind an HTTP port."""

    def __init__(self, grpc_endpoint, family, name, self_nexthop=None,
                 stub=None):
        self.endpoint = grpc_endpoint
        self.family = family
        self.name = name
        self.self_nexthop = self_nexthop  # ptf local ip, for 'next-hop self'
        self._lock = threading.Lock()
        if stub is not None:  # dependency injection for tests
            self._chan = None
            self._stub = stub
        else:
            self._chan = grpc.insecure_channel(grpc_endpoint)
            self._stub = gbg.GoBgpServiceStub(self._chan)

    @property
    def stub(self):
        return self._stub

    def _resolve_nh(self, nh):
        # Only an explicit 'next-hop self' maps to the local IP. A missing
        # next-hop (None) is left as-is so build_path fails an announce fast and
        # a bare withdraw carries no NEXT_HOP.
        if nh == "self":
            return self.self_nexthop
        return nh

    def build_paths(self, parsed_list):
        """Flatten parsed commands into ``(add_paths, del_paths, errors)``.

        Each command is translated independently: one malformed prefix or an
        as-path-too-long only drops *that* command (its message is appended to
        ``errors``) instead of aborting the whole POST, so a single bad route in
        a full-table announce never discards the thousands of good ones -- the
        best-effort behaviour ExaBGP callers expect. ``errors`` is empty on a
        clean batch.
        """
        add_paths, del_paths, errors = [], [], []
        for parsed in parsed_list:
            if not parsed or parsed.get("op") == "noop":
                continue
            nh = self._resolve_nh(parsed.get("nexthop"))
            for prefix in parsed["prefixes"]:
                try:
                    p = build_path(
                        prefix, self.family, nexthop=nh,
                        aspath=parsed.get("aspath"),
                        communities=parsed.get("communities"),
                        large_communities=parsed.get("large_communities"),
                        ext_communities=parsed.get("ext_communities"),
                        local_pref=parsed.get("local_pref"),
                        med=parsed.get("med"), origin=parsed.get("origin"),
                        is_withdraw=parsed["is_withdraw"])
                except Exception as exc:  # bad single route -- skip, keep the rest
                    errors.append("%s: %s" % (prefix, exc))
                    continue
                (del_paths if parsed["is_withdraw"] else add_paths).append(p)
        return add_paths, del_paths, errors

    def apply_many(self, parsed_list):
        """Apply every command from one HTTP POST, streaming adds and
        withdrawals as one ``AddPathStream`` per direction.

        ``announce_routes`` emits one ``announce route <prefix>`` per prefix, so
        a full-table announce arrives as one POST of thousands of one-prefix
        commands -- all one direction, sent as a single chunked stream. Building
        all paths first turns thousands of round-trips into one streamed call --
        the behaviour that lets gobgp match/beat exabgp convergence. A POST that
        mixes adds and withdrawals uses one stream per direction (two calls).

        Returns the list of per-route error strings (empty on success). Good
        routes are always applied even when some routes errored; because
        AddPath is idempotent per NLRI, a caller may safely retry on a non-empty
        result without duplicating state.
        """
        add_paths, del_paths, errors = self.build_paths(parsed_list)
        if not add_paths and not del_paths:
            return errors
        with self._lock:
            if add_paths:
                self._stub.AddPathStream(stream_requests(add_paths))
            if del_paths:
                # is_withdraw already set by build_path -> same stream API
                self._stub.AddPathStream(stream_requests(del_paths))
        return errors

    def adj_in_prefixes(self):
        """Prefixes the DUT advertised to us (this neighbor's ADJ_IN RIB)."""
        with self._lock:
            return receive.adj_in_prefixes(self._stub, self.family)
