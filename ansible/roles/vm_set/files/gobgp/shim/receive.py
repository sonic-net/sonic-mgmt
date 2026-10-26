"""Structured receive path -- prefixes the DUT advertised to us (BGP ADJ_IN).

This replaces the ExaBGP text ``dump`` process that bgpmon-style tests scraped:
instead of parsing free-form text, tests GET ``/adj-in`` and read a JSON prefix
list sourced directly from gobgpd's per-neighbor ADJ_IN RIB. Kept in its own
module (no HTTP, no parser) so U6 can exercise it against a fake stub.
"""
from ._gbapi import gb, family_msg


def adj_in_prefixes(stub, family):
    """Return the ADJ_IN prefixes for ``family`` across ``stub``'s peers.

    gobgpd's ADJ_IN table is per-neighbor, so we enumerate peers (each shim
    gobgpd holds exactly one neighbor -- the DUT/cEOS VM) and collect their
    ADJ_IN prefixes for this address family. ``stub`` is injected so the caller
    (and U6) controls the gRPC endpoint / fake.
    """
    out = []
    for peer in stub.ListPeer(gb.ListPeerRequest()):
        addr = (peer.peer.conf.neighbor_address
                or peer.peer.state.neighbor_address)
        if not addr:
            continue
        req = gb.ListPathRequest(table_type=gb.TABLE_TYPE_ADJ_IN, name=addr,
                                 family=family_msg(family))
        for dst in stub.ListPath(req):
            out.append(dst.destination.prefix)
    return out
