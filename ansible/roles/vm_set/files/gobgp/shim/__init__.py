"""ExaBGP-compatible HTTP shim over per-neighbor gobgpd (gRPC).

Public surface:

* :mod:`gobgp.shim.parser` -- ExaBGP text grammar -> command dicts (pure).
* :mod:`gobgp.shim.translator` -- command dicts -> batched gRPC (``NeighborClient``).
* :mod:`gobgp.shim.receive` -- ADJ_IN structured receive view.
* :mod:`gobgp.shim.server` -- per-port HTTP front end.

Run as ``python -m gobgp.shim --portmap <file> --shard i/k`` (see ``__main__``).
"""
