"""Shard-aware shim entrypoint.

Run one shim process of the POOL::

    python -m gobgp.shim --portmap /etc/gobgp/portmap.json --shard 0/4

``--shard i/k`` means "this is shim ``i`` of ``k``": the process serves only the
ports :func:`gobgp.shardmap.shard_for` assigns to shard ``i`` of a ``k``-way
split of the full portmap. The manager (``gobgp`` ansible module, landing in a
follow-up change) launches ``k = min(cores, sessions)`` supervisord programs, one per shard, so the pool
collectively covers every neighbor port with no overlap and no single-process
GIL bottleneck. ``--shard`` defaults to ``0/1`` (serve the whole portmap), which
is handy for local testing.
"""
import argparse
import json
import logging
import sys
import threading
import time

from .. import shardmap
from .server import make_server

LOG = logging.getLogger("gobgp_shim")


def _parse_shard(spec):
    """``"i/k"`` -> ``(i, k)`` with ``0 <= i < k`` and ``k >= 1``."""
    try:
        i_str, k_str = spec.split("/")
        i, k = int(i_str), int(k_str)
    except (ValueError, AttributeError):
        raise argparse.ArgumentTypeError(
            "shard must be 'i/k' (e.g. 0/4), got %r" % spec)
    if k < 1 or not 0 <= i < k:
        raise argparse.ArgumentTypeError(
            "shard 'i/k' needs k>=1 and 0<=i<k, got %r" % spec)
    return i, k


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gobgp.shim")
    ap.add_argument("--portmap", required=True,
                    help="JSON file: {port: {grpc, family, name, self_nexthop}}")
    ap.add_argument("--shard", type=_parse_shard, default=(0, 1),
                    help="this shim's slot as 'i/k' (default 0/1 = all ports)")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    with open(args.portmap) as f:
        full_portmap = json.load(f)

    shard_index, k = args.shard
    my_ports = shardmap.shard_for(full_portmap, k, shard_index)

    # Bind all ports up front so a bind failure is fatal (exit non-zero ->
    # supervisord restarts) instead of a serve thread dying silently.
    servers = []
    for port, spec in my_ports.items():
        try:
            servers.append((port, spec, make_server(port, spec)))
        except Exception:
            LOG.exception("shard %d/%d: failed to bind port %s", shard_index, k,
                          port)
            return 1

    threads = []
    for port, spec, httpd in servers:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        threads.append(t)
        LOG.info("shim listening on :%s -> %s (%s, neighbor %s)",
                 port, spec["grpc"], spec["family"], spec.get("name"))
    LOG.info("gobgp_shim shard %d/%d up: %d of %d port(s)",
             shard_index, k, len(servers), len(full_portmap))

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
