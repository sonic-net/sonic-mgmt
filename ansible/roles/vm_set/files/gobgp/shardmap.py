"""Portmap sharding -- the single source of truth for how per-neighbor HTTP
ports are partitioned across the shim process pool.

The shim entrypoint imports this module to select the ports it owns; the
ansible module that launches one supervisord program per shard will import the
same helpers, so the two can never disagree on which shim owns which port.

The layout follows the design (https://github.com/sonic-net/sonic-mgmt/pull/26382
-> "Daemon topology and the shim", "Memory consumption"):

* one gobgpd per (neighbor, family) -- untouched here, that is the manager's job;
* ``k = min(core_count, session_count)`` **shim** processes (the POOL config),
  each owning a disjoint shard of the per-neighbor ports. This keeps shim memory
  ``O(cores)`` instead of ``O(sessions)`` and avoids GIL-serializing the
  CPU-bound protobuf build in a single process (the rejected CONS config).

A "portmap" is the JSON object the manager renders::

    {
      "5000": {"grpc": "127.0.0.1:50052", "family": "v4", "name": "ARISTA01T1"},
      "6000": {"grpc": "127.0.0.1:50052", "family": "v6", "name": "ARISTA01T1"},
      ...
    }

Ports are the stable contract (``filters.py`` port math: ``5000+off`` v4 /
``6000+off`` v6), so sharding is defined purely in terms of ports and never
perturbs that math.
"""
from __future__ import division


def num_shards(core_count, session_count):
    """Number of shim processes in the pool: ``min(cores, sessions)``, >= 1.

    ``session_count`` is the number of ports to serve (each (neighbor, family)
    port is one intake slot). Capping at the port count avoids spawning idle
    shims when there are fewer ports than cores.
    """
    core_count = int(core_count)
    session_count = int(session_count)
    if session_count <= 0:
        return 1
    return max(1, min(max(core_count, 1), session_count))


def _sorted_ports(portmap):
    """Deterministic port ordering so shard assignment is stable across the
    manager and every shim (numeric sort; ports are ints-as-strings in JSON)."""
    return sorted(portmap, key=int)


def partition(portmap, k):
    """Split ``portmap`` into disjoint sub-portmaps (shards).

    Returns one dict per effective shard, where ``k`` is clamped to
    ``[1, len(portmap)]`` so callers can pass a raw core count without
    special-casing tiny portmaps and no shard comes back empty; an empty
    ``portmap`` yields a single empty shard. The shards' union is ``portmap``
    and their pairwise intersection is empty (every port owned by exactly one
    shard). Assignment is round-robin over numerically sorted ports, which
    spreads the two families of one neighbor across shards and keeps shard
    sizes balanced to within one port.
    """
    ports = _sorted_ports(portmap)
    if not ports:
        return [{}]
    k = max(1, min(int(k), len(ports)))
    shards = [dict() for _ in range(k)]
    for idx, port in enumerate(ports):
        shards[idx % k][port] = portmap[port]
    return shards


def shard_for(portmap, k, shard_index):
    """Convenience: the single sub-portmap owned by ``shard_index`` of ``k``.

    Raises ``IndexError`` if ``shard_index`` is out of range for the effective
    (clamped) shard count, so a mis-launched shim fails loudly instead of
    silently serving nothing.
    """
    shards = partition(portmap, k)
    if not 0 <= shard_index < len(shards):
        raise IndexError(
            "shard_index %d out of range for %d shard(s)"
            % (shard_index, len(shards)))
    return shards[shard_index]
