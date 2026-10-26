"""Sharding invariants -- the POOL layout the HLD mandates.

The pool is only correct if every neighbor port is owned by exactly one shim
(disjoint) and no port is dropped (covering). These properties are what let the
manager launch ``k`` independent shims with no coordination beyond this map.
"""
from gobgp import shardmap


def _portmap(n):
    return {str(5000 + i): {"grpc": "127.0.0.1:5005%d" % i, "family": "v4",
                            "name": "N%d" % i} for i in range(n)}


def test_num_shards_min_cores_sessions():
    assert shardmap.num_shards(8, 4) == 4      # capped by sessions
    assert shardmap.num_shards(2, 100) == 2    # capped by cores
    assert shardmap.num_shards(8, 0) == 1      # floor of 1
    assert shardmap.num_shards(0, 5) == 1      # cores floored to 1


def test_partition_disjoint_and_covering():
    pm = _portmap(7)
    shards = shardmap.partition(pm, 4)
    assert len(shards) == 4
    seen = []
    for s in shards:
        seen.extend(s.keys())
    assert sorted(seen) == sorted(pm)          # covering
    assert len(seen) == len(set(seen))         # disjoint


def test_partition_balanced_within_one():
    shards = shardmap.partition(_portmap(7), 4)
    sizes = sorted(len(s) for s in shards)
    assert sizes[-1] - sizes[0] <= 1


def test_partition_k_clamped_to_port_count():
    shards = shardmap.partition(_portmap(3), 10)
    assert len(shards) == 3 and all(len(s) == 1 for s in shards)


def test_partition_empty_portmap():
    assert shardmap.partition({}, 4) == [{}]


def test_shard_for_matches_partition():
    pm = _portmap(7)
    parts = shardmap.partition(pm, 3)
    for i in range(3):
        assert shardmap.shard_for(pm, 3, i) == parts[i]


def test_shard_for_out_of_range_raises():
    import pytest
    with pytest.raises(IndexError):
        shardmap.shard_for(_portmap(3), 3, 5)
