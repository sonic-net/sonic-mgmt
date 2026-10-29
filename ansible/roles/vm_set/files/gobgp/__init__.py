"""GoBGP PTF speaker: ExaBGP-compatible HTTP shim over per-neighbor gobgpd.

Nothing in the ansible or test paths imports this package, so it cannot affect
the ExaBGP speaker that remains the default; the vm_set wiring lands in a
follow-up change. The shim itself runs as a pool of processes, one per core
and portmap-sharded -- see :mod:`gobgp.shim`.

Design: https://github.com/sonic-net/sonic-mgmt/pull/26382
"""
