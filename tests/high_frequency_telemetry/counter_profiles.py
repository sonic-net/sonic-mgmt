"""High frequency telemetry counter configuration keyed by platform and object type.

Each platform maps to counter definitions grouped by `CounterObjectType`.  Tests
should call `get_support_counter_list(duthost, counter_type)` so they always get
the counters that are supported on the current DUT platform.  New platforms can
reference the same sequence by reusing the tuple constant defined above.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping, Sequence


class CounterObjectType(Enum):
    PORT = "port"
    BUFFER_POOL = "buffer_pool"
    INGRESS_PRIORITY_GROUP = "ingress_priority_group"
    QUEUE = "queue"


_DEFAULT_PLATFORM = "default"

_PORT_COUNTERS_SN5640 = (
    "IF_IN_OCTETS",
    # "IF_IN_UCAST_PKTS",
    "IF_IN_DISCARDS",
    "IF_OUT_OCTETS",
    # "IF_OUT_ERRORS",
    # "IF_OUT_UCAST_PKTS",
    # "TRIM_PACKETS"
)

_QUEUE_COUNTERS_SN5640 = (
    # "PACKETS",
    "BYTES",
    # "DROPPED_PACKETS",
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
    "WRED_ECN_MARKED_PACKETS",
)

_INGRESS_PRIORITY_GROUP_COUNTERS_SN5640 = (
    # "PACKETS",
    # "BYTES",
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
)

_BUFFER_POOL_COUNTERS_SN5640 = (
    # "CURR_OCCUPANCY_CELLS",
    # "WATERMARK_CELLS",
)

SUPPORTED_STATS: Mapping[str, Mapping[CounterObjectType, Sequence[str]]] = {
    "x86_64-nvidia_sn5640-r0": {
        CounterObjectType.PORT: _PORT_COUNTERS_SN5640,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS_SN5640,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS_SN5640,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS_SN5640,
    },
    "x86_64-arista_7060x6_64pe_b": {
        CounterObjectType.PORT: (),
        CounterObjectType.QUEUE: (),
    },
    _DEFAULT_PLATFORM: {
        CounterObjectType.PORT: (),
        CounterObjectType.QUEUE: (),
        CounterObjectType.BUFFER_POOL: (),
        CounterObjectType.INGRESS_PRIORITY_GROUP: (),
    },
}


def _normalize_platform(platform: str | None) -> str:
    if not platform:
        return _DEFAULT_PLATFORM
    return platform.strip().lower()


def _get_platform(duthost) -> str:
    facts = getattr(duthost, "facts", {})
    return facts.get("platform", "")


def get_support_counter_list(duthost, counter_type: CounterObjectType) -> Sequence[str]:
    """Return the list of supported counters for `counter_type` on the DUT platform."""

    platform_key = _normalize_platform(_get_platform(duthost))
    platform_defs = SUPPORTED_STATS.get(platform_key)

    if not platform_defs:
        platform_defs = SUPPORTED_STATS.get(_DEFAULT_PLATFORM, {})

    counters = platform_defs.get(counter_type)
    if counters is None:
        return ()

    return counters
