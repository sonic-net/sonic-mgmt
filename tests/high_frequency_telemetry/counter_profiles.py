"""High frequency telemetry counter configuration keyed by platform and object type.

The counters listed here are supported on Spectrum-4 (SN5600 / SPC4) and above.
``_QUEUE_COUNTERS_SPC6_EXTRA`` are the queue counters that are additionally
supported only on Spectrum-6 (SN6600 / SPC6) and above.

Each entry in ``SUPPORTED_STATS`` lists exactly the counters that platform
supports for each object type.

Tests should call ``get_support_counter_list(duthost, counter_type)``.
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

# Counters supported on Spectrum-4 (SN5600 / SPC4) and above
_PORT_COUNTERS = (
    "IF_IN_OCTETS",
    "IF_IN_DISCARDS",
    "IF_OUT_OCTETS",
    "IF_IN_UCAST_PKTS",
    "IF_OUT_ERRORS",
    "IF_OUT_UCAST_PKTS",
)

_QUEUE_COUNTERS = (
    "BYTES",
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
    "WRED_ECN_MARKED_PACKETS",
    "PACKETS",
)

_INGRESS_PRIORITY_GROUP_COUNTERS = (
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
    "PACKETS",
    "BYTES",
)

_BUFFER_POOL_COUNTERS = (
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
)

# Queue counters supported only on Spectrum-6 (SN6600 / SPC6) and above
_QUEUE_COUNTERS_SPC6_EXTRA = (
    "DROPPED_PACKETS",
)

SUPPORTED_STATS: Mapping[str, Mapping[CounterObjectType, Sequence[str]]] = {
    "x86_64-nvidia_sn5600-r0": {
        CounterObjectType.PORT: _PORT_COUNTERS,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS,
    },
    "x86_64-nvidia_sn5640-r0": {
        CounterObjectType.PORT: _PORT_COUNTERS,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS,
    },
    "x86_64-nvidia_sn6600_ld-r0": {
        CounterObjectType.PORT: _PORT_COUNTERS,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS + _QUEUE_COUNTERS_SPC6_EXTRA,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS,
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
