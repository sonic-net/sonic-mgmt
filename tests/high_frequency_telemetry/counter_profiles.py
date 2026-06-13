"""High frequency telemetry counter configuration keyed by platform and object type.

Counter sets are built from two pieces:
  * ``_*_BASE``           counters supported on every Nvidia platform, including
                          older SDKs such as SPC6 ES images.
  * ``_*_<PLATFORM>_EXTRA``  the additional counters supported by ``<PLATFORM>``
                          on top of the base set.

Each entry in ``SUPPORTED_STATS`` concatenates the base and that platform's
extras inline, so it is easy to see what a given platform actually supports.

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

# Base counters
_PORT_COUNTERS_BASE = (
    "IF_IN_OCTETS",
    "IF_IN_DISCARDS",
    "IF_OUT_OCTETS",
)

_QUEUE_COUNTERS_BASE = (
    "BYTES",
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
    "WRED_ECN_MARKED_PACKETS",
)

_INGRESS_PRIORITY_GROUP_COUNTERS_BASE = (
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
)

_BUFFER_POOL_COUNTERS_BASE = ()

# Extra counters supported by SN5640
_PORT_COUNTERS_SN5640_EXTRA = (
    "IF_IN_UCAST_PKTS",
    "IF_OUT_ERRORS",
    "IF_OUT_UCAST_PKTS"
)

_QUEUE_COUNTERS_SN5640_EXTRA = (
    "PACKETS",
)

_INGRESS_PRIORITY_GROUP_COUNTERS_SN5640_EXTRA = (
    "PACKETS",
    "BYTES",
)

_BUFFER_POOL_COUNTERS_SN5640_EXTRA = (
    "CURR_OCCUPANCY_CELLS",
    "WATERMARK_CELLS",
)

SUPPORTED_STATS: Mapping[str, Mapping[CounterObjectType, Sequence[str]]] = {
    "x86_64-nvidia_sn5640-r0": {
        CounterObjectType.PORT: _PORT_COUNTERS_BASE + _PORT_COUNTERS_SN5640_EXTRA,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS_BASE + _QUEUE_COUNTERS_SN5640_EXTRA,
        CounterObjectType.INGRESS_PRIORITY_GROUP:
            _INGRESS_PRIORITY_GROUP_COUNTERS_BASE + _INGRESS_PRIORITY_GROUP_COUNTERS_SN5640_EXTRA,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS_BASE + _BUFFER_POOL_COUNTERS_SN5640_EXTRA,
    },
    "x86_64-nvidia_sn6600_ld-r0": {
        CounterObjectType.PORT: _PORT_COUNTERS_BASE,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS_BASE,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS_BASE,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS_BASE,
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
