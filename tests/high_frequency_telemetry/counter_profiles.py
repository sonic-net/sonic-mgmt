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

SAI_OBJECT_TYPE_IDS = {
    CounterObjectType.PORT: 1,
    CounterObjectType.QUEUE: 21,
    CounterObjectType.BUFFER_POOL: 24,
    CounterObjectType.INGRESS_PRIORITY_GROUP: 26,
}

SAI_STAT_IDS = {
    CounterObjectType.PORT: {
        "IF_IN_OCTETS": 0,
        "IF_IN_UCAST_PKTS": 1,
        "IF_IN_DISCARDS": 3,
        "IF_OUT_OCTETS": 9,
        "IF_OUT_UCAST_PKTS": 10,
        "IF_OUT_ERRORS": 13,
    },
    CounterObjectType.QUEUE: {
        "PACKETS": 0,
        "BYTES": 1,
        "DROPPED_PACKETS": 2,
        "WRED_ECN_MARKED_PACKETS": 34,
        "CURR_OCCUPANCY_CELLS": 41,
        "WATERMARK_CELLS": 42,
    },
    CounterObjectType.BUFFER_POOL: {
        "CURR_OCCUPANCY_CELLS": 23,
        "WATERMARK_CELLS": 24,
    },
    CounterObjectType.INGRESS_PRIORITY_GROUP: {
        "PACKETS": 0,
        "BYTES": 1,
        "CURR_OCCUPANCY_CELLS": 9,
        "WATERMARK_CELLS": 10,
    },
}

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

_LEGACY_COUNTERS = {
    CounterObjectType.PORT: (
        "IF_IN_OCTETS",
        "IF_IN_DISCARDS",
        "IF_OUT_OCTETS",
    ),
    CounterObjectType.QUEUE: (
        "BYTES",
        "CURR_OCCUPANCY_CELLS",
        "WATERMARK_CELLS",
        "WRED_ECN_MARKED_PACKETS",
    ),
    CounterObjectType.INGRESS_PRIORITY_GROUP: (
        "CURR_OCCUPANCY_CELLS",
        "WATERMARK_CELLS",
    ),
    CounterObjectType.BUFFER_POOL: (),
}

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


def _get_release(duthost) -> str:
    release = getattr(duthost, "sonic_release", "")
    if release:
        return str(release)
    facts = getattr(duthost, "facts", {})
    return str(facts.get("release", ""))


def get_support_counter_list(duthost, counter_type: CounterObjectType) -> Sequence[str]:
    """Return the list of supported counters for `counter_type` on the DUT platform."""

    platform_key = _normalize_platform(_get_platform(duthost))
    platform_defs = SUPPORTED_STATS.get(platform_key)

    release = _get_release(duthost)
    if platform_key in {
        "x86_64-nvidia_sn5600-r0",
        "x86_64-nvidia_sn5640-r0",
    } and release.isdigit() and int(release) < 202605:
        return _LEGACY_COUNTERS.get(counter_type, ())

    if not platform_defs:
        platform_defs = SUPPORTED_STATS.get(_DEFAULT_PLATFORM, {})

    counters = platform_defs.get(counter_type)
    if counters is None:
        return ()

    return counters


def get_sai_object_type_id(counter_type: CounterObjectType) -> int:
    """Return the SAI object type ID exported by countersyncd."""
    return SAI_OBJECT_TYPE_IDS[counter_type]


def get_sai_stat_id(counter_type: CounterObjectType, counter_name: str) -> int:
    """Return the SAI stat ID exported by countersyncd for a CLI counter name."""
    try:
        return SAI_STAT_IDS[counter_type][counter_name]
    except KeyError as exc:
        raise ValueError(
            f"No SAI stat mapping for {counter_type.value} counter {counter_name}"
        ) from exc


def get_poll_interval_range(duthost):
    """Return the known hardware poll interval range in microseconds."""
    platform = _normalize_platform(_get_platform(duthost))
    release = _get_release(duthost)
    if platform in {
        "x86_64-nvidia_sn5600-r0",
        "x86_64-nvidia_sn5640-r0",
    } and release.isdigit() and int(release) < 202605:
        return 100, 12_750
    return None
