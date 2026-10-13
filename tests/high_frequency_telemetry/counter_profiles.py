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

# ── Arista 7060X6 counters ──────────────────────────────────────────────
# Applies to both x86_64-arista_7060x6_64pe and x86_64-arista_7060x6_64pe_b.

_PORT_COUNTERS_7060X6 = (
    "IF_IN_OCTETS",
    "IF_IN_UCAST_PKTS",
    "IF_IN_DISCARDS",
    "IF_IN_ERRORS",
    "IF_OUT_OCTETS",
    "IF_OUT_DISCARDS",
    "IF_OUT_ERRORS",
    "IF_OUT_UCAST_PKTS",
    "PFC_0_RX_PKTS",
    "PFC_1_RX_PKTS",
    "PFC_2_RX_PKTS",
    "PFC_3_RX_PKTS",
    "PFC_4_RX_PKTS",
    "PFC_5_RX_PKTS",
    "PFC_6_RX_PKTS",
    "PFC_7_RX_PKTS",
    "PFC_0_TX_PKTS",
    "PFC_1_TX_PKTS",
    "PFC_2_TX_PKTS",
    "PFC_3_TX_PKTS",
    "PFC_4_TX_PKTS",
    "PFC_5_TX_PKTS",
    "PFC_6_TX_PKTS",
    "PFC_7_TX_PKTS",
    "PFC_0_XOFF_TOTAL_DURATION",
    "PFC_1_XOFF_TOTAL_DURATION",
    "PFC_2_XOFF_TOTAL_DURATION",
    "PFC_3_XOFF_TOTAL_DURATION",
    "PFC_4_XOFF_TOTAL_DURATION",
    "PFC_5_XOFF_TOTAL_DURATION",
    "PFC_6_XOFF_TOTAL_DURATION",
    "PFC_7_XOFF_TOTAL_DURATION",
    "PFC_0_XOFF_MAX_DURATION",
    "PFC_1_XOFF_MAX_DURATION",
    "PFC_2_XOFF_MAX_DURATION",
    "PFC_3_XOFF_MAX_DURATION",
    "PFC_4_XOFF_MAX_DURATION",
    "PFC_5_XOFF_MAX_DURATION",
    "PFC_6_XOFF_MAX_DURATION",
    "PFC_7_XOFF_MAX_DURATION",
)

_QUEUE_COUNTERS_7060X6 = (
    "DROPPED_PACKETS",
    "CURR_OCCUPANCY_BYTES",
    "WATERMARK_BYTES",
    "PACKETS",
    "BYTES",
    "WRED_ECN_MARKED_PACKETS",
)

_INGRESS_PRIORITY_GROUP_COUNTERS_7060X6 = (
    "CURR_OCCUPANCY_BYTES",
    "XOFF_ROOM_CURR_OCCUPANCY_BYTES",
    "XOFF_ROOM_WATERMARK_BYTES",
    "PACKETS",
    "BYTES",
    "DROPPED_PACKETS",
    "SHARED_WATERMARK_BYTES",
)

_BUFFER_POOL_COUNTERS_7060X6 = (
    "CURR_OCCUPANCY_BYTES",
    "WATERMARK_BYTES",
    "XOFF_ROOM_WATERMARK_BYTES",
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
        CounterObjectType.PORT: _PORT_COUNTERS_7060X6,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS_7060X6,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS_7060X6,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS_7060X6,
    },
    "x86_64-arista_7060x6_64pe": {
        CounterObjectType.PORT: _PORT_COUNTERS_7060X6,
        CounterObjectType.QUEUE: _QUEUE_COUNTERS_7060X6,
        CounterObjectType.INGRESS_PRIORITY_GROUP: _INGRESS_PRIORITY_GROUP_COUNTERS_7060X6,
        CounterObjectType.BUFFER_POOL: _BUFFER_POOL_COUNTERS_7060X6,
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
