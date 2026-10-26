"""SAI enum IDs used to identify exported telemetry series.

The values mirror the OCP SAI headers and countersyncd's SAI enums:
https://github.com/opencomputeproject/SAI/tree/master/inc
https://github.com/sonic-net/sonic-swss/tree/master/crates/countersyncd/src/sai

Only identifiers used by sonic-mgmt tests are included here.
"""


SAI_OBJECT_TYPE_IDS = {
    "SAI_OBJECT_TYPE_PORT": 1,
    "SAI_OBJECT_TYPE_QUEUE": 21,
    "SAI_OBJECT_TYPE_BUFFER_POOL": 24,
    "SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP": 26,
}

SAI_STAT_IDS = {
    "SAI_PORT_STAT_IF_IN_OCTETS": 0,
    "SAI_PORT_STAT_IF_IN_UCAST_PKTS": 1,
    "SAI_PORT_STAT_IF_IN_DISCARDS": 3,
    "SAI_PORT_STAT_IF_OUT_OCTETS": 9,
    "SAI_PORT_STAT_IF_OUT_UCAST_PKTS": 10,
    "SAI_PORT_STAT_IF_OUT_ERRORS": 13,
    "SAI_QUEUE_STAT_PACKETS": 0,
    "SAI_QUEUE_STAT_BYTES": 1,
    "SAI_QUEUE_STAT_DROPPED_PACKETS": 2,
    "SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS": 34,
    "SAI_QUEUE_STAT_CURR_OCCUPANCY_CELLS": 41,
    "SAI_QUEUE_STAT_WATERMARK_CELLS": 42,
    "SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_CELLS": 23,
    "SAI_BUFFER_POOL_STAT_WATERMARK_CELLS": 24,
    "SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS": 0,
    "SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES": 1,
    "SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_CELLS": 9,
    "SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_CELLS": 10,
}


def get_sai_object_type_id(name):
    """Return the numeric ID for an OCP SAI object type name."""
    try:
        return SAI_OBJECT_TYPE_IDS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown SAI object type: {name}") from exc


def get_sai_stat_id(name):
    """Return the numeric ID for an OCP SAI statistic name."""
    try:
        return SAI_STAT_IDS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown SAI statistic: {name}") from exc
