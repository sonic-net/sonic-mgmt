#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# The modules sai_base_test.py, switch.py, and texttable.py are already available in the legacy directory (../py3).
# To avoid maintaining duplicate files in the refactor directory, we import these modules from the legacy directory.
# Once the refactor directory is stable and the migration is complete, we can consider moving these files to the
# refactor directory.
# Somehow, relative paths may not be correctly resolved, leading to modules not being found.
# Using absolute paths ensures that the paths are correctly resolved, allowing the modules to be imported.
current_dir = os.path.dirname(os.path.abspath(__file__))
legacy_dir = os.path.abspath(os.path.join(current_dir, "../py3"))
sys.path.append(legacy_dir)

import sai_base_test
from switch import (
    sai_thrift_read_port_counters,
    port_list,
    sai_thrift_read_port_watermarks,
    sai_thrift_read_pg_counters,
    sai_thrift_read_pg_drop_counters,
)
from ptf.testutils import port_to_tuple

from platform_qos_base import PlatformQosBase
from topology_qos_base import TopologyQosBase
from qos_helper import instantiate_helper, log_message
import texttable


port_counter_fields = [
    "OutDiscard",  # SAI_PORT_STAT_IF_OUT_DISCARDS
    "InDiscard",  # SAI_PORT_STAT_IF_IN_DISCARDS
    "Pfc0TxPkt",  # SAI_PORT_STAT_PFC_0_TX_PKTS
    "Pfc1TxPkt",  # SAI_PORT_STAT_PFC_1_TX_PKTS
    "Pfc2TxPkt",  # SAI_PORT_STAT_PFC_2_TX_PKTS
    "Pfc3TxPkt",  # SAI_PORT_STAT_PFC_3_TX_PKTS
    "Pfc4TxPkt",  # SAI_PORT_STAT_PFC_4_TX_PKTS
    "Pfc5TxPkt",  # SAI_PORT_STAT_PFC_5_TX_PKTS
    "Pfc6TxPkt",  # SAI_PORT_STAT_PFC_6_TX_PKTS
    "Pfc7TxPkt",  # SAI_PORT_STAT_PFC_7_TX_PKTS
    "OutOct",  # SAI_PORT_STAT_IF_OUT_OCTETS
    "OutUcPkt",  # SAI_PORT_STAT_IF_OUT_UCAST_PKTS
    "InDropPkt",  # SAI_PORT_STAT_IN_DROPPED_PKTS
    "OutDropPkt",  # SAI_PORT_STAT_OUT_DROPPED_PKTS
    "InUcPkt",  # SAI_PORT_STAT_IF_IN_UCAST_PKTS
    "InNonUcPkt",  # SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS
    "OutNonUcPkt",  # SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS
    "OutQlen",  # SAI_PORT_STAT_IF_OUT_QLEN
]

queue_counter_field_template = "Que{}Cnt"  # SAI_QUEUE_STAT_PACKETS

# sai_thrift_read_port_watermarks
queue_share_wm_field_template = "Que{}ShareWm"  # SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES
pg_share_wm_field_template = "Pg{}ShareWm"  # SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES
pg_headroom_wm_field_template = "pg{}HdrmWm"  # SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES

# sai_thrift_read_pg_counters
pg_counter_field_template = "Pg{}Cnt"  # SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS

# sai_thrift_read_pg_drop_counters
pg_drop_field_template = "Pg{}Drop"  # SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS

QUEUE_0 = 0
QUEUE_1 = 1
QUEUE_2 = 2
QUEUE_3 = 3
QUEUE_4 = 4
QUEUE_5 = 5
QUEUE_6 = 6
QUEUE_7 = 7
PG_NUM = 8
QUEUE_NUM = 8

# Constants
STOP_PORT_MAX_RATE = 1
RELEASE_PORT_MAX_RATE = 0
ECN_INDEX_IN_HEADER = 53  # Fits the ptf hex_dump_buffer() parse function
DSCP_INDEX_IN_HEADER = 52  # Fits the ptf hex_dump_buffer() parse function
COUNTER_MARGIN = 2  # Margin for counter check

# Constants for the IP IP DSCP to PG mapping test
DEFAULT_DSCP = 4
DEFAULT_TTL = 64
DEFAULT_ECN = 1
DEFAULT_PKT_COUNT = 10
PG_TOLERANCE = 2


def read_ptf_counters(dataplane, port):
    ptfdev, ptfport = port_to_tuple(port)
    rx, tx = dataplane.get_counters(ptfdev, ptfport)
    return [rx, tx]


def flat_test_port_ids(hierarchy):
    if isinstance(hierarchy, int):
        yield hierarchy
    elif isinstance(hierarchy, list):
        for item in hierarchy:
            yield from flat_test_port_ids(item)
    elif isinstance(hierarchy, dict):
        for value in hierarchy.values():
            yield from flat_test_port_ids(value)


class CounterCollector:
    """Collect, compare and display counters for test"""

    counter_info = {
        "PortCnt": [
            port_counter_fields,
            lambda _ptftest, _asic_type, _port: sai_thrift_read_port_counters(
                _ptftest.clients["src"], _asic_type, port_list["src"][_port]
            )[0],
        ],
        "QueCnt": [
            [queue_counter_field_template.format(i) for i in range(QUEUE_NUM)],
            lambda _ptftest, _asic_type, _port: sai_thrift_read_port_counters(
                _ptftest.clients["src"], _asic_type, port_list["src"][_port]
            )[1],
        ],
        "QueShareWm": [
            [queue_share_wm_field_template.format(i) for i in range(QUEUE_NUM)],
            lambda _ptftest, _, _port: sai_thrift_read_port_watermarks(
                _ptftest.clients["src"], port_list["src"][_port]
            )[0],
        ],
        "PgShareWm": [
            [pg_share_wm_field_template.format(i) for i in range(PG_NUM)],
            lambda _ptftest, _, _port: sai_thrift_read_port_watermarks(
                _ptftest.clients["src"], port_list["src"][_port]
            )[1],
        ],
        "PgHdrmWm": [
            [pg_headroom_wm_field_template.format(i) for i in range(PG_NUM)],
            lambda _ptftest, _, _port: sai_thrift_read_port_watermarks(
                _ptftest.clients["src"], port_list["src"][_port]
            )[2],
        ],
        "PgCnt": [
            [pg_counter_field_template.format(i) for i in range(PG_NUM)],
            lambda _ptftest, _, _port: sai_thrift_read_pg_counters(_ptftest.clients["src"], port_list["src"][_port]),
        ],
        "PgDrop": [
            [pg_drop_field_template.format(i) for i in range(PG_NUM)],
            lambda _ptftest, _, _port: sai_thrift_read_pg_drop_counters(
                _ptftest.clients["src"], port_list["src"][_port]
            ),
        ],
        "PtfCnt": [["rx", "tx"], lambda _ptftest, _, _port: read_ptf_counters(_ptftest.dataplane, _port)],
    }

    def __init__(self, ptftest, counter_name, port_ids=None):
        self.ptftest = ptftest
        self.valid = True
        if "dst" in self.ptftest.clients and self.ptftest.clients["src"] != self.ptftest.clients["dst"]:
            # For first revision, tests do not cover chassis device, so not support chassis temporarily
            # when tests cover chassi device, will open this feature to chassis device
            self.valid = False
        else:
            self.steps = []
            self.counter_name = counter_name
            self.asic_type = ptftest.test_params.get("sonic_asic_type", None)
            self.port_ids = (
                port_ids
                if port_ids is not None
                else list(flat_test_port_ids(ptftest.test_params.get("test_port_ids", None)))
            )
            if self.counter_name not in self.counter_info:
                self.valid = False
            else:
                self.counter_fields, self.query_func = self.counter_info[self.counter_name]

    def collect_counter(self, step_name, step_desc=None, compare=True):
        if not self.valid:
            return

        table = texttable.TextTable(["port"] + self.counter_fields, attr_name="step", attr_value=step_name)
        for port in self.port_ids:
            data = self.query_func(self.ptftest, self.asic_type, port)
            table.add_row([port] + data)

        self.steps.append({"table": table, "name": step_name, "desc": step_desc})
        current = len(self.steps) - 1

        if compare:
            compare_table = self.__find_table(compare, from_curr_to_prev=current)
            merged_table = texttable.TextTable.merge_table(table, compare_table)
            log_message(
                "collect_counter {} {}\n{}\n".format(
                    self.counter_name,
                    step_name + "({})".format(step_desc) if step_desc is not None else "",
                    merged_table,
                )
            )
        return current

    def __find_table(self, counter, from_curr_to_prev=False):
        if isinstance(counter, str):
            return next((s["table"] for s in self.steps if s["name"] == counter), None)
        elif isinstance(counter, int) and not isinstance(counter, bool):  # True is instance of int, so exclude bool
            return self.steps[counter]["table"] if counter in list(range(len(self.steps))) or counter == -1 else None
        if from_curr_to_prev:
            return self.steps[from_curr_to_prev - 1]["table"] if from_curr_to_prev != 0 else None
        return None

    def compare_counter(self, changed_step_name, base_step_name):
        if not self.valid:
            return
        base_table = self.__find_table(base_step_name)
        changed_table = self.__find_table(changed_step_name)
        if base_table and changed_table:
            merged_table = texttable.TextTable.merge_table(changed_table, base_table)
            log_message(
                "compare_counter {} {}~{}\n{}\n".format(
                    self.counter_name, base_step_name, changed_step_name, merged_table
                )
            )

    def get_counter_value(self, step_name, test_port_id, field_id_or_name):
        if not self.valid:
            return None
        table = self.__find_table(step)
        if not table:
            return None

        return self.__get_field_value(table, test_port_id, field_id_or_name)

    def get_counter_delta(self, changed_step_name, base_step_name, test_port_id, field_id_or_name):
        if not self.valid:
            return None
        base_table = self.__find_table(base_step_name)
        changed_table = self.__find_table(changed_step_name)
        if not base_table or not changed_table:
            return None

        base_value = self.__get_field_value(base_table, test_port_id, field_id_or_name)
        changed_value = self.__get_field_value(changed_table, test_port_id, field_id_or_name)

        if base_value is None or changed_value is None:
            return None

        return changed_value - base_value

    def __get_field_value(self, table, port, field_id_or_name):
        if isinstance(field_id_or_name, int):
            return table.get_field_value(port, field_id_or_name + 1)  # for TextTable, first field is port
        elif isinstance(field_id_or_name, str):
            if self.counter_name in ["PortCnt", "PtfCnt"]:
                field_id = table.get_field_index(field_id_or_name)
                if field_id is not None:
                    return table.get_field_value(port, field_id)
        return None


def initialize_diag_counter(ptftest):
    ptftest.counter_collectors = {}
    for counter_name in ["PortCnt", "QueCnt", "QueShareWm", "PgShareWm", "PgHdrmWm", "PgCnt", "PgDrop", "PtfCnt"]:
        ptftest.counter_collectors[counter_name] = CounterCollector(ptftest, counter_name)
        # not need to show counter for init stage
        ptftest.counter_collectors[counter_name].collect_counter("init", compare=True)


def capture_diag_counter(ptftest, step_name="run", step_desc=None):
    if not hasattr(ptftest, "counter_collectors") or not ptftest.counter_collectors:
        return
    for collector in ptftest.counter_collectors.values():
        if isinstance(collector, CounterCollector):
            collector.collect_counter(step_name, step_desc)


def summarize_diag_counter(ptftest, changed_counter=-1, base_counter=0):
    if not hasattr(ptftest, "counter_collectors") or not ptftest.counter_collectors:
        return
    for collector in ptftest.counter_collectors.values():
        if isinstance(collector, CounterCollector):
            collector.compare_counter(changed_counter, base_counter)
