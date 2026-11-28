"""Behavior checks for SAI buffer cases without loading a PTF installation."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase

import pytest


SOURCE = (Path(__file__).resolve().parents[2] / 'cases' / 'ptf'
          / 'saibufferqos.py')


def _class(name, methods, namespace):
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    node = next(node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == name)
    node.decorator_list = []
    node.body = [child for child in node.body
                 if isinstance(child, ast.FunctionDef)
                 and child.name in methods]
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    scope = {'SaiHelperScaleTM': type('SaiHelperScaleTM', (),
                                    {'setUp': lambda self: None})}
    scope.update(namespace)
    exec(compile(module, str(SOURCE), 'exec'), scope)
    return scope[name]


def test_cpu_queue_closes_hostif_socket_after_sending():
    class Socket:
        closed = False

        def send(self, payload):
            assert payload == b'packet'

        def close(self):
            self.closed = True

    sock = Socket()
    namespace = {
        'get_platform': lambda: 'brcm',
        'simple_udp_packet': lambda **kwargs: b'packet',
        'sai_thrift_create_hostif': lambda *args, **kwargs: 7,
        'sai_thrift_object_list_t': lambda **kwargs: None,
        'sai_thrift_get_port_attribute': lambda *args, **kwargs: {
            'SAI_PORT_ATTR_QOS_QUEUE_LIST': SimpleNamespace(idlist=list(range(20)))},
        'open_packet_socket': lambda name: sock,
        'verify_packet': lambda *args: None,
        'query_counter': lambda *args: {'SAI_QUEUE_STAT_PACKETS': 1},
        'sai_thrift_clear_queue_stats': lambda *args: None,
        'clear_counter': lambda *args: None,
        'sai_thrift_remove_hostif': lambda *args: None,
        'sai_thrift_get_queue_stats': lambda *args: None,
        'SAI_HOSTIF_TYPE_NETDEV': 1,
    }
    cls = _class('CpuQueue', {'runTest'}, namespace)
    case = cls()
    case.client, case.port0, case.dev_port0 = object(), 3, 4
    case.assertNotEqual = TestCase().assertNotEqual
    case.assertEqual = TestCase().assertEqual

    case.runTest()

    assert sock.closed


def test_lossless_pfc_case_builds_packet_on_non_clx():
    cls = _class('LosslessPfcRxTxTest', {'setUp'}, {
        'get_platform': lambda: 'brcm',
        'simple_udp_packet': lambda **kwargs: 'udp',
    })
    cls.create_pfc_packet = lambda self, *args: 'pfc'
    case = cls()

    case.setUp()

    assert hasattr(case, 'pkt_pfc')


def test_lossless_pfc_case_sends_and_checks_pfc_on_non_clx():
    sent, queried = [], []

    def query(_case, _func, port):
        queried.append(port)
        return {'SAI_PORT_STAT_PFC_1_TX_PKTS': 1,
                'SAI_PORT_STAT_PFC_1_RX_PKTS': 1}

    cls = _class('LosslessPfcRxTxTest', {'runTest'}, {
        'get_platform': lambda: 'brcm',
        'send_packet': lambda _case, port, pkt: sent.append((port, pkt)),
        'query_counter': query,
        'sai_thrift_get_port_stats': lambda *args: None,
        'sai_thrift_clear_port_stats': lambda *args: None,
        'clear_counter': lambda *args: None,
        'time': SimpleNamespace(sleep=lambda _seconds: None),
    })
    case = cls()
    case.client = object()
    case.tx_cnt = 1
    case.dev_port1, case.dev_port2 = 11, 12
    case.port1, case.port2 = 21, 22
    case.pkt_p2, case.pkt_pfc = 'udp', 'pfc'
    case.assertGreater = TestCase().assertGreater

    case.runTest()

    assert (12, 'pfc') in sent
    assert 22 in queried


def test_lossy_pfc_case_initializes_count_on_non_clx():
    cls = _class('LossyPfcRxTest', {'setUp'}, {
        'get_platform': lambda: 'brcm',
        'simple_udp_packet': lambda **kwargs: 'udp',
        'simple_eth_packet': lambda **kwargs: 'pfc',
    })
    case = cls()

    case.setUp()

    assert hasattr(case, 'pfc_cnt')
    assert case.pfc_cnt == case.tx_cnt


def test_lossy_pfc_case_rejects_missing_rx_count_on_non_clx():
    cls = _class('LossyPfcRxTest', {'runTest'}, {
        'get_platform': lambda: 'brcm',
        'send_packet': lambda *args: None,
        'query_counter': lambda _case, func, *args: (
            {'SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES': 1,
             'SAI_QUEUE_STAT_DROPPED_PACKETS': 1}
            if func.__name__ == 'queue_stats' else
            {'SAI_PORT_STAT_PFC_2_RX_PKTS': 0}),
        'sai_thrift_get_queue_stats': lambda *args: None,
        'sai_thrift_get_port_stats': lambda *args: None,
    })
    cls.runTest.__globals__['sai_thrift_get_queue_stats'].__name__ = 'queue_stats'
    case = cls()
    case.tx_cnt = case.pfc_cnt = 1
    case.dev_port5, case.dev_port6 = 5, 6
    case.port6, case.queues6 = 16, list(range(20))
    case.pkt_pfc, case.pkt_p6 = 'pfc', 'udp'
    case.assertGreater = TestCase().assertGreater
    case.assertEqual = TestCase().assertEqual

    with pytest.raises(AssertionError):
        case.runTest()


def test_lossy_alpha_uses_tolerance_and_calculated_drain_on_non_clx():
    class StopAfterWait(Exception):
        pass

    waits, cleared = [], []

    def sleep(seconds):
        waits.append(seconds)
        raise StopAfterWait

    def query(_case, func, *_args):
        if func is get_pool_stats:
            return {'SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES': 1000}
        return {'SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES': 1001}

    def get_pool_stats(*_args):
        pass

    cls = _class('LossyAlphaTest', {'runTest'}, {
        'get_platform': lambda: 'brcm',
        'query_counter': query,
        'sai_thrift_get_buffer_pool_stats': get_pool_stats,
        'sai_thrift_get_queue_stats': lambda *_args: None,
        'sai_thrift_clear_queue_stats': lambda *_args: None,
        'sai_thrift_clear_buffer_pool_stats': lambda *_args: None,
        'clear_counter': lambda *args: cleared.append(args),
        'time': SimpleNamespace(sleep=sleep),
    })
    case = cls()
    case.client, case.egr_pool = object(), 7
    case.queues2 = list(range(10))
    case.tx_cnt, case.pkt_len = 0, 64
    case.buf_size, case.alpha1, case.pir = 2000, 0, 1000
    case.assertEqual = TestCase().assertEqual
    case.assertLessEqual = TestCase().assertLessEqual

    with pytest.raises(StopAfterWait):
        case.runTest()

    assert waits == [3]
    assert len(cleared) == 2


def test_lossy_wred_uses_calculated_watermark_on_non_clx():
    class StopAfterWait(Exception):
        pass

    waits = []

    def sleep(seconds):
        waits.append(seconds)
        raise StopAfterWait

    cls = _class('LossyWredTest', {'runTest'}, {
        'get_platform': lambda: 'brcm',
        'query_counter': lambda *_args: {
            'SAI_QUEUE_STAT_PACKETS': 1,
            'SAI_QUEUE_STAT_DROPPED_PACKETS': 1,
            'SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES': 5000},
        'sai_thrift_get_queue_stats': lambda *_args: None,
        'sai_thrift_clear_queue_stats': lambda *_args: None,
        'clear_counter': lambda *_args: None,
        'time': SimpleNamespace(sleep=sleep),
    })
    case = cls()
    case.client = object()
    case.queues2 = list(range(10))
    case.tx_cnt, case.pkt_len = 0, 64
    case.dev_port2, case.dev_port3 = 2, 3
    case.buf_size, case.alpha1, case.pir = 10000, 0, 1000
    case.assertGreater = TestCase().assertGreater
    case.assertGreaterEqual = TestCase().assertGreaterEqual
    case.assertLessEqual = TestCase().assertLessEqual

    with pytest.raises(StopAfterWait):
        case.runTest()

    assert waits == [7]


def test_lossy_ecn_wait_depends_on_buffer_size():
    class StopAfterWait(Exception):
        pass

    waits = []

    def sleep(seconds):
        waits.append(seconds)
        raise StopAfterWait

    cls = _class('LossyEcnTest', {'runTest'}, {
        'query_counter': lambda *_args: {
            'SAI_QUEUE_STAT_PACKETS': 1,
            'SAI_QUEUE_STAT_DROPPED_PACKETS': 1,
            'SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS': 1},
        'sai_thrift_get_queue_stats': lambda *_args: None,
        'sai_thrift_set_queue_attribute': lambda *_args, **_kwargs: None,
        'verify_packet': lambda *_args: None,
        'time': SimpleNamespace(sleep=sleep),
    })
    case = cls()
    case.client = object()
    case.queues2 = list(range(10))
    case.tx_cnt, case.pkt_len = 0, 64
    case.dev_port2, case.dev_port6 = 2, 6
    case.rev_pkt = 'packet'
    case.buf_size, case.alpha1, case.pir = 10000, 0, 1000
    case.assertGreater = TestCase().assertGreater

    with pytest.raises(StopAfterWait):
        case.runTest()

    assert waits == [7]


def test_source_balancing_checks_drop_before_unthrottling():
    state = {'unthrottled': False}

    def set_scheduler(*_args, **_kwargs):
        state['unthrottled'] = True
        return 0

    def query(_case, func, *_args):
        if func is queue_stats:
            return {'SAI_QUEUE_STAT_DROPPED_PACKETS':
                    1 if state['unthrottled'] else 0,
                    'SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES': 0}
        return {'SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES': 0,
                'SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES': 0}

    def queue_stats(*_args):
        pass

    cls = _class('LossySrcBalancingTest', {'runTest'}, {
        'get_platform': lambda: 'clx',
        'query_counter': query,
        'sai_thrift_get_queue_stats': queue_stats,
        'sai_thrift_get_ingress_priority_group_stats': lambda *_args: None,
        'sai_thrift_set_scheduler_group_attribute': set_scheduler,
        'sai_thrift_get_acl_counter_attribute': lambda *_args, **_kwargs: {},
        'sai_thrift_clear_queue_stats': lambda *_args: None,
        'sai_thrift_clear_ingress_priority_group_stats': lambda *_args: None,
        'clear_counter': lambda *_args: None,
        'SAI_STATUS_SUCCESS': 0,
        'time': SimpleNamespace(sleep=lambda *_args: None),
    })
    case = cls()
    case.client = object()
    case.tx_cnt = 0
    case.queues1 = list(range(10))
    case.queues1_2_parent_sch_grp = 10
    case.egress_acl_counter_id_list = []
    for port in (2, 3, 4, 5, 6, 20, 21):
        setattr(case, 'ipg_idx{}'.format(port), list(range(10)))
    case.FlowCntCreate = lambda: None
    case.FlowCntDestroy = lambda: None
    case.assertEqual = TestCase().assertEqual
    case.assertGreater = TestCase().assertGreater

    with pytest.raises(AssertionError):
        case.runTest()

    assert not state['unthrottled']


def test_lossless_alpha_wait_uses_buffer_size_on_non_clx():
    class StopAfterWait(Exception):
        pass

    waits = []

    def sleep(seconds):
        waits.append(seconds)
        raise StopAfterWait

    def get_queue_stats(*_args):
        pass

    def get_pg_stats(*_args):
        pass

    def get_pool_stats(*_args):
        pass

    def query(_case, func, *_args):
        if func is get_queue_stats:
            return {'SAI_QUEUE_STAT_SHARED_CURR_OCCUPANCY_BYTES': 1000}
        if func is get_pg_stats:
            return {'SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES': 1000}
        return {'SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES': 1000}

    cls = _class('LosslessAlphaTest', {'runTest'}, {
        'get_platform': lambda: 'brcm',
        'query_counter': query,
        'sai_thrift_get_queue_stats': get_queue_stats,
        'sai_thrift_get_ingress_priority_group_stats': get_pg_stats,
        'sai_thrift_get_buffer_pool_stats': get_pool_stats,
        'sai_thrift_clear_buffer_pool_stats': lambda *_args: None,
        'sai_thrift_clear_queue_stats': lambda *_args: None,
        'sai_thrift_clear_ingress_priority_group_stats': lambda *_args: None,
        'clear_counter': lambda *_args: None,
        'send_packet': lambda *_args: None,
        'time': SimpleNamespace(sleep=sleep),
    })
    case = cls()
    case.client = object()
    case.queues1, case.ipg_idx2 = list(range(10)), list(range(10))
    case.ingr_pool, case.dev_port2, case.pkt = 7, 2, 'packet'
    case.tx_cnt, case.pkt_len = 80001, 64
    case.buf_size, case.headroom_size = 2000, 0
    case.alpha1, case.pir = 0, 1000
    case.assertLessEqual = TestCase().assertLessEqual

    with pytest.raises(StopAfterWait):
        case.runTest()

    assert waits == [2]
