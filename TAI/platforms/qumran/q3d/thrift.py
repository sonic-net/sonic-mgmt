"""
Q3D (Qumran 3D) ThriftAdapter.
"""

import logging
from typing import Any, Dict, Optional

from TAI.core.thrift import ThriftAdapter
from TAI.core.factory import AdapterFactory

logger = logging.getLogger(__name__)


@AdapterFactory.register(ThriftAdapter, 'q3d')
class Q3DThriftAdapter(ThriftAdapter):
    """
    SAI thrift counter adapter for Broadcom Qumran Q3D (NH-5010).

    Qumran counts drops on ingress (broadcom-dnx) rather than egress.
    Only counter index 1 reliably tracks ingress drops.
    """

    platform_name = 'q3d'

    supported_features = {
        'get_pg_counters',
        'get_pg_drop_counters',
        'get_pg_all_drop_counters',
        'get_pg_pkts_received',
        'get_pkts_num_leak_out',
        'compensate_leakout',
        'get_port_counters',
        'get_ingress_drop_margin',
        'get_active_ingress_drop_counters',
        'tx_disable',
        'tx_enable',
        'send_pkts_short_of_pfc',
        'check_rx_drop',
        'check_tx_drop',
        'check_pfc_triggered',
    }

    def get_pkts_num_leak_out(self, pkts_num_leak_out: int) -> int:
        """Q3D: leakout is compensated dynamically — static value is not needed."""
        return 0

    def get_pg_drop_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                             baseline: Optional[Dict] = None) -> int:
        """Q3D: drops appear on ingress (broadcom-dnx counts at ingress)."""
        counters = self.get_pg_counters(test_case, src_port_id, dst_port_id, baseline)
        return counters['ingress_drops']

    def get_ingress_drop_margin(self) -> int:
        """Q3D: allow up to 10 extra ingress drop counts (extra IPv6 NS/RA traffic)."""
        return 10

    def get_active_ingress_drop_counters(self, ingress_counters: list) -> list:
        """Q3D: only counter index 1 reliably tracks ingress drops on broadcom-dnx."""
        return [c for c in ingress_counters if c == 1]

    def get_pg_pkts_received(self, test_case: Any, src_port_id: int, dst_port_id: int,
                             pg_number: int, baseline: Optional[Dict] = None) -> int:
        """
        Q3D: adds ingress drops to PG counter delta.

        On broadcom-dnx, ingress-dropped packets are still counted at the PG level.
        """
        counters = self.get_pg_counters(test_case, src_port_id, dst_port_id)
        if baseline is None:
            return counters['pg_counters'][pg_number]
        pg_delta = counters['pg_counters'][pg_number] - baseline['pg_counters'][pg_number]
        ingress_delta = counters['ingress_drops'] - baseline['ingress_drops']
        return pg_delta + ingress_delta
