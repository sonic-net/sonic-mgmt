"""
TH5 (Tomahawk 5) ThriftAdapter — base for all Tomahawk generations.
"""

import logging

from TAI.core.thrift import ThriftAdapter
from TAI.core.factory import AdapterFactory

logger = logging.getLogger(__name__)


@AdapterFactory.register(ThriftAdapter, 'th5')
class TH5ThriftAdapter(ThriftAdapter):
    """
    SAI thrift counter adapter for Broadcom Tomahawk 5 (NH-4010).

    First of the Tomahawk generation; TH6 and later inherit from this class.
    """

    platform_name = 'th5'

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
        """TH5: leakout is compensated dynamically — static value is not needed."""
        return 0

    def compensate_leakout(self, test_case, dst_port_id, src_port_id,
                           pkt, xmit_counters_base, max_retry=10) -> int:
        """TH5: leakout compensation not needed — return immediately."""
        return 0

    def get_ingress_drop_margin(self) -> int:
        """TH5: allow up to 2 extra ingress drop counts for background traffic."""
        return 2
