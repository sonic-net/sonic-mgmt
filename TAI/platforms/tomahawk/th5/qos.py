"""
TH5 (Tomahawk 5) QoS adapter — base for all Tomahawk generations.
"""

from typing import Optional
import logging

from TAI.core.qos import QoSAdapter
from TAI.core.factory import AdapterFactory

logger = logging.getLogger(__name__)


@AdapterFactory.register(QoSAdapter, 'th5')
class TH5QoSAdapter(QoSAdapter):
    """
    QoS adapter for Broadcom Tomahawk 5.

    TH6 and later generations inherit from this class.
    """

    platform_name = 'th5'

    supported_features = {
        'discover_queue_key',
        'create_scheduler',
        'apply_scheduler',
        'read_queue_scheduler',
        'revert_scheduler',
        'get_interface_drop_count',
        'get_pg_profile',
        'create_or_update_pg_profile',
        'apply_pg_profile',
        'delete_pg_profile',
    }

    def discover_queue_key(self, interface: str, queue: int, **platform_params) -> Optional[str]:
        """
        Discover queue key for TH5.

        Tries Redis first (parent), then falls back to standard format:
        QUEUE|{interface}|{queue}
        """
        queue_key = super().discover_queue_key(interface, queue, **platform_params)
        if queue_key:
            return queue_key
        queue_key = f"QUEUE|{interface}|{queue}"
        logger.info(f"Using standard format queue key: {queue_key}")
        return queue_key

    def get_interface_drop_count(self, interface: str, **platform_params) -> int:
        """TH5: TX drop counters (TX_DRP)."""
        logger.info(f"Getting TX drop count for interface: {interface} (TH5)")
        try:
            result = self.duthost.show_interface(command='counter', interfaces=[interface])
            if 'ansible_facts' in result and 'int_counter' in result['ansible_facts']:
                counters = result['ansible_facts']['int_counter'].get(interface, {})
                if 'TX_DRP' in counters:
                    return int(str(counters['TX_DRP']).replace(',', ''))
        except Exception as e:
            logger.error(f"Exception while getting TX drop count: {str(e)}")
        return 0
