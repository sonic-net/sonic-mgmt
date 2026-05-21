"""
Q3D (Qumran 3D) QoS adapter.
"""

from typing import Any, Optional
import logging

from TAI.core.qos import QoSAdapter
from TAI.core.factory import AdapterFactory

logger = logging.getLogger(__name__)


@AdapterFactory.register(QoSAdapter, 'q3d')
class Q3DQoSAdapter(QoSAdapter):
    """
    QoS adapter for Broadcom Qumran Q3D.
    """

    platform_name = 'q3d'

    supported_features = {
        'discover_queue_key',
        'create_scheduler',
        'apply_scheduler',
        'read_queue_scheduler',
        'revert_scheduler',
        'read_dbal_field',
        'apply_dbal_field',
        'get_interface_drop_count',
        'get_pg_profile',
        'create_or_update_pg_profile',
        'apply_pg_profile',
        'delete_pg_profile',
    }

    def discover_queue_key(self, interface: str, queue: int, **platform_params) -> Optional[str]:
        """
        Discover queue key for Q3D.

        Tries Redis first (parent), then falls back to Q3D format:
        QUEUE|{hostname}|Asic0|{interface}|{queue}
        """
        queue_key = super().discover_queue_key(interface, queue, **platform_params)
        if queue_key:
            return queue_key
        hostname = self.duthost.hostname
        queue_key = f"QUEUE|{hostname}|Asic0|{interface}|{queue}"
        logger.info(f"Using Q3D format queue key: {queue_key}")
        return queue_key

    def read_dbal_field(self, table_name: str, field_name: str) -> Optional[str]:
        """
        Read a single field from a DNX dbal table via `bcmcmd "dbal entry get"`.

        Q3D-only. Tomahawk/XGS platforms do not have dbal.

        Output of `dbal entry get` looks like:
            Result:
              CREDIT_WORTH                             131

        We find the line containing `field_name` and return the last whitespace
        token on that line as a raw string. Caller is responsible for any type
        coercion (e.g. int(...)).

        Args:
            table_name: dbal table name (e.g. 'SCH_PORT_CREDIT_CONFIGURATION')
            field_name: field name to read (e.g. 'CREDIT_WORTH')

        Returns:
            The field value as a string, or None on read failure / field not found.
        """
        try:
            result = self.duthost.shell(
                f'bcmcmd "dbal entry get table={table_name}"',
                module_ignore_errors=True,
            )
            if result.get('rc') != 0:
                logger.warning(f"Failed to read dbal table {table_name}: {result.get('stderr', '')}")
                return None
            for line in result.get('stdout', '').splitlines():
                if field_name in line:
                    parts = line.split()
                    if parts:
                        return parts[-1]
            logger.warning(f"Field {field_name} not found in dbal table {table_name}")
            return None
        except Exception as e:
            logger.warning(f"Error reading {field_name} from {table_name}: {e}")
            return None

    def apply_dbal_field(self, table_name: str, field_name: str, value: Any) -> bool:
        """
        Write a single field to a DNX dbal table via `bcmcmd "dbal Entry commit"`.

        Q3D-only. Tomahawk/XGS platforms do not have dbal.

        Args:
            table_name: dbal table name (e.g. 'SCH_PORT_CREDIT_CONFIGURATION')
            field_name: field name to write (e.g. 'CREDIT_WORTH')
            value:      value to write (formatted with str())

        Returns:
            True if the bcmcmd succeeded, False otherwise.
        """
        bcm_cmd = (
            f'bcmcmd "dbal Entry commit table={table_name} {field_name}={value}"'
        )
        try:
            result = self.duthost.shell(bcm_cmd, module_ignore_errors=True)
            if result.get('rc') == 0:
                logger.info(f"dbal {table_name}.{field_name}={value} applied")
                return True
            logger.warning(
                f"dbal {table_name}.{field_name}={value} failed: {result.get('stderr', '')}"
            )
        except Exception as e:
            logger.error(f"Exception writing dbal {table_name}.{field_name}: {e}")
        return False

    def get_interface_drop_count(self, interface: str, **platform_params) -> int:
        """Q3D: RX drop counters (RX_DRP)."""
        logger.info(f"Getting RX drop count for interface: {interface} (Q3D)")
        try:
            result = self.duthost.show_interface(command='counter', interfaces=[interface])
            if 'ansible_facts' in result and 'int_counter' in result['ansible_facts']:
                counters = result['ansible_facts']['int_counter'].get(interface, {})
                if 'RX_DRP' in counters:
                    return int(str(counters['RX_DRP']).replace(',', ''))
        except Exception as e:
            logger.error(f"Exception while getting RX drop count: {str(e)}")
        return 0
