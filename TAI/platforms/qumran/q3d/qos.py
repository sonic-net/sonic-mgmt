"""
Q3D (Qumran 3D) QoS adapter.
"""

from typing import Any, Dict, Optional
import logging

from TAI.core.qos import QoSAdapter
from TAI.core.factory import AdapterFactory

logger = logging.getLogger(__name__)

# DNX per-port scheduler credit. A STRICT scheduler on broadcom-dnx needs
# CREDIT_WORTH configured for rate limiting to engage; Tomahawk has no equivalent.
_DNX_CREDIT_TABLE = 'SCH_PORT_CREDIT_CONFIGURATION'
_DNX_CREDIT_FIELD = 'CREDIT_WORTH'


@AdapterFactory.register(QoSAdapter, 'q3d')
class Q3DQoSAdapter(QoSAdapter):
    """
    QoS adapter for Broadcom Qumran Q3D (NH-5010).
    """

    platform_name = 'q3d'

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

    def __init__(self, duthost):
        super().__init__(duthost)
        # Previous CREDIT_WORTH captured by create_scheduler, restored by revert_scheduler.
        self._prev_credit_worth = None

    def create_scheduler(self, scheduler_key: str, config: Dict[str, Any],
                         **platform_params) -> bool:
        """
        Create a scheduler policy and, on Q3D, configure the DNX credit worth.

        A STRICT scheduler on broadcom-dnx needs SCH_PORT_CREDIT_CONFIGURATION.
        CREDIT_WORTH set for rate limiting to take effect. When the caller passes
        ``credit_worth`` we stash the current value (so revert_scheduler can
        restore it) and apply the requested one. Other platforms receive the same
        argument and ignore it, so callers stay platform-agnostic.

        Args:
            scheduler_key:  SCHEDULER policy key (e.g. 'SCHEDULER|scheduler.0')
            config:         Scheduler field/value pairs (e.g. {'type': 'STRICT', ...})
            **platform_params: credit_worth=<int> to set the DNX credit worth

        Returns:
            True on success, False otherwise.
        """
        if not super().create_scheduler(scheduler_key, config, **platform_params):
            return False

        credit_worth = platform_params.get('credit_worth')
        if credit_worth is not None:
            self._prev_credit_worth = self._read_dbal_field(_DNX_CREDIT_TABLE, _DNX_CREDIT_FIELD)
            logger.info("Q3D: prev CREDIT_WORTH=%s, setting %s",
                        self._prev_credit_worth, credit_worth)
            if not self._apply_dbal_field(_DNX_CREDIT_TABLE, _DNX_CREDIT_FIELD, credit_worth):
                logger.error("Q3D: failed to set CREDIT_WORTH=%s", credit_worth)
                return False
        return True

    def revert_scheduler(self, scheduler_key: str, queue_key: str,
                         prev_scheduler: Optional[str], **platform_params) -> bool:
        """
        Restore the DNX credit worth, then revert the scheduler binding.

        CREDIT_WORTH is restored first. If that fails we return False without
        touching the SCHEDULER state, so the framework CONFIG_DB diff check fires
        a config reload to reset SDK state.
        """
        if self._prev_credit_worth is not None:
            logger.info("Q3D: reverting CREDIT_WORTH to %s", self._prev_credit_worth)
            if not self._apply_dbal_field(_DNX_CREDIT_TABLE, _DNX_CREDIT_FIELD,
                                          self._prev_credit_worth):
                logger.error("Q3D: CREDIT_WORTH revert failed; leaving scheduler intact "
                             "for framework reload")
                return False
            self._prev_credit_worth = None
        return super().revert_scheduler(scheduler_key, queue_key, prev_scheduler,
                                        **platform_params)

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

    def _read_dbal_field(self, table_name: str, field_name: str) -> Optional[str]:
        """
        Read a single field from a DNX dbal table via `bcmcmd "dbal entry get"`.

        Internal Q3D helper (broadcom-dnx only). Output of `dbal entry get` looks
        like:
            Result:
              CREDIT_WORTH                             131

        We find the line containing `field_name` and return the last whitespace
        token on that line as a raw string.

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

    def _apply_dbal_field(self, table_name: str, field_name: str, value: Any) -> bool:
        """
        Write a single field to a DNX dbal table via `bcmcmd "dbal Entry commit"`.

        Internal Q3D helper (broadcom-dnx only).

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
