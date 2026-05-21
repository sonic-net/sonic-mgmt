"""
QoS adapter base class for TAI framework.

Defines the interface for QoS-related test operations.
"""

import ast
from typing import Any, Dict, Optional, Tuple
import logging

from TAI.core.base import AdapterBase

logger = logging.getLogger(__name__)


class QoSAdapter(AdapterBase):
    """
    Base adapter for QoS-related test operations.

    Provides interface for platform-specific QoS testing.

    Note:
        Platform-specific adapters should declare their supported_features.
        Example:
            supported_features = {
                'discover_queue_key',
                'apply_scheduler',
                'get_interface_drop_count',
            }
    """

    def discover_queue_key(self, interface: str, queue: int, **platform_params) -> Optional[str]:
        """
        Discover queue key from Redis by searching existing keys.

        This is the base implementation that searches Redis database 4
        for existing queue keys. Platform-specific adapters can call this
        and provide fallback formats if not found.

        Args:
            interface: Interface name (e.g., 'Ethernet0')
            queue: Queue number (e.g., 0)
            **platform_params: Platform-specific parameters (ignored by base class)

        Returns:
            Queue key if found in Redis, None otherwise
        """
        logger.info(f"Attempting to discover queue key for {interface} queue {queue} from Redis...")
        search_cmd = f"redis-cli -n 4 KEYS 'QUEUE|*{interface}|{queue}'"
        result = self.duthost.shell(search_cmd, module_ignore_errors=True)

        if result['rc'] == 0 and result['stdout'].strip():
            keys = result['stdout'].strip().split('\n')
            discovered_key = keys[0].strip()
            if discovered_key:
                logger.info(f"✓ Discovered queue key from Redis: {discovered_key}")
                return discovered_key

        logger.info(f"✗ No queue key found in Redis for {interface} queue {queue}")
        return None

    def create_scheduler(self, scheduler_key: str, config: Dict[str, Any],
                         **platform_params) -> bool:
        """
        Create scheduler policy in Redis.

        This method creates a scheduler policy by setting fields in Redis
        using HSET. It works the same way for all platforms, so it's implemented
        in the base class.

        Args:
            scheduler_key: Redis key for the scheduler (e.g., 'SCHEDULER|scheduler.0')
            config: Dictionary of field-value pairs to set
                   Example: {'type': 'DWRR', 'weight': '14'}
            **platform_params: Platform-specific parameters (ignored by base class)

        Returns:
            True if successful, False otherwise

        Note:
            Platform-specific adapters may override this method to use platform_params.
            The base implementation ignores all platform-specific parameters.
        """
        if not config:
            logger.warning(f"No configuration provided for scheduler key: {scheduler_key}")
            return False

        logger.info(f"Creating scheduler policy: {scheduler_key}")
        logger.info(f"Configuration: {config}")

        try:
            # Build HSET command with all field-value pairs
            # Format: redis-cli -n 4 HSET 'key' field1 value1 field2 value2 ...
            hset_args = []
            for field, value in config.items():
                hset_args.append(f"{field}")
                hset_args.append(f"{value}")

            hset_cmd = f"redis-cli -n 4 HSET '{scheduler_key}' {' '.join(hset_args)}"

            logger.info(f"Executing: {hset_cmd}")
            result = self.duthost.shell(hset_cmd, module_ignore_errors=True)

            if result['rc'] == 0:
                logger.info(f"✓ Successfully created scheduler policy: {scheduler_key}")

                # Show the created scheduler configuration
                show_cmd = f"redis-cli -n 4 HGETALL '{scheduler_key}'"
                show_result = self.duthost.shell(show_cmd, module_ignore_errors=True)

                if show_result['rc'] == 0 and show_result['stdout'].strip():
                    logger.info("Scheduler policy configuration for %s:", scheduler_key)
                    logger.info(f"  {show_result['stdout']}")
                else:
                    logger.warning("Could not retrieve scheduler configuration for verification")

                return True
            else:
                logger.error(f"✗ Failed to create scheduler policy. Return code: {result['rc']}")
                logger.error(f"Error output: {result.get('stderr', 'N/A')}")
                return False

        except Exception as e:
            logger.error(f"✗ Exception while creating scheduler policy: {str(e)}")
            return False

    def read_dbal_field(self, table_name: str, field_name: str) -> Optional[str]:
        """
        Read a single field from a DNX dbal table via bcmcmd.

        Default base implementation is a no-op that returns None — DNX dbal
        only exists on Qumran/DNX platforms. The Q3D adapter overrides this
        with a real implementation; XGS/Tomahawk platforms inherit this no-op.

        Args:
            table_name: dbal table name (e.g. 'SCH_PORT_CREDIT_CONFIGURATION')
            field_name: field name to read (e.g. 'CREDIT_WORTH')

        Returns:
            Raw string value, or None on platforms without dbal.
        """
        return None

    def apply_dbal_field(self, table_name: str, field_name: str, value: Any) -> bool:
        """
        Write a single field to a DNX dbal table via bcmcmd.

        Default base implementation is a no-op that returns True — DNX dbal
        only exists on Qumran/DNX platforms. The Q3D adapter overrides this
        with a real implementation; XGS/Tomahawk platforms inherit this no-op.

        Args:
            table_name: dbal table name
            field_name: field name to write
            value:      value to write

        Returns:
            True (no-op succeeds) on platforms without dbal.
        """
        return True

    def read_queue_scheduler(self, queue_key: str, **platform_params) -> Optional[str]:
        """
        Read the scheduler currently bound to a queue.

        Args:
            queue_key: Redis key for the queue (e.g., 'QUEUE|Ethernet0|0')
            **platform_params: Platform-specific parameters (ignored by base class)

        Returns:
            Scheduler name (without 'SCHEDULER|' prefix) if set, None otherwise.
        """
        result = self.duthost.shell(
            f"redis-cli -n 4 HGET '{queue_key}' scheduler",
            module_ignore_errors=True,
        )
        if result.get('rc') == 0 and result.get('stdout', '').strip():
            return result['stdout'].strip()
        return None

    def revert_scheduler(self, scheduler_key: str, queue_key: str,
                         prev_scheduler: Optional[str], **platform_params) -> bool:
        """
        Revert a queue's scheduler binding and delete the policy created by the test.

        If `prev_scheduler` is set, it is restored on the queue. Otherwise the
        'scheduler' field is removed from the queue. The SCHEDULER policy key
        passed in `scheduler_key` is then deleted.

        Args:
            scheduler_key: SCHEDULER policy key created by the test
                           (e.g., 'SCHEDULER|test_policy')
            queue_key:     Queue key whose binding is being reverted
                           (e.g., 'QUEUE|Ethernet0|0')
            prev_scheduler: Scheduler name previously bound to the queue, or None
                            if the queue had no scheduler before the test
            **platform_params: Platform-specific parameters (ignored by base class)

        Returns:
            True if revert and delete both succeeded, False otherwise.
        """
        if prev_scheduler:
            logger.info(f"Restoring scheduler '{prev_scheduler}' on {queue_key}")
            cmd = f"redis-cli -n 4 HSET '{queue_key}' scheduler '{prev_scheduler}'"
        else:
            logger.info(f"Removing scheduler field from {queue_key}")
            cmd = f"redis-cli -n 4 HDEL '{queue_key}' scheduler"

        result = self.duthost.shell(cmd, module_ignore_errors=True)
        if result.get('rc') != 0:
            logger.error(
                f"Failed to revert scheduler on {queue_key}: {result.get('stderr', '')}"
            )
            return False

        logger.info(f"Deleting scheduler policy {scheduler_key}")
        result = self.duthost.shell(
            f"redis-cli -n 4 DEL '{scheduler_key}'", module_ignore_errors=True
        )
        if result.get('rc') != 0:
            logger.error(
                f"Failed to delete scheduler policy {scheduler_key}: "
                f"{result.get('stderr', '')}"
            )
            return False

        logger.info("✓ Scheduler reverted via redis")
        return True

    def apply_scheduler(self, scheduler_key: str, queue_key: str,
                        **platform_params) -> bool:
        """
        Apply scheduler policy to a queue.

        This method binds a scheduler policy to a specific queue by setting
        the 'scheduler' field in the queue's Redis entry.

        Args:
            scheduler_key: Redis key for the scheduler (e.g., 'SCHEDULER|scheduler.0')
            queue_key: Redis key for the queue (e.g., 'QUEUE|Ethernet0|0')
            **platform_params: Platform-specific parameters (ignored by base class)

        Returns:
            True if successful, False otherwise

        Note:
            Platform-specific adapters may override this method to use platform_params.
            The base implementation ignores all platform-specific parameters.
        """
        logger.info(f"Applying scheduler {scheduler_key} to queue {queue_key}")

        try:
            # Extract scheduler name from key (e.g., 'SCHEDULER|scheduler.0' -> 'scheduler.0')
            scheduler_name = scheduler_key.split('|', 1)[1] if '|' in scheduler_key else scheduler_key

            # Set the scheduler field in the queue
            hset_cmd = f"redis-cli -n 4 HSET '{queue_key}' scheduler '{scheduler_name}'"

            logger.info(f"Executing: {hset_cmd}")
            result = self.duthost.shell(hset_cmd, module_ignore_errors=True)

            if result['rc'] == 0:
                logger.info("✓ Successfully applied scheduler to queue")

                # Show the updated queue configuration
                show_cmd = f"redis-cli -n 4 HGETALL '{queue_key}'"
                show_result = self.duthost.shell(show_cmd, module_ignore_errors=True)

                if show_result['rc'] == 0 and show_result['stdout'].strip():
                    logger.info("Queue configuration for %s:", queue_key)
                    logger.info(f"  {show_result['stdout']}")
                else:
                    logger.warning("Could not retrieve queue configuration for verification")

                return True
            else:
                logger.error(f"✗ Failed to apply scheduler to queue. Return code: {result['rc']}")
                logger.error(f"Error output: {result.get('stderr', 'N/A')}")
                return False

        except Exception as e:
            logger.error(f"✗ Exception while applying scheduler to queue: {str(e)}")
            return False

    def get_pg_profile(
        self, pg_number: int, interface: str, exact: bool = False
    ) -> Tuple[Optional[str], Optional[str], Optional[Dict]]:
        """
        Find the buffer profile name, BUFFER_PG key, and current profile config
        for a given PG number on an interface.

        Searches CONFIG_DB for BUFFER_PG|{interface}|* keys and finds the entry whose
        PG range contains pg_number (supports single PGs and ranges like '3-4').

        Args:
            pg_number: PG number to look up (e.g., 3)
            interface: Interface name (e.g., 'Ethernet0')
            exact: If True, only match keys whose range is a single PG equal to
                pg_number (e.g., '|4'). If False (default), also match range
                supersets (e.g., '|3-4' matches pg_number=3 and 4).

        Returns:
            (profile_name, pg_key, profile_config) or (None, None, None) if not found
        """
        result = self.duthost.shell(
            'sonic-db-cli CONFIG_DB keys "BUFFER_PG|{}|*"'.format(interface),
            module_ignore_errors=True
        )
        if result['rc'] != 0 or not result['stdout'].strip():
            logger.warning("No BUFFER_PG keys found for interface {}".format(interface))
            return None, None, None

        for pg_key in result['stdout'].strip().splitlines():
            pg_key = pg_key.strip()
            if not pg_key:
                continue
            pg_range = pg_key.split('|')[-1]
            if '-' in pg_range:
                if exact:
                    continue
                start, end = map(int, pg_range.split('-'))
                in_range = start <= pg_number <= end
            else:
                in_range = int(pg_range) == pg_number

            if not in_range:
                continue

            hget = self.duthost.shell(
                'sonic-db-cli CONFIG_DB HGET "{}" "profile"'.format(pg_key),
                module_ignore_errors=True
            )
            if hget['rc'] != 0 or not hget['stdout'].strip():
                continue

            profile_name = hget['stdout'].strip()

            hgetall = self.duthost.shell(
                'sonic-db-cli CONFIG_DB HGETALL "BUFFER_PROFILE|{}"'.format(profile_name),
                module_ignore_errors=True
            )
            profile_config = {}
            if hgetall['rc'] == 0 and hgetall['stdout'].strip():
                profile_config = ast.literal_eval(hgetall['stdout'].strip())

            logger.info("Found profile '{}' for PG {} on {}".format(
                profile_name, pg_number, interface))
            return profile_name, pg_key, profile_config

        logger.warning("No profile found for PG {} on {}".format(pg_number, interface))
        return None, None, None

    def create_or_update_pg_profile(self, profile_name: str, fields: Dict[str, Any]) -> None:
        """
        Create a new BUFFER_PROFILE or update fields on an existing one.

        Uses HMSET so only the supplied fields are written; existing fields
        not listed in `fields` are left unchanged.

        Args:
            profile_name: Profile name (without 'BUFFER_PROFILE|' prefix)
            fields:        Dict of field→value pairs to write
                           e.g., {'size': '0'} to update a single field, or
                           a full copy of profile_config to create a new profile

        Raises:
            ValueError: if the write fails
        """
        hmset_args = ' '.join('"{}" "{}"'.format(k, v) for k, v in fields.items())
        result = self.duthost.shell(
            'sonic-db-cli CONFIG_DB -- HMSET "BUFFER_PROFILE|{}" {}'.format(
                profile_name, hmset_args),
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            raise ValueError("Failed to write profile {}: {}".format(
                profile_name, result.get('stderr', '')))
        logger.info("Wrote BUFFER_PROFILE|{} with fields: {}".format(profile_name, list(fields.keys())))

    def apply_pg_profile(self, pg_key: str, profile_name: str) -> None:
        """
        Apply a buffer profile to a BUFFER_PG key.

        Sets the 'profile' field on the given BUFFER_PG key in CONFIG_DB.

        Args:
            pg_key:       BUFFER_PG key (e.g., 'BUFFER_PG|Ethernet0|3')
            profile_name: Profile name to apply (without 'BUFFER_PROFILE|' prefix)

        Raises:
            ValueError: if the write fails
        """
        result = self.duthost.shell(
            'sonic-db-cli CONFIG_DB HSET "{}" "profile" "{}"'.format(pg_key, profile_name),
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            raise ValueError("Failed to apply profile '{}' to {}: {}".format(
                profile_name, pg_key, result.get('stderr', '')))
        logger.info("Applied profile '{}' to {}".format(profile_name, pg_key))

    def delete_pg_profile(self, profile_name: str) -> None:
        """
        Delete a BUFFER_PROFILE entry from CONFIG_DB.

        Args:
            profile_name: Profile name (without 'BUFFER_PROFILE|' prefix)

        Raises:
            ValueError: if the DEL fails
        """
        result = self.duthost.shell(
            'sonic-db-cli CONFIG_DB DEL "BUFFER_PROFILE|{}"'.format(profile_name),
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            raise ValueError("Failed to delete profile {}: {}".format(
                profile_name, result.get('stderr', '')))
        logger.info("Deleted BUFFER_PROFILE|{}".format(profile_name))

    def get_interface_drop_count(self, interface: str, **platform_params) -> int:
        """
        Get drop counter for the specified interface using Ansible show_interface module.

        This base implementation uses the Ansible show_interface module to get counters
        and returns TX_DRP by default. Platform-specific adapters can override this
        to return different counter types (e.g., RX_DRP).

        Args:
            interface: Interface name (e.g., 'Ethernet0')
            **platform_params: Platform-specific parameters (ignored by base class)

        Returns:
            Drop count as integer (TX_DRP by default)

        Note:
            Platform-specific adapters can override this method to return different
            counter types or implement custom logic.
        """
        logger.info(f"Getting drop count for interface: {interface}")

        try:
            # Use show_interface Ansible module to get counters
            result = self.duthost.show_interface(command='counter', interfaces=[interface])

            if 'ansible_facts' in result and 'int_counter' in result['ansible_facts']:
                interface_counters = result['ansible_facts']['int_counter'].get(interface, {})

                if interface_counters:
                    # Extract TX_DRP counter value (default for base implementation)
                    # Convert string values to integers, handling commas
                    if 'TX_DRP' in interface_counters:
                        tx_drp = int(str(interface_counters['TX_DRP']).replace(',', ''))
                        logger.info(f"✓ TX_DRP for {interface}: {tx_drp}")
                        return tx_drp
                    else:
                        logger.warning("TX_DRP missing from interface counters")
                        return 0
                else:
                    logger.warning(f"Interface {interface} not in counters output")
                    return 0
            else:
                logger.warning("Failed to get interface counters from Ansible module")
                return 0

        except Exception as e:
            logger.error(f"✗ Exception while getting drop count: {str(e)}")
            return 0
