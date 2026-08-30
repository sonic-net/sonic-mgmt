"""
Facade pattern implementation for TAI framework.

Provides a unified interface to all platform adapters, hiding the complexity
of managing multiple adapter types.
"""

import logging
from typing import Any, Dict, Type, Optional, Set, List
from .base import AdapterBase
from .qos import QoSAdapter
from .thrift import ThriftAdapter
from .factory import AdapterFactory

logger = logging.getLogger(__name__)


class PlatformAdapter:
    """
    Facade that provides unified interface to all platform adapters.

    This is the main entry point for users. It automatically manages all
    adapter types internally and provides a single, simple interface.

    Users don't need to know about QoSAdapter, RebootAdapter, etc.
    Just create one PlatformAdapter and call any method.

    Usage:
        # Simple - create one adapter
        platform = PlatformAdapter(duthost)

        # Get specific adapter and call methods
        qos = platform.get_adapter(QoSAdapter)
        queue_key = qos.discover_queue_key("Ethernet0", 0)
        qos.create_scheduler("SCHEDULER|scheduler.0", {'type': 'DWRR'})
        qos.apply_scheduler("SCHEDULER|scheduler.0", queue_key)

    Advanced Usage:
        # Get specific adapter if needed
        qos_adapter = platform.get_adapter(QoSAdapter)
    """

    # Registry of adapter types to auto-load
    _adapter_types = [
        QoSAdapter,
        ThriftAdapter,
        # RebootAdapter,    # Add when implemented
        # ThermalAdapter,   # Add when implemented
        # MemoryAdapter,    # Add when implemented
        # InterfaceAdapter, # Add when implemented
    ]

    def __init__(self, duthost: Any):
        """
        Initialize the platform facade.

        Args:
            duthost: The DUT host object
        """
        self.duthost = duthost
        self._adapters: Dict[Type[AdapterBase], AdapterBase] = {}
        self._platform_info = None

        logger.info(f"Initializing PlatformAdapter for {duthost.facts.get('platform', 'unknown')}")

        # Collect all supported features during initialization
        self._supported_features: Set[str] = self._collect_supported_features()
        logger.info(f"Platform supports {len(self._supported_features)} features: {sorted(self._supported_features)}")

    def _collect_supported_features(self) -> Set[str]:
        """
        Collect all supported features from all adapters during initialization.

        Returns:
            Set of all supported feature names
        """
        logger.debug("Collecting supported features from all adapters...")
        all_features = set()

        # Collect features from all adapter types
        for adapter_type in self._adapter_types:
            adapter = self._get_or_create_adapter(adapter_type)
            adapter_features = adapter.get_supported_features()
            all_features.update(adapter_features)
            logger.debug(f"{adapter.__class__.__name__} supports: {adapter_features}")

        return all_features

    def _get_or_create_adapter(self, adapter_type: Type[AdapterBase]) -> AdapterBase:
        """
        Get or create an adapter of the specified type.

        Uses lazy loading - adapters are only created when first accessed.

        Args:
            adapter_type: The type of adapter to get/create

        Returns:
            The adapter instance
        """
        if adapter_type not in self._adapters:
            logger.debug(f"Creating {adapter_type.__name__} for the first time")
            self._adapters[adapter_type] = AdapterFactory.create_adapter(
                adapter_type, self.duthost
            )
        return self._adapters[adapter_type]

    def get_adapter(self, adapter_type: Type[AdapterBase]) -> AdapterBase:
        """
        Get a specific adapter for advanced use cases.

        This allows users to access specific adapters directly if needed,
        while still benefiting from the facade's adapter management.

        Args:
            adapter_type: The type of adapter to get (e.g., QoSAdapter)

        Returns:
            The adapter instance

        Example:
            qos = platform.get_adapter(QoSAdapter)
            queue_key = qos.discover_queue_key("Ethernet0", 0)
        """
        return self._get_or_create_adapter(adapter_type)

    def get_supported_features(self) -> Set[str]:
        """
        Get all features supported by this platform across all adapters.

        Features are collected during initialization and cached.

        Returns:
            Set of all supported feature names

        Example:
            features = platform.get_supported_features()
            # {'discover_queue_key', 'apply_scheduler', 'get_interface_drop_count'}
        """
        return self._supported_features.copy()

    def is_feature_supported(self, feature_name: str) -> bool:
        """
        Check if a specific feature is supported by this platform.

        Args:
            feature_name: Name of the feature to check

        Returns:
            True if feature is supported, False otherwise

        Example:
            if platform.is_feature_supported('get_interface_drop_count'):
                # Feature is available
        """
        return feature_name in self._supported_features

    def require_features(self, feature_names: List[str]) -> bool:
        """
        Check if ALL specified features are supported.

        Returns True if all features are supported, False otherwise.
        This allows you to handle unsupported features in your own way.

        The facade does NOT skip - it's up to the test to decide how to
        handle unsupported features.

        Args:
            feature_names: List of feature names required by the test

        Returns:
            True if all features are supported, False if any are missing

        Example:
            platform = PlatformAdapter(duthost)
            if not platform.require_features([
                'discover_queue_key',
                'apply_scheduler',
                'get_interface_drop_count',
            ]):
                # Handle unsupported features in your test
                ...

            qos = platform.get_adapter(QoSAdapter)
        """
        missing = [f for f in feature_names if f not in self._supported_features]
        return len(missing) == 0

    def get_missing_features(self, feature_names: List[str]) -> List[str]:
        """
        Get list of features that are NOT supported by this platform.

        Useful for custom error handling or conditional logic.

        Args:
            feature_names: List of feature names to check

        Returns:
            List of feature names that are NOT supported (empty if all supported)

        Example:
            required = ['discover_queue_key', 'warm_reboot']
            missing = platform.get_missing_features(required)
            if missing:
                print(f"Missing: {missing}")
        """
        return [f for f in feature_names if f not in self._supported_features]

    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get comprehensive platform information.

        Returns:
            Dictionary with platform details
        """
        if self._platform_info is None:
            self._platform_info = {
                'platform': self.duthost.facts.get('platform'),
                'asic_type': self.duthost.facts.get('asic_type'),
                'hwsku': self.duthost.facts.get('hwsku'),
                'loaded_adapters': [
                    adapter.__class__.__name__
                    for adapter in self._adapters.values()
                ],
                'supported_features': sorted(self._supported_features),
            }
        return self._platform_info

    # =========================================================================
    # QoS Adapter Methods - Delegate to QoSAdapter
    # =========================================================================

    def discover_queue_key(self, interface: str, queue: int, **platform_params) -> Optional[str]:
        """
        Discover queue key for the specified interface and queue.

        Automatically uses the correct platform-specific format.

        Args:
            interface: Interface name (e.g., 'Ethernet0')
            queue: Queue number (e.g., 0)
            **platform_params: Platform-specific parameters

        Returns:
            Queue key string (e.g., 'QUEUE|Ethernet0|0' for Tomahawk)

        Example:
            queue_key = platform.discover_queue_key("Ethernet0", 0)
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.discover_queue_key(interface, queue, **platform_params)

    def create_scheduler(self, scheduler_key: str, config: Dict[str, Any],
                         **platform_params) -> bool:
        """
        Create scheduler policy.

        Automatically handles platform-specific requirements.

        Args:
            scheduler_key: Redis key for scheduler (e.g., 'SCHEDULER|scheduler.0')
            config: Configuration dictionary (e.g., {'type': 'STRICT', 'cir': '500000'})
            **platform_params: Platform-specific parameters (e.g., credit_worth for DNX)

        Returns:
            True if successful, False otherwise

        Example:
            success = platform.create_scheduler(
                "SCHEDULER|scheduler.0",
                {'type': 'STRICT', 'cir': '500000', 'pir': '750000'},
                credit_worth=4096  # For DNX platforms
            )
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.create_scheduler(scheduler_key, config, **platform_params)

    def apply_scheduler(self, scheduler_key: str, queue_key: str,
                        **platform_params) -> bool:
        """
        Apply scheduler policy to a queue.

        Automatically handles platform-specific requirements.

        Args:
            scheduler_key: Redis key for scheduler (e.g., 'SCHEDULER|scheduler.0')
            queue_key: Redis key for queue (e.g., 'QUEUE|Ethernet0|0')
            **platform_params: Platform-specific parameters

        Returns:
            True if successful, False otherwise

        Example:
            success = platform.apply_scheduler(
                "SCHEDULER|scheduler.0",
                "QUEUE|Ethernet0|0"
            )
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.apply_scheduler(scheduler_key, queue_key, **platform_params)

    def read_queue_scheduler(self, queue_key: str, **platform_params) -> Optional[str]:
        """
        Read the scheduler currently bound to a queue.

        Args:
            queue_key: Redis key for the queue (e.g., 'QUEUE|Ethernet0|0')
            **platform_params: Platform-specific parameters

        Returns:
            Scheduler name if set, None otherwise.

        Example:
            prev = platform.read_queue_scheduler("QUEUE|Ethernet0|0")
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.read_queue_scheduler(queue_key, **platform_params)

    def revert_scheduler(self, scheduler_key: str, queue_key: str,
                         prev_scheduler: Optional[str], **platform_params) -> bool:
        """
        Revert a queue's scheduler binding and delete the test-created policy.

        Args:
            scheduler_key:  SCHEDULER policy key created by the test
            queue_key:      Queue whose binding is being reverted
            prev_scheduler: Scheduler previously bound, or None if the queue
                            had no scheduler before the test
            **platform_params: Platform-specific parameters

        Returns:
            True on full success, False otherwise.

        Example:
            prev = platform.read_queue_scheduler(queue_key)
            ...  # apply test policy, run test
            platform.revert_scheduler("SCHEDULER|test_policy", queue_key, prev)
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.revert_scheduler(scheduler_key, queue_key, prev_scheduler,
                                    **platform_params)

    def get_interface_drop_count(self, interface: str, **platform_params) -> int:
        """
        Get drop counter for the specified interface.

        Automatically selects the correct counter type for the platform.

        Args:
            interface: Interface name (e.g., 'Ethernet0')
            **platform_params: Platform-specific parameters

        Returns:
            Drop count as integer

        Example:
            drops = platform.get_interface_drop_count("Ethernet0")
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.get_interface_drop_count(interface, **platform_params)

    # =========================================================================
    # QoS Adapter — DUT-shell methods (buffer profile management)
    # =========================================================================

    def get_pg_profile(self, pg_number: int, interface: str, exact: bool = False):
        """
        Find buffer profile name and BUFFER_PG key for a given PG on an interface.

        Args:
            pg_number: PG number to look up (e.g., 3)
            interface: Interface name (e.g., 'Ethernet0')
            exact: If True, only match keys whose range is a single PG equal to
                pg_number. If False (default), also match range supersets.

        Returns:
            (profile_name, pg_key, profile_config) or (None, None, None) if not found
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.get_pg_profile(pg_number, interface, exact=exact)

    def create_or_update_pg_profile(self, profile_name: str, fields: Dict[str, Any]) -> None:
        """
        Create a new BUFFER_PROFILE or update fields on an existing one.

        Args:
            profile_name: Profile name (without 'BUFFER_PROFILE|' prefix)
            fields:        Dict of field→value pairs to write
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.create_or_update_pg_profile(profile_name, fields)

    def apply_pg_profile(self, pg_key: str, profile_name: str) -> None:
        """
        Apply a buffer profile to a BUFFER_PG key.

        Args:
            pg_key:       BUFFER_PG key (e.g., 'BUFFER_PG|Ethernet0|3')
            profile_name: Profile name to apply (without 'BUFFER_PROFILE|' prefix)
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.apply_pg_profile(pg_key, profile_name)

    def delete_pg_profile(self, profile_name: str) -> None:
        """
        Delete a BUFFER_PROFILE entry from CONFIG_DB.

        Args:
            profile_name: Profile name (without 'BUFFER_PROFILE|' prefix)
        """
        qos = self._get_or_create_adapter(QoSAdapter)
        return qos.delete_pg_profile(profile_name)

    # =========================================================================
    # ThriftAdapter Methods — SAI thrift counter operations (PTF context)
    # =========================================================================

    def get_pg_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                        baseline=None) -> Dict[str, Any]:
        """
        Read PG and port counters via SAI thrift, returning snapshot or delta.

        Requires PTF context (test_case with thrift clients).

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    Previous snapshot for delta mode

        Returns:
            dict with pg_counters, recv_counters, xmit_counters,
            total_received, ingress_drops, egress_drops, total_drops
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.get_pg_counters(test_case, src_port_id, dst_port_id, baseline)

    def get_pg_drop_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                             baseline=None) -> int:
        """
        Get platform-appropriate drop count (egress for Tomahawk, ingress for Qumran).

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    Previous snapshot for delta mode

        Returns:
            Drop count as integer
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.get_pg_drop_counters(test_case, src_port_id, dst_port_id, baseline)

    def get_pg_all_drop_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                                 baseline=None) -> Dict[str, int]:
        """
        Get all drop counter types (ingress, egress, total).

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    Previous snapshot for delta mode

        Returns:
            dict with ingress_drops, egress_drops, total_drops
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.get_pg_all_drop_counters(test_case, src_port_id, dst_port_id, baseline)

    def get_port_counters(self, test_case: Any, src_port_id: int, dst_port_id: int,
                          baseline=None):
        """
        Read recv and xmit port counters.

        Returns (recv_counters, xmit_counters) as lists.
        If baseline (a previously returned (recv, xmit) tuple) is provided,
        returns element-wise deltas.

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            baseline:    (recv, xmit) tuple from a previous call, or None

        Returns:
            (recv_counters, xmit_counters) — absolute or delta lists
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.get_port_counters(test_case, src_port_id, dst_port_id, baseline)

    def get_pkts_num_leak_out(self, pkts_num_leak_out: int) -> int:
        """
        Return the effective pkts_num_leak_out for this platform.

        Broadcom platforms (Tomahawk, Qumran) return 0 because leakout is
        handled dynamically by compensate_leakout.  Other platforms return
        the raw value unchanged.

        Args:
            pkts_num_leak_out: Raw value from test_params
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.get_pkts_num_leak_out(pkts_num_leak_out)

    def check_rx_drop(self, recv_delta: List, ingress_counters: List):
        """
        Check whether ingress drops occurred.  Returns (True, reason) when drops present.

        Use ``not ok`` when asserting no drops should have occurred.
        Margin and active counter selection are determined by the platform adapter.

        Args:
            recv_delta:       Delta recv list from get_port_counters()
            ingress_counters: Counter index list from get_counter_names()
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.check_rx_drop(recv_delta, ingress_counters)

    def check_tx_drop(self, xmit_delta: List, egress_counters: List):
        """
        Check whether egress drops occurred.  Returns (True, reason) when drops present.

        Use ``not ok`` when asserting no drops should have occurred.

        Args:
            xmit_delta:      Delta xmit list from get_port_counters()
            egress_counters: Counter index list from get_counter_names()
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.check_tx_drop(xmit_delta, egress_counters)

    def check_pfc_triggered(self, recv_delta: List, pg: int):
        """
        Check whether PFC counter increased (PFC fired).  Returns (True, reason) when triggered.

        Use ``not ok`` when asserting PFC should NOT have triggered.

        Args:
            recv_delta: Delta recv list from get_port_counters()
            pg:         PFC counter index (test_params['pg'] + 2)
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.check_pfc_triggered(recv_delta, pg)

    def tx_disable(self, test_case: Any, dst_port_id: int) -> None:
        """
        Disable TX on dst_port_id via platform-appropriate method.

        Args:
            test_case:   PTF test instance
            dst_port_id: Destination port index
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.tx_disable(test_case, dst_port_id)

    def tx_enable(self, test_case: Any, dst_port_id: int) -> None:
        """
        Re-enable TX on dst_port_id.

        Args:
            test_case:   PTF test instance
            dst_port_id: Destination port index
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.tx_enable(test_case, dst_port_id)

    def send_pkts_short_of_pfc(self, test_case: Any, src_port_id: int, pkt: Any,
                               pkts_num_leak_out: int, pkts_num_trig_pfc: int,
                               cell_occupancy: int, margin: int, **kwargs) -> int:
        """
        Send packets just short of triggering PFC.

        Base: (pkts_num_leak_out + pkts_num_trig_pfc) // cell_occupancy - 1 - margin.
        Overridable per platform for different formulas or prologue steps.

        Args:
            test_case:         PTF test instance
            src_port_id:       Source port index
            pkt:               Packet to send
            pkts_num_leak_out: Static leakout count from test params
            pkts_num_trig_pfc: PFC trigger threshold from test params
            cell_occupancy:    Cells per packet
            margin:            Packet count margin
            **kwargs:          Passed through to platform override

        Returns:
            Number of packets sent
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.send_pkts_short_of_pfc(
            test_case, src_port_id, pkt,
            pkts_num_leak_out, pkts_num_trig_pfc, cell_occupancy, margin, **kwargs)

    def compensate_leakout(self, test_case: Any, dst_port_id: int, src_port_id: int,
                           pkt: Any, xmit_counters_base: list, max_retry: int = 10) -> int:
        """
        Compensate for packet leakout after TX disable.

        Tomahawk: no-op (returns 0).
        Qumran: polls egress TX counter and sends fill packets up to max_retry times.

        Args:
            test_case:          PTF test instance
            dst_port_id:        Destination port index
            src_port_id:        Source port index for compensation packets
            pkt:                Packet to send
            xmit_counters_base: TX counter snapshot before TX disable
            max_retry:          Max compensation iterations (default 10)

        Returns:
            Number of compensation packets sent
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.compensate_leakout(
            test_case, dst_port_id, src_port_id, pkt, xmit_counters_base, max_retry)

    def get_pg_pkts_received(self, test_case: Any, src_port_id: int, dst_port_id: int,
                             pg_number: int, baseline=None) -> int:
        """
        Platform-adjusted received packet count for a given PG.

        Args:
            test_case:   PTF test instance
            src_port_id: Source port index
            dst_port_id: Destination port index
            pg_number:   PG index to read from pg_counters list
            baseline:    Previous snapshot from get_pg_counters() for delta mode

        Returns:
            Platform-adjusted received packet count (or absolute if no baseline)
        """
        thrift = self._get_or_create_adapter(ThriftAdapter)
        return thrift.get_pg_pkts_received(test_case, src_port_id, dst_port_id,
                                           pg_number, baseline)

    # =========================================================================
    # Future: Add methods for other adapters as they are implemented
    # =========================================================================

    # def get_pmon_wait_time(self) -> int:
    #     """Get PMON wait time after reboot."""
    #     return self._get_or_create_adapter(RebootAdapter).get_pmon_wait_time()

    # def get_temperature_thresholds(self) -> Dict[str, Dict[str, float]]:
    #     """Get temperature thresholds."""
    #     return self._get_or_create_adapter(ThermalAdapter).get_temperature_thresholds()

    def __repr__(self) -> str:
        """String representation of the facade."""
        platform = self.duthost.facts.get('platform', 'unknown')
        num_adapters = len(self._adapters)
        return f"PlatformAdapter(platform='{platform}', loaded_adapters={num_adapters})"
