#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ProbingBase - Common base class for MMU threshold probing test cases

This module provides the common infrastructure for all probing test cases using
the Template Method Pattern:

Probing Types:
- PfcXoffProbing: PFC Xoff threshold probing (1 src -> N dst)
- IngressDropProbing: Ingress Drop threshold probing (1 src -> N dst)
- HeadroomPoolProbing: Headroom Pool Size probing (N src -> 1 dst)

Design Pattern: Template Method
- ProbingBase.runTest() defines the workflow skeleton
- Subclasses implement abstract methods: setup_traffic(), probe()
- Subclasses implement get_probe_config() to provide standardized parameters

Call Flow:
    PTF -> PfcXoffProbing.setUp()
            ├── super().setUp()  -> ProbingBase.setUp()
            │       ├── ThriftInterfaceDataPlane.setUp()
            │       ├── switch_init()
            │       └── ProbingBase.parse_param()  # common params
            └── self.parse_param()  # subclass-specific params

    PTF -> PfcXoffProbing.runTest() [inherited from ProbingBase]
            ├── get_probe_config()   # subclass provides config
            ├── setup_traffic()      # abstract - subclass implements
            ├── init buffer_ctrl     # common
            ├── hold_buffer          # common
            └── probe()              # abstract - subclass implements
"""

import time
import os
import sys
from typing import List, NamedTuple

# Add legacy py3 directory to Python path for sai_base_test and switch imports
current_dir = os.path.dirname(os.path.abspath(__file__))
py3_dir = os.path.abspath(os.path.join(current_dir, "../py3"))
if py3_dir not in sys.path:
    sys.path.insert(0, py3_dir)

import sai_base_test  # noqa: E402
from switch import switch_init  # noqa: E402

# Import helper functions from sai_qos_tests
from sai_qos_tests import get_rx_port, log_message  # noqa: E402

# Import for runTest template
from ptf.testutils import send_packet  # noqa: E402
from buffer_occupancy_controller import BufferOccupancyController  # noqa: E402

# Factory imports (for create_executor)
from executor_registry import ExecutorRegistry  # noqa: E402


class ProbeConfig(NamedTuple):
    """
    Standardized configuration for probe test cases.

    Subclasses must implement get_probe_config() to return this.
    This ensures consistent parameter naming across all probes.
    """
    probing_port_ids: List[int]  # Port IDs to probe
    thrift_client: object        # dst_client or src_client
    asic_type: str               # ASIC type string


class ProbingBase(sai_base_test.ThriftInterfaceDataPlane):
    """
    Base class for MMU threshold probing test cases.

    Uses Template Method Pattern:
    - runTest() is the template method defining the workflow
    - Subclasses implement setup_traffic(), probe(), get_probe_config()

    Subclass Requirements:
    - Override setUp(): call super().setUp(), then self.parse_param()
    - Implement parse_param(): subclass-specific params (no super call needed)
    - Implement get_probe_config(): return ProbeConfig with standardized params
    - Implement setup_traffic(): build self.stream_mgr
    - Implement probe(): execute probing logic
    """

    #
    # Probing Configuration (can be overridden by subclasses)
    #
    PRECISION_TARGET_RATIO = 0.05        # 5% precision for binary search
    ENABLE_PRECISE_DETECTION = False     # Disable Phase 4 by default (PfcXoff/IngressDrop don't need it)
    PRECISE_DETECTION_RANGE_LIMIT = 100  # Max range for precise detection
    POINT_PROBING_STEP_SIZE = 1          # Step size for point probing (1, 2, 4, etc.)

    # PROBING_ENV: Determined dynamically in setUp() based on hwsku
    # Values: "physical" (real device), "mock" (unit test)
    PROBING_ENV = None

    #
    # PTF Lifecycle Methods
    #

    def setUp(self):
        """
        Common PTF test setup.

        1. Initialize Thrift interface (via super)
        2. Wait for switch stability
        3. Initialize switch
        4. Parse common parameters
        5. Determine probing environment (default: physical, override via testParams)

        Note: Subclass setUp() should:
            super().setUp()
            self.parse_param()  # subclass-specific
        """
        sai_base_test.ThriftInterfaceDataPlane.setUp(self)
        time.sleep(5)
        switch_init(self.clients)

        # Parse common parameters (explicitly call base class method to avoid polymorphism)
        ProbingBase.parse_param(self)

        # Determine probing environment from hwsku (can be overridden via testParams)
        self.EXECUTOR_ENV = self._determine_executor_env()

        # Import observer for logging (lazy import to avoid circular dependency)
        from probing_observer import ProbingObserver

        # Override POINT_PROBING_STEP_SIZE from environment variable if set
        ProbingObserver.trace(
            f"[{self.__class__.__name__}] POINT_PROBING_STEP_SIZE before env check: "
            f"{self.POINT_PROBING_STEP_SIZE}"
        )

        step_size = os.getenv("POINT_PROBING_STEP_SIZE", "")
        if step_size.isdigit() and int(step_size) > 0:
            self.POINT_PROBING_STEP_SIZE = int(step_size)
            ProbingObserver.trace(
                f"[{self.__class__.__name__}] Applied env "
                f"POINT_PROBING_STEP_SIZE={self.POINT_PROBING_STEP_SIZE}"
            )
        else:
            ProbingObserver.trace(
                f"[{self.__class__.__name__}] Using class default "
                f"POINT_PROBING_STEP_SIZE={self.POINT_PROBING_STEP_SIZE}"
            )

        # Read INGRESS_DROP_USE_PG_COUNTER from environment variable
        # Default: False (Port counter - Broadcom compatible)
        # Override: True (PG counter - Mellanox/Cisco-8000)
        env_value = os.getenv('INGRESS_DROP_USE_PG_COUNTER', '').lower()
        if env_value in ('true', '1', 'yes'):
            self.use_pg_drop_counter = True
        elif env_value in ('false', '0', 'no'):
            self.use_pg_drop_counter = False
        else:
            # Environment variable not set or has invalid value, use default
            self.use_pg_drop_counter = False

        ProbingObserver.trace(
            f"[{self.__class__.__name__}] use_pg_drop_counter={self.use_pg_drop_counter} "
            f"(env='{env_value}')"
        )

    def tearDown(self):
        """Common PTF test teardown."""
        sai_base_test.ThriftInterfaceDataPlane.tearDown(self)

    #
    # Template Method - runTest
    #

    def runTest(self):
        """
        Template method defining the probing workflow.

        Steps:
        1. Get standardized config from subclass
        2. Enable TX on all probing ports
        3. Setup traffic streams (subclass)
        4. Initialize BufferOccupancyController
        5. Execute probing logic (subclass)

        Note: Buffer hold/drain is managed by executor.prepare() in each algorithm phase,
              not by this base class.

        Subclasses should NOT override this method.
        Instead, implement get_probe_config(), setup_traffic(), probe().
        """
        # Step 1: Get config from subclass (ensures standardized param names)
        config = self.get_probe_config()

        # Step 2: Enable TX on all probing ports
        self.sai_thrift_port_tx_enable(
            config.thrift_client, config.asic_type,
            config.probing_port_ids, last_port=False
        )

        # Step 3: Setup traffic streams (abstract method)
        self.setup_traffic()

        # Step 4: Initialize BufferOccupancyController
        self.buffer_ctrl = BufferOccupancyController(
            hold_buf_fn=self.sai_thrift_port_tx_disable,
            drain_buf_fn=self.sai_thrift_port_tx_enable,
            stream_mgr=self.stream_mgr,
            send_packet_fn=send_packet,
            ptftest_ref=self,
            thrift_client=config.thrift_client,
            asic_type=config.asic_type
        )

        # Step 5: Execute probing logic (abstract method)
        # Note: Buffer hold/drain is managed by executor.prepare() in each algorithm phase
        # Step 6: Assert result against expected value (if provided)
        self.assert_probing_result(self.probe(), self.get_expected_threshold())

    #
    # Abstract Methods - Must be implemented by subclasses
    #

    def get_probe_config(self) -> ProbeConfig:
        """
        Abstract method: Return standardized probe configuration.

        Must return ProbeConfig with:
        - probing_port_ids: List of port IDs to probe
        - thrift_client: self.dst_client or self.src_client
        - asic_type: self.asic_type

        Raises:
            NotImplementedError: If subclass does not implement
        """
        raise NotImplementedError("Subclass must implement get_probe_config()")

    def setup_traffic(self):
        """
        Abstract method: Setup traffic streams.

        Must set self.stream_mgr with configured flows.

        Traffic Patterns:
        - PfcXoffProbe/IngressDropProbe: 1 src -> N dst
        - HdrmPoolProbe: N src -> 1 dst

        Raises:
            NotImplementedError: If subclass does not implement
        """
        raise NotImplementedError("Subclass must implement setup_traffic()")

    def probe(self):
        """
        Abstract method: Execute probing logic.

        Should contain the main probing algorithm execution.

        Raises:
            NotImplementedError: If subclass does not implement
        """
        raise NotImplementedError("Subclass must implement probe()")

    def get_expected_threshold(self):
        """
        Get expected threshold value for assertion.

        Subclasses must implement to provide expected value and threshold name.
        Return None to skip assertion.

        Returns:
            Optional[Tuple[int, str]]: (expected_value, threshold_name), or None to skip assertion

        Raises:
            NotImplementedError: If subclass does not implement

        Example:
            # PfcXoffProbing
            def get_expected_threshold(self):
                value = getattr(self, 'pkts_num_trig_pfc', None)
                return (value, "PFC XOFF threshold") if value is not None else None

            # HeadroomPoolProbing
            def get_expected_threshold(self):
                if hasattr(self, 'pkts_num_hdrm_full') and hasattr(self, 'pgs_num'):
                    value = self.pkts_num_hdrm_full * (self.pgs_num - 1) + self.pkts_num_hdrm_partial
                    return (value, "Headroom Pool Size")
                return None
        """
        raise NotImplementedError("Subclass must implement get_expected_threshold()")

    #
    # Common Helper Methods
    #

    def parse_param(self):
        """
        Parse common test parameters from self.test_params.

        - Convert string digits to integers
        - Set asic_type from sonic_asic_type
        - Initialize counter_margin

        Note: This is called by ProbingBase.setUp().
              Subclass parse_param() should NOT call super().parse_param()
              because it's already done in setUp().
        """
        for key, value in self.test_params.items():
            if isinstance(value, str) and value.isdigit():
                setattr(self, key, int(value))
            else:
                setattr(self, key, value)

        self.asic_type = self.sonic_asic_type
        self.counter_margin = 0

    def get_rx_port(self, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, dst_port_id, src_vlan):
        """
        Resolve actual destination port (handles LAG scenarios).

        Wrapper around module-level get_rx_port function.
        Used as rx_port_resolver in StreamManager.
        """
        log_message(f"dst_port_id:{dst_port_id}, src_port_id:{src_port_id}", to_stderr=False)
        dst_port_id = get_rx_port(
            self, 0, src_port_id, pkt_dst_mac, dst_port_ip, src_port_ip, src_vlan
        )
        log_message(f"actual dst_port_id: {dst_port_id}", to_stderr=False)
        return dst_port_id

    def get_pool_size(self):
        """
        Get ingress lossless pool size in cells.

        Checks environment variable 'ipoolsz' first,
        falls back to self.ingress_lossless_pool_size / cell_size.
        """
        ipoolsz = os.getenv("ipoolsz", "")
        if ipoolsz:
            return int(ipoolsz)
        return self.ingress_lossless_pool_size // self.cell_size

    def _determine_executor_env(self):
        """
        Determine executor environment based on hwsku and testParams.

        Priority:
        1. Explicit 'executor_env' in testParams (highest priority)
        2. Default -> 'physical'

        Returns:
            str: 'physical' or 'sim'
        """
        # 1. Check explicit testParams override
        if hasattr(self, 'test_params') and 'executor_env' in self.test_params:
            return self.test_params['executor_env']

        # 2. Default to physical
        return 'physical'

    def assert_probing_result(self, result, expected_info):
        """
        Assert probing result against expected value.

        Validation criteria:
        - If Point: |point - expected_value| <= expected_value * PRECISION_TARGET_RATIO
        - If Range: lower <= expected <= upper AND (upper - lower) <= expected * PRECISION_TARGET_RATIO

        Args:
            result: ThresholdResult from probing
            expected_info: Tuple[int, str] as (expected_value, threshold_name), or None to skip

        Returns:
            bool: True if validation passes or skipped
        """
        # Skip assertion if no expected value provided
        if expected_info is None:
            return True

        # Handle failed probing result (e.g., pool not exhausted)
        if result.lower_bound is None or result.upper_bound is None:
            threshold_name = expected_info[1] if isinstance(expected_info, tuple) else "Threshold"
            assert False, (
                f"{threshold_name} probing failed: "
                f"result contains None values (lower={result.lower_bound}, upper={result.upper_bound}). "
                f"This usually indicates incomplete probing (e.g., pool not exhausted)."
            )

        expected_value, threshold_name = expected_info

        # Perform validation based on probing type
        if result.is_point:
            # Point validation: use PRECISE_DETECTION_RANGE_LIMIT as absolute threshold
            expected_delta = self.PRECISE_DETECTION_RANGE_LIMIT
            actual_delta = abs(result.lower_bound - expected_value)

            assert actual_delta < expected_delta, (
                f"{threshold_name} validation failed: "
                f"delta({result.lower_bound}, {expected_value}) = {actual_delta} >= "
                f"{expected_delta} (POINT_PROBING_LIMIT)"
            )
        else:
            # Range validation: containment check + range size check
            # Check 1: Range contains expected value
            assert result.lower_bound <= expected_value <= result.upper_bound, (
                f"{threshold_name} validation failed: "
                f"expected {expected_value} not in range [{result.lower_bound}, {result.upper_bound}]"
            )

            # Check 2: Range size meets precision requirement
            actual_range = result.upper_bound - result.lower_bound
            expected_range = round(expected_value * self.PRECISION_TARGET_RATIO)

            assert actual_range <= expected_range, (
                f"{threshold_name} validation failed: "
                f"range size {actual_range} > {expected_range} "
                f"({self.PRECISION_TARGET_RATIO * 100}% of {expected_value})"
            )

        # Report validation result using Observer (unified for both point and range)
        from probing_observer import ProbingObserver
        ProbingObserver.report_validation_result(
            probe_target=threshold_name,
            result=result,
            expected_value=expected_value,
            precision_ratio=self.PRECISION_TARGET_RATIO if not result.is_point else None,
            precision_range=self.PRECISE_DETECTION_RANGE_LIMIT if result.is_point else None,
            unit="pkt"
        )

        return True

    #
    # Factory Methods (for mock/UT: use ExecutorRegistry + lazy import)
    #

    def create_executor(self, probe_type, observer, name, **kwargs):
        """
        Create probing executor based on EXECUTOR_ENV.

        Uses ExecutorRegistry for environment-specific implementations:
        - physical: Real executor with thrift calls
        - sim: Sim executor for unit tests

        Args:
            probe_type: Type of probe ('pfc_xoff', 'ingress_drop')
            observer: ProbingObserver instance
            name: Executor name for identification
            **kwargs: Additional parameters including:
                - scenario: Sim scenario name (for EXECUTOR_ENV='sim')
                  None - normal sim
                  'noisy' - hardware noise
                  'wrong_config' - wrong threshold
                  'intermittent' - intermittent failure
                - Other executor-specific params (noise_level, offset, etc.)

        Returns:
            Executor instance appropriate for the environment

        Example:
            # Physical
            exec = self.create_executor('ingress_drop', observer, 'pg3')

            # Sim - normal
            exec = self.create_executor('ingress_drop', observer, 'pg3')

            # Sim - noisy
            exec = self.create_executor('ingress_drop', observer, 'pg3',
                                       scenario='noisy', noise_level=10)
        """
        # Extract scenario from kwargs (if present)
        scenario = kwargs.pop('scenario', None)

        return ExecutorRegistry.create(
            probe_type=probe_type,
            executor_env=self.EXECUTOR_ENV,
            scenario=scenario,
            ptftest=self,
            observer=observer,
            verbose=True,
            name=name,
            **kwargs
        )
