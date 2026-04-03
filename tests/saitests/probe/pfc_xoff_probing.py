#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PfcXoffProbing - PFC Xoff Threshold Probing Test

Traffic Pattern: 1 src -> N dst
- Single source port sends to multiple destination ports
- Detects the PFC Xoff threshold by observing PFC frame generation

Design:
- setUp(): PTF initialization + parse_param
- setup_traffic(): Build stream_mgr (1 src -> N dst)
- probe(): Main entry - calls _create_algorithms() + _run_probing()

Extensibility (for mock/UT):
- EXECUTOR_ENV auto-detected (default: physical)
- Can override via testParams['executor_env'] = 'sim'
- ExecutorRegistry + lazy import handles environment-specific executors
- No subclassing needed for UT/mock

Usage:
    Called from test_qos_sai.py via PTF with test_subdir='probe':
    self.runPtfTest(ptfhost, testCase="pfc_xoff_probing.PfcXoffProbing",
                    testParams=testParams, test_subdir='probe')
"""

import os
import sys

# Add probe directory and py3 directory to Python path
# IMPORTANT: py3_dir must be FIRST to ensure correct switch.py is found
current_dir = os.path.dirname(os.path.abspath(__file__))
probe_dir = current_dir
py3_dir = os.path.abspath(os.path.join(current_dir, "../py3"))

# Add py3 first, then probe - do NOT add saitests root (it has old switch.py)
if py3_dir not in sys.path:
    sys.path.insert(0, py3_dir)
if probe_dir not in sys.path:
    sys.path.insert(0, probe_dir)

from probing_base import ProbingBase, ProbeConfig  # noqa: E402
from probing_result import ThresholdResult  # noqa: E402
from sai_qos_tests import log_message, construct_ip_pkt  # noqa: E402
from stream_manager import PortInfo, FlowConfig, StreamManager, determine_traffic_dmac  # noqa: E402

# Algorithm imports
from upper_bound_probing_algorithm import UpperBoundProbingAlgorithm  # noqa: E402
from lower_bound_probing_algorithm import LowerBoundProbingAlgorithm  # noqa: E402
from threshold_range_probing_algorithm import ThresholdRangeProbingAlgorithm  # noqa: E402
from threshold_point_probing_algorithm import ThresholdPointProbingAlgorithm  # noqa: E402

# Executor: lazy import via ExecutorRegistry (no direct import here)
# Note: create_executor is inherited from ProbingBase

# Observer imports
from probing_observer import ProbingObserver  # noqa: E402
from observer_config import ObserverConfig  # noqa: E402


class PfcXoffProbing(ProbingBase):
    """
    PFC Xoff Threshold Probing Test Case

    Traffic Pattern: 1 src -> N dst
    Probe Target: Detect PFC Xoff threshold by observing PFC frame generation

    Inherits from ProbingBase which provides:
    - setUp(): PTF init + common parse_param
    - runTest(): Template method (calls setup_traffic, probe)
    - tearDown(): PTF cleanup
    """

    #
    # Probing Configuration (uses base class defaults)
    #
    PROBE_TARGET = "pfc_xoff"

    #
    # PTF Lifecycle
    #

    def setUp(self):
        """
        PfcXoffProbe setup.

        1. Call super().setUp() for common initialization + parse_param + EXECUTOR_ENV
        2. Parse subclass-specific parameters
        3. Override point probing config from POINT_PROBING_LIMIT env var (for testing)
        """
        super().setUp()
        self.parse_param()

        # Override from POINT_PROBING_LIMIT environment variable (for point probing testing)
        # POINT_PROBING_LIMIT=10  -> enable point probing with limit=10
        # POINT_PROBING_LIMIT=0 or unset or invalid -> disable point probing
        point_limit = os.getenv("POINT_PROBING_LIMIT", "")
        if point_limit.isdigit() and int(point_limit) > 0:
            self.ENABLE_PRECISE_DETECTION = True
            self.PRECISE_DETECTION_RANGE_LIMIT = int(point_limit)
            log_message(f"[ENV] Point probing enabled with limit={self.PRECISE_DETECTION_RANGE_LIMIT}", to_stderr=True)

    def parse_param(self):
        """
        Parse PfcXoffProbe-specific parameters.

        Note: Common parameters already parsed by ProbingBase.setUp()
        """
        # PFC counter index (starts from index 2 in sai_thrift_read_port_counters)
        self.cnt_pg_idx = self.pg + 2

    def get_probe_config(self):
        """Return standardized probe configuration."""
        return ProbeConfig(
            probing_port_ids=self.probing_port_ids,
            thrift_client=self.dst_client,
            asic_type=self.asic_type
        )

    def get_expected_threshold(self):
        """Get expected PFC XOFF threshold from test parameters."""
        value = getattr(self, 'pkts_num_trig_pfc', None)
        return (value, "PFC XOFF threshold") if value is not None else None

    #
    # Abstract Method Implementation: setup_traffic
    #

    def setup_traffic(self):
        """
        Setup traffic streams for 1 src -> N dst pattern.

        Uses probing_port_ids:
        - First port is src
        - Remaining ports are dst
        """
        if not self.probing_port_ids:
            log_message("ERROR: No probing ports available", to_stderr=True)
            return

        dut_idx = 0
        asic_idx = 0
        port_ips = self.test_port_ips[dut_idx][asic_idx]

        # 1 src -> N dst: First is src, rest are dst
        srcport = PortInfo(
            self.probing_port_ids[0],
            mac=self.dataplane.get_mac(0, self.probing_port_ids[0]),
            ip=port_ips[self.probing_port_ids[0]]["peer_addr"],
            vlan=port_ips[self.probing_port_ids[0]].get("vlan_id", None)
        )

        dstports = []
        for dpid in self.probing_port_ids[1:]:
            dstports.append(PortInfo(
                dpid,
                mac=self.dataplane.get_mac(0, dpid),
                ip=port_ips[dpid]["peer_addr"],
                vlan=port_ips[dpid].get("vlan_id", None)
            ))

        # Platform-independent: 64-byte packets = 1 cell
        packet_length = 64
        ttl = 64

        # Log platform info
        original_packet_length = getattr(self, "packet_size", 64)
        original_cell_occupancy = (
            (original_packet_length + self.cell_size - 1) // self.cell_size
            if hasattr(self, "cell_size") else 1
        )
        log_message(
            f"Platform-specific: packet_length={original_packet_length}, "
            f"cell_occupancy={original_cell_occupancy}", to_stderr=True
        )
        log_message(f"Probing uses: packet_length={packet_length}, cell_occupancy=1", to_stderr=True)

        is_dualtor = getattr(self, "is_dualtor", False)
        def_vlan_mac = getattr(self, "def_vlan_mac", None)

        # Initialize stream manager
        self.stream_mgr = StreamManager(
            packet_constructor=construct_ip_pkt,
            rx_port_resolver=self.get_rx_port
        )

        for dstport in dstports:
            self.stream_mgr.add_flow(FlowConfig(
                srcport, dstport,
                dmac=determine_traffic_dmac(dstport.mac, self.router_mac, is_dualtor, def_vlan_mac),
                dscp=self.dscp, ecn=self.ecn, ttl=ttl, length=packet_length
            ), pg=self.pg)  # Add pg as traffic_key for consistency

        self.stream_mgr.generate_packets()

    #
    # Abstract Method Implementation: probe
    #

    def probe(self) -> ThresholdResult:
        """
        Execute PFC Xoff threshold probing.

        Workflow:
        1. create_algorithms(): Create timer, observers, executors, algorithms
        2. run_algorithms(): Execute 4-phase probing (upper->lower->range->point)
        3. Report results

        Returns:
            ThresholdResult: Probing result with PFC XOFF threshold
        """
        # Get pool size and ports
        pool_size = self.get_pool_size()
        src_port = self.probing_port_ids[0]
        dst_port = self.stream_mgr.get_port_ids("dst")[0]

        # Get traffic_keys for this flow (single-PG case: pass pg for consistency)
        traffic_keys = {'pg': self.pg}

        # Log probing start
        ProbingObserver.console("=" * 80)
        ProbingObserver.console(f"[{self.PROBE_TARGET}] Starting threshold probing")
        ProbingObserver.console(f"  src_port={src_port}, dst_port={dst_port}")
        ProbingObserver.console(f"  pool_size={pool_size}")
        ProbingObserver.console(f"  precision_target_ratio={self.PRECISION_TARGET_RATIO}")
        ProbingObserver.console(f"  enable_precise_detection={self.ENABLE_PRECISE_DETECTION}")
        ProbingObserver.console(f"  executor_env={self.EXECUTOR_ENV}")
        ProbingObserver.console("=" * 80)

        # Create and run algorithms
        algorithms = self._create_algorithms()
        lower_bound, upper_bound = self._run_algorithms(
            algorithms, src_port, dst_port, pool_size, **traffic_keys
        )

        # Build result
        result = ThresholdResult.from_bounds(lower_bound, upper_bound)

        # Report results using Observer's unified method
        ProbingObserver.report_probing_result("PFC XOFF", result, unit="pkt")

        return result

    #
    # Algorithm Creation
    #

    def _create_algorithms(self):
        """
        Create 4-phase probing algorithms.

        Creates timer, observers, executors, and algorithms for:
        - Phase 1: Upper bound discovery (exponential growth)
        - Phase 2: Lower bound detection (logarithmic reduction)
        - Phase 3: Threshold range narrowing (binary search)
        - Phase 4: Precise point detection (step-by-step scan)

        Returns:
            dict: Algorithm instances keyed by phase name
                  {"upper_bound", "lower_bound", "threshold_range", "threshold_point"}
        """
        verbose = True

        # Create 4 observers
        upper_bound_observer = ProbingObserver(
            name="upper_bound", iteration_prefix=1, verbose=verbose,
            observer_config=ObserverConfig(
                probe_target=self.PROBE_TARGET,
                algorithm_name="Upper Bound Probing",
                strategy="exponential growth",
                check_column_title=''.join(word.capitalize() for word in self.PROBE_TARGET.split('_')),
                context_template="",
                completion_template="Upper bound = {value}",
                completion_format_type="value",
                table_column_mapping={
                    "lower_bound": None, "upper_bound": "value",
                    "candidate_threshold": None, "range_step": None,
                },
            ),
        )

        lower_bound_observer = ProbingObserver(
            name="lower_bound", iteration_prefix=2, verbose=verbose,
            observer_config=ObserverConfig(
                probe_target=self.PROBE_TARGET,
                algorithm_name="Lower Bound Probing",
                strategy="logarithmic reduction",
                check_column_title=''.join(word.capitalize() for word in self.PROBE_TARGET.split('_')),
                context_template=" [{probe_target} upper bound: {window_upper}]",
                completion_template="Lower bound = {value}",
                completion_format_type="value",
                table_column_mapping={
                    "lower_bound": "value", "upper_bound": "window_upper",
                    "candidate_threshold": None, "range_step": None,
                },
            ),
        )

        threshold_range_observer = ProbingObserver(
            name="threshold_range", iteration_prefix=3, verbose=verbose,
            observer_config=ObserverConfig(
                probe_target=self.PROBE_TARGET,
                algorithm_name="Threshold Range Probing",
                strategy="binary search",
                check_column_title=''.join(word.capitalize() for word in self.PROBE_TARGET.split('_')),
                context_template=" [{probe_target} window: {window_lower}-{window_upper}]",
                completion_template="Final range = [{lower}, {upper}]",
                completion_format_type="range",
                table_column_mapping={
                    "lower_bound": "window_lower", "upper_bound": "window_upper",
                    "candidate_threshold": "value", "range_step": "range_size",
                },
            ),
        )

        # Create 3 executors (via base class factory method)
        upper_bound_executor = self.create_executor(self.PROBE_TARGET, upper_bound_observer, "upper_bound")
        lower_bound_executor = self.create_executor(self.PROBE_TARGET, lower_bound_observer, "lower_bound")
        threshold_range_executor = self.create_executor(self.PROBE_TARGET, threshold_range_observer, "threshold_range")

        # Create 3 core algorithms
        algorithms = {
            "upper_bound": UpperBoundProbingAlgorithm(
                executor=upper_bound_executor,
                observer=upper_bound_observer,
                verification_attempts=1
            ),
            "lower_bound": LowerBoundProbingAlgorithm(
                executor=lower_bound_executor,
                observer=lower_bound_observer,
                verification_attempts=1
            ),
            "threshold_range": ThresholdRangeProbingAlgorithm(
                executor=threshold_range_executor,
                observer=threshold_range_observer,
                precision_target_ratio=self.PRECISION_TARGET_RATIO,
                verification_attempts=2,
                enable_precise_detection=self.ENABLE_PRECISE_DETECTION,
                precise_detection_range_limit=self.PRECISE_DETECTION_RANGE_LIMIT
            ),
        }

        # Only create point algorithm if precise detection is enabled
        if self.ENABLE_PRECISE_DETECTION:
            threshold_point_observer = ProbingObserver(
                name="threshold_point", iteration_prefix=4, verbose=verbose,
                observer_config=ObserverConfig(
                    probe_target=self.PROBE_TARGET,
                    algorithm_name="Threshold Point Probing",
                    strategy="sequential scan",
                    check_column_title=''.join(word.capitalize() for word in self.PROBE_TARGET.split('_')),
                    context_template="",
                    completion_template=None,
                    completion_format_type="value",
                    table_column_mapping={
                        "lower_bound": "value", "upper_bound": "window_upper",
                        "candidate_threshold": "value", "range_step": 1,
                    },
                ),
            )
            threshold_point_executor = self.create_executor(
                self.PROBE_TARGET, threshold_point_observer, "threshold_point"
            )
            algorithms["threshold_point"] = ThresholdPointProbingAlgorithm(
                executor=threshold_point_executor,
                observer=threshold_point_observer,
                verification_attempts=1,
                step_size=self.POINT_PROBING_STEP_SIZE
            )

        return algorithms

    #
    # Algorithm Execution
    #

    def _run_algorithms(self, algorithms, src_port, dst_port, pool_size, **traffic_keys):
        """
        Execute 4-phase probing algorithm sequence.

        Phase 1: Upper bound discovery (exponential growth)
        Phase 2: Lower bound detection (logarithmic reduction)
        Phase 3: Threshold range narrowing (binary search)
        Phase 4: Precise point detection (optional, step-by-step scan)

        Args:
            algorithms: Dict of algorithm instances from _create_algorithms()
            src_port: Source port ID
            dst_port: Destination port ID
            pool_size: Buffer pool size (upper limit for search)
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Returns:
            tuple: (lower_bound, upper_bound) or (None, None) on failure
        """
        # Phase 1: Upper bound discovery (exponential growth)
        upper_bound, _ = algorithms["upper_bound"].run(src_port, dst_port, pool_size, **traffic_keys)
        if upper_bound is None:
            ProbingObserver.console("[ERROR] Upper bound detection failed")
            return (None, None)

        # Phase 2: Lower bound detection (logarithmic reduction)
        lower_bound, _ = algorithms["lower_bound"].run(src_port, dst_port, upper_bound, **traffic_keys)
        if lower_bound is None:
            ProbingObserver.console("[ERROR] Lower bound detection failed")
            return (None, None)

        # Phase 3: Threshold range precision refinement (binary search)
        final_lower, final_upper, _ = algorithms["threshold_range"].run(
            src_port, dst_port, lower_bound, upper_bound, **traffic_keys
        )
        if final_lower is None or final_upper is None:
            ProbingObserver.console("[ERROR] Threshold range detection failed")
            return (lower_bound, upper_bound)

        # Phase 4: Optional precise threshold point detection (step-by-step)
        point_algorithm = algorithms.get("threshold_point")
        if self.ENABLE_PRECISE_DETECTION and point_algorithm is not None:
            range_size = final_upper - final_lower
            if range_size <= self.PRECISE_DETECTION_RANGE_LIMIT:
                point_lower, point_upper, _ = point_algorithm.run(
                    src_port=src_port,
                    dst_port=dst_port,
                    lower_bound=final_lower,
                    upper_bound=final_upper,
                    **traffic_keys
                )
                if point_lower is not None and point_upper is not None:
                    final_lower, final_upper = point_lower, point_upper

        return (final_lower, final_upper)
