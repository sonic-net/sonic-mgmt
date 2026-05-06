#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EgressDropProbing - Egress Drop Threshold Probing Test

Traffic Pattern: 1 src -> 1 dst
- Single source port sends to single destination port
- Detects the Egress Drop threshold by observing egress drop counters on dst port

Key Differences from IngressDropProbing:
- Detection on dst port (egress side) vs src port (ingress side)
- Uses EGRESS_DROP and EGRESS_PORT_BUFFER_DROP counters
- Pool size: egress_lossy_pool instead of ingress_lossless_pool
- Traffic pattern: 1:1 (matching legacy LossyQueueTest)
- Expected threshold: pkts_num_trig_egr_drp (from lossy queue config)

Design:
- setUp(): PTF initialization + parse_param
- setup_traffic(): Build stream_mgr (1 src -> 1 dst)
- probe(): Main entry - calls _create_algorithms() + _run_probing()

Reference: Legacy LossyQueueTest in sai_qos_tests.py

Usage:
    Called from test_qos_probe.py via PTF with test_subdir='probe':
    self.runPtfTest(ptfhost, testCase="egress_drop_probing.EgressDropProbing",
                    testParams=testParams, test_subdir='probe')
"""

import os
import sys

# Add probe directory and py3 directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
probe_dir = current_dir
py3_dir = os.path.abspath(os.path.join(current_dir, "../py3"))

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

# Observer imports
from probing_observer import ProbingObserver  # noqa: E402
from observer_config import ObserverConfig  # noqa: E402


class EgressDropProbing(ProbingBase):
    """
    Egress Drop Threshold Probing Test Case

    Traffic Pattern: 1 src -> 1 dst
    Probe Target: Detect Egress Drop threshold by observing egress drop counters

    Inherits from ProbingBase which provides:
    - setUp(): PTF init + common parse_param
    - runTest(): Template method (calls setup_traffic, probe)
    - tearDown(): PTF cleanup
    """

    PROBE_TARGET = "egress_drop"

    def setUp(self):
        """EgressDropProbe setup."""
        super().setUp()
        # No subclass-specific parse_param needed: ProbingBase.parse_param() is
        # called from super().setUp() and auto-setattrs every test_params field
        # onto self. EgressDrop's only relevant attr is `self.queue`, which is
        # populated directly by test_qos_probe.py passing `queue=...` in
        # testParams (no internal pg→queue alias).

        # Override from POINT_PROBING_LIMIT environment variable
        point_limit = os.getenv("POINT_PROBING_LIMIT", "")
        if point_limit.isdigit() and int(point_limit) > 0:
            self.ENABLE_PRECISE_DETECTION = True
            self.PRECISE_DETECTION_RANGE_LIMIT = int(point_limit)
            log_message(f"[ENV] Point probing enabled with limit={self.PRECISE_DETECTION_RANGE_LIMIT}", to_stderr=True)

    def get_probe_config(self):
        """Return standardized probe configuration.

        Uses dst_client for both BufferOccupancyController and executor counter reads.
        """
        return ProbeConfig(
            probing_port_ids=self.probing_port_ids,
            thrift_client=self.dst_client,
            asic_type=self.asic_type
        )

    def get_expected_threshold(self):
        """Get expected Egress Drop threshold from test parameters."""
        value = getattr(self, 'pkts_num_trig_egr_drp', None)
        return (value, "Egress Drop threshold") if value is not None else None

    def get_pool_size(self):
        """
        Get egress lossy pool size in cells.

        Override base class which uses ingress_lossless_pool_size. Egress drop probing
        searches within the egress lossy pool space; the ingress pool has a different
        capacity and using it as a fallback would cause the binary search to operate
        over the wrong range and produce a meaningless threshold.

        Resolution order:
          1. ``epoolsz`` env override (debug)
          2. ``egress_lossy_pool_size`` from test params
        Fail loudly if neither is available — better diagnostics than silent fallback.
        """
        epoolsz = os.getenv("epoolsz", "")
        if epoolsz:
            return int(epoolsz)
        egress_lossy_pool_size = getattr(self, 'egress_lossy_pool_size', 0)
        if not egress_lossy_pool_size:
            raise RuntimeError(
                "egress_lossy_pool_size is not configured for this platform; "
                "EgressDropProbing cannot determine the buffer search space. "
                "Add `egress_lossy_pool` to BUFFER_POOL in qos.yml, or set the "
                "`epoolsz` env var for debug runs."
            )
        if self.cell_size <= 0:
            raise RuntimeError(
                f"cell_size must be > 0 for EgressDropProbing; got {self.cell_size}"
            )
        return egress_lossy_pool_size // self.cell_size

    #
    # Abstract Method Implementation: setup_traffic
    #

    def setup_traffic(self):
        """
        Setup traffic streams for 1 src -> 1 dst pattern.

        Uses probing_port_ids:
        - First port is src
        - Second port is dst
        """
        if not self.probing_port_ids or len(self.probing_port_ids) < 2:
            log_message("ERROR: Need at least 2 probing ports (src + dst)", to_stderr=True)
            return

        # Use first available dut/asic index from test_port_ips
        dut_idx = next(iter(self.test_port_ips))
        asic_idx = next(iter(self.test_port_ips[dut_idx]))
        port_ips = self.test_port_ips[dut_idx][asic_idx]

        # 1 src -> 1 dst
        srcport = PortInfo(
            self.probing_port_ids[0],
            mac=self.dataplane.get_mac(0, self.probing_port_ids[0]),
            ip=port_ips[self.probing_port_ids[0]]["peer_addr"],
            vlan=port_ips[self.probing_port_ids[0]].get("vlan_id", None)
        )

        dstport = PortInfo(
            self.probing_port_ids[1],
            mac=self.dataplane.get_mac(0, self.probing_port_ids[1]),
            ip=port_ips[self.probing_port_ids[1]]["peer_addr"],
            vlan=port_ips[self.probing_port_ids[1]].get("vlan_id", None)
        )

        # Probing always uses 64-byte packets (1 cell = 1 packet) for consistent unit counting.
        # The algorithm counts in "packets" which equals "cells" when packet_length=64.
        packet_length = 64
        ttl = 64

        # Log platform-specific packet_size for reference (not used in probing)
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

        # stream_manager's `pg=` is its traffic-class selector kwarg (shared
        # across all probes); we pass the egress queue index here.
        self.stream_mgr.add_flow(FlowConfig(
            srcport, dstport,
            dmac=determine_traffic_dmac(dstport.mac, self.router_mac, is_dualtor, def_vlan_mac),
            dscp=self.dscp, ecn=self.ecn, ttl=ttl, length=packet_length
        ), pg=self.queue)

        self.stream_mgr.generate_packets()

    #
    # Abstract Method Implementation: probe
    #

    def probe(self) -> ThresholdResult:
        """
        Execute Egress Drop threshold probing.

        Returns:
            ThresholdResult: Probing result with Egress Drop threshold
        """
        pool_size = self.get_pool_size()
        src_port = self.probing_port_ids[0]
        dst_port = self.stream_mgr.get_port_ids("dst")[0]

        traffic_keys = {'pg': self.queue}

        ProbingObserver.console("=" * 80)
        ProbingObserver.console(f"[{self.PROBE_TARGET}] Starting threshold probing")
        ProbingObserver.console(f"  src_port={src_port}, dst_port={dst_port}")
        ProbingObserver.console(f"  pool_size={pool_size}")
        ProbingObserver.console(f"  precision_target_ratio={self.PRECISION_TARGET_RATIO}")
        ProbingObserver.console(f"  enable_precise_detection={self.ENABLE_PRECISE_DETECTION}")
        ProbingObserver.console(f"  executor_env={self.EXECUTOR_ENV}")
        ProbingObserver.console("=" * 80)

        algorithms = self._create_algorithms()
        lower_bound, upper_bound = self._run_algorithms(
            algorithms, src_port, dst_port, pool_size, **traffic_keys
        )

        result = ThresholdResult.from_bounds(lower_bound, upper_bound)
        ProbingObserver.report_probing_result("Egress Drop", result, unit="pkt")

        return result

    def _create_algorithms(self):
        """Create 4-phase probing algorithms for Egress Drop detection."""
        verbose = True

        upper_bound_observer = ProbingObserver(
            name="upper_bound", iteration_prefix=1, verbose=verbose,
            observer_config=ObserverConfig(
                probe_target=self.PROBE_TARGET,
                algorithm_name="Upper Bound Probing",
                strategy="exponential growth",
                check_column_title=''.join(word.capitalize() for word in self.PROBE_TARGET.split('_')),
                context_template="range=[{window_lower}, {window_upper}]",
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

        # Create executors via base class factory
        upper_bound_executor = self.create_executor(self.PROBE_TARGET, upper_bound_observer, "upper_bound")
        lower_bound_executor = self.create_executor(self.PROBE_TARGET, lower_bound_observer, "lower_bound")
        threshold_range_executor = self.create_executor(self.PROBE_TARGET, threshold_range_observer, "threshold_range")

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

    def _run_algorithms(self, algorithms, src_port, dst_port, pool_size, **traffic_keys):
        """Execute 4-phase probing algorithm sequence."""
        # Phase 1: Upper bound discovery
        upper_bound, _ = algorithms["upper_bound"].run(src_port, dst_port, pool_size, **traffic_keys)
        if upper_bound is None:
            ProbingObserver.console("[ERROR] Upper bound detection failed")
            return (None, None)

        # Phase 2: Lower bound detection
        lower_bound, _ = algorithms["lower_bound"].run(src_port, dst_port, upper_bound, **traffic_keys)
        if lower_bound is None:
            ProbingObserver.console("[ERROR] Lower bound detection failed")
            return (None, None)

        # Phase 3: Threshold range precision refinement
        final_lower, final_upper, _ = algorithms["threshold_range"].run(
            src_port, dst_port, lower_bound, upper_bound, **traffic_keys
        )
        if final_lower is None or final_upper is None:
            ProbingObserver.console("[ERROR] Threshold range detection failed")
            return (lower_bound, upper_bound)

        # Phase 4: Optional precise threshold point detection
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
