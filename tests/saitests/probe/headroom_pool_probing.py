#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HeadroomPoolProbing - Headroom Pool Size Probing Test

Traffic Pattern: N src -> 1 dst
- Multiple source ports send to a single destination port
- Each src port has its own PG (Priority Group)
- PG is an ingress concept, bound to src ports

This probe detects:
- Headroom Pool Size threshold (aggregate of per-PG headrooms)

Design:
- setUp(): PTF initialization + parse_param
- setup_traffic(): Build stream_mgr (N src -> 1 dst)
- probe(): Main entry - calls _create_probing_components() + multi-PG iteration

Multi-PG Probing:
- For each PG: probe PFC XOFF (Phase 1) + Ingress Drop (Phase 2)
- Calculate headroom = Ingress Drop - PFC XOFF
- Detect pool exhaustion when headroom <= 1

Extensibility (for mock/UT):
- EXECUTOR_ENV auto-detected (default: physical)
- Can override via testParams['executor_env'] = 'sim'
- ExecutorRegistry + lazy import handles environment-specific executors
- No subclassing needed for UT/mock

Usage:
    Called from test_qos_sai.py via PTF with test_subdir='probe':
    self.runPtfTest(ptfhost, testCase="headroom_pool_probing.HeadroomPoolProbing",
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


class HeadroomPoolProbing(ProbingBase):
    """
    Headroom Pool Size Probing Test Case

    Traffic Pattern: N src -> 1 dst
    - Multiple source ports, each with its own PG
    - Single destination port receives all traffic

    Multi-PG Probing Logic (merged from HeadroomPoolSizeProbingOrchestrator):
    - For each PG: probe PFC XOFF threshold, then Ingress Drop threshold
    - Headroom = Ingress Drop - PFC XOFF
    - Persist buffer state after each PG
    - Detect pool exhaustion when headroom <= 1

    Inherits from ProbingBase which provides:
    - setUp(): PTF init + common parse_param
    - runTest(): Template method (calls setup_traffic, probe)
    - tearDown(): PTF cleanup
    """

    #
    # Probing Configuration (overrides base class)
    #
    PROBE_TARGET = "headroom_pool"
    PRECISION_TARGET_RATIO = 0.005  # 0.5% (tighter than default 5%)
    ENABLE_PRECISE_DETECTION = True  # HdrmPool needs precise points to calculate headroom
    POINT_PROBING_STEP_SIZE = 2  # Optimal balance: excellent accuracy (0.39% error) with good time efficiency
    # Analysis: Step 2 provides best accuracy-time trade-off - 61.8 min, +37 cells error for 21 PGs
    # Physical test validated: 37% better accuracy than step=4, only 12% slower

    #
    # PTF Lifecycle
    #

    def setUp(self):
        """
        HdrmPoolProbe setup.

        1. Call super().setUp() for common initialization + parse_param + EXECUTOR_ENV
        2. Parse subclass-specific parameters
        """
        super().setUp()
        self.parse_param()

    def parse_param(self):
        """
        Parse HdrmPoolProbe-specific parameters.

        Note: Common parameters already parsed by ProbingBase.setUp()
        """
        # Ensure pgs and dscps are lists
        if not isinstance(self.pgs, list):
            self.pgs = [self.pgs]
        if not isinstance(self.dscps, list):
            self.dscps = [self.dscps]

        # Validate for N src -> 1 dst pattern
        num_src_ports = len(self.probing_port_ids) - 1
        if len(self.pgs) > num_src_ports:
            log_message(f"Warning: Too many PGs ({len(self.pgs)}) for src ports ({num_src_ports})", to_stderr=True)
        if len(self.dscps) > num_src_ports:
            log_message(f"Warning: Too many DSCPs ({len(self.dscps)}) for src ports ({num_src_ports})", to_stderr=True)

    def get_probe_config(self):
        """Return standardized probe configuration."""
        return ProbeConfig(
            probing_port_ids=self.probing_port_ids,
            thrift_client=self.dst_client,
            asic_type=self.asic_type
        )

    def get_expected_threshold(self):
        """
        Get expected headroom pool size from test parameters.

        Formula: pkts_num_hdrm_full * (pgs_num - 1) + pkts_num_hdrm_partial
        """
        if hasattr(self, 'pkts_num_hdrm_full') and hasattr(self, 'pgs_num') and hasattr(self, 'pkts_num_hdrm_partial'):
            value = self.pkts_num_hdrm_full * (self.pgs_num - 1) + self.pkts_num_hdrm_partial
            return (value, "Headroom Pool Size")
        return None

    #
    # Abstract Method Implementation: setup_traffic
    #

    def setup_traffic(self):
        """
        Setup traffic streams for N src -> 1 dst pattern.

        Uses probing_port_ids:
        - Last port is dst
        - All other ports are src
        - Each src port gets its own PG from self.pgs
        """
        if not self.probing_port_ids:
            log_message("ERROR: No probing ports available", to_stderr=True)
            return

        dut_idx = 0
        asic_idx = 0
        port_ips = self.test_port_ips[dut_idx][asic_idx]

        # N src -> 1 dst: Last port is dst, all others are src
        src_port_ids = self.probing_port_ids[:-1]
        dst_port_id = self.probing_port_ids[-1]

        # Create single dst port
        dstport = PortInfo(
            dst_port_id,
            mac=self.dataplane.get_mac(0, dst_port_id),
            ip=port_ips[dst_port_id]["peer_addr"],
            vlan=port_ips[dst_port_id].get("vlan_id", None)
        )

        # Create src ports list
        srcports = []
        for spid in src_port_ids:
            srcport = PortInfo(
                spid,
                mac=self.dataplane.get_mac(0, spid),
                ip=port_ips[spid]["peer_addr"],
                vlan=port_ips[spid].get("vlan_id", None)
            )
            srcports.append(srcport)

        log_message(f"Setup traffic: src_ports={src_port_ids}, dst_port={dst_port_id}", to_stderr=False)

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
        log_message(
            f"Probing uses: packet_length={packet_length}, cell_occupancy=1",
            to_stderr=True
        )

        is_dualtor = getattr(self, "is_dualtor", False)
        def_vlan_mac = getattr(self, "def_vlan_mac", None)

        # Initialize stream manager
        self.stream_mgr = StreamManager(
            packet_constructor=construct_ip_pkt,
            rx_port_resolver=self.get_rx_port
        )

        # Create flows: Each src port uses all available PGs
        # Example: 13 src ports × 2 PGs = 26 flows
        flow_count = 0

        for src_idx, srcport in enumerate(srcports):
            # Each src port creates flows for all PGs
            for pg_idx, pg in enumerate(self.pgs):
                # Use same index to get corresponding DSCP
                dscp = self.dscps[pg_idx]

                self.stream_mgr.add_flow(
                    FlowConfig(
                        srcport, dstport,
                        dmac=determine_traffic_dmac(
                            dstport.mac, self.router_mac, is_dualtor, def_vlan_mac
                        ),
                        dscp=dscp, ecn=self.ecn, ttl=ttl, length=packet_length
                    ),
                    pg=pg  # traffic_keys to identify flow
                )
                log_message(
                    f"Added flow #{flow_count+1}: src={srcport.port_id} "
                    f"(port {src_idx+1}/{len(srcports)}, PG {pg_idx+1}/{len(self.pgs)}) "
                    f"-> dst={dstport.port_id}, dscp={dscp}, pg={pg}", to_stderr=False
                )
                flow_count += 1

        self.stream_mgr.generate_packets()
        log_message(
            f"Traffic setup completed: {len(self.stream_mgr.flows)} flows "
            f"({len(srcports)} src ports × {len(self.pgs)} PGs -> 1 dst)",
            to_stderr=True
        )

    #
    # Abstract Method Implementation: probe
    #

    def probe(self) -> ThresholdResult:
        """
        Execute Headroom Pool Size probing.

        Main loop iterates through each PG flow from stream_mgr:
        - Probe PFC XOFF threshold
        - Probe Ingress Drop threshold
        - Calculate headroom = Ingress Drop - PFC XOFF
        - Detect pool exhaustion when headroom <= 1

        Returns:
            ThresholdResult: Pool size result (point format: lower == upper)
        """
        # Get pool size
        pool_size = self.get_pool_size()

        # Log probing start
        ProbingObserver.console("=" * 80)
        ProbingObserver.console(f"[{self.PROBE_TARGET}] Starting Headroom Pool Size probing")
        ProbingObserver.console("  Traffic pattern: N src -> 1 dst")
        ProbingObserver.console(f"  pool_size={pool_size}")
        ProbingObserver.console(f"  precision_target_ratio={self.PRECISION_TARGET_RATIO}")
        ProbingObserver.console(f"  enable_precise_detection={self.ENABLE_PRECISE_DETECTION}")
        ProbingObserver.console(f"  executor_env={self.EXECUTOR_ENV}")
        ProbingObserver.console("=" * 80)

        # Results tracking
        pg_results = []
        total_headroom = 0
        total_time = 0.0  # Track cumulative time across all PGs and phases
        num_flows = len(self.stream_mgr.flows)
        ProbingObserver.console(f"Flow configs: {num_flows} flows")

        # =====================================================================
        # Main loop: iterate through each PG flow from stream_mgr
        # =====================================================================
        for i, (flow_key, flow_config) in enumerate(self.stream_mgr.flows.items()):
            # Check PG limit (pgnumlmt env var)
            pg_limit_str = os.environ.get('pgnumlmt', '')
            if pg_limit_str.isdigit() and i + 1 > int(pg_limit_str):
                ProbingObserver.trace(f"[DEBUG pgnumlmt] Reached PG limit ({pg_limit_str}), terminating")
                break

            # Extract flow info from stream_mgr
            src_port_id, dst_port_id, traffic_keys_frozen = flow_key
            traffic_keys = dict(traffic_keys_frozen)
            pg = traffic_keys.get('pg')
            dscp = flow_config.dscp

            ProbingObserver.console(f"\n{'='*60}")
            ProbingObserver.console(f"PG #{i+1}/{num_flows}: src={src_port_id}, dst={dst_port_id}, pg={pg}")
            ProbingObserver.console(f"{'='*60}")

            # Set ptftest context for this flow
            self.cnt_pg_idx = pg + 2

            # =================================================================
            # PFC XOFF Probing
            # =================================================================
            ProbingObserver.console("\n[PFC XOFF] Probing threshold...")

            # Create PFC XOFF algorithms with independent executors
            pfc_configs = self._get_observer_configs('pfc_xoff', i)
            pfc_upper_obs = ProbingObserver(
                name=f"pg{i}_pfc_upper", iteration_prefix=f"{i+1}.1",
                verbose=True, observer_config=pfc_configs['upper']
            )
            pfc_lower_obs = ProbingObserver(
                name=f"pg{i}_pfc_lower", iteration_prefix=f"{i+1}.2",
                verbose=True, observer_config=pfc_configs['lower']
            )
            pfc_range_obs = ProbingObserver(
                name=f"pg{i}_pfc_range", iteration_prefix=f"{i+1}.3",
                verbose=True, observer_config=pfc_configs['range']
            )

            pfc_algos = {
                'upper': UpperBoundProbingAlgorithm(
                    executor=self.create_executor('pfc_xoff', pfc_upper_obs, f"pg{i}_pfc_upper"),
                    observer=pfc_upper_obs, verification_attempts=1),
                'lower': LowerBoundProbingAlgorithm(
                    executor=self.create_executor('pfc_xoff', pfc_lower_obs, f"pg{i}_pfc_lower"),
                    observer=pfc_lower_obs, verification_attempts=1),
                'range': ThresholdRangeProbingAlgorithm(
                    executor=self.create_executor('pfc_xoff', pfc_range_obs, f"pg{i}_pfc_range"),
                    observer=pfc_range_obs,
                    precision_target_ratio=self.PRECISION_TARGET_RATIO,
                    verification_attempts=2,
                    enable_precise_detection=self.ENABLE_PRECISE_DETECTION,
                    precise_detection_range_limit=self.PRECISE_DETECTION_RANGE_LIMIT
                ),
            }
            if self.ENABLE_PRECISE_DETECTION:
                pfc_point_obs = ProbingObserver(
                    name=f"pg{i}_pfc_point", iteration_prefix=f"{i+1}.4",
                    verbose=True, observer_config=pfc_configs['point']
                )
                pfc_algos['point'] = ThresholdPointProbingAlgorithm(
                    executor=self.create_executor('pfc_xoff', pfc_point_obs, f"pg{i}_pfc_point"),
                    observer=pfc_point_obs, verification_attempts=1,
                    step_size=self.POINT_PROBING_STEP_SIZE)

            # PFC XOFF: Upper Bound (optimization: use previous PG's threshold)
            pfc_upper_init = (
                pg_results[-1]['pfc_xoff_threshold'] if pg_results else pool_size
            )
            pfc_upper, pfc_upper_time = pfc_algos['upper'].run(
                src_port_id, dst_port_id, pfc_upper_init, **traffic_keys
            )
            total_time += pfc_upper_time
            if pfc_upper is None:
                ProbingObserver.console(f"  Skipping PG #{i+1} due to PFC XOFF upper bound failure")
                continue
            ProbingObserver.console(f"  PFC Upper bound = {pfc_upper}")

            # PFC XOFF: Lower Bound
            pfc_lower, pfc_lower_time = pfc_algos['lower'].run(
                src_port_id, dst_port_id, pfc_upper, **traffic_keys
            )
            total_time += pfc_lower_time
            if pfc_lower is None:
                ProbingObserver.console(f"  Skipping PG #{i+1} due to PFC XOFF lower bound failure")
                continue
            ProbingObserver.console(f"  PFC Lower bound = {pfc_lower}")

            # PFC XOFF: Range Narrowing
            pfc_range_lower, pfc_range_upper, pfc_range_time = pfc_algos['range'].run(
                src_port_id, dst_port_id, pfc_lower, pfc_upper, **traffic_keys
            )
            total_time += pfc_range_time
            if pfc_range_lower is None:
                ProbingObserver.console(f"  Skipping PG #{i+1} due to PFC XOFF range failure")
                continue
            ProbingObserver.console(f"  PFC Range = [{pfc_range_lower}, {pfc_range_upper}]")

            # PFC XOFF: Precise Point (if enabled)
            pfc_xoff_threshold = pfc_range_lower
            if self.ENABLE_PRECISE_DETECTION and 'point' in pfc_algos:
                if (pfc_range_upper - pfc_range_lower) <= self.PRECISE_DETECTION_RANGE_LIMIT:
                    point_lower, point_upper, point_time = pfc_algos['point'].run(
                        src_port=src_port_id, dst_port=dst_port_id,
                        lower_bound=pfc_range_lower, upper_bound=pfc_range_upper,
                        **traffic_keys
                    )
                    total_time += point_time
                    if point_lower is not None:
                        pfc_xoff_threshold = point_lower
                        ProbingObserver.console(f"  PFC Precise point = {pfc_xoff_threshold}")

            # =================================================================
            # Ingress Drop Probing
            # =================================================================
            ProbingObserver.console("\n[Ingress Drop] Probing threshold...")

            # Create Ingress Drop algorithms with independent executors
            drop_configs = self._get_observer_configs('ingress_drop', i)
            drop_upper_obs = ProbingObserver(
                name=f"pg{i}_drop_upper", iteration_prefix=f"{i+1}.5",
                verbose=True, observer_config=drop_configs['upper']
            )
            drop_lower_obs = ProbingObserver(
                name=f"pg{i}_drop_lower", iteration_prefix=f"{i+1}.6",
                verbose=True, observer_config=drop_configs['lower']
            )
            drop_range_obs = ProbingObserver(
                name=f"pg{i}_drop_range", iteration_prefix=f"{i+1}.7",
                verbose=True, observer_config=drop_configs['range']
            )

            drop_algos = {
                'upper': UpperBoundProbingAlgorithm(
                    executor=self.create_executor(
                        'ingress_drop', drop_upper_obs, f"pg{i}_drop_upper",
                        use_pg_drop_counter=self.use_pg_drop_counter
                    ),
                    observer=drop_upper_obs, verification_attempts=1
                ),
                'lower': LowerBoundProbingAlgorithm(
                    executor=self.create_executor(
                        'ingress_drop', drop_lower_obs, f"pg{i}_drop_lower",
                        use_pg_drop_counter=self.use_pg_drop_counter
                    ),
                    observer=drop_lower_obs, verification_attempts=1
                ),
                'range': ThresholdRangeProbingAlgorithm(
                    executor=self.create_executor(
                        'ingress_drop', drop_range_obs, f"pg{i}_drop_range",
                        use_pg_drop_counter=self.use_pg_drop_counter
                    ),
                    observer=drop_range_obs,
                    precision_target_ratio=self.PRECISION_TARGET_RATIO,
                    verification_attempts=2,
                    enable_precise_detection=self.ENABLE_PRECISE_DETECTION,
                    precise_detection_range_limit=self.PRECISE_DETECTION_RANGE_LIMIT
                ),
            }
            if self.ENABLE_PRECISE_DETECTION:
                drop_point_obs = ProbingObserver(
                    name=f"pg{i}_drop_point", iteration_prefix=f"{i+1}.8",
                    verbose=True, observer_config=drop_configs['point']
                )
                drop_algos['point'] = ThresholdPointProbingAlgorithm(
                    executor=self.create_executor(
                        'ingress_drop', drop_point_obs, f"pg{i}_drop_point",
                        use_pg_drop_counter=self.use_pg_drop_counter
                    ),
                    observer=drop_point_obs, verification_attempts=1,
                    step_size=self.POINT_PROBING_STEP_SIZE
                )

            # Ingress Drop: Upper Bound (optimization: use previous PG's threshold)
            drop_upper_init = (
                pg_results[-1]['ingress_drop_threshold'] if pg_results else pool_size
            )
            drop_upper, drop_upper_time = drop_algos['upper'].run(
                src_port_id, dst_port_id, drop_upper_init, **traffic_keys
            )
            total_time += drop_upper_time
            if drop_upper is None:
                ProbingObserver.console(f"  Skipping PG #{i+1} due to Ingress Drop upper bound failure")
                continue
            ProbingObserver.console(f"  Drop Upper bound = {drop_upper}")

            # Ingress Drop: Lower Bound (optimization: start from PFC XOFF - 1)
            drop_lower, drop_lower_time = drop_algos['lower'].run(
                src_port_id, dst_port_id, drop_upper,
                start_value=pfc_xoff_threshold - 1, **traffic_keys
            )
            total_time += drop_lower_time
            if drop_lower is None:
                ProbingObserver.console(f"  Skipping PG #{i+1} due to Ingress Drop lower bound failure")
                continue
            ProbingObserver.console(f"  Drop Lower bound = {drop_lower}")

            # Ingress Drop: Range Narrowing
            drop_range_lower, drop_range_upper, drop_range_time = drop_algos['range'].run(
                src_port_id, dst_port_id, drop_lower, drop_upper, **traffic_keys
            )
            total_time += drop_range_time
            if drop_range_lower is None:
                ProbingObserver.console(f"  Skipping PG #{i+1} due to Ingress Drop range failure")
                continue
            ProbingObserver.console(f"  Drop Range = [{drop_range_lower}, {drop_range_upper}]")

            # Ingress Drop: Precise Point (if enabled)
            ingress_drop_threshold = drop_range_lower
            if self.ENABLE_PRECISE_DETECTION and 'point' in drop_algos:
                if (drop_range_upper - drop_range_lower) <= self.PRECISE_DETECTION_RANGE_LIMIT:
                    point_lower, point_upper, point_time = drop_algos['point'].run(
                        src_port=src_port_id, dst_port=dst_port_id,
                        lower_bound=drop_range_lower, upper_bound=drop_range_upper,
                        **traffic_keys
                    )
                    total_time += point_time
                    if point_lower is not None:
                        ingress_drop_threshold = point_lower
                        ProbingObserver.console(f"  Drop Precise point = {ingress_drop_threshold}")

            # Calculate headroom
            pg_headroom = ingress_drop_threshold - pfc_xoff_threshold
            ProbingObserver.console(f"  Headroom = {ingress_drop_threshold} - {pfc_xoff_threshold} = {pg_headroom}")

            # Persist buffer state with margin for multi-PG Port counter compatibility
            # Default: use step_size as margin (Solution 2 - Port counter)
            # When using PG drop counter (Mellanox/Cisco), margin=0 (no contamination issue)
            margin = self.POINT_PROBING_STEP_SIZE
            if self.use_pg_drop_counter:
                margin = 0
            if margin > 0:
                ProbingObserver.console(
                    f"  Using Port counter mode: persist with margin "
                    f"({ingress_drop_threshold - margin} = {ingress_drop_threshold} - {margin} step_size)"
                )
            self.buffer_ctrl.persist_buffer_occupancy(
                src_port_id=src_port_id, dst_port_id=dst_port_id,
                count=ingress_drop_threshold - margin, pg=pg
            )

            total_headroom += pg_headroom

            # Store PG result
            pg_results.append({
                'pg_index': i,
                'src_port_id': src_port_id,
                'dst_port_id': dst_port_id,
                'pg': pg,
                'dscp': dscp,
                'pfc_xoff_threshold': pfc_xoff_threshold,
                'ingress_drop_threshold': ingress_drop_threshold,
                'headroom': pg_headroom
            })

            ProbingObserver.console(f"\n[Result] PG #{i+1} Headroom = {pg_headroom} cells")
            ProbingObserver.console(f"         Total accumulated = {total_headroom} cells")

            # Early termination: pool exhaustion
            # Empirical data from 12 tests (testbed bjw2-can-t0-7260-2/8, step 1-16):
            #   Step | Testbed | PGs | Last PG Headroom | Min | Max | Pattern
            #   -----|---------|-----|------------------|-----|-----|----------
            #      1 | TB-2    |  21 |        1 cells   |   1 | 487 | = step
            #      2 | TB-2    |  21 |        2 cells   |   2 | 488 | = step
            #      4 | TB-8    |  21 |        4 cells   |   4 | 492 | = step
            #      6 | TB-8    |  21 |        6 cells   |   6 | 495 | = step
            #      8 | TB-8    |  21 |        8 cells   |   8 | 497 | = step
            #     10 | TB-2    |  22 |       10 cells   |  10 | 498 | = step
            #     12 | TB-2    |  22 |        0 cells   |   0 | 492 | < step (anomaly)
            #     12 | TB-8    |  22 |        0 cells   |   0 | 492 | < step (anomaly)
            #     14 | TB-2    |  21 |       14 cells   |  14 | 495 | = step
            #     14 | TB-8    |  21 |       14 cells   |  14 | 495 | = step
            #     16 | TB-2    |  22 |       16 cells   |  16 | 493 | = step
            #     16 | TB-8    |  22 |       16 cells   |  16 | 493 | = step
            #
            # Result: 10/12 tests (83%) last PG headroom = step, 2/12 tests < step
            # Conclusion: threshold = step * 1 is optimal (100% coverage, no false negatives)
            exhaustion_threshold = self.POINT_PROBING_STEP_SIZE
            if pg_headroom <= exhaustion_threshold:
                ProbingObserver.console(
                    f"\n[Pool Exhausted] Headroom = {pg_headroom} cells "
                    f"(<= {exhaustion_threshold})"
                )
                ProbingObserver.console("         Terminating probing")
                break

        # Build and report results (pass exhaustion_threshold for consistent logic)
        result = self._build_result(
            pg_results, total_headroom, num_flows, exhaustion_threshold
        )

        # Report total probing time
        ProbingObserver.console(
            f"\nTotal probing time: {total_time/60:.2f} minutes "
            f"({total_time:.1f} seconds)"
        )

        return self._report_results(result)

    #
    # Observer Configs (centralized definition to reduce noise in main loop)
    #

    # Table column mapping shared by all algorithms
    _UPPER_TABLE_MAPPING = {
        "lower_bound": None, "upper_bound": "value",
        "candidate_threshold": None, "range_step": None
    }
    _LOWER_TABLE_MAPPING = {
        "lower_bound": "value", "upper_bound": "window_upper",
        "candidate_threshold": None, "range_step": None
    }
    _RANGE_TABLE_MAPPING = {
        "lower_bound": "window_lower", "upper_bound": "window_upper",
        "candidate_threshold": "value", "range_step": "range_step"
    }
    _POINT_TABLE_MAPPING = {
        "lower_bound": "window_lower", "upper_bound": "window_upper",
        "candidate_threshold": "value", "range_step": None
    }

    def _get_observer_configs(self, probe_target, pg_index):
        """
        Get observer configs for all algorithms of a probe target.

        Args:
            probe_target: 'pfc_xoff' or 'ingress_drop'
            pg_index: PG index for naming

        Returns:
            dict: {'upper': config, 'lower': config, 'range': config, 'point': config}
        """
        # prefix = f"pg{pg_index}_{'pfc' if probe_target == 'pfc_xoff' else 'drop'}"
        # seq_base = 1 if probe_target == 'pfc_xoff' else 5

        context_upper = f" [{probe_target} upper: {{window_upper}}]"
        context_range = f" [{probe_target} range: [{{window_lower}}, {{window_upper}}]]"

        # Auto-format probe_target to check column title (e.g., pfc_xoff -> PfcXoff, ingress_drop -> IngressDrop)
        check_column_title = ''.join(word.capitalize() for word in probe_target.split('_'))

        return {
            'upper': ObserverConfig(
                probe_target=probe_target, algorithm_name="Upper Bound Probing",
                strategy="exponential growth", check_column_title=check_column_title,
                context_template="",
                completion_template="Upper bound = {value}", completion_format_type="value",
                table_column_mapping=self._UPPER_TABLE_MAPPING
            ),
            'lower': ObserverConfig(
                probe_target=probe_target, algorithm_name="Lower Bound Probing",
                strategy="logarithmic reduction", check_column_title=check_column_title,
                context_template=context_upper,
                completion_template="Lower bound = {value}", completion_format_type="value",
                table_column_mapping=self._LOWER_TABLE_MAPPING
            ),
            'range': ObserverConfig(
                probe_target=probe_target, algorithm_name="Threshold Range Probing",
                strategy="binary search", check_column_title=check_column_title,
                context_template=context_range,
                completion_template="Range = [{lower}, {upper}]", completion_format_type="range",
                table_column_mapping=self._RANGE_TABLE_MAPPING
            ),
            'point': ObserverConfig(
                probe_target=probe_target, algorithm_name="Threshold Point Probing",
                strategy="step-by-step scan", check_column_title=check_column_title,
                context_template=context_range,
                completion_template="Point = {value}", completion_format_type="value",
                table_column_mapping=self._POINT_TABLE_MAPPING
            ),
        }

    #
    # Result Building and Reporting
    #

    def _build_result(self, pg_results, total_headroom, num_flows, exhaustion_threshold=1):
        """Build final result dictionary.

        Args:
            pg_results: List of PG probing results
            total_headroom: Total accumulated headroom
            num_flows: Total number of flows
            exhaustion_threshold: Threshold for pool exhaustion (default 1, adjusted by step_size)
        """
        pool_exhausted = len(pg_results) > 0 and pg_results[-1]['headroom'] <= exhaustion_threshold

        if pool_exhausted:
            effective_headroom = total_headroom - pg_results[-1]['headroom']
            return {
                'success': True,
                'total_headroom': effective_headroom,
                'pg_results': pg_results,
                'pgs_probed': len(pg_results),
                'pool_exhausted': True,
                'pg_min': pg_results[-1]['pfc_xoff_threshold']
            }
        else:
            return {
                'success': False,
                'total_headroom': None,
                'partial_headroom': total_headroom,
                'pg_results': pg_results,
                'pgs_probed': len(pg_results),
                'pool_exhausted': False
            }

    def _report_results(self, result) -> ThresholdResult:
        """Report final probing results and return ThresholdResult."""
        ProbingObserver.console(f"\n{'='*60}")
        ProbingObserver.console("FINAL RESULTS")
        ProbingObserver.console(f"{'='*60}")
        ProbingObserver.console(f"PGs probed: {result['pgs_probed']}")

        if result['success']:
            pool_size = result['total_headroom']
            ProbingObserver.console("Status: SUCCESS - Pool exhaustion detected")
            ProbingObserver.console(f"Total Headroom Pool Size: {pool_size} cells")
            ProbingObserver.console(f"Detected pg_min: {result.get('pg_min')} cells")

            # Create ThresholdResult (pool size as point: lower == upper)
            threshold_result = ThresholdResult.from_bounds(pool_size, pool_size)
        else:
            ProbingObserver.console("Status: INCOMPLETE - Pool not exhausted")
            ProbingObserver.console(f"Partial headroom: {result.get('partial_headroom')} cells")

            # Create failed ThresholdResult
            threshold_result = ThresholdResult.failed()

        # Report using Observer's unified method (works for both success and failure)
        ProbingObserver.report_probing_result("Headroom Pool", threshold_result, unit="cells")

        return threshold_result
