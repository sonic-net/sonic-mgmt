#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PfcXonProbing - PFC XOn Threshold (XOn offset) Probing Test

Traffic Pattern: 1 src -> 2 dst (dst_A is drain target, dst_B is the holder)
Both dst flows enter the SAME ingress PG (same source port + same DSCP).

Detects pkts_num_dismiss_pfc + pkts_num_hysteresis (XOn offset) via
"drain after xoff" protocol:
  1. Fill: send N packets to dst_A and (pfcxoff_point - N) packets to dst_B
     so they accumulate on the same ingress PG. xoff fires.
  2. Drain: tx_enable(dst_A) drains its portion. If buffer level fell past
     xon threshold, src is resumed -> sends more -> next xoff fires
     -> PFC_PAUSE_RX increments AGAIN. Detect this re-fire to find XOn offset.

Algorithm dispatch (per design v3):
  - Step (3-step):  Brcm TD2/TD3/TH/TH2/TH3/TH5, Mlx SPC1/SPC2 (effective offset 12-23)
  - Binary (4-step): Brcm GB, Mlx SPC3 PAC, Cisco J2C/JR2/Q3D (effective offset 200-12985)

Selected at runtime via testParams['enable_xon_range_probe']:
  - False (default): step-by-step from D=1, max_iter=50
  - True: binary search to range_limit=32, then step within window

Design:
- setUp(): PTF initialization + parse_param (gets pfcxoff_point + flag)
- setup_traffic(): Build stream_mgr (1 src -> 2 dst via StreamManager flows)
- probe(): Main entry - creates executor + algorithm, runs single-phase probing

Extensibility (for mock/UT):
- EXECUTOR_ENV auto-detected (default: physical)
- Can override via testParams['executor_env'] = 'sim'

Usage:
    Called from test_qos_probe.py via PTF with test_subdir='probe':
    self.runPtfTest(ptfhost, testCase="pfc_xon_probing.PfcXonProbing",
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

# Algorithm imports - PfcXon-specific dispatch
from xon_drain_step_algorithm import XonDrainStepAlgorithm  # noqa: E402
from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm  # noqa: E402

# Observer imports
from probing_observer import ProbingObserver  # noqa: E402
from observer_config import ObserverConfig  # noqa: E402


class PfcXonProbing(ProbingBase):
    """
    PFC XOn Threshold (XOn offset) Probing Test Case

    Traffic Pattern: 1 src -> 2 dst (dst_A is drain target, dst_B is holder)
    Probe Target: Detect pkts_num_dismiss_pfc + pkts_num_hysteresis (XOn offset)
                  by observing PFC_PAUSE_RX re-fire after partial drain

    Inherits from ProbingBase which provides:
    - setUp(): PTF init + common parse_param + EXECUTOR_ENV
    - runTest(): Template method (calls setup_traffic, probe)
    - tearDown(): PTF cleanup

    Diverges from PfcXoff/IngressDrop pattern in:
    - 2 dst ports instead of N dst (dst_A drain target, dst_B holder)
    - Single-phase probing (step OR binary, no upper/lower/range/point cascade)
    - Requires pfcxoff_point as input (typically from prior PfcXoff probe)
    """

    #
    # Probing Configuration
    #
    PROBE_TARGET = "pfc_xon"

    # Algorithm dispatch defaults (can be tuned per-platform via testParams)
    DEFAULT_STEP_MAX_ITER = 50
    DEFAULT_BINARY_RANGE_LIMIT = 32
    DEFAULT_BINARY_MAX_ITER = 20
    DEFAULT_BINARY_STEP_MAX_ITER = 50
    DEFAULT_VERIFICATION_ATTEMPTS = 2

    #
    # PTF Lifecycle
    #

    def setUp(self):
        """
        PfcXonProbing setup.

        1. Call super().setUp() for common initialization
        2. Parse subclass-specific parameters (pfcxoff_point, enable_xon_range_probe)
        """
        super().setUp()
        self.parse_param()

    def parse_param(self):
        """
        Parse PfcXonProbing-specific parameters.

        Required testParams:
        - pfcxoff_point (int): Known PFC Xoff threshold from prior probe (or yaml).
            The fill phase uses this as total fill (dst_A + dst_B = pfcxoff_point).
        - dscp, pg, ecn: traffic identification (parsed by base class)

        Optional testParams:
        - enable_xon_range_probe (bool): True -> binary algorithm (4-step path)
                                         False -> step algorithm (3-step path, default)
        - xon_step_max_iter (int): Override DEFAULT_STEP_MAX_ITER
        - xon_binary_range_limit (int): Override DEFAULT_BINARY_RANGE_LIMIT
        - xon_binary_max_iter (int): Override DEFAULT_BINARY_MAX_ITER
        - xon_binary_step_max_iter (int): Override DEFAULT_BINARY_STEP_MAX_ITER
        - xon_verification_attempts (int): Per-check verification rounds
        """
        # PFC counter index (starts from index 2 in sai_thrift_read_port_counters)
        self.cnt_pg_idx = self.pg + 2

        # Required: pfcxoff_point (without it the fill phase can't compute split)
        self.pfcxoff_point = int(self.test_params.get("pfcxoff_point", 0))
        if self.pfcxoff_point <= 0:
            log_message(
                f"[PfcXonProbing] WARNING: pfcxoff_point={self.pfcxoff_point} invalid; "
                "test will fail at executor init",
                to_stderr=True,
            )

        # Algorithm dispatch flag (default: step algorithm)
        self.enable_xon_range_probe = bool(
            self.test_params.get("enable_xon_range_probe", False)
        )

        # Tunables with defaults
        self.xon_step_max_iter = int(
            self.test_params.get("xon_step_max_iter", self.DEFAULT_STEP_MAX_ITER)
        )
        self.xon_binary_range_limit = int(
            self.test_params.get("xon_binary_range_limit", self.DEFAULT_BINARY_RANGE_LIMIT)
        )
        self.xon_binary_max_iter = int(
            self.test_params.get("xon_binary_max_iter", self.DEFAULT_BINARY_MAX_ITER)
        )
        self.xon_binary_step_max_iter = int(
            self.test_params.get("xon_binary_step_max_iter", self.DEFAULT_BINARY_STEP_MAX_ITER)
        )
        self.xon_verification_attempts = int(
            self.test_params.get("xon_verification_attempts", self.DEFAULT_VERIFICATION_ATTEMPTS)
        )

    def get_probe_config(self):
        """Return standardized probe configuration."""
        return ProbeConfig(
            probing_port_ids=self.probing_port_ids,
            thrift_client=self.dst_client,
            asic_type=self.asic_type,
        )

    def get_expected_threshold(self):
        """Get expected XOn offset from test parameters (if known, for assertion)."""
        value = self.test_params.get("expected_xon_offset", None)
        return (value, "XOn offset") if value is not None else None

    #
    # Abstract Method Implementation: setup_traffic
    #

    def setup_traffic(self):
        """
        Setup traffic streams for 1 src -> 2 dst pattern.

        Uses probing_port_ids:
        - First port is src
        - Second port is dst_A (drain target)
        - Third port is dst_B (holder)

        Both flows go to the SAME ingress PG.
        """
        if not self.probing_port_ids or len(self.probing_port_ids) < 3:
            log_message(
                f"ERROR: PfcXonProbing requires 3 probing ports (1 src + 2 dst); "
                f"got {len(self.probing_port_ids) if self.probing_port_ids else 0}",
                to_stderr=True,
            )
            return

        # Use first available dut/asic index from test_port_ips
        dut_idx = next(iter(self.test_port_ips))
        asic_idx = next(iter(self.test_port_ips[dut_idx]))
        port_ips = self.test_port_ips[dut_idx][asic_idx]

        # 1 src -> 2 dst: First is src, [1] is dst_A, [2] is dst_B
        srcport = PortInfo(
            self.probing_port_ids[0],
            mac=self.dataplane.get_mac(0, self.probing_port_ids[0]),
            ip=port_ips[self.probing_port_ids[0]]["peer_addr"],
            vlan=port_ips[self.probing_port_ids[0]].get("vlan_id", None),
        )

        dst_a_id = self.probing_port_ids[1]
        dst_b_id = self.probing_port_ids[2]
        dst_a = PortInfo(
            dst_a_id,
            mac=self.dataplane.get_mac(0, dst_a_id),
            ip=port_ips[dst_a_id]["peer_addr"],
            vlan=port_ips[dst_a_id].get("vlan_id", None),
        )
        dst_b = PortInfo(
            dst_b_id,
            mac=self.dataplane.get_mac(0, dst_b_id),
            ip=port_ips[dst_b_id]["peer_addr"],
            vlan=port_ips[dst_b_id].get("vlan_id", None),
        )

        # Platform-independent: 64-byte packets = 1 cell
        packet_length = 64
        ttl = 64

        is_dualtor = getattr(self, "is_dualtor", False)
        def_vlan_mac = getattr(self, "def_vlan_mac", None)

        # Initialize stream manager
        self.stream_mgr = StreamManager(
            packet_constructor=construct_ip_pkt,
            rx_port_resolver=self.get_rx_port,
        )

        # Add 2 flows: src->dst_A and src->dst_B (same ingress PG)
        for dstport in (dst_a, dst_b):
            self.stream_mgr.add_flow(
                FlowConfig(
                    srcport,
                    dstport,
                    dmac=determine_traffic_dmac(dstport.mac, self.router_mac, is_dualtor, def_vlan_mac),
                    dscp=self.dscp,
                    ecn=self.ecn,
                    ttl=ttl,
                    length=packet_length,
                ),
                pg=self.pg,
            )

        self.stream_mgr.generate_packets()

        log_message(
            f"[PfcXonProbing] Traffic setup: src={self.probing_port_ids[0]} "
            f"dst_A={dst_a_id} dst_B={dst_b_id} pfcxoff_point={self.pfcxoff_point} "
            f"pg={self.pg} dscp={self.dscp}",
            to_stderr=True,
        )

    #
    # Abstract Method Implementation: probe
    #

    def probe(self) -> ThresholdResult:
        """
        Execute PFC XOn offset probing.

        Workflow:
        1. Create executor (PfcXonProbingExecutor) via factory
        2. Dispatch algorithm based on enable_xon_range_probe flag:
           - True  -> XonDrainBinaryAlgorithm (binary then step within window)
           - False -> XonDrainStepAlgorithm (step from D=1)
        3. Run algorithm; report result

        Returns:
            ThresholdResult: Probing result with XOn offset
        """
        src_port = self.probing_port_ids[0]
        dst_a = self.probing_port_ids[1]
        dst_b = self.probing_port_ids[2]
        traffic_keys = {"pg": self.pg}

        # Single observer for the dispatched algorithm
        observer = ProbingObserver(
            name="xon_probe",
            iteration_prefix=1,
            verbose=True,
            observer_config=ObserverConfig(
                probe_target=self.PROBE_TARGET,
                algorithm_name=("XOn Drain Binary" if self.enable_xon_range_probe
                                else "XOn Drain Step"),
                strategy=("binary-then-step" if self.enable_xon_range_probe
                          else "step-by-step"),
                check_column_title="Xon",
                completion_template="XOn offset = [{lower}, {upper}]",
                completion_format_type="range",
                table_column_mapping={
                    "lower_bound": "lower",
                    "upper_bound": "upper",
                    "candidate_threshold": "value",
                    "range_step": None,
                },
            ),
        )

        # Create executor via factory (handles env-specific dispatch: physical vs sim)
        executor = self.create_executor(
            self.PROBE_TARGET,
            observer,
            "xon_probe",
            pfcxoff_point=self.pfcxoff_point,
        )

        # Dispatch algorithm based on flag
        if self.enable_xon_range_probe:
            algorithm = XonDrainBinaryAlgorithm(
                executor=executor,
                observer=observer,
                verification_attempts=self.xon_verification_attempts,
                range_limit=self.xon_binary_range_limit,
                binary_max_iter=self.xon_binary_max_iter,
                step_max_iter=self.xon_binary_step_max_iter,
            )
            algo_label = "binary"
        else:
            algorithm = XonDrainStepAlgorithm(
                executor=executor,
                observer=observer,
                verification_attempts=self.xon_verification_attempts,
                max_iter=self.xon_step_max_iter,
            )
            algo_label = "step"

        # Log probing start
        ProbingObserver.console("=" * 80)
        ProbingObserver.console(f"[{self.PROBE_TARGET}] Starting XOn offset probing")
        ProbingObserver.console(f"  src_port={src_port}, dst_A={dst_a}, dst_B={dst_b}")
        ProbingObserver.console(f"  pfcxoff_point={self.pfcxoff_point} pg={self.pg}")
        ProbingObserver.console(f"  algorithm={algo_label}")
        ProbingObserver.console(f"  enable_xon_range_probe={self.enable_xon_range_probe}")
        ProbingObserver.console(f"  executor_env={self.EXECUTOR_ENV}")
        ProbingObserver.console("=" * 80)

        # Run probing
        lower, upper, elapsed = algorithm.run(src_port, dst_a, dst_b, **traffic_keys)

        # Build result
        result = ThresholdResult.from_bounds(lower, upper)

        # Report
        ProbingObserver.report_probing_result(
            "PFC XOn Offset", result, unit="pkt"
        )
        ProbingObserver.console(
            f"[{self.PROBE_TARGET}] Algorithm '{algo_label}' completed in {elapsed:.1f}s"
        )

        return result
