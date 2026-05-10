#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PfcXonProbing - PFC XOn Threshold (XOn offset) Probing Test

Traffic Pattern: 1 src -> 2 dst (dst_drain is the drain target, dst_holder
holds back its share of the buffer fill).
Both dst flows enter the SAME ingress PG (same source port + same DSCP).

Detects pkts_num_dismiss_pfc + pkts_num_hysteresis (XOn offset) via
"drain after xoff" protocol:
  1. Fill: send N packets to dst_drain and (pfcxoff_point - N) packets to
     dst_holder so they accumulate on the same ingress PG. xoff fires.
  2. Drain: tx_enable(dst_drain) drains its portion. If buffer level fell
     past xon threshold, src is resumed -> sends more -> next xoff fires
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

# Algorithm imports - PfcXoff chain (Step 1+2 of design v3, 2026-05-09)
from upper_bound_probing_algorithm import UpperBoundProbingAlgorithm  # noqa: E402
from lower_bound_probing_algorithm import LowerBoundProbingAlgorithm  # noqa: E402
from threshold_range_probing_algorithm import ThresholdRangeProbingAlgorithm  # noqa: E402
from threshold_point_probing_algorithm import ThresholdPointProbingAlgorithm  # noqa: E402

# Observer imports
from probing_observer import ProbingObserver  # noqa: E402
from observer_config import ObserverConfig  # noqa: E402


class PfcXonProbing(ProbingBase):
    """
    PFC XOn Threshold (XOn offset) Probing Test Case

    Traffic Pattern: 1 src -> 2 dst (dst_drain is drain target, dst_holder holds back)
    Probe Target: Detect pkts_num_dismiss_pfc + pkts_num_hysteresis (XOn offset)
                  by observing PFC_PAUSE_RX re-fire after partial drain

    Inherits from ProbingBase which provides:
    - setUp(): PTF init + common parse_param + EXECUTOR_ENV
    - runTest(): Template method (calls setup_traffic, probe)
    - tearDown(): PTF cleanup

    Diverges from PfcXoff/IngressDrop pattern in:
    - 2 dst ports instead of N dst (dst_drain target, dst_holder buffer-share holder)
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
        3. Override ENABLE_PRECISE_DETECTION = True so Step 1+2 chain's
           ThresholdRangeProbingAlgorithm + ThresholdPointProbingAlgorithm produces
           an exact xoff_point (mirrors PfcXoffProbing / HeadroomPoolProbing pattern).
        """
        super().setUp()
        self.parse_param()
        # Step 1+2 chain (design v3 §2 Step 2) requires precise xoff_point detection
        # to remove the fill_retry_margin systematic bias. Mirrors peer probing
        # classes — pfc_xoff_probing.py:100, ingress_drop_probing.py same pattern.
        self.ENABLE_PRECISE_DETECTION = True

    def parse_param(self):
        """
        Parse PfcXonProbing-specific parameters.

        Required testParams:
        - pfcxoff_point (int): YAML hint of PFC Xoff threshold. With Step 1+2 chain
            enabled (default), this is used only as a sanity-check seed; the
            actual value comes from a fresh PfcXoff probe (see _run_pfcxoff_chain).
            With chain disabled (enable_xoff_chain_probe=False), this becomes the
            value the executor uses directly (legacy / pre-design-v3 behavior).
        - dscp, pg, ecn: traffic identification (parsed by base class)

        Optional testParams:
        - enable_xoff_chain_probe (bool, default True): when True, run Step 1+2 of
            design v3 (4-phase PfcXoff probe -> measured xoff_point) before the
            XOn drain probe. When False, skip the chain and use yaml pfcxoff_point
            directly. Default True ensures real-hardware execution measures xoff
            instead of trusting yaml; False is for UT/IT mocking and as an escape
            hatch when the PfcXoff probe path is unhealthy.
        - enable_xon_range_probe (bool): True -> binary algorithm (4-step path,
            i.e., Step 1+2 chain + Step 2.5 + Step 3)
                                         False -> step algorithm (3-step path,
            i.e., Step 1+2 chain + Step 3 default)
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

        # Step 1+2 chain flag (design v3, 2026-05-09): default True so real-hardware
        # execution measures xoff_point instead of trusting the yaml hint. UT/IT
        # paths set this to False to avoid driving an extra 4-phase PfcXoff probe.
        self.enable_xoff_chain_probe = bool(
            self.test_params.get("enable_xoff_chain_probe", True)
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

        # Periodic-PAUSE counter-stop detection tunables (per code review I3,
        # 2026-05-09). Defaults are calibrated for TH2 7260CX3 (~2200 pauses/sec
        # ⇒ ~220 in a 100ms window, well above tolerance=5). Surface as
        # test_params so cross-platform V9 runs (Mellanox SPC1/SPC2/SPC3, Cisco,
        # Brcm GB) can tune without code change. None means "use executor default".
        # Per r2 N2 (2026-05-09): validate > 0 to fail loudly on bad input
        # (test_params=0 silently produced wrong results; both
        # pause_observation_window=0.0 and pause_stop_tolerance=0 break
        # detection in different ways without crashing).
        self.pause_observation_window = self.test_params.get(
            "pause_observation_window", None
        )
        if self.pause_observation_window is not None and self.pause_observation_window <= 0:
            raise ValueError(
                f"pause_observation_window must be > 0 (got "
                f"{self.pause_observation_window}); zero or negative breaks "
                "the 2-sample counter-stop detection in _drain_phase."
            )
        self.pause_stop_tolerance = self.test_params.get(
            "pause_stop_tolerance", None
        )
        if self.pause_stop_tolerance is not None and self.pause_stop_tolerance <= 0:
            raise ValueError(
                f"pause_stop_tolerance must be > 0 (got "
                f"{self.pause_stop_tolerance}); zero or negative makes "
                "`growth < tolerance` always False (xon never detected)."
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
        - Second port is dst_drain (the drain target — opened during drain
          phase to release packets and observe xon)
        - Third port is dst_holder (the buffer-share holder — stays held
          during drain to keep ingress occupancy above xon threshold until
          the dst_drain queue's release crosses it)

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

        # 1 src -> 2 dst: [0] is src, [1] is dst_drain (drain target),
        # [2] is dst_holder (holds back its share of the buffer).
        srcport = PortInfo(
            self.probing_port_ids[0],
            mac=self.dataplane.get_mac(0, self.probing_port_ids[0]),
            ip=port_ips[self.probing_port_ids[0]]["peer_addr"],
            vlan=port_ips[self.probing_port_ids[0]].get("vlan_id", None),
        )

        drain_port_id = self.probing_port_ids[1]
        holder_port_id = self.probing_port_ids[2]
        dst_drain = PortInfo(
            drain_port_id,
            mac=self.dataplane.get_mac(0, drain_port_id),
            ip=port_ips[drain_port_id]["peer_addr"],
            vlan=port_ips[drain_port_id].get("vlan_id", None),
        )
        dst_holder = PortInfo(
            holder_port_id,
            mac=self.dataplane.get_mac(0, holder_port_id),
            ip=port_ips[holder_port_id]["peer_addr"],
            vlan=port_ips[holder_port_id].get("vlan_id", None),
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

        # Add 2 flows: src->dst_drain and src->dst_holder (same ingress PG)
        for dstport in (dst_drain, dst_holder):
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
            f"dst_drain={drain_port_id} dst_holder={holder_port_id} "
            f"pfcxoff_point={self.pfcxoff_point} pg={self.pg} dscp={self.dscp}",
            to_stderr=True,
        )

    #
    # Abstract Method Implementation: probe
    #

    def _run_pfcxoff_chain(self, src_port, dst_port, **traffic_keys):
        """Step 1+2 of design v3: probe PfcXoff threshold to obtain exact xoff_point.

        Runs a 4-phase PfcXoff probe on (src_port, dst_port):
          - Phase 1 (UpperBound):       discover an upper bound for xoff threshold
          - Phase 2 (LowerBound):       narrow the lower bound
          - Phase 3 (ThresholdRange):   binary-search the [lower, upper] window
          - Phase 4 (ThresholdPoint):   step-by-step within the narrowed window

        Returns:
            int: measured xoff_point (smallest packet count that fires xoff) on
                 full success.
            int: range_upper as approximation when Phase 4 is skipped (window
                 too wide) or fails — still much better than yaml.
            None: when any earlier phase fails — caller should fall back to the
                 yaml hint.

        Why design v3 mandates this:
            yaml `pkts_num_trig_pfc` is a per-platform NOMINAL value; real
            hardware can differ by a few packets due to per-port noise, ASIC
            occupancy quantization, or buffer pool sizing variation. Using yaml
            directly forces the XOn drain phase to compensate via
            `fill_retry_margin` (a hack), and the resulting offset is biased
            by that margin. Running a fresh PfcXoff probe right before XOn
            drain produces a precise xoff_point that the XOn drain phase can
            consume directly.

        =====================================================================
        Architectural note (review C2, 2026-05-10)
        =====================================================================
        This method composes the same 4-phase probing chain
        (UpperBound -> LowerBound -> ThresholdRange -> ThresholdPoint) that
        already exists in 3 other places in the probe framework:

          - PfcXoffProbing.probe() / _create_algorithms() / _run_algorithms()
            (pfc_xoff_probing.py:202-433)
          - HeadroomPoolProbing — PFC threshold block
            (headroom_pool_probing.py:351-371)
          - HeadroomPoolProbing — Drop threshold block
            (headroom_pool_probing.py:444-475)

        Why we do NOT directly invoke PfcXoffProbing.probe() here:
          1. PfcXoffProbing is a PTF test entry class (extends
             sai_base_test.ThriftInterfaceDataPlane via ProbingBase). Its
             setUp/probe() are coupled to PTF runner state, not callable as
             a standalone helper.
          2. probe() reads self.probing_port_ids[0] and
             self.stream_mgr.get_port_ids("dst")[0] — there is no public API
             to override which (src, dst) pair to probe.
          3. probe() returns ThresholdResult; we would still need to convert
             it into the integer xoff_point we consume below.
          4. ProbingObserver iteration_prefix would collide: PfcXoffProbing
             uses 1..4; PfcXonProbing uses prefix=1 for the XOn drain phase.
             This method explicitly uses prefix 10..13 to keep the chain
             logs distinguishable from XOn drain logs.

        Why we do NOT extract a shared helper here:
          A helper would need to live in either ProbingBase or a new module
          AND PfcXoffProbing.probe() / HeadroomPoolProbing.probe() would
          need to be migrated to use it. Modifying those proven peer probes
          is explicitly out of scope for this PR — the rule is "new probes
          must not perturb existing probes' code or executors". HeadroomPool
          itself observed the same rule when it composed PfcXoff + drop
          algorithms without modifying PfcXoffProbing.

        Follow-up: extracting a reusable run_4phase_chain() helper that
        consolidates all 4 sites is best done as a dedicated refactor PR
        that touches PfcXoff + HeadroomPool×2 + PfcXon at once, with full
        physical regression on each. Tracked in
        cortex/sessions/mmu-probe-status-0507/STATUS.md follow-ups.
        """
        pool_size = self.get_pool_size()

        ProbingObserver.console("=" * 80)
        ProbingObserver.console(
            f"[{self.PROBE_TARGET}] Step 1+2 — PfcXoff chain probe (design v3)"
        )
        ProbingObserver.console(
            f"  src_port={src_port}  dst_port={dst_port}  pool_size={pool_size}"
        )
        ProbingObserver.console(
            f"  yaml pfcxoff_point hint = {self.pfcxoff_point} "
            "(used as fallback if chain fails)"
        )
        ProbingObserver.console("=" * 80)

        XOFF_TARGET = "pfc_xoff"

        # Per-phase observers (iteration_prefix offset 10..13 to keep XOff chain
        # logs distinct from XOn drain phase prefix=1 used below).
        def _make_obs(name, prefix, algo_name, strategy, completion_tpl, fmt_type, mapping):
            return ProbingObserver(
                name=name,
                iteration_prefix=prefix,
                verbose=True,
                observer_config=ObserverConfig(
                    probe_target=XOFF_TARGET,
                    algorithm_name=algo_name,
                    strategy=strategy,
                    check_column_title="PfcXoff",
                    completion_template=completion_tpl,
                    completion_format_type=fmt_type,
                    table_column_mapping=mapping,
                ),
            )

        upper_obs = _make_obs(
            "step1_upper", 10, "Upper Bound Probing", "exponential growth",
            "Upper bound = {value}", "value",
            {"lower_bound": None, "upper_bound": "value",
             "candidate_threshold": None, "range_step": None},
        )
        lower_obs = _make_obs(
            "step1_lower", 11, "Lower Bound Probing", "logarithmic reduction",
            "Lower bound = {value}", "value",
            {"lower_bound": "value", "upper_bound": "window_upper",
             "candidate_threshold": None, "range_step": None},
        )
        range_obs = _make_obs(
            "step1_range", 12, "Threshold Range Probing", "binary search",
            "Range = [{lower}, {upper}]", "range",
            {"lower_bound": "window_lower", "upper_bound": "window_upper",
             "candidate_threshold": "value", "range_step": "range_size"},
        )
        point_obs = _make_obs(
            "step2_point", 13, "Threshold Point Probing", "sequential scan",
            None, "value",
            {"lower_bound": "value", "upper_bound": "window_upper",
             "candidate_threshold": "value", "range_step": 1},
        )

        # Per-phase executors via factory (handles real vs sim dispatch consistently
        # with the existing PfcXonProbing executor — same EXECUTOR_ENV).
        upper_exec = self.create_executor(XOFF_TARGET, upper_obs, "step1_upper")
        lower_exec = self.create_executor(XOFF_TARGET, lower_obs, "step1_lower")
        range_exec = self.create_executor(XOFF_TARGET, range_obs, "step1_range")
        point_exec = self.create_executor(XOFF_TARGET, point_obs, "step2_point")

        # Phase 1: Upper bound discovery (exponential)
        upper_bound, _ = UpperBoundProbingAlgorithm(
            executor=upper_exec, observer=upper_obs,
            verification_attempts=1,
        ).run(src_port, dst_port, pool_size, **traffic_keys)
        if upper_bound is None:
            ProbingObserver.console(
                "[Step 1+2] Upper bound discovery failed; falling back to yaml hint"
            )
            return None

        # Phase 2: Lower bound (logarithmic reduction within [0, upper_bound])
        lower_bound, _ = LowerBoundProbingAlgorithm(
            executor=lower_exec, observer=lower_obs,
            verification_attempts=1,
        ).run(src_port, dst_port, upper_bound, **traffic_keys)
        if lower_bound is None:
            ProbingObserver.console(
                "[Step 1+2] Lower bound detection failed; falling back to yaml hint"
            )
            return None

        # Phase 3: Range narrowing (binary search within [lower, upper])
        range_lower, range_upper, _ = ThresholdRangeProbingAlgorithm(
            executor=range_exec, observer=range_obs,
            precision_target_ratio=self.PRECISION_TARGET_RATIO,
            verification_attempts=2,
            enable_precise_detection=self.ENABLE_PRECISE_DETECTION,
            precise_detection_range_limit=self.PRECISE_DETECTION_RANGE_LIMIT,
        ).run(src_port, dst_port, lower_bound, upper_bound, **traffic_keys)
        if range_lower is None or range_upper is None:
            ProbingObserver.console(
                "[Step 1+2] Range narrowing failed; falling back to yaml hint"
            )
            return None

        # Phase 4: Exact point (step-by-step within narrowed window).
        # Conditional on ENABLE_PRECISE_DETECTION class attribute -- mirrors
        # HeadroomPoolProbing.probe() pattern (headroom_pool_probing.py:366-374).
        # Per r2 N3 (2026-05-09): both Phase-4-skip paths log explicitly so
        # V9 log scrubbing can distinguish "Phase 4 skipped because the class
        # is configured for fast/imprecise mode" from "Phase 4 skipped because
        # the range is too wide".
        if not self.ENABLE_PRECISE_DETECTION:
            ProbingObserver.console(
                f"[Step 2] ENABLE_PRECISE_DETECTION=False; using "
                f"range_upper={range_upper} as xoff_point. "
                "Phase 4 (exact point) SKIPPED."
            )
            return range_upper

        range_size = range_upper - range_lower
        if range_size > self.PRECISE_DETECTION_RANGE_LIMIT:
            ProbingObserver.console(
                f"[Step 2] ⚠️ APPROXIMATION: Range width {range_size} exceeds "
                f"limit {self.PRECISE_DETECTION_RANGE_LIMIT}; using "
                f"range_upper={range_upper} as xoff_point. "
                "Phase 4 (exact point) SKIPPED."
            )
            return range_upper

        point_lower, point_upper, _ = ThresholdPointProbingAlgorithm(
            executor=point_exec, observer=point_obs,
            verification_attempts=1,
            step_size=self.POINT_PROBING_STEP_SIZE,
        ).run(
            src_port=src_port, dst_port=dst_port,
            lower_bound=range_lower, upper_bound=range_upper,
            **traffic_keys,
        )
        if point_lower is None or point_upper is None:
            ProbingObserver.console(
                f"[Step 2] Point detection failed; using range_upper={range_upper} "
                "as xoff_point approximation."
            )
            return range_upper

        # point_upper is the smallest packet count that fires xoff: that IS
        # xoff_point per design v3 §2 Step 2 definition.
        return point_upper

    def probe(self) -> ThresholdResult:
        """
        Execute PFC XOn offset probing.

        Workflow:
        1. (Step 1+2 of design v3, default) Run PfcXoff chain to measure exact
           xoff_point on this port; override yaml hint when chain succeeds.
           Disabled via test_params['enable_xoff_chain_probe']=False (UT/IT paths).
        2. Create XOn executor via factory.
        3. Dispatch algorithm based on enable_xon_range_probe flag:
           - True  -> XonDrainBinaryAlgorithm (Step 2.5+3, "binary then step within window")
           - False -> XonDrainStepAlgorithm   (Step 3, "step from D=1")
        4. Run algorithm; report result.

        Returns:
            ThresholdResult: Probing result with XOn offset
        """
        src_port = self.probing_port_ids[0]
        drain_port = self.probing_port_ids[1]
        holder_port = self.probing_port_ids[2]
        traffic_keys = {"pg": self.pg}

        # Step 1+2: PfcXoff chain probe to obtain exact xoff_point (design v3,
        # 2026-05-09). Single dst is sufficient for Step 1+2 since PfcXoff probe
        # is a 1-src/1-dst protocol; we use drain_port (the same port that'll
        # be the drain target in Step 3 for occupancy continuity).
        if self.enable_xoff_chain_probe:
            measured_xoff = self._run_pfcxoff_chain(src_port, drain_port, **traffic_keys)
            if measured_xoff is not None and measured_xoff > 0:
                yaml_hint = self.pfcxoff_point
                self.pfcxoff_point = int(measured_xoff)
                delta = self.pfcxoff_point - yaml_hint
                if delta == 0:
                    delta_msg = "matches yaml exactly"
                elif delta > 0:
                    delta_msg = f"measured exceeds yaml by +{delta} pkts"
                else:
                    delta_msg = f"measured is below yaml by {delta} pkts"
                ProbingObserver.console(
                    f"[Step 1+2] xoff_point = {self.pfcxoff_point} (measured); "
                    f"yaml hint was {yaml_hint}; {delta_msg}"
                )
            else:
                ProbingObserver.console(
                    f"[Step 1+2] chain returned no measurement; falling back to "
                    f"yaml pfcxoff_point={self.pfcxoff_point}"
                )
        else:
            ProbingObserver.console(
                f"[Step 1+2] chain disabled (enable_xoff_chain_probe=False); "
                f"using yaml pfcxoff_point={self.pfcxoff_point} directly"
            )

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
        # Build executor kwargs: only pass periodic-PAUSE tunables when
        # explicitly set via test_params (None = use executor's defaults).
        # This keeps the surface compatible while letting V9 cross-platform
        # runs override per-platform without code change (per code review I3).
        executor_kwargs = {"pfcxoff_point": self.pfcxoff_point}
        if self.pause_observation_window is not None:
            executor_kwargs["pause_observation_window"] = float(
                self.pause_observation_window
            )
        if self.pause_stop_tolerance is not None:
            executor_kwargs["pause_stop_tolerance"] = int(self.pause_stop_tolerance)

        executor = self.create_executor(
            self.PROBE_TARGET,
            observer,
            "xon_probe",
            **executor_kwargs,
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
        ProbingObserver.console(
            f"  src_port={src_port}, dst_drain={drain_port}, dst_holder={holder_port}"
        )
        ProbingObserver.console(f"  pfcxoff_point={self.pfcxoff_point} pg={self.pg}")
        ProbingObserver.console(f"  algorithm={algo_label}")
        ProbingObserver.console(f"  enable_xon_range_probe={self.enable_xon_range_probe}")
        ProbingObserver.console(f"  executor_env={self.EXECUTOR_ENV}")
        ProbingObserver.console("=" * 80)

        # Run probing
        lower, upper, elapsed = algorithm.run(src_port, drain_port, holder_port, **traffic_keys)

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
