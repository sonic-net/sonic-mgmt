"""
Unit tests for PfcXonProbingExecutor (Physical Executor)

Tests initialization, parameter validation, prepare logic, fill phase
(with verification retries), drain phase, full check flow, and error
handling — all using mocked PTF dependencies.
"""

import pytest
from unittest.mock import MagicMock, patch

# sys.path injection is handled by conftest.py (probe_dir prepended);
# no per-file hardcoded path needed.

from observer_config import ObserverConfig  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


def _make_observer():
    config = ObserverConfig(
        probe_target="pfc_xon",
        algorithm_name="Test",
        strategy="test",
        check_column_title="Xon",
        table_column_mapping={}
    )
    return ProbingObserver("test", 1, observer_config=config)


def _make_ptftest(cnt_pg_idx=5):
    ptf = MagicMock()
    ptf.buffer_ctrl = MagicMock()
    ptf.src_client = MagicMock()
    ptf.asic_type = "broadcom"
    ptf.cnt_pg_idx = cnt_pg_idx
    return ptf


class TestPfcXonProbingExecutorInit:
    """Initialization and parameter validation."""

    def setup_method(self):
        self.observer = _make_observer()
        self.ptf = _make_ptftest()

    @pytest.mark.order(8800)
    def test_init_with_required_params(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        assert ex.ptftest is self.ptf
        assert ex.observer is self.observer
        assert ex.pfcxoff_point == 1000
        assert ex.holder_port == 29
        assert ex.verbose is False
        assert ex.name == ""
        assert ex.max_fill_attempts == 3
        assert ex.fill_retry_margin == 2
        assert ex.drain_settle_delay == 2  # default = PFC_TRIGGER_DELAY (per code review I3)

    @pytest.mark.order(8801)
    def test_init_rejects_zero_pfcxoff_point(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        with pytest.raises(ValueError, match="positive pfcxoff_point"):
            PfcXonProbingExecutor(
                ptftest=self.ptf, observer=self.observer, pfcxoff_point=0
            )

    @pytest.mark.order(8802)
    def test_init_rejects_none_pfcxoff_point(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        with pytest.raises(ValueError, match="positive pfcxoff_point"):
            PfcXonProbingExecutor(
                ptftest=self.ptf, observer=self.observer
            )

    @pytest.mark.order(8803)
    def test_init_rejects_negative_pfcxoff_point(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        with pytest.raises(ValueError, match="positive pfcxoff_point"):
            PfcXonProbingExecutor(
                ptftest=self.ptf, observer=self.observer, pfcxoff_point=-5
            )

    @pytest.mark.order(8804)
    def test_init_rejects_none_holder_port(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        with pytest.raises(ValueError, match="requires holder_port"):
            PfcXonProbingExecutor(
                ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
            )

    @pytest.mark.order(8805)
    def test_init_with_custom_tunables(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf,
            observer=self.observer,
            pfcxoff_point=500, holder_port=29,
            verbose=True,
            name="step3",
            max_fill_attempts=5,
            fill_retry_margin=4,
            drain_settle_delay=1.0,
            pause_observation_window=0.25,
            pause_stop_tolerance=10,
        )
        assert ex.verbose is True
        assert ex.name == "step3"
        assert ex.max_fill_attempts == 5
        assert ex.fill_retry_margin == 4
        assert ex.drain_settle_delay == 1.0
        assert ex.pause_observation_window == 0.25
        assert ex.pause_stop_tolerance == 10

    @pytest.mark.order(8806)
    def test_init_default_pause_window_and_tolerance(self):
        """Defaults: pause_observation_window=0.1s, pause_stop_tolerance=5."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        assert ex.pause_observation_window == 0.1
        assert ex.pause_stop_tolerance == 5


class TestPfcXonExecutorPrepare:
    """prepare() drains both dst ports and re-holds them."""

    def setup_method(self):
        self.observer = _make_observer()
        self.ptf = _make_ptftest()

    @pytest.mark.order(8810)
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_prepare_drains_and_holds_both_dsts(self, mock_sleep):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        ex.prepare(src_port=24, dst_port=28)

        # Both ports should be drained then held
        self.ptf.buffer_ctrl.drain_buffer.assert_called_once_with([28, 29])
        self.ptf.buffer_ctrl.hold_buffer.assert_called_once_with([28, 29])
        # 2 sleep calls (PORT_TX_CTRL_DELAY x 2)
        assert mock_sleep.call_count == 2


class TestPfcXonExecutorCheckRangeValidation:
    """check() rejects out-of-range D values."""

    def setup_method(self):
        self.observer = _make_observer()
        self.ptf = _make_ptftest()

    @pytest.mark.order(8820)
    def test_check_value_zero_returns_no_xon(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=0)
        assert success is True
        assert xon_fired is False
        # No traffic should be sent
        self.ptf.buffer_ctrl.send_traffic.assert_not_called()

    @pytest.mark.order(8821)
    def test_check_value_above_pfcxoff_point_returns_no_xon(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=1001)
        assert success is True
        assert xon_fired is False
        self.ptf.buffer_ctrl.send_traffic.assert_not_called()


class TestPfcXonExecutorCheckFlow:
    """End-to-end check() flow with mocked counters."""

    def setup_method(self):
        self.observer = _make_observer()
        self.ptf = _make_ptftest()

    @pytest.mark.order(8830)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_check_xon_fires(self, mock_sleep, mock_read):
        """xon fires: pre-fill=10, post-fill=11 (xoff fired). After drain,
        PAUSE counter has STOPPED (pause_t1=11, pause_t2=11, growth=0 <
        tolerance=5) — PFC released, xon fired.

        Note on counter values: physical hardware would show pause_t1 grow
        substantially during drain_settle_delay (~2200 pauses/sec on TH2,
        so ~4400 over 2s). These mocked values represent the IDEALIZED
        post-xon-fired state where periodic PAUSE has already stopped. The
        executor's decision logic depends only on pause_t2 - pause_t1, so
        this UT correctly exercises the xon-fired path with stable counter."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        # cnt_pg_idx=5
        pre_cnt = [10 if i == 5 else 0 for i in range(20)]
        post_fill_cnt = [11 if i == 5 else 0 for i in range(20)]   # xoff fired
        drain_t1_cnt = [11 if i == 5 else 0 for i in range(20)]    # counter froze
        drain_t2_cnt = [11 if i == 5 else 0 for i in range(20)]    # delta=0 < tolerance=5

        # Order of reads: pre-fill, post-fill, drain_t1, drain_t2
        mock_read.side_effect = [
            (pre_cnt, [0] * 10),
            (post_fill_cnt, [0] * 10),
            (drain_t1_cnt, [0] * 10),
            (drain_t2_cnt, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=5, pg=3)
        assert success is True
        assert xon_fired is True

        # Verify traffic split: 5 to A, 995 to B
        sends = self.ptf.buffer_ctrl.send_traffic.call_args_list
        assert len(sends) == 2
        assert sends[0][0] == (24, 28, 5)         # to A
        assert sends[1][0] == (24, 29, 995)       # to B (1000 - 5)
        assert sends[0][1] == {"pg": 3}

    @pytest.mark.order(8831)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_check_xon_does_not_fire(self, mock_sleep, mock_read):
        """xon does not fire: PAUSE counter still incrementing in observation
        window (delta=20 > tolerance=5) — PFC still asserted, xon not fired."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre_cnt = [10 if i == 5 else 0 for i in range(20)]
        post_fill_cnt = [11 if i == 5 else 0 for i in range(20)]    # xoff fired
        drain_t1_cnt = [11 if i == 5 else 0 for i in range(20)]
        drain_t2_cnt = [31 if i == 5 else 0 for i in range(20)]     # delta=20 > tolerance=5

        mock_read.side_effect = [
            (pre_cnt, [0] * 10),
            (post_fill_cnt, [0] * 10),
            (drain_t1_cnt, [0] * 10),
            (drain_t2_cnt, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=2, pg=3)
        assert success is True
        assert xon_fired is False

    @pytest.mark.order(8832)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_fill_retry_succeeds_on_second_attempt(self, mock_sleep, mock_read):
        """First fill attempt: xoff doesn't fire. Second attempt: fires
        (extra margin packets pushed it over). Drain then sees PAUSE
        counter freeze (xon fired)."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre_cnt = [10 if i == 5 else 0 for i in range(20)]

        # Attempt 1: pre=10, post=10 (no xoff)
        # Attempt 2: pre=10, post=11 (xoff fired with margin=2 extra)
        # After fill: drain phase reads pause_t1=11, pause_t2=11 (frozen = xon fired)
        attempt1_post_fill = [10 if i == 5 else 0 for i in range(20)]   # not fired
        attempt2_pre = [10 if i == 5 else 0 for i in range(20)]
        attempt2_post_fill = [11 if i == 5 else 0 for i in range(20)]   # fired
        drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        drain_t2 = [11 if i == 5 else 0 for i in range(20)]              # frozen = xon

        mock_read.side_effect = [
            (pre_cnt, [0] * 10),                # attempt 1 pre
            (attempt1_post_fill, [0] * 10),     # attempt 1 post
            (attempt2_pre, [0] * 10),           # attempt 2 pre
            (attempt2_post_fill, [0] * 10),     # attempt 2 post
            (drain_t1, [0] * 10),               # drain pause_t1
            (drain_t2, [0] * 10),               # drain pause_t2
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000,
            holder_port=29, max_fill_attempts=3, fill_retry_margin=2,
        )
        success, xon_fired = ex.check(24, 28, value=10, pg=3)
        assert success is True
        assert xon_fired is True

        # Verify second fill used margin=2 extra (so B got 990+2=992)
        sends = self.ptf.buffer_ctrl.send_traffic.call_args_list
        # Order: A=10/B=990 (attempt 1), A=10/B=992 (attempt 2)
        assert sends[0][0] == (24, 28, 10)
        assert sends[1][0] == (24, 29, 990)
        assert sends[2][0] == (24, 28, 10)
        assert sends[3][0] == (24, 29, 992)

    @pytest.mark.order(8833)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_fill_fails_after_max_retries(self, mock_sleep, mock_read):
        """All fill attempts fail to trigger xoff -> success=False."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        # Always pre=10, post=10 (xoff never fires)
        baseline = [10 if i == 5 else 0 for i in range(20)]
        max_attempts = 3
        # 2 reads per attempt
        mock_read.side_effect = [(baseline, [0] * 10) for _ in range(max_attempts * 2)]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000,
            holder_port=29, max_fill_attempts=max_attempts,
        )
        success, xon_fired = ex.check(24, 28, value=5, pg=3)
        assert success is False
        assert xon_fired is False

    @pytest.mark.order(8834)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_check_handles_exception_gracefully(self, mock_sleep, mock_read):
        """If counter read raises, return (False, False) instead of crashing."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        mock_read.side_effect = RuntimeError("PTF lost connection")

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=5, pg=3)
        assert success is False
        assert xon_fired is False


class TestPfcXonExecutorMultipleAttempts:
    """attempts > 1: outer verification loop."""

    def setup_method(self):
        self.observer = _make_observer()
        self.ptf = _make_ptftest()

    @pytest.mark.order(8840)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_attempts_2_consistent_xon(self, mock_sleep, mock_read):
        """2 attempts both report xon -> success.

        Per-attempt read order: pre, post-fill, drain_t1, drain_t2.
        xon means PAUSE counter is frozen between t1 and t2."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [10 if i == 5 else 0 for i in range(20)]
        post_fill = [11 if i == 5 else 0 for i in range(20)]
        drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        drain_t2 = [11 if i == 5 else 0 for i in range(20)]    # frozen = xon

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10),
            (drain_t1, [0] * 10), (drain_t2, [0] * 10),         # attempt 1
            (pre, [0] * 10), (post_fill, [0] * 10),
            (drain_t1, [0] * 10), (drain_t2, [0] * 10),         # attempt 2
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=5, pg=3, attempts=2)
        assert success is True
        assert xon_fired is True

    @pytest.mark.order(8841)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_attempts_2_inconsistent(self, mock_sleep, mock_read):
        """2 attempts disagree -> success=False.

        Attempt 1: PAUSE frozen (xon fired). Attempt 2: PAUSE still
        incrementing (xon NOT fired). Inconsistent -> success=False."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [10 if i == 5 else 0 for i in range(20)]
        post_fill = [11 if i == 5 else 0 for i in range(20)]
        # Attempt 1: drain frozen (xon)
        a1_drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        a1_drain_t2 = [11 if i == 5 else 0 for i in range(20)]
        # Attempt 2: drain still counting (no xon)
        a2_drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        a2_drain_t2 = [40 if i == 5 else 0 for i in range(20)]   # delta=29 > tol=5

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10),
            (a1_drain_t1, [0] * 10), (a1_drain_t2, [0] * 10),     # attempt 1: xon
            (pre, [0] * 10), (post_fill, [0] * 10),
            (a2_drain_t1, [0] * 10), (a2_drain_t2, [0] * 10),     # attempt 2: no xon
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000, holder_port=29)
        success, xon_fired = ex.check(24, 28, value=5, pg=3, attempts=2)
        assert success is False
        assert xon_fired is False


class TestPfcXonExecutorDrainStopDetection:
    """New UT (drain-bug fix 2026-05-08): boundary cases for the
    counter-stop detection logic."""

    def setup_method(self):
        self.observer = _make_observer()
        self.ptf = _make_ptftest()

    @pytest.mark.order(8850)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_drain_growth_below_tolerance_is_xon_fired(self, mock_sleep, mock_read):
        """Counter delta within tolerance (small noise) still counts as
        xon fired. tol=5, delta=4 -> xon fired."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [10 if i == 5 else 0 for i in range(20)]
        post_fill = [11 if i == 5 else 0 for i in range(20)]
        drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        drain_t2 = [15 if i == 5 else 0 for i in range(20)]   # delta=4 < tol=5 -> xon

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10),
            (drain_t1, [0] * 10), (drain_t2, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer,
            pfcxoff_point=1000, holder_port=29, pause_stop_tolerance=5,
        )
        success, xon_fired = ex.check(24, 28, value=5, pg=3)
        assert success is True
        assert xon_fired is True

    @pytest.mark.order(8851)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_drain_growth_equal_tolerance_is_xoff_active(self, mock_sleep, mock_read):
        """Boundary: delta == tolerance means PFC still active (xon NOT
        fired). The condition is strict: growth < tolerance."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [10 if i == 5 else 0 for i in range(20)]
        post_fill = [11 if i == 5 else 0 for i in range(20)]
        drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        drain_t2 = [16 if i == 5 else 0 for i in range(20)]   # delta=5 == tol=5 -> xoff active

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10),
            (drain_t1, [0] * 10), (drain_t2, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer,
            pfcxoff_point=1000, holder_port=29, pause_stop_tolerance=5,
        )
        success, xon_fired = ex.check(24, 28, value=5, pg=3)
        assert success is True
        assert xon_fired is False

    @pytest.mark.order(8852)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_drain_high_growth_is_pfc_still_active(self, mock_sleep, mock_read):
        """Counter delta way above tolerance (PFC at full periodic rate) ->
        xon NOT fired. This is the SCENARIO THAT EXPOSED THE ORIGINAL BUG
        on physical TH2: counter grew ~40 in 100ms window from periodic
        PFC PAUSE frames while xoff was still asserted."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [10 if i == 5 else 0 for i in range(20)]
        post_fill = [4080 if i == 5 else 0 for i in range(20)]   # high baseline (real-hw rate)
        drain_t1 = [4090 if i == 5 else 0 for i in range(20)]
        drain_t2 = [4130 if i == 5 else 0 for i in range(20)]    # delta=40 -> PFC active

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10),
            (drain_t1, [0] * 10), (drain_t2, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer,
            pfcxoff_point=1000, holder_port=29, pause_stop_tolerance=5,
        )
        success, xon_fired = ex.check(24, 28, value=1, pg=3)
        # With the OLD buggy logic, this would have returned xon_fired=True
        # because post_drain (4130) > baseline (4080). The new logic
        # correctly identifies that the PAUSE counter is still ramping
        # and reports xon_NOT fired.
        assert success is True
        assert xon_fired is False

    @pytest.mark.order(8853)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_drain_phase_uses_observation_window_sleep(self, mock_sleep, mock_read):
        """Verify _drain_phase actually waits pause_observation_window
        between the two PAUSE samples — exact count and ordering."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [10 if i == 5 else 0 for i in range(20)]
        post_fill = [11 if i == 5 else 0 for i in range(20)]
        drain_t1 = [11 if i == 5 else 0 for i in range(20)]
        drain_t2 = [11 if i == 5 else 0 for i in range(20)]

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10),
            (drain_t1, [0] * 10), (drain_t2, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer,
            pfcxoff_point=1000, holder_port=29,
            drain_settle_delay=0.5,
            pause_observation_window=0.25,
        )
        ex.check(24, 28, value=5, pg=3)

        # Tighten beyond mere `in` membership: verify exact count + ordering.
        # This locks in the contract that _drain_phase calls each sleep
        # exactly once and in the documented order (settle BEFORE window).
        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert sleep_args.count(0.5) == 1, \
            f"drain_settle_delay (0.5) should be slept exactly once: {sleep_args}"
        assert sleep_args.count(0.25) == 1, \
            f"pause_observation_window (0.25) should be slept exactly once: {sleep_args}"
        i_settle = sleep_args.index(0.5)
        i_window = sleep_args.index(0.25)
        assert i_settle < i_window, \
            f"drain_settle_delay must precede observation window: {sleep_args}"
