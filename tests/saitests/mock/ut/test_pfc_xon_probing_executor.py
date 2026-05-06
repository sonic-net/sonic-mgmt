"""
Unit tests for PfcXonProbingExecutor (Physical Executor)

Tests initialization, parameter validation, prepare logic, fill phase
(with verification retries), drain phase, full check flow, and error
handling — all using mocked PTF dependencies.
"""

import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, r'c:\ws\repo\sonic-mgmt-int\sonic-mgmt-int\tests\saitests\probe')

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
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        assert ex.ptftest is self.ptf
        assert ex.observer is self.observer
        assert ex.pfcxoff_point == 1000
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
    def test_init_with_custom_tunables(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf,
            observer=self.observer,
            pfcxoff_point=500,
            verbose=True,
            name="step3",
            max_fill_attempts=5,
            fill_retry_margin=4,
            drain_settle_delay=1.0,
        )
        assert ex.verbose is True
        assert ex.name == "step3"
        assert ex.max_fill_attempts == 5
        assert ex.fill_retry_margin == 4
        assert ex.drain_settle_delay == 1.0


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
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        ex.prepare(src_port=24, dst_port_a=28, dst_port_b=29)

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
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=0)
        assert success is True
        assert xon_fired is False
        # No traffic should be sent
        self.ptf.buffer_ctrl.send_traffic.assert_not_called()

    @pytest.mark.order(8821)
    def test_check_value_above_pfcxoff_point_returns_no_xon(self):
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=1001)
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
        """xon fires: pre-fill PAUSE=10, post-fill PAUSE=11 (xoff fired),
        post-drain PAUSE=12 (xoff re-fired = xon was triggered)."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        # cnt_pg_idx=5
        pre_cnt = [0] * 20; pre_cnt[5] = 10
        post_fill_cnt = [0] * 20; post_fill_cnt[5] = 11      # xoff fired
        post_drain_cnt = [0] * 20; post_drain_cnt[5] = 12    # xon resumed

        # Order of reads: pre-fill, post-fill, post-drain
        mock_read.side_effect = [
            (pre_cnt, [0] * 10),
            (post_fill_cnt, [0] * 10),
            (post_drain_cnt, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=5, pg=3)
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
        """xon does not fire: post-drain counter stays at baseline."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre_cnt = [0] * 20; pre_cnt[5] = 10
        post_fill_cnt = [0] * 20; post_fill_cnt[5] = 11      # xoff fired
        post_drain_cnt = [0] * 20; post_drain_cnt[5] = 11    # no change = xon NOT fired

        mock_read.side_effect = [
            (pre_cnt, [0] * 10),
            (post_fill_cnt, [0] * 10),
            (post_drain_cnt, [0] * 10),
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=2, pg=3)
        assert success is True
        assert xon_fired is False

    @pytest.mark.order(8832)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_fill_retry_succeeds_on_second_attempt(self, mock_sleep, mock_read):
        """First fill attempt: xoff doesn't fire. Second attempt: fires
        (extra margin packets pushed it over)."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre_cnt = [0] * 20; pre_cnt[5] = 10

        # Attempt 1: pre=10, post=10 (no xoff)
        # Attempt 2: pre=10, post=11 (xoff fired with margin=2 extra)
        # After fill: drain phase reads post_drain=12 (xon)
        attempt1_post_fill = [0] * 20; attempt1_post_fill[5] = 10  # not fired
        attempt2_pre = [0] * 20; attempt2_pre[5] = 10
        attempt2_post_fill = [0] * 20; attempt2_post_fill[5] = 11  # fired
        post_drain = [0] * 20; post_drain[5] = 12                  # xon

        mock_read.side_effect = [
            (pre_cnt, [0] * 10),                # attempt 1 pre
            (attempt1_post_fill, [0] * 10),     # attempt 1 post
            (attempt2_pre, [0] * 10),           # attempt 2 pre
            (attempt2_post_fill, [0] * 10),     # attempt 2 post
            (post_drain, [0] * 10),             # drain phase
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000,
            max_fill_attempts=3, fill_retry_margin=2,
        )
        success, xon_fired = ex.check(24, 28, 29, value=10, pg=3)
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
        baseline = [0] * 20; baseline[5] = 10
        max_attempts = 3
        # 2 reads per attempt
        mock_read.side_effect = [(baseline, [0] * 10) for _ in range(max_attempts * 2)]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000,
            max_fill_attempts=max_attempts,
        )
        success, xon_fired = ex.check(24, 28, 29, value=5, pg=3)
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
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=5, pg=3)
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
        """2 attempts both report xon -> success."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        # Pattern per attempt: pre, post-fill (xoff fired), post-drain (xon)
        pre = [0] * 20; pre[5] = 10
        post_fill = [0] * 20; post_fill[5] = 11
        post_drain = [0] * 20; post_drain[5] = 12

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10), (post_drain, [0] * 10),  # attempt 1
            (pre, [0] * 10), (post_fill, [0] * 10), (post_drain, [0] * 10),  # attempt 2
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=5, pg=3, attempts=2)
        assert success is True
        assert xon_fired is True

    @pytest.mark.order(8841)
    @patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_port_24"}})
    @patch('pfc_xon_probing_executor.sai_thrift_read_port_counters')
    @patch('pfc_xon_probing_executor.time.sleep')
    def test_attempts_2_inconsistent(self, mock_sleep, mock_read):
        """2 attempts disagree -> success=False."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor

        pre = [0] * 20; pre[5] = 10
        post_fill = [0] * 20; post_fill[5] = 11
        post_drain_xon = [0] * 20; post_drain_xon[5] = 12   # xon fired
        post_drain_no_xon = [0] * 20; post_drain_no_xon[5] = 11  # no xon

        mock_read.side_effect = [
            (pre, [0] * 10), (post_fill, [0] * 10), (post_drain_xon, [0] * 10),     # attempt 1: xon
            (pre, [0] * 10), (post_fill, [0] * 10), (post_drain_no_xon, [0] * 10),  # attempt 2: no xon
        ]

        ex = PfcXonProbingExecutor(
            ptftest=self.ptf, observer=self.observer, pfcxoff_point=1000
        )
        success, xon_fired = ex.check(24, 28, 29, value=5, pg=3, attempts=2)
        assert success is False
        assert xon_fired is False
