#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit Tests for SimPfcXonProbingExecutor + HardwareModel.

Tests sim executor behavior without PTF dependency:
- Registry contract: ExecutorRegistry.create('pfc_xon', 'sim', ...) works.
- HardwareModel physics: counter pumps in xoff, freezes after xon.
- Sim executor inherits real algorithm + overrides only counter seam.
"""

import pytest
import sys
import os
from unittest.mock import patch

# Add probe directory to path
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)


# =============================================================================
# HardwareModel direct tests
#
# Pin the simulation physics independently of executor / algorithm. Without
# these the drain-bug regression (counter periodic-pump while in xoff) could
# silently re-emerge if someone "optimizes" the model -- algorithm-level IT
# would still pass with a wrong model.
# =============================================================================

@pytest.mark.order(8810)
def test_hwmodel_pumps_counter_while_in_xoff():
    """While _in_xoff is True, every read_counter() bumps pause_counter
    by pause_rate_per_read. This is the periodic-PAUSE physics that the
    original buggy _drain_phase mistook for "xon not yet fired"."""
    from sim_pfc_xon_probing_executor import HardwareModel

    hw = HardwareModel(pfcxoff_point=100, true_xon_offset=10,
                       pause_rate_per_read=10)

    # Trigger xoff: queue fills above threshold.
    hw.send_traffic(src_port=0, dst_port=1, pkts=100)
    assert hw._in_xoff is True
    assert hw.pause_counter == 1  # initial xoff-fire event

    # 5 reads while still in xoff -> +50 (5 * pause_rate_per_read).
    for _ in range(5):
        hw.read_counter()
    assert hw.pause_counter == 1 + 5 * 10
    assert hw._in_xoff is True  # still xoff (no drain yet)


@pytest.mark.order(8811)
def test_hwmodel_freezes_counter_after_drain_crosses_xon():
    """drain_buffer with total_drained >= true_xon_offset releases
    PFC. Subsequent read_counter() calls must NOT bump (counter
    frozen). This is what the new _drain_phase detects via its
    2-sample observation window."""
    from sim_pfc_xon_probing_executor import HardwareModel

    hw = HardwareModel(pfcxoff_point=100, true_xon_offset=50,
                       pause_rate_per_read=10)

    hw.send_traffic(src_port=0, dst_port=1, pkts=100)  # xoff
    # Let counter pump while in xoff.
    for _ in range(3):
        hw.read_counter()
    snapshot = hw.pause_counter  # 1 + 3 * 10 = 31

    # Drain 100 pkts (>> true_xon_offset=50) -> xon released.
    hw.drain_buffer([1])
    assert hw._in_xoff is False

    # After release, reads must not bump anymore.
    for _ in range(5):
        hw.read_counter()
    assert hw.pause_counter == snapshot  # frozen at 31


@pytest.mark.order(8812)
def test_hwmodel_resets_xoff_when_queues_empty_below_xon():
    """If queues drain to empty but cumulative drain count is below
    true_xon_offset, the cleanup branch in drain_buffer (queues
    empty -> _in_xoff = False) still resets state so the next fill
    cycle starts clean. Defends against multi-port partial-drain
    scenarios where additive criterion alone might not fire."""
    from sim_pfc_xon_probing_executor import HardwareModel

    # true_xon_offset > pfcxoff_point so additive criterion can't fire
    # by the buffer alone (pathological config -- model invariant only).
    hw = HardwareModel(pfcxoff_point=100, true_xon_offset=200,
                       pause_rate_per_read=10)

    hw.send_traffic(src_port=0, dst_port=1, pkts=100)  # xoff
    assert hw._in_xoff is True

    # Drain 100 < true_xon_offset 200 -> additive criterion does NOT
    # fire. But queues become empty -> cleanup branch fires.
    hw.drain_buffer([1])
    assert hw.queues == {}
    assert hw._in_xoff is False  # cleanup branch reset

    # Next fill cycle is clean: xoff fires again, counter += 1.
    snapshot = hw.pause_counter
    hw.send_traffic(src_port=0, dst_port=2, pkts=100)
    assert hw._in_xoff is True
    assert hw.pause_counter == snapshot + 1


# =============================================================================
# SimPfcXonProbingExecutor — direct instantiation + executor protocol
# =============================================================================

@pytest.mark.order(8820)
def test_sim_executor_requires_true_xon_offset(mock_observer):
    """SimPfcXonProbingExecutor must reject construction without
    true_xon_offset (the answer the algorithm should converge to)."""
    from sim_pfc_xon_probing_executor import SimPfcXonProbingExecutor

    with pytest.raises(ValueError, match="true_xon_offset"):
        SimPfcXonProbingExecutor(
            observer=mock_observer,
            pfcxoff_point=8800,
            # missing true_xon_offset
        )


@pytest.mark.order(8821)
def test_sim_executor_check_drain_above_offset_fires_xon(mock_observer):
    """End-to-end check() with drain count above true_xon_offset:
    fill phase + drain phase + cleanup -> returns (True, True) i.e.
    xon fired."""
    from sim_pfc_xon_probing_executor import SimPfcXonProbingExecutor

    with patch('pfc_xon_probing_executor.time.sleep'):
        executor = SimPfcXonProbingExecutor(
            observer=mock_observer,
            pfcxoff_point=100,
            true_xon_offset=10,
        )
        # Drain 50 packets from dst_drain: 50 >= 10 (true_xon_offset) -> xon fires.
        success, xon_fired = executor.check(
            src_port=24, dst_port=28,
            value=50, attempts=1, pg=3,
        )

    assert success is True
    assert xon_fired is True


@pytest.mark.order(8822)
def test_sim_executor_check_drain_below_offset_xoff_active(mock_observer):
    """End-to-end check() with drain count below true_xon_offset:
    fill phase fires xoff, drain phase observes counter still pumping
    -> returns (True, False) i.e. xon NOT fired (xoff still active)."""
    from sim_pfc_xon_probing_executor import SimPfcXonProbingExecutor

    with patch('pfc_xon_probing_executor.time.sleep'):
        executor = SimPfcXonProbingExecutor(
            observer=mock_observer,
            pfcxoff_point=100,
            true_xon_offset=50,
        )
        # Drain 5 packets from dst_drain: 5 < 50 (true_xon_offset) -> xon NOT fired.
        # (The 95 remaining packets in dst_holder's queue keep total ingress
        # well above pfcxoff_point, so xoff stays asserted; counter pumps
        # via pause_rate_per_read=10 each read; window_growth >=
        # pause_stop_tolerance=5 -> xoff_active.)
        success, xon_fired = executor.check(
            src_port=24, dst_port=28,
            value=5, attempts=1, pg=3,
        )

    assert success is True
    assert xon_fired is False


# =============================================================================
# ExecutorRegistry contract
# =============================================================================

@pytest.mark.order(8830)
def test_sim_executor_registers_with_executor_registry(mock_observer):
    """sim_pfc_xon_probing_executor module registers with
    ExecutorRegistry under (probe_type='pfc_xon', executor_env='sim').
    ExecutorRegistry.create() returns a SimPfcXonProbingExecutor."""
    import importlib
    from executor_registry import ExecutorRegistry

    # Force fresh module import so the @register decorator runs.
    if 'sim_pfc_xon_probing_executor' in sys.modules:
        importlib.reload(sys.modules['sim_pfc_xon_probing_executor'])
    else:
        importlib.import_module('sim_pfc_xon_probing_executor')

    # Mark the module as loaded for ExecutorRegistry.create's import-once
    # convention (mirrors test_executor_registry.py pattern).
    ExecutorRegistry._loaded_modules.add('sim_pfc_xon_probing_executor')

    executor = ExecutorRegistry.create(
        'pfc_xon', 'sim',
        observer=mock_observer,
        pfcxoff_point=8800,
        true_xon_offset=13,
    )

    assert type(executor).__name__ == 'SimPfcXonProbingExecutor'
    # Inherits real executor's interface
    assert executor.pfcxoff_point == 8800
    # Sim-specific state
    assert executor.hw_model.true_xon_offset == 13
