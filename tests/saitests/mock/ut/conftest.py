#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pytest fixtures and configuration for probe unit tests"""

import pytest
import sys
import os

# Probe directory path (used by pytest_sessionstart for cache cleanup)
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)

from probing_observer import ProbingObserver  # noqa: E402
from executor_registry import ExecutorRegistry  # noqa: E402


@pytest.fixture(autouse=True)
def reset_executor_registry():
    """
    Automatically reset ExecutorRegistry before each test.

    This ensures test isolation by:
    1. Clearing the executor registry
    2. Clearing loaded modules cache
    3. Removing executor modules from sys.modules

    This fixture runs automatically before every test (autouse=True).
    """
    # Clear ExecutorRegistry state
    ExecutorRegistry.clear_registry()

    # Remove ALL probe modules from sys.modules to force fresh imports
    # This ensures complete test isolation
    probe_modules = [
        'ingress_drop_probing_executor',
        'pfc_xoff_probing_executor',
        'sim_ingress_drop_probing_executor',
        'sim_pfc_xoff_probing_executor',
        'observer_config',
        'probing_result',
        'buffer_occupancy_controller',
        'stream_manager',
        'upper_bound_probing_algorithm',
        'lower_bound_probing_algorithm',
        'threshold_range_probing_algorithm',
        'threshold_point_probing_algorithm',
        'iteration_outcome'
    ]
    for mod in probe_modules:
        if mod in sys.modules:
            del sys.modules[mod]

    yield  # Test runs here

    # Cleanup after test
    ExecutorRegistry.clear_registry()
    for mod in probe_modules:
        if mod in sys.modules:
            del sys.modules[mod]


@pytest.fixture
def mock_observer():
    """
    Minimal observer for unit tests.

    Delegates to ProbingObserver static methods which already have fallback:
    - console(): stderr output when sai_qos_tests unavailable
    - trace(): logging output when sai_qos_tests unavailable
    - error(): stderr output when sai_qos_tests unavailable
    """
    class SimpleObserver:
        trace = staticmethod(ProbingObserver.trace)
        console = staticmethod(ProbingObserver.console)
        error = staticmethod(lambda msg: ProbingObserver.console(f"[ERROR] {msg}"))

    return SimpleObserver()


def pytest_sessionstart(session):
    """
    Pytest hook: Clean up Python bytecode cache before test session starts.

    This prevents issues with stale .pyc files that can cause tests to run
    against old code even after source files have been modified.
    """
    import shutil

    # Clean __pycache__ in current directory
    cache_dir = os.path.join(os.path.dirname(__file__), '__pycache__')
    if os.path.exists(cache_dir):
        try:
            shutil.rmtree(cache_dir)
            print(f"[Cleanup] Removed {cache_dir}")
        except Exception as e:
            print(f"[Warning] Failed to remove {cache_dir}: {e}")

    # Clean __pycache__ in probe directory (to refresh imported modules)
    probe_cache = os.path.join(probe_dir, '__pycache__')
    if os.path.exists(probe_cache):
        try:
            shutil.rmtree(probe_cache)
            print(f"[Cleanup] Removed {probe_cache}")
        except Exception as e:
            print(f"[Warning] Failed to remove {probe_cache}: {e}")
