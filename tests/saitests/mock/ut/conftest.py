#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pytest fixtures and configuration for probe unit tests"""

import argparse
import logging
import pytest
import sys
import os

# Probe directory path (used by pytest_sessionstart for cache cleanup)
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)

from probing_observer import ProbingObserver  # noqa: E402
from executor_registry import ExecutorRegistry  # noqa: E402


def _is_option_registered(parser, option):
    """Return True if `option` is already declared by pytest or an installed plugin.

    conftest `pytest_addoption` hooks run after plugin hooks, so anything a plugin owns
    is already present on the parser by the time this file is processed. Re-declaring
    such an option makes argparse raise "conflicting option string" and pytest aborts
    before collecting a single test - that is what happens with `--cov*` whenever
    pytest-cov is installed (the Probe UT/IT CI job installs it), and with
    `--inventory`/`--host-pattern` whenever pytest-ansible is installed (the sonic-mgmt
    docker image ships it).
    """
    groups = [parser._anonymous] + list(getattr(parser, "_groups", []))
    for group in groups:
        for argument in getattr(group, "options", []):
            if option in argument.names():
                return True
    return False


def pytest_addoption(parser):
    """Accept SONiC nightly runner options that are unused by these unit tests.

    These unit tests ship their own pytest.ini, so pytest's rootdir is this directory
    and the repository level tests/conftest.py - which declares the nightly runner
    options - is never loaded. Without local no-op declarations pytest exits with
    "unrecognized arguments" before collection. Options that the running pytest
    installation already provides are left alone.
    """
    ignored_options = [
        ("--testbed", {"action": "store", "default": None}),
        ("--testbed_file", {"action": "store", "default": None}),
        ("--kube_master", {"action": "store", "default": None}),
        ("--topology", {"action": "store", "default": None}),
        ("--skip_pre_sanity", {"action": "store_true", "default": False}),
        ("--post_check", {"action": "store_true", "default": False}),
        ("--py_saithrift_url", {"action": "store", "default": None}),
        ("--sad_case_list", {"action": "store", "default": None}),
        ("--allow_recover", {"action": "store_true", "default": False}),
        ("--inventory", {"action": "store", "default": None}),
        ("--host-pattern", {"action": "store", "default": None}),
        ("--cov", {"action": "append", "default": []}),
        ("--cov-branch", {"action": "store_true", "default": False}),
        ("--cov-report", {"action": "append", "default": []}),
    ]
    for option, kwargs in ignored_options:
        if _is_option_registered(parser, option):
            continue
        try:
            parser.addoption(option, help="Ignored by saitests mock unit tests", **kwargs)
        except (ValueError, argparse.ArgumentError):
            # Belt and braces: the option is owned by something already registered, so
            # its own declaration wins and this no-op stub is not needed.
            logging.getLogger(__name__).debug("Option %s is already registered, skipping stub", option)


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
        'iteration_outcome',
        'pfc_xon_probing_executor',
        'sim_pfc_xon_probing_executor',
        'xon_drain_step_algorithm',
        'xon_drain_binary_algorithm'
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
