#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pytest configuration for Probe Mock Tests
"""

import pytest


@pytest.fixture
def mock_observer():
    """Mock observer for simple tests (deprecated - use ProbingObserver)"""
    class MockObserver:
        def __init__(self):
            pass

        def on_iteration_start(self, *args, **kwargs):
            pass

        def on_iteration_complete(self, *args, **kwargs):
            pass
    return MockObserver()
