"""
Tests package for SONiC telemetry framework.

This package contains comprehensive tests for the telemetry framework:

- test_metrics.py: Tests for metric classes and collections using mock reporters
- test_reporters.py: Tests for DB and TS reporters with actual output verification
- metric_collections_baseline.json: Baseline data for metric collection tests

The tests use a divide-and-conquer approach where metrics are tested with mock
reporters to verify behavior, while reporters are tested for actual output.
"""
