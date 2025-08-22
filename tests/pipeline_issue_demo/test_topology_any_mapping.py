import pytest
import logging

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]

"""
This test demonstrates a pipeline issue where tests marked with topology('any')
are not mapped to specialized topology checkers like:
- dpu_checker
- dualtor_checker  
- t1-multi-asic_checker (shown as multi-asic-t1 in pipeline)
- t0-2vlans_checker
- t0-sonic_checker

The issue occurs in .azure-pipelines/impacted_area_testing/get_test_scripts.py
where topology('any') only maps to t0_checker, t1_checker, and t2_checker.

This causes the pipeline to fail with:
"calculate_instance_number.py: error: argument --scripts: expected one argument"

Because SCRIPTS variable is empty for these specialized topologies.
"""


def test_dummy_for_any_topology():
    """
    Dummy test to demonstrate the pipeline issue.
    This test should run on ANY topology, but the pipeline
    fails to recognize it for specialized topologies.
    """
    logger.info("This test should run on any topology")
    assert True, "This is a dummy test"