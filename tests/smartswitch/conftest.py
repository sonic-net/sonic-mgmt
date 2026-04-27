"""
Pytest fixtures for SmartSwitch tests.
"""
import pytest

from tests.smartswitch.common.device_utils_dpu import DPU_SYSLOG_ERROR_IGNORE_PATTERNS


@pytest.fixture(autouse=True)
def dpu_loganalyzer_ignore_patterns(dpuhosts, loganalyzer):
    """
    Feed DPU_SYSLOG_ERROR_IGNORE_PATTERNS into loganalyzer's ignore_regex
    for all DPU hosts so that known/expected syslog errors are suppressed
    automatically when loganalyzer runs with --dpu-pattern.
    """
    if not loganalyzer:
        return
    for dpuhost in dpuhosts:
        if dpuhost.hostname in loganalyzer:
            loganalyzer[dpuhost.hostname].ignore_regex.extend(
                DPU_SYSLOG_ERROR_IGNORE_PATTERNS
            )
