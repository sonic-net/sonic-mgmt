from pathlib import Path

import pytest


pytest_plugins = ["pytester"]


@pytest.mark.parametrize(
    "feature,features,running,exposed,phase,outcome",
    [
        ("bmp", {}, False, False, "setup", "failed"),
        ("bmp", {"bmp": "enabled"}, False, False, "setup", "failed"),
        ("bmp", {"bmp": "disabled"}, False, False, "setup", "skipped"),
        ("pmon", {"pmon": "enabled"}, False, False, "setup", "skipped"),
        ("bmp", {"bmp": "enabled"}, True, False, "call", "passed"),
        ("bmp", {"bmp": "enabled"}, True, True, "call", "failed"),
    ],
    ids=["missing-feature", "stopped-container", "disabled", "exempt", "isolated-device", "exposed-device"],
)
def test_block_device_prerequisite_classification(pytester, feature, features, running, exposed, phase, outcome):
    repo_root = Path(__file__).resolve().parents[3]
    pytester.makepyfile(
        f"""
        import sys
        from unittest.mock import Mock

        import pytest

        sys.path.insert(0, {str(repo_root)!r})
        from tests.container_hardening.test_container_hardening import (
            block_device_test_container,
            test_container_block_device_mounted,
        )

        dut = Mock()
        dut.asic_instance.return_value.get_docker_name.return_value = {feature!r}
        dut.get_feature_status.return_value = ({features!r}, True)

        def shell(command, **kwargs):
            if command.startswith("docker ps"):
                return {{"stdout_lines": [{feature!r}] if {running!r} else []}}
            if "mount | grep" in command:
                return {{"rc": 0, "stdout": "/dev/sda1"}}
            if "'ls " in command:
                return {{"stdout": "/dev/sda1" if {exposed!r} else ""}}
            raise AssertionError("Unexpected command: " + command)

        dut.shell.side_effect = shell

        @pytest.fixture
        def duthosts():
            return {{"dut": dut}}

        @pytest.fixture
        def enum_rand_one_per_hwsku_hostname():
            return "dut"

        @pytest.fixture
        def enum_rand_one_asic_index():
            return 0

        @pytest.fixture
        def enum_dut_feature():
            return {feature!r}

        @pytest.fixture
        def vendor_specific_privileged_containers():
            return []
        """
    )

    class Reports:
        def __init__(self):
            self.items = []

        def pytest_runtest_logreport(self, report):
            self.items.append(report)

    reports = Reports()
    result = pytester.runpytest_inprocess("--noconftest", "-q", plugins=[reports])
    summary_key = "errors" if phase == "setup" and outcome == "failed" else outcome
    result.assert_outcomes(**{summary_key: 1})
    report = next(item for item in reports.items if item.when == phase)
    assert report.outcome == outcome
    if phase == "setup":
        assert not any(item.when == "call" for item in reports.items)
        if outcome == "failed":
            assert "Prerequisite failed: container 'bmp' is not running" in str(report.longrepr)
