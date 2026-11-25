from pathlib import Path

import pytest


pytest_plugins = ["pytester"]


@pytest.mark.parametrize(
    "feature,features,running,exposed,mount_error,phase,outcome",
    [
        ("bmp", {}, False, None, None, "setup", "failed"),
        ("bmp", {"bmp": "enabled"}, False, None, None, "setup", "failed"),
        ("bmp", {"bmp": "disabled"}, False, None, None, "setup", "skipped"),
        ("pmon", {"pmon": "enabled"}, False, None, None, "setup", "skipped"),
        ("bmp", {"bmp": "enabled"}, True, None, None, "call", "passed"),
        ("bmp", {"bmp": "enabled"}, True, "/dev/sda1", None, "call", "failed"),
        ("bmp", {"bmp": "enabled"}, True, "/dev/sda", None, "call", "failed"),
        ("otel", {"otel": "enabled"}, True, None, "exec", "call", "failed"),
        ("radv", {"radv": "enabled"}, True, None, "missing", "call", "failed"),
    ],
    ids=["missing-feature", "stopped-container", "disabled", "exempt", "isolated-device",
         "exposed-partition", "exposed-base-device", "mount-exec-failed", "missing-hosts-mount"],
)
def test_block_device_prerequisite_classification(pytester, feature, features, running, exposed, mount_error,
                                                  phase, outcome):
    """Keep setup outcomes and device enforcement while diagnosing invalid mount evidence."""
    repo_root = Path(__file__).resolve().parents[3]
    config = pytester.makeini("[pytest]\nmarkers = topology: supported topologies\n")
    pytester.makepyfile(
        """
        import sys
        from unittest.mock import Mock

        import pytest

        sys.path.insert(0, {repo_root!r})
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
            if command.endswith(" mount"):
                if {mount_error!r} == "exec":
                    return {{"rc": 126, "stdout": "", "stderr": "mount unavailable", "failed": True}}
                mountpoint = "/etc/hosts.bak" if {mount_error!r} == "missing" else "/etc/hosts"
                return {{"rc": 0, "stdout": f"/dev/sda1 on {{mountpoint}} type ext4 (ro)", "stderr": ""}}
            if command.endswith(" /proc/self/mountinfo"):
                return {{"rc": 0, "stdout": "", "stderr": ""}}
            if "docker inspect --format" in command:
                return {{"rc": 0, "stdout": "container-under-test", "stderr": ""}}
            if " ls " in command:
                assert {mount_error!r} is None, "Invalid mount evidence must not reach ls"
                device = command.split()[-1]
                return {{"stdout": device if device == {exposed!r} else ""}}
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
        """.format(repo_root=str(repo_root), feature=feature, features=features, running=running,
                   exposed=exposed, mount_error=mount_error)
    )

    class Reports:
        def __init__(self):
            self.items = []

        def pytest_runtest_logreport(self, report):
            self.items.append(report)

    reports = Reports()
    result = pytester.runpytest_inprocess("-c", str(config), "--noconftest", "-q", plugins=[reports])
    summary_key = "errors" if phase == "setup" and outcome == "failed" else outcome
    result.assert_outcomes(**{summary_key: 1})
    report = next(item for item in reports.items if item.when == phase)
    assert report.outcome == outcome
    if phase == "setup":
        assert not any(item.when == "call" for item in reports.items)
        if outcome == "failed":
            assert "Prerequisite failed: container 'bmp' is not running" in str(report.longrepr)
    if mount_error == "exec":
        assert "rc=126, stderr='mount unavailable'" in str(report.longrepr)
    if mount_error == "missing":
        assert "Expected one /dev/ mount source for /etc/hosts in container 'radv', got []" in str(report.longrepr)
    if mount_error:
        log = "\n".join(content for title, content in report.sections if title.startswith("Captured log"))
        assert "hosts mountinfo: rc=0" in log
        assert "container ID: rc=0 stdout='container-under-test'" in log
    if exposed:
        assert "{} exists".format(exposed) in str(report.longrepr)
