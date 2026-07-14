"""Unit tests for .azure-pipelines/testbed_health_check.py."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT_PATH = _REPO_ROOT / ".azure-pipelines" / "testbed_health_check.py"


def load_testbed_health_check():
    """Load the script without requiring the full Ansible runtime."""
    factory = ModuleType("devutil.devices.factory")
    factory.init_host = MagicMock()
    factory.init_localhost = MagicMock()
    factory.init_sonichosts = MagicMock()

    ansible_hosts = ModuleType("devutil.devices.ansible_hosts")
    ansible_hosts.HostsUnreachable = type("HostsUnreachable", (Exception,), {})
    ansible_hosts.RunAnsibleModuleFailed = type(
        "RunAnsibleModuleFailed", (Exception,), {}
    )

    dpu_utils = ModuleType("devutil.devices.dpu_utils")
    dpu_utils.is_nat_enabled_for_dpu = MagicMock()
    dpu_utils.enable_nat_for_dpuhosts = MagicMock()

    spec = importlib.util.spec_from_file_location(
        "testbed_health_check", _SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "devutil.devices.factory": factory,
            "devutil.devices.ansible_hosts": ansible_hosts,
            "devutil.devices.dpu_utils": dpu_utils,
        },
    ):
        spec.loader.exec_module(module)
    return module


testbed_health_check = load_testbed_health_check()


def make_checker():
    """Create a checker without contacting a testbed."""
    return testbed_health_check.TestbedHealthChecker(
        inventory=["inventory"],
        testbed_name="testbed",
        testbed_file="testbed.yaml",
        log_verbosity=0,
    )


def test_get_dut_basic_facts_rejects_uninitialized_config_db():
    """Report an empty CONFIG_DB without waiting indefinitely."""
    sonichosts = MagicMock()
    sonichosts.hostnames = ["dut-1", "dut-2"]
    sonichosts.command.return_value = {
        "dut-1": {"stdout": "0"},
    }

    with pytest.raises(
        testbed_health_check.HostInitFailed,
        match=r"CONFIG_DB is not initialized on host\(s\): dut-1, dut-2",
    ):
        make_checker()._get_dut_basic_facts(sonichosts)

    sonichosts.dut_basic_facts.assert_not_called()


def test_get_dut_basic_facts_uses_bounded_ansible_tasks():
    """Bound the CONFIG_DB probe and DUT fact gathering."""
    sonichosts = MagicMock()
    sonichosts.hostnames = ["dut-1"]
    sonichosts.command.return_value = {
        "dut-1": {"stdout": "1"},
    }
    expected_facts = {"dut-1": {"ansible_facts": {"dut_basic_facts": {}}}}
    sonichosts.dut_basic_facts.return_value = expected_facts

    result = make_checker()._get_dut_basic_facts(sonichosts)

    assert result == expected_facts
    sonichosts.command.assert_called_once_with(
        "sonic-db-cli CONFIG_DB GET CONFIG_DB_INITIALIZED",
        module_attrs={
            "async": testbed_health_check.CONFIG_DB_CHECK_TIMEOUT_SECONDS,
            "poll": testbed_health_check.ANSIBLE_POLL_INTERVAL_SECONDS,
        },
    )
    sonichosts.dut_basic_facts.assert_called_once_with(
        module_attrs={
            "async": testbed_health_check.DUT_BASIC_FACTS_TIMEOUT_SECONDS,
            "poll": testbed_health_check.ANSIBLE_POLL_INTERVAL_SECONDS,
        },
    )


def test_init_hosts_skips_dpu_with_uninitialized_config_db():
    """Keep optional DPU initialization failures non-fatal."""
    checker = make_checker()
    checker._get_testbed_dut_names = MagicMock(
        return_value=["npu-1", "dpu-1"]
    )
    checker.enable_nat_for_dpuhosts = MagicMock()

    npu_host = MagicMock()
    npu_host.hostname = "npu-1"
    npu_sonichosts = MagicMock()
    npu_sonichosts.__iter__.return_value = iter([npu_host])
    npu_sonichosts.__getitem__.return_value = npu_host
    dpu_sonichosts = MagicMock()
    combined_sonichosts = MagicMock()
    npu_facts = {
        "npu-1": {
            "ansible_facts": {
                "dut_basic_facts": {
                    "is_multi_asic": False,
                    "is_chassis": False,
                },
            },
        },
    }
    checker._get_dut_basic_facts = MagicMock(
        side_effect=[
            npu_facts,
            testbed_health_check.HostInitFailed(
                "CONFIG_DB is not initialized on host(s): dpu-1"
            ),
        ]
    )

    with patch.object(
        testbed_health_check,
        "init_localhost",
        return_value=MagicMock(),
    ), patch.object(
        testbed_health_check.logger,
        "warning",
    ), patch.object(
        testbed_health_check,
        "init_sonichosts",
        side_effect=[
            npu_sonichosts,
            dpu_sonichosts,
            combined_sonichosts,
        ],
    ) as init_sonichosts:
        checker.init_hosts()

    assert checker.dpu_hosts == []
    assert checker.sonichosts is combined_sonichosts
    assert init_sonichosts.call_args_list[-1].args[1] == ["npu-1"]
