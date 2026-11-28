"""Focused unit tests for cSONiC front-panel network capacity."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import patch

import pytest


pytestmark = [
    pytest.mark.topology("any"),
]


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = (
    REPO_ROOT / "ansible" / "roles" / "vm_set" / "library" /
    "csonic_network.py"
)


def _load_csonic_network():
    """Load the Ansible module without requiring docker-py on the test host."""
    ansible = ModuleType("ansible")
    module_utils = ModuleType("ansible.module_utils")
    basic = ModuleType("ansible.module_utils.basic")
    debug_utils = ModuleType("ansible.module_utils.debug_utils")
    docker = ModuleType("docker")
    basic.AnsibleModule = object
    debug_utils.config_module_logging = lambda *args, **kwargs: None
    stubs = {
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
        "ansible.module_utils.debug_utils": debug_utils,
        "docker": docker,
    }
    with patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location(
            "csonic_network", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


CSONIC_NETWORK = _load_csonic_network()


def _network(max_fp_num, num_fp_links):
    with patch.object(
            CSONIC_NETWORK.CsonicNetwork, "get_pid", return_value=1234):
        return CSONIC_NETWORK.CsonicNetwork(
            "net-vms-VM0100",
            "VM0100",
            "br-mgmt",
            0,
            max_fp_num,
            sonic_naming=False,
            num_fp_links=num_fp_links,
        )


def test_accepts_num_fp_links_equal_to_max_fp_num():
    network = _network(max_fp_num=31, num_fp_links=31)

    assert network.num_fp_links == 31


def test_rejects_num_fp_links_above_csonic_capacity():
    with pytest.raises(
            ValueError, match=r"num_fp_links 32.*cSONiC maximum 31"):
        _network(max_fp_num=32, num_fp_links=32)


def test_rejects_num_fp_links_greater_than_max_fp_num():
    with pytest.raises(
            ValueError, match=r"num_fp_links 5.*max_fp_num 4"):
        _network(max_fp_num=4, num_fp_links=5)
