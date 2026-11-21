"""Unit tests for get_portchannel_status in ansible/library/ptf_portchannel.py."""

import importlib.util
import os
import sys
import types

import pytest


def _load_ptf_portchannel_module():
    """Load ptf_portchannel with its load-time imports stubbed.

    The module imports ansible.module_utils.basic and jinja2 at load time,
    which only the sonic-mgmt container is sure to have. Stub them so the
    module's helpers can be unit-tested on any host.
    """
    jinja2 = types.ModuleType("jinja2")
    jinja2.Template = object

    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = object

    saved_modules = {}
    fake_modules = {
        "jinja2": jinja2,
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
    }
    for name, module in fake_modules.items():
        saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module

    try:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        module_path = os.path.join(repo_root, "ansible", "library", "ptf_portchannel.py")
        spec = importlib.util.spec_from_file_location("ptf_portchannel", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, module in saved_modules.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


ptf_portchannel = _load_ptf_portchannel_module()


class FakeModule(object):
    """Stands in for AnsibleModule: run_command() returns the given output."""

    def __init__(self, output):
        self.output = output
        self.commands = []

    def run_command(self, cmd):
        self.commands.append(cmd)
        return 0, self.output, ""

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs.get("msg"))


STATUS_LINE = "portchannel-PortChannel1         RUNNING   pid 3141, uptime 0:05:26\n"


@pytest.mark.parametrize("output", [
    # Python 3 Ansible: run_command() returns str.
    STATUS_LINE,
    # Python 2 Ansible: run_command() returns bytes.
    STATUS_LINE.encode("utf-8"),
], ids=["str", "bytes"])
def test_get_portchannel_status(output):
    module = FakeModule(output)
    assert ptf_portchannel.get_portchannel_status(module, "PortChannel1") == "RUNNING"
    assert module.commands == ["supervisorctl status portchannel-PortChannel1"]
