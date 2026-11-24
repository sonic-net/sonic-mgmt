"""Offline coverage for preserve_config_db across SONiC upgrade entry points."""

import importlib.util
import ipaddress
from pathlib import Path
import runpy
import sys
import types
from unittest.mock import Mock, call

from jinja2 import Environment
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
IMAGE_URL = "https://images.example/sonic.bin"
PREV_IMAGE_URL = "https://images.example/previous.bin"
PRESERVE_CASES = [
    pytest.param({}, False, id="default"),
    pytest.param({"preserve_config_db": False}, False, id="explicit-false"),
    pytest.param({"preserve_config_db": True}, True, id="explicit-true"),
]


def stub_modules(monkeypatch, definitions):
    """Build isolated package trees without importing Ansible or DUT fixtures."""
    modules = {}
    for name, attributes in definitions.items():
        parts = name.split(".")
        for depth in range(1, len(parts) + 1):
            qualified_name = ".".join(parts[:depth])
            if qualified_name not in modules:
                module = types.ModuleType(qualified_name)
                module.__path__ = []
                modules[qualified_name] = module
                monkeypatch.setitem(sys.modules, qualified_name, module)
                if depth > 1:
                    setattr(modules[".".join(parts[:depth - 1])], parts[depth - 1], module)
        modules[name].__dict__.update(attributes)


def load_module(monkeypatch, name, *path):
    spec = importlib.util.spec_from_file_location(name, ROOT.joinpath(*path))
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sonic_module(monkeypatch):
    stub_modules(monkeypatch, {
        "devutil.devices.ansible_hosts": {
            "AnsibleHosts": object,
            "RunAnsibleModuleFailed": type("RunAnsibleModuleFailed", (Exception,), {}),
            "HostsUnreachable": type("HostsUnreachable", (Exception,), {}),
        },
        "devutil.devices.chassis_utils": {
            "is_chassis": Mock(return_value=False),
            "get_chassis_hostnames": Mock(),
            "ChassisCardType": Mock(),
        },
    })
    return load_module(monkeypatch, "devutil.devices.sonic", "ansible", "devutil", "devices", "sonic.py")


@pytest.mark.parametrize("options, expected", PRESERVE_CASES)
@pytest.mark.parametrize("entry_point", ["upgrade_image", "upgrade_by_sonic"])
def test_sonic_upgrade_propagates_to_installer(sonic_module, monkeypatch, options, expected, entry_point):
    """Both device helpers forward an omitted or explicit boolean to the installer."""
    hosts = Mock(SUPPORTED_UPGRADE_TYPES=["sonic", "onie"])
    localhost = Mock()
    post_upgrade = Mock(return_value=True)
    monkeypatch.setattr(sonic_module, "post_upgrade_actions", post_upgrade)

    assert getattr(sonic_module, entry_point)(hosts, localhost, IMAGE_URL, **(
        {"disk_used_percent": 61} if entry_point == "upgrade_by_sonic" else {}
    ), **options)

    disk_used_percent = 61 if entry_point == "upgrade_by_sonic" else 50
    hosts.reduce_and_add_sonic_images.assert_called_once_with(
        disk_used_pcent=disk_used_percent, new_image_url=IMAGE_URL,
        preserve_config_db=expected, module_attrs={"become": True})
    if entry_point == "upgrade_image":
        post_upgrade.assert_called_once_with(hosts, localhost, disk_used_percent)
    else:
        post_upgrade.assert_not_called()


@pytest.mark.parametrize("options, expected", PRESERVE_CASES)
def test_onie_does_not_receive_preservation_option(sonic_module, monkeypatch, options, expected):
    """The SONiC-only option does not change the ONIE or post-upgrade interfaces."""
    hosts = Mock(SUPPORTED_UPGRADE_TYPES=["sonic", "onie"])
    localhost = Mock()
    onie_upgrade = Mock(return_value=True)
    post_upgrade = Mock(return_value=True)
    monkeypatch.setattr(sonic_module, "upgrade_by_onie", onie_upgrade)
    monkeypatch.setattr(sonic_module, "post_upgrade_actions", post_upgrade)

    assert sonic_module.upgrade_image(
        hosts, localhost, IMAGE_URL, "onie", 61, 17, **options)

    onie_upgrade.assert_called_once_with(hosts, localhost, IMAGE_URL, 17)
    post_upgrade.assert_called_once_with(hosts, localhost, 61)
    hosts.reduce_and_add_sonic_images.assert_not_called()


@pytest.mark.parametrize("preserve", [False, True], ids=["default-false", "explicit-true"])
@pytest.mark.parametrize("pipeline", [False, True], ids=["upgrade-sonic-cli", "pipeline-cli"])
def test_cli_parsing_and_upgrade_calls(monkeypatch, sonic_module, preserve, pipeline):
    """Execute real CLI parsers and main functions, including both pipeline installs."""
    localhost = Mock()
    localhost.conn_graph_facts.return_value = {"ansible_facts": {}}
    hosts = Mock(hostnames=["switch"], sonic_version={"switch": {"build_version": "test"}})
    upgrade = Mock(return_value=True)
    monkeypatch.setattr(sonic_module, "upgrade_image", upgrade)
    stub_modules(monkeypatch, {
        "devutil.devices.factory": {
            "init_localhost": Mock(return_value=localhost),
            "init_testbed_sonichosts": Mock(return_value=hosts),
            "init_sonichosts": Mock(return_value=hosts),
        },
        "devutil.devices.dpu_utils": {"enable_nat_for_dpuhosts": Mock()},
        "common": {
            "get_pdu_managers": Mock(return_value={}),
            "check_reachability": Mock(return_value={"switch": True}),
        },
        "requests": {"head": Mock(return_value=Mock(status_code=200))},
        "setuptools": {"distutils": types.SimpleNamespace(util=types.SimpleNamespace(strtobool=Mock()))},
    })
    path = ROOT.joinpath(".azure-pipelines", "upgrade_image.py") if pipeline else ROOT.joinpath(
        "ansible", "upgrade_sonic.py")
    argv = [str(path), "-i", "inventory", "-t", "testbed", "-u", IMAGE_URL]
    if pipeline:
        argv += ["--prev-url", PREV_IMAGE_URL]
    if preserve:
        argv.append("--preserve-config-db")
    monkeypatch.setattr(sys, "argv", argv)
    # The pipeline adjusts sys.path; restore it after each script execution.
    monkeypatch.setattr(sys, "path", sys.path.copy())

    namespace = runpy.run_path(str(path), run_name="__main__")

    assert namespace["args"].preserve_config_db is preserve
    if pipeline:
        assert upgrade.call_args_list == [
            call(hosts, localhost, url, upgrade_type="sonic", onie_pause_time=30,
                 preserve_config_db=preserve)
            for url in [PREV_IMAGE_URL, IMAGE_URL]
        ]
    else:
        upgrade.assert_called_once_with(
            hosts, localhost, IMAGE_URL, upgrade_type="sonic", disk_used_percent=50,
            onie_pause_time=0, preserve_config_db=preserve)
    with pytest.raises(SystemExit) as error:
        namespace["parser"].parse_args(argv[1:] + ["--preserve-config-db=false"])
    assert error.value.code == 2


@pytest.fixture
def upgrade_helpers(monkeypatch):
    stub_modules(monkeypatch, {
        "tests.common.fixtures.grpc_fixtures": {},
        "tests.common.helpers.assertions": {"pytest_assert": Mock()},
        "tests.common.helpers.multi_thread_utils": {"SafeThreadPoolExecutor": Mock()},
        "tests.common.reboot": {
            "get_reboot_cause": Mock(), "reboot_ctrl_dict": {},
            "REBOOT_TYPE_WARM": "warm", "REBOOT_TYPE_COLD": "cold",
        },
        "tests.common.platform.reboot_utils": {"reboot_and_check": Mock()},
        "tests.common.utilities": {"wait_until": Mock(), "setup_ferret": Mock()},
        "tests.common.platform.device_utils": {"check_neighbors": Mock()},
    })
    return load_module(
        monkeypatch, "upgrade_helpers_propagation", "tests", "common", "helpers", "upgrade_helpers.py")


@pytest.mark.parametrize("options, expected", PRESERVE_CASES)
@pytest.mark.parametrize("image", [IMAGE_URL, "http://images.example/sonic.bin", "sonic.bin"],
                         ids=["https", "http", "local"])
def test_install_sonic_propagates_to_installer(upgrade_helpers, options, expected, image):
    """URL downloads and locally copied images preserve the explicitly selected policy."""
    hosts = Mock()
    hosts.get_extended_minigraph_facts.return_value = {
        "minigraph_mgmt_interface": {"gwaddr": "192.0.2.1"}}
    hosts.get_ip_route_info.return_value = {"nexthops": [(ipaddress.IPv4Address("192.0.2.1"), "eth0")]}
    hosts.command.return_value = {"stdout": "Avail\n3000M"}
    hosts.reduce_and_add_sonic_images.return_value = {
        "ansible_facts": {"downloaded_image_version": "target-version"}}

    assert upgrade_helpers.install_sonic(
        hosts, image, {}, skip_platform_check=True, **options) == "target-version"

    installer_args = {"skip_platform_check": True, "preserve_config_db": expected}
    if image == "sonic.bin":
        installer_args["save_as"] = "/host/downloaded-sonic-image"
        hosts.copy.assert_called_once_with(src=image, dest=installer_args["save_as"])
    else:
        installer_args["new_image_url"] = image
        hosts.copy.assert_not_called()
    hosts.reduce_and_add_sonic_images.assert_called_once_with(**installer_args)


def playbook_tasks(tasks):
    for task in tasks:
        yield task
        yield from playbook_tasks(task.get("block", []))


@pytest.mark.parametrize("options, expected", PRESERVE_CASES + [
    pytest.param({"preserve_config_db": "false"}, False, id="string-false"),
    pytest.param({"preserve_config_db": "true"}, True, id="string-true"),
])
def test_playbook_preserves_only_for_installation(options, expected):
    """Render the install argument with an offline bool filter; cleanup has no option."""
    with ROOT.joinpath("ansible", "upgrade_sonic.yml").open(encoding="utf-8") as stream:
        plays = yaml.safe_load(stream)
    installers = [
        task for play in plays for task in playbook_tasks(play["tasks"])
        if "reduce_and_add_sonic_images" in task
    ]
    install, cleanup = installers
    expression = install["args"]["preserve_config_db"]
    assert expression == "{{ preserve_config_db | default(false) | bool }}"
    # Only evaluates the asserted boolean expression above; no HTML or request data is rendered.
    environment = Environment(autoescape=True)  # nosemgrep: direct-use-of-jinja2
    # Match Ansible's bool filter for the supported inputs without importing Ansible.
    bool_filter = Mock(side_effect=lambda value: value in (True, "true"))
    environment.filters["bool"] = bool_filter
    rendered = environment.compile_expression(expression[2:-2])(**options)

    assert rendered is expected
    bool_filter.assert_called_once_with(options.get("preserve_config_db", False))
    assert cleanup["args"] == {"disk_used_pcent": "{{disk_used_pcent}}"}
