"""Unit tests for the cSONiC userspace-OVS LAG helper."""

import importlib.util
import os


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
_MODULE_PATH = os.path.join(
    _REPO_ROOT, "ansible", "roles", "sonic", "files", "csonic_ovs_lag.py")
_DOCKERFILE_PATH = os.path.join(
    _REPO_ROOT, "ansible", "roles", "vm_set", "files",
    "csonic-userspace-ovs.Dockerfile")
_CSONIC_TASK_PATH = os.path.join(
    _REPO_ROOT, "ansible", "roles", "sonic", "tasks", "csonic.yml")
_SPEC = importlib.util.spec_from_file_location("csonic_ovs_lag", _MODULE_PATH)
csonic_ovs_lag = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(csonic_ovs_lag)


def test_userspace_ovs_image_bakes_macsec_runtime_dependencies():
    with open(_DOCKERFILE_PATH, encoding="utf-8") as dockerfile:
        contents = dockerfile.read()

    assert "openvswitch-switch" in contents
    assert "CONFIG_DRIVER_MACSEC_SONIC=y" in contents
    assert "macsec_sonic" in contents
    assert "/etc/wpa_supplicant.conf" in contents
    assert "/etc/supervisor/conf.d/sonic-mgmt-macsec.conf" in contents
    assert "autostart=false" in contents
    assert "apt-get install -y --no-install-recommends \\\n        wpasupplicant" not in contents


def test_userspace_ovs_provisions_host_macsec_kernel_module():
    with open(_CSONIC_TASK_PATH, encoding="utf-8") as task_file:
        contents = task_file.read()

    assert "command: modprobe macsec" in contents
    assert "linux-modules-extra-{{ csonic_macsec_host_kernel.stdout | trim }}" in contents
    assert "name: macsec" in contents
    assert contents.count("csonic_lag_backend == 'userspace_ovs'") >= 4
    assert contents.count("SONIC_MGMT_CSONIC_MACSEC") >= 4


def test_missing_addresses_compares_canonical_exact_ips():
    address_output = "\n".join([
        "10: PortChannel1 inet 10.0.0.10/31 scope global PortChannel1",
        "10: PortChannel1 inet6 fc00::2/126 scope global",
        "10: PortChannel1 inet6 fc00::2a/126 scope global",
    ])
    expected = [
        "FC00::2/126",
        "fc00::2A/126",
        "10.0.0.1/31",
        "10.0.0.10/31",
        "2001:DB8::1/64",
    ]

    assert csonic_ovs_lag._missing_addresses(expected, address_output) == [
        "10.0.0.1/31",
        "2001:DB8::1/64",
    ]


def test_kernel_member_uses_port_order_for_noncontiguous_names(monkeypatch):
    monkeypatch.setattr(
        csonic_ovs_lag.os, "listdir",
        lambda path: ["eth0", "eth1", "eth2", "Ethernet0", "Ethernet4"])

    assert csonic_ovs_lag.kernel_member("Ethernet0") == "eth1"
    assert csonic_ovs_lag.kernel_member("Ethernet4") == "eth2"
