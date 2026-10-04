"""Unit tests for dual-ToR management metadata generation."""

import importlib.util
import ipaddress
import os
import sys
import types
from unittest import mock

import pytest
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from lxml import etree as ET
from lxml.etree import QName


EVOLUTION_NS = "Microsoft.Search.Autopilot.Evolution"
NETMUX_NS = "Microsoft.Search.Autopilot.NetMux"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"


def _load_dual_tor_facts():
    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = object
    dualtor_utils = types.ModuleType("ansible.module_utils.dualtor_utils")
    dualtor_utils.generate_mux_cable_facts = lambda **_: {}

    fake_modules = {
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
        "ansible.module_utils.dualtor_utils": dualtor_utils,
    }
    module_path = os.path.join(os.path.dirname(__file__), "dual_tor_facts.py")
    spec = importlib.util.spec_from_file_location("dual_tor_facts_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, fake_modules):
        spec.loader.exec_module(module)
    return module


def _load_minigraph_facts():
    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = object
    port_utils = types.ModuleType("ansible.module_utils.port_utils")
    port_utils.get_port_alias_to_name_map = lambda *_: {}
    port_utils.get_port_indices_for_asic = lambda *_: {}

    ipaddr = types.ModuleType("ipaddr")
    ipaddr.IPv4Address = ipaddress.IPv4Address
    ipaddr.IPv4Network = ipaddress.IPv4Network
    ipaddr.IPv6Address = ipaddress.IPv6Address
    ipaddr.IPv6Network = ipaddress.IPv6Network
    natsort = types.ModuleType("natsort")
    natsort.natsorted = sorted

    fake_modules = {
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
        "ansible.module_utils.port_utils": port_utils,
        "ipaddr": ipaddr,
        "natsort": natsort,
    }
    module_path = os.path.join(os.path.dirname(__file__), "minigraph_facts.py")
    spec = importlib.util.spec_from_file_location("minigraph_facts_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, fake_modules):
        spec.loader.exec_module(module)

    module.port_alias_to_name_map = {}
    module.port_alias_asic_map = {}
    module.port_alias_to_port_asic_alias_map = {}
    return module


dual_tor_facts = _load_dual_tor_facts()
minigraph_facts = _load_minigraph_facts()


def _jinja_bool(value):
    if isinstance(value, str):
        return value.lower() in ("1", "on", "true", "yes")
    return bool(value)


def _render_png(local_addresses, neighbor_addresses, local_transport, neighbor_transport):
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    # This test renders a repository-controlled XML template, not user-facing HTML.
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    environment = Environment(
        autoescape=True,
        loader=FileSystemLoader(template_dir),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["bool"] = _jinja_bool
    template = environment.get_template("minigraph_png.j2")
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    rendered = template.render(
        ansible_host=local_transport,
        card_type="supervisor",
        dual_tor_facts={
            "neighbor": {
                "hostname": "tor-b",
                "hwsku": "Test-HwSku",
                "ip": neighbor_transport,
            },
            "management_addresses": {
                "tor-a": local_addresses,
                "tor-b": neighbor_addresses,
            },
        },
        fabric_info=[],
        hwsku="Test-HwSku",
        inventory_hostname="tor-a",
        num_asics=1,
        VM_topo=False,
        vm_topo_config={"dut_type": "ToRRouter"},
        vms_number=0,
    )
    wrapped = (
        '<Root xmlns="{}" xmlns:i="{}">{}</Root>'
        .format(EVOLUTION_NS, XSI_NS, rendered)
    )
    return ET.fromstring(wrapped.encode("utf-8")).find(str(QName(EVOLUTION_NS, "PngDec")))


def _management_addresses(device):
    addresses = {}
    for family, element_name in (
        ("ipv4", "ManagementAddress"),
        ("ipv6", "ManagementAddressV6"),
    ):
        element = device.find(str(QName(EVOLUTION_NS, element_name)))
        if element is not None:
            addresses[family] = element.find(str(QName(NETMUX_NS, "IPPrefix"))).text
    return addresses


def _devices_by_hostname(png):
    devices = png.find(str(QName(EVOLUTION_NS, "Devices")))
    return {
        device.find(str(QName(EVOLUTION_NS, "Hostname"))).text: device
        for device in devices.findall(str(QName(EVOLUTION_NS, "Device")))
    }


def _parser(host_vars, use_ipv6_mgmt=False):
    return dual_tor_facts.DualTorParser(
        "tor-a",
        {"duts": ["tor-a", "tor-b"]},
        host_vars,
        {},
        [],
        [],
        None,
        use_ipv6_mgmt,
    )


def test_temporary_ipv4_outage_keeps_inventory_ipv4_metadata():
    """Transport fallback must not replace canonical IPv4 topology metadata."""
    parser = _parser({
        "tor-a": {
            "ansible_host": "2001:db8::1",
            "ansible_hostv6": "2001:db8::1",
            "original_ipv4_address": "10.0.0.1",
        },
        "tor-b": {
            "ansible_host": "2001:db8::2",
            "ansible_hostv6": "2001:db8::2",
            "original_ipv4_address": "10.0.0.2",
        },
    })

    parser.parse_management_addresses()

    assert parser.dual_tor_facts["management_addresses"] == {
        "tor-a": {"ipv4": "10.0.0.1", "ipv6": "2001:db8::1"},
        "tor-b": {"ipv4": "10.0.0.2", "ipv6": "2001:db8::2"},
    }


def test_explicit_ipv6_management_omits_ipv4_metadata():
    """Intentional IPv6-only deployment should advertise only IPv6 management."""
    parser = _parser({
        "tor-a": {
            "ansible_host": "10.0.0.1",
            "ansible_hostv6": "2001:db8::1",
            "original_ipv4_address": "10.0.0.1",
        },
        "tor-b": {
            "ansible_host": "10.0.0.2",
            "ansible_hostv6": "2001:db8::2",
            "original_ipv4_address": "10.0.0.2",
        },
    }, use_ipv6_mgmt=True)

    parser.parse_management_addresses()

    assert parser.dual_tor_facts["management_addresses"] == {
        "tor-a": {"ipv6": "2001:db8::1"},
        "tor-b": {"ipv6": "2001:db8::2"},
    }


def test_ipv6_only_inventory_does_not_fabricate_ipv4_metadata():
    """A true IPv6-only inventory should retain IPv6 without inventing IPv4."""
    parser = _parser({
        "tor-a": {"ansible_host": "2001:db8::1"},
        "tor-b": {
            "ansible_host": "2001:db8::2",
            "ansible_hostv6": "2001:db8::2",
        },
    })

    parser.parse_management_addresses()

    assert parser.dual_tor_facts["management_addresses"] == {
        "tor-a": {"ipv6": "2001:db8::1"},
        "tor-b": {"ipv6": "2001:db8::2"},
    }


def test_dual_stack_addresses_render_in_separate_elements():
    """Dual-stack metadata should render each address family in its own XML element."""
    png = _render_png(
        {"ipv4": "10.0.0.1", "ipv6": "2001:db8::1"},
        {"ipv4": "10.0.0.2", "ipv6": "2001:db8::2"},
        "2001:db8::1",
        "2001:db8::2",
    )
    devices = _devices_by_hostname(png)

    assert _management_addresses(devices["tor-a"]) == {
        "ipv4": "10.0.0.1",
        "ipv6": "2001:db8::1",
    }
    assert _management_addresses(devices["tor-b"]) == {
        "ipv4": "10.0.0.2",
        "ipv6": "2001:db8::2",
    }


def test_ipv6_only_metadata_never_uses_management_address():
    """IPv6-only inventory must not put an IPv6 value in ManagementAddress."""
    png = _render_png(
        {"ipv6": "2001:db8::1"},
        {"ipv6": "2001:db8::2"},
        "2001:db8::1",
        "2001:db8::2",
    )
    devices = _devices_by_hostname(png)

    assert _management_addresses(devices["tor-a"]) == {"ipv6": "2001:db8::1"}
    assert _management_addresses(devices["tor-b"]) == {"ipv6": "2001:db8::2"}


def test_ipv4_only_rendering_is_unchanged():
    """Existing IPv4-only dual-ToR metadata should remain unchanged."""
    png = _render_png(
        {"ipv4": "10.0.0.1"},
        {"ipv4": "10.0.0.2"},
        "10.0.0.1",
        "10.0.0.2",
    )
    devices = _devices_by_hostname(png)

    assert _management_addresses(devices["tor-a"]) == {"ipv4": "10.0.0.1"}
    assert _management_addresses(devices["tor-b"]) == {"ipv4": "10.0.0.2"}


@pytest.mark.parametrize("parser_name", ["parse_png", "parse_asic_png"])
def test_minigraph_facts_preserve_management_address_families(parser_name):
    """Minigraph facts should expose both IPv4 and IPv6 management metadata."""
    png = _render_png(
        {"ipv4": "10.0.0.1", "ipv6": "2001:db8::1"},
        {"ipv4": "10.0.0.2", "ipv6": "2001:db8::2"},
        "2001:db8::1",
        "2001:db8::2",
    )

    if parser_name == "parse_png":
        devices = minigraph_facts.parse_png(png, "tor-a")[1]
    else:
        devices = minigraph_facts.parse_asic_png(png, "asic0", "tor-a")[1]

    assert devices["tor-a"]["mgmt_addr"] == "10.0.0.1"
    assert devices["tor-a"]["mgmt_addr_v6"] == "2001:db8::1"
    assert devices["tor-b"]["mgmt_addr"] == "10.0.0.2"
    assert devices["tor-b"]["mgmt_addr_v6"] == "2001:db8::2"
