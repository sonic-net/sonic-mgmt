"""parametrize_vlan_config_from_topo -- unified multi-vlan fixture.

Auto-parametrizes any test that names ``parametrize_vlan_config_from_topo``
across every variant the topo yaml's ``DUT.vlan_configs`` block defines
(``one_vlan_a``, ``two_vlan_a``, ``four_vlan_a``, ...). Auto-parametrize hook
lives in ``tests/conftest.py``.

Builds an atomic CONFIG_DB JSON patch from the variant, applies via
``config apply-patch`` + ``config save -y``. Teardown applies the reverse
patch back to the topo's ``default_vlan_config``. Supports dualtor MUX_CABLE
and dualtor-shared mac.
"""

import ipaddress
import json
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require

logger = logging.getLogger(__name__)


def vlan_n2i(vlan_name):
    """Convert vlan name to vlan id."""
    return vlan_name.replace("Vlan", "")


def add_vlan_patch(vlan_name, dhcp_servers, dhcpv6_servers, vlan_intf_value=None, mac=None):
    if vlan_intf_value is None:
        vlan_intf_value = {}
    patch = [
        {
            "op": "add",
            "path": "/VLAN/%s" % vlan_name,
            "value": {
                "vlanid": vlan_n2i(vlan_name)
            }
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/%s" % vlan_name,
            "value": vlan_intf_value
        }
    ]
    if mac:
        patch[0]["value"]["mac"] = mac
    if dhcp_servers:
        patch[0]["value"]["dhcp_servers"] = dhcp_servers
    if dhcpv6_servers:
        patch[0]["value"]["dhcpv6_servers"] = dhcpv6_servers
    return patch


def remove_vlan_patch(vlan_name):
    return [
        {
            "op": "remove",
            "path": "/VLAN/%s" % vlan_name
        },
        {
            "op": "remove",
            "path": "/VLAN_INTERFACE/%s" % vlan_name
        }
    ]


def add_dhcp_relay_patch(vlan_name, dhcpv4_servers=None, dhcpv6_servers=None):
    """Build a JSON patch that creates the /DHCP_RELAY/<vlan> entry with
    whichever server lists are non-empty. Emits one atomic `add` op so that
    a vlan with both v4 and v6 relay servers ends up with both keys in the
    same value dict (a separate v4 then v6 add would overwrite)."""
    value = {}
    if dhcpv4_servers:
        value["dhcpv4_servers"] = dhcpv4_servers
    if dhcpv6_servers:
        value["dhcpv6_servers"] = dhcpv6_servers
    return [{
        "op": "add",
        "path": "/DHCP_RELAY/%s" % vlan_name,
        "value": value,
    }]


def remove_dhcp_relay_patch(vlan_name):
    return [{
        "op": "remove",
        "path": "/DHCP_RELAY/%s" % vlan_name,
    }]


def add_vlan_member_patch(vlan_name, member_name):
    return [{
        "op": "add",
        "path": "/VLAN_MEMBER/%s|%s" % (vlan_name, member_name),
        "value": {
            "tagging_mode": "untagged"
        }
    }]


def remove_vlan_member_patch(vlan_name, member_name):
    return [{
        "op": "remove",
        "path": "/VLAN_MEMBER/%s|%s" % (vlan_name, member_name)
    }]


def add_vlan_ip_patch(vlan_name, ip):
    return [{
        "op": "add",
        "path": "/VLAN_INTERFACE/%s|%s" % (vlan_name, ip.replace('/', '~1')),
        "value": {}
    }]


def remove_vlan_ip_patch(vlan_name, ip):
    return [{
        "op": "remove",
        "path": "/VLAN_INTERFACE/%s|%s" % (vlan_name, ip.replace('/', '~1'))
    }]


def _parse_intf_index(host_intf_str):
    """Parse a host_interfaces entry like '0.5,1.5' or '0.5@10,1.5@10' and
    return the integer intf_idx (the part after the first '.', before any '@').
    Mirrors `ansible/module_utils/dualtor_utils.py::get_intf_index`.
    """
    first = host_intf_str.split(",")[0]
    parts = re.split(r"\.|@", first.strip())
    try:
        return int(parts[1])
    except (IndexError, ValueError):
        return None


def add_mux_cable_patch(intf_name, cable_type, server_ipv4, server_ipv6, soc_ipv4=None):
    """Build a JSON patch that creates the /MUX_CABLE/<intf> entry."""
    value = {
        "cable_type": cable_type,
        "server_ipv4": server_ipv4,
        "server_ipv6": server_ipv6,
        "state": "auto",
    }
    if soc_ipv4 is not None:
        value["soc_ipv4"] = soc_ipv4
    return [{
        "op": "add",
        "path": "/MUX_CABLE/%s" % intf_name,
        "value": value,
    }]


def remove_mux_cable_patch(intf_name):
    return [{
        "op": "remove",
        "path": "/MUX_CABLE/%s" % intf_name,
    }]


def _compute_mux_cable_entries(variant, aa_intf_set, intf_index_to_dut_name):
    """Return list of (dut_port_name, mux_cable_value_dict) tuples for the
    requested variant. Mirrors
    `ansible/module_utils/dualtor_utils.py::generate_mux_cable_facts` but
    emits the host-mask form (/32 and /128) that sonic-cfggen writes into
    CONFIG_DB when rendering minigraph, rather than the vlan-prefix mask
    form the original algorithm returns.

    The active-active branch is taken only for intf_idx values present in
    `aa_intf_set`; when the topology has no active-active list (plain
    dualtor), all entries are active-standby.
    """
    entries = []
    for vlan_name, vparams in variant.items():
        prefix_v4 = vparams.get("prefix")
        prefix_v6 = vparams.get("prefix_v6")
        if not prefix_v4 or not prefix_v6:
            continue
        v4_addr, _v4_mask = prefix_v4.split("/")
        v6_addr, _v6_mask = prefix_v6.split("/")
        v4_base = ipaddress.ip_address(v4_addr)
        v6_base = ipaddress.ip_address(v6_addr)
        for index, intf_idx in enumerate(vparams.get("intfs", []) or []):
            dut_port = intf_index_to_dut_name(intf_idx)
            if dut_port is None:
                continue
            is_aa = (intf_idx in aa_intf_set) if aa_intf_set else False
            if is_aa:
                entries.append((dut_port, {
                    "cable_type": "active-active",
                    "server_ipv4": "%s/32" % (v4_base + index * 2 + 1),
                    "server_ipv6": "%s/128" % (v6_base + index * 2 + 1),
                    "soc_ipv4": "%s/32" % (v4_base + (index + 1) * 2),
                    "state": "auto",
                }))
            else:
                entries.append((dut_port, {
                    "cable_type": "active-standby",
                    "server_ipv4": "%s/32" % (v4_base + index + 1),
                    "server_ipv6": "%s/128" % (v6_base + index + 1),
                    "state": "auto",
                }))
    return entries


def apply_config_patch(duthost, config_to_apply):
    logger.debug("The config patch: %s", config_to_apply)
    tmpfile = duthost.shell('mktemp')['stdout']
    try:
        duthost.copy(content=json.dumps(config_to_apply, indent=4), dest=tmpfile)
        output = duthost.shell('config apply-patch {}'.format(tmpfile), module_ignore_errors=True)
        pytest_assert(
            not output['rc'],
            "apply-patch failed: rc=%s stdout=%s stderr=%s" % (
                output['rc'],
                (output.get('stdout') or '')[:500],
                (output.get('stderr') or '')[:500],
            ),
        )
        pytest_assert(
            "Patch applied successfully" in output['stdout'],
            "apply-patch returned rc=0 but no success line; stdout=%s" % (
                (output.get('stdout') or '')[:500],
            ),
        )
    finally:
        duthost.file(path=tmpfile, state='absent')


def _generate_config_patch_from_variant(duthost, tbinfo, variant_name):
    """Build the JSON config-patch and sub_vlans_info structure for the
    requested variant. See module docstring for the returned schema.
    """
    topo_name = tbinfo["topo"]["name"]
    topo_dut = tbinfo.get("topo", {}).get("properties", {}).get("topology", {}).get("DUT", {})
    vlan_configs = topo_dut.get("vlan_configs")
    pytest_require(
        vlan_configs,
        "Topo {} does not define a DUT.vlan_configs block; "
        "parametrize_vlan_config_from_topo not applicable".format(topo_name),
    )
    pytest_require(
        variant_name in vlan_configs,
        "Variant {!r} not defined in topo {}; available variants: {}".format(
            variant_name, topo_name,
            [k for k in vlan_configs.keys() if k != "default_vlan_config"],
        ),
    )
    variant = vlan_configs[variant_name]

    # Read what's currently deployed so we know what to remove.
    running_config = duthost.get_running_config_facts()
    current_vlan_names = list(running_config.get("VLAN", {}).keys())
    # DHCP and DHCP_RELAY servers carry forward from the deployed config.
    # Look up per-Vlan by exact name (covers same-name swaps), fall back to
    # the first deployed Vlan's servers for variants that rename Vlans.
    deployed_vlan = running_config.get("VLAN", {})
    deployed_relay = running_config.get("DHCP_RELAY", {})
    fallback_vlan = current_vlan_names[0] if current_vlan_names else None

    def _carry(vlan_name, table, key):
        entry = table.get(vlan_name) or (
            table.get(fallback_vlan, {}) if fallback_vlan else {}
        )
        return entry.get(key, []) or []

    # Build remove ops for every currently-deployed Vlan + its IPs + members
    # + DHCP_RELAY entry.
    vlan_intfs = running_config.get("VLAN_INTERFACE", {})
    vlan_members = running_config.get("VLAN_MEMBER", {})
    dhcp_relay = running_config.get("DHCP_RELAY", {})
    config_patch = []
    for vlan_name in current_vlan_names:
        config_patch += remove_vlan_patch(vlan_name)
        if vlan_name in dhcp_relay:
            config_patch += remove_dhcp_relay_patch(vlan_name)
        # Only ip-bearing entries (vlan|ip/prefix); bare vlan removed above.
        for key in list(vlan_intfs.get(vlan_name, {}).keys()):
            if "/" in key:
                config_patch += remove_vlan_ip_patch(vlan_name, key)
        for member in list(vlan_members.get(vlan_name, {}).keys()):
            config_patch += remove_vlan_member_patch(vlan_name, member)

    # Dualtor MUX_CABLE: detected via running CONFIG_DB; remove deployed
    # entries (re-emitted in the add phase below).
    running_mux_cable = running_config.get("MUX_CABLE", {})
    is_dualtor_mux = bool(running_mux_cable)
    if is_dualtor_mux:
        for intf_name in list(running_mux_cable.keys()):
            config_patch += remove_mux_cable_patch(intf_name)

    # Resolve intf_idx -> dut_port via extended minigraph facts.
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    dut_intf_to_ptf_index = minigraph_facts["minigraph_ptf_indices"]

    _ptf_idx_to_dut_port = {v: k for k, v in dut_intf_to_ptf_index.items()}

    def _intf_index_to_dut_name(idx):
        return _ptf_idx_to_dut_port.get(idx)

    # Dualtor topologies need proxy_arp+grat_arp set on every VLAN_INTERFACE
    # entry (mirrors sonic-config-engine/minigraph.py which sets these when
    # PEER_SWITCH is present).
    is_dualtor_topo = "dualtor" in tbinfo.get("topo", {}).get("name", "")
    vlan_intf_value = (
        {"proxy_arp": "enabled", "grat_arp": "enabled"}
        if is_dualtor_topo else None
    )

    sub_vlans_info = []
    for vlan_name, vparams in variant.items():
        ipv4 = vparams.get("prefix")
        ipv6 = vparams.get("prefix_v6")
        ipv4_secondary = vparams.get("secondary_subnet")
        mac = vparams.get("mac")
        intf_indices = vparams.get("intfs", []) or []

        # Build (dut_port, ptf_idx) pairs. By construction ptf_idx == idx
        # whenever _intf_index_to_dut_name(idx) resolves.
        members_with_ptf_idx = [
            (_intf_index_to_dut_name(idx), idx)
            for idx in intf_indices
            if _intf_index_to_dut_name(idx) is not None
        ]

        sub_vlans_info.append({
            "vlan_name": vlan_name,
            "interface_ipv4": ipv4,
            "interface_ipv4_secondary": ipv4_secondary,
            "interface_ipv6": ipv6,
            "members_with_ptf_idx": members_with_ptf_idx,
            "vlan_plan": variant_name,
        })

        # Per-VLAN carry-forward of dhcp servers / dhcp_relay servers.
        dhcp_servers = _carry(vlan_name, deployed_vlan, "dhcp_servers")
        dhcpv6_servers = _carry(vlan_name, deployed_vlan, "dhcpv6_servers")
        relay_v4 = _carry(vlan_name, deployed_relay, "dhcpv4_servers")
        relay_v6 = _carry(vlan_name, deployed_relay, "dhcpv6_servers")

        config_patch += add_vlan_patch(
            vlan_name, dhcp_servers, dhcpv6_servers,
            vlan_intf_value=vlan_intf_value,
            mac=mac,
        )
        if relay_v4 or relay_v6:
            config_patch += add_dhcp_relay_patch(
                vlan_name,
                dhcpv4_servers=relay_v4,
                dhcpv6_servers=relay_v6,
            )
        if ipv4:
            config_patch += add_vlan_ip_patch(vlan_name, ipv4)
        if ipv4_secondary:
            # Mark secondary:true so docker-dhcp-relay get_primary_addr picks
            # the primary for -pg <giaddr> (dhcrelay duplicate -iu trigger).
            config_patch.append({
                'op': 'add',
                'path': '/VLAN_INTERFACE/%s|%s' % (vlan_name, ipv4_secondary.replace('/', '~1')),
                'value': {'secondary': 'true'},
            })
        if ipv6:
            config_patch += add_vlan_ip_patch(vlan_name, ipv6)
        for member, _ in members_with_ptf_idx:
            config_patch += add_vlan_member_patch(vlan_name, member)

    # Dualtor MUX_CABLE: emit new entries for the variant.
    if is_dualtor_mux:
        topo_props = tbinfo.get("topo", {}).get("properties", {}).get("topology", {})
        host_aa = topo_props.get("host_interfaces_active_active", []) or []
        aa_intf_set = set()
        for entry in host_aa:
            idx = _parse_intf_index(entry)
            if idx is not None:
                aa_intf_set.add(idx)
        for dut_port, val in _compute_mux_cable_entries(
            variant, aa_intf_set, _intf_index_to_dut_name
        ):
            config_patch += add_mux_cable_patch(
                dut_port,
                val["cable_type"],
                val["server_ipv4"],
                val["server_ipv6"],
                soc_ipv4=val.get("soc_ipv4"),
            )

    return sub_vlans_info, config_patch, is_dualtor_mux


def _apply_and_persist(host, patch, refresh_caclmgrd):
    """Apply CONFIG_DB patch, save, and optionally restart caclmgrd to
    refresh iptables NAT rules. caclmgrd subscribes to STATE_DB
    MUX_CABLE_TABLE but not to CONFIG_DB MUX_CABLE config changes, so an
    apply-patch on MUX_CABLE does not re-render iptables without this
    nudge (~8s, lighter than a full config_reload).
    """
    apply_config_patch(host, patch)
    host.shell("sudo config save -y")
    if refresh_caclmgrd:
        host.shell("sudo systemctl restart caclmgrd && sleep 5")


@pytest.fixture(scope="module")
def parametrize_vlan_config_from_topo(
    request, rand_selected_dut, rand_unselected_dut, tbinfo
):
    """See module docstring. `request.param` is the variant name, supplied
    by the `pytest_generate_tests` hook in `tests/conftest.py` (or by an
    explicit `@pytest.mark.parametrize(..., indirect=True)` on the test)."""
    variant_name = request.param
    is_dualtor = "dualtor" in tbinfo["topo"]["name"]
    duthost = rand_selected_dut

    topo_dut = tbinfo.get("topo", {}).get("properties", {}).get("topology", {}).get("DUT", {})
    vlan_configs = topo_dut.get("vlan_configs") or {}
    default_variant_name = vlan_configs.get("default_vlan_config")
    is_non_default = (variant_name != default_variant_name)

    sub_vlans_info, config_patch, is_dualtor_mux = _generate_config_patch_from_variant(
        duthost, tbinfo, variant_name
    )

    logger.info(
        "parametrize_vlan_config_from_topo: variant=%s default=%s is_non_default=%s on %s",
        variant_name, default_variant_name, is_non_default, duthost.hostname,
    )
    logger.debug("config_patch=%s", config_patch)

    if is_non_default:
        _apply_and_persist(duthost, config_patch, is_dualtor_mux)
        if is_dualtor:
            # Recompute patch against the unselected DUT in case its CONFIG_DB
            # has drifted from the selected DUT's.
            _, config_patch_u, _ = _generate_config_patch_from_variant(
                rand_unselected_dut, tbinfo, variant_name
            )
            _apply_and_persist(rand_unselected_dut, config_patch_u, is_dualtor_mux)
        logger.info("Applied %s on %s; sub_vlans=%s", variant_name, duthost.hostname, sub_vlans_info)

    yield sub_vlans_info

    if is_non_default:
        logger.info("Restoring %s -> %s on %s", variant_name, default_variant_name, duthost.hostname)
        _, restore_patch, _ = _generate_config_patch_from_variant(duthost, tbinfo, default_variant_name)
        _apply_and_persist(duthost, restore_patch, is_dualtor_mux)
        if is_dualtor:
            _, restore_patch_u, _ = _generate_config_patch_from_variant(
                rand_unselected_dut, tbinfo, default_variant_name
            )
            _apply_and_persist(rand_unselected_dut, restore_patch_u, is_dualtor_mux)
