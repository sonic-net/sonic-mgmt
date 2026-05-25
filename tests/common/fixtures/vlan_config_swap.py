"""parametrize_vlan_config_from_topo -- unified multi-vlan fixture.

Auto-parametrizes any test that names ``parametrize_vlan_config_from_topo``
across every variant the topo yaml's ``DUT.vlan_configs`` block defines
(``one_vlan_a``, ``two_vlan_a``, ``four_vlan_a``, ...). Auto-parametrize hook
lives in ``tests/conftest.py``.

Builds an atomic CONFIG_DB JSON patch from the variant, applies via
``config apply-patch`` + ``config save -y``. Teardown applies a fresh
patch that restores the topo's ``default_vlan_config`` (not a true reverse
patch -- it is built the same way as the apply patch, just against the
default variant). Supports dualtor MUX_CABLE and dualtor-shared mac.
"""

import logging

import pytest

from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.helpers.parallel import parallel_run_threaded
from tests.common.helpers.assertions import pytest_require

logger = logging.getLogger(__name__)


def add_vlan_patch(vlan_name, dhcp_servers, dhcpv6_servers, vlan_intf_value=None, mac=None):
    if vlan_intf_value is None:
        vlan_intf_value = {}
    patch = [
        {
            "op": "add",
            "path": "/VLAN/%s" % vlan_name,
            "value": {
                "vlanid": vlan_name.replace("Vlan", "")
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


def _generate_config_patch_from_variant(duthost, localhost, tbinfo, variant_name, is_dualtor):
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

    def _inherit_servers_from_running(vlan_name, table, key):
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

    # Dualtor MUX_CABLE: detected from topology (is_dualtor). All dualtor
    # variants (regular, active-active, active-active-mixed) deploy MUX_CABLE;
    # non-dualtor topos never do. Detecting from running config would be
    # drift-vulnerable (a previous failed teardown that cleared MUX_CABLE
    # would silently classify the topology as non-dualtor here).
    if is_dualtor:
        running_mux_cable = running_config.get("MUX_CABLE", {})
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
    vlan_intf_value = (
        {"proxy_arp": "enabled", "grat_arp": "enabled"}
        if is_dualtor else None
    )

    sub_vlans_info = []
    for vlan_name, vparams in variant.items():
        ipv4 = vparams.get("prefix")
        ipv6 = vparams.get("prefix_v6")
        ipv4_secondary = vparams.get("secondary_subnet")
        mac = vparams.get("mac")
        intf_indices = vparams.get("intfs", []) or []

        # Build (dut_port, ptf_idx) pairs. By construction ptf_idx == idx
        # whenever _intf_index_to_dut_name(idx) resolves. Log skipped
        # indices so a topo/minigraph mismatch is visible at fixture time
        # instead of silently producing a half-populated variant.
        members_with_ptf_idx = []
        for idx in intf_indices:
            dut_port = _intf_index_to_dut_name(idx)
            if dut_port is None:
                # This is a gap in the topo yaml: the variant declares an
                # interface index that does not exist in the minigraph for
                # this DUT. The fixture skips it so the test can proceed,
                # but the topo definition should be fixed.
                logger.warning(
                    "vlan %s: intf_idx %s declared in topo yaml has no "
                    "dut port in minigraph_ptf_indices -- this is a topo "
                    "definition gap, skipping; fix the topo yaml so the "
                    "variant only references indices present in the minigraph",
                    vlan_name, idx,
                )
                continue
            members_with_ptf_idx.append((dut_port, idx))

        sub_vlans_info.append({
            "vlan_name": vlan_name,
            "interface_ipv4": ipv4,
            "interface_ipv4_secondary": ipv4_secondary,
            "interface_ipv6": ipv6,
            "members_with_ptf_idx": members_with_ptf_idx,
            "vlan_plan": variant_name,
        })

        # Per-VLAN carry-forward of dhcp servers / dhcp_relay servers.
        dhcp_servers = _inherit_servers_from_running(vlan_name, deployed_vlan, "dhcp_servers")
        dhcpv6_servers = _inherit_servers_from_running(vlan_name, deployed_vlan, "dhcpv6_servers")
        relay_v4 = _inherit_servers_from_running(vlan_name, deployed_relay, "dhcpv4_servers")
        relay_v6 = _inherit_servers_from_running(vlan_name, deployed_relay, "dhcpv6_servers")

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

    # Dualtor MUX_CABLE: re-emit via the canonical ansible module
    # (ansible/library/mux_cable_facts.py -> dualtor_utils.generate_mux_cable_facts)
    # so the active-standby / active-active / active-active-mixed algorithm
    # stays in one place. The module returns server/soc IPs with the vlan
    # netmask; CONFIG_DB MUX_CABLE uses host masks (/32, /128) so rewrite.
    if is_dualtor:
        mux_cable_facts = localhost.mux_cable_facts(
            topology=tbinfo["topo"]["properties"]["topology"],
            vlan_config=variant_name,
        )["ansible_facts"]["mux_cable_facts"]
        for intf_idx, info in mux_cable_facts.items():
            dut_port = _intf_index_to_dut_name(intf_idx)
            if dut_port is None:
                continue
            server_ipv4 = info["server_ipv4"].split("/")[0] + "/32"
            server_ipv6 = info["server_ipv6"].split("/")[0] + "/128"
            soc_ipv4 = info["soc_ipv4"].split("/")[0] + "/32" if "soc_ipv4" in info else None
            config_patch += add_mux_cable_patch(
                dut_port, info["cable_type"], server_ipv4, server_ipv6, soc_ipv4=soc_ipv4,
            )

    return sub_vlans_info, config_patch


def _apply_and_persist(host, patch, refresh_caclmgrd):
    """Apply CONFIG_DB patch, save, and optionally restart caclmgrd to
    refresh iptables NAT rules. caclmgrd subscribes to STATE_DB
    MUX_CABLE_TABLE but not to CONFIG_DB MUX_CABLE config changes, so an
    apply-patch on MUX_CABLE does not re-render iptables without this
    nudge (~8s, lighter than a full config_reload).
    """
    tmpfile = host.shell("mktemp")["stdout"]
    try:
        output = apply_patch(host, patch, tmpfile)
        expect_op_success(host, output)
    finally:
        host.file(path=tmpfile, state="absent")
    host.shell("sudo config save -y")
    if refresh_caclmgrd:
        host.shell("sudo systemctl restart caclmgrd && sleep 5")


@pytest.fixture(scope="module")
def parametrize_vlan_config_from_topo(
    request, rand_selected_dut, rand_unselected_dut, localhost, tbinfo
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

    def _swap_one_dut(node, target_variant):
        info, patch = _generate_config_patch_from_variant(
            node, localhost, tbinfo, target_variant, is_dualtor,
        )
        _apply_and_persist(node, patch, is_dualtor)
        return info

    # Always apply, even for the default variant: a previous test may have
    # polluted CONFIG_DB, and we want every test to start from the variant
    # the topo declares, not from whatever happened to be running.
    logger.info(
        "parametrize_vlan_config_from_topo: variant=%s default=%s on %s",
        variant_name, default_variant_name, duthost.hostname,
    )
    if is_dualtor:
        # Both DUTs in parallel (~32s saved on the 30s+30s apply-and-persist
        # sequence). Each side does its own _generate_config_patch_from_variant
        # so a drifted unselected DUT still gets a correct patch.
        try:
            outs = parallel_run_threaded(
                [
                    lambda: _swap_one_dut(duthost, variant_name),
                    lambda: _swap_one_dut(rand_unselected_dut, variant_name),
                ],
                timeout=1200,
            )
        except TimeoutError:
            logger.error(
                "parametrize_vlan_config_from_topo apply timed out (>1200s) "
                "applying variant=%s on DUTs=%s,%s",
                variant_name, duthost.hostname, rand_unselected_dut.hostname,
            )
            raise
        sub_vlans_info = outs[0]
    else:
        sub_vlans_info = _swap_one_dut(duthost, variant_name)
    logger.info("Applied %s on %s; sub_vlans=%s", variant_name, duthost.hostname, sub_vlans_info)

    yield sub_vlans_info

    # Always teardown to the default variant so the next test (or next
    # session) starts from a known state.
    logger.info("Restoring %s -> %s on %s", variant_name, default_variant_name, duthost.hostname)
    if is_dualtor:
        try:
            parallel_run_threaded(
                [
                    lambda: _swap_one_dut(duthost, default_variant_name),
                    lambda: _swap_one_dut(rand_unselected_dut, default_variant_name),
                ],
                timeout=1200,
            )
        except TimeoutError:
            logger.error(
                "parametrize_vlan_config_from_topo teardown timed out (>1200s) "
                "restoring variant=%s on DUTs=%s,%s",
                default_variant_name, duthost.hostname, rand_unselected_dut.hostname,
            )
            raise
    else:
        _swap_one_dut(duthost, default_variant_name)
