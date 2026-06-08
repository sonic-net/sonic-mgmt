"""HA planned-shutdown stress test driven by external Ixia traffic."""
import logging
import time

import paramiko
import configs.privatelink_config as pl
import pytest
from constants import REMOTE_DUT_INTF
from tests.common.helpers.assertions import pytest_assert
from gnmi_utils import apply_messages
from tests.common.config_reload import config_reload
from ha_utils import activate_primary_dash_ha, activate_secondary_dash_ha, \
         verify_ha_state, set_dead_dash_ha_scope
from conftest import get_interface_ip

logger = logging.getLogger(__name__)

STRESS_ITERATIONS = 5

# --- Ixia-side fake gateway / capture-steering configuration ---
# These must match the IxExplorer stream construction and fanout VLAN bridge.
IXIA_GATEWAY_IP = "10.99.0.100"
IXIA_GATEWAY_MAC = "00:11:22:33:44:55"
IXIA_DUT_INTF = "Ethernet96"
PE_PA_PREFIX = "101.1.2.3/32"           # GRE return outer dst — pl.PE_PA

# Eth96 L3 addressing on each DUT (indexed by duthosts position).
# Both DUTs sit on the same fanout VLAN 99 bridge as the Ixia port.
ETH96_IP_BY_DUT = {0: "10.99.0.1/24", 1: "10.99.0.2/24"}

# Next-hop for direct-link HA steering: from DUT[i]'s view, the peer DUT's
# IP on the direct inter-DUT link. So DUT1 -> 10.99.0.2, DUT2 -> 10.99.0.1.
DIRECT_LINK_PEER_NPU_IP = {0: "10.99.0.2", 1: "10.99.0.1"}

# Peer-DPU PA subnet to redirect onto the direct inter-DUT link. This is the
# outer-dst of the steady-state HA DP/CP channel packets (UDP/11368 +
# UDP/11362). Pattern from generate_golden_config_db.py:
#   pa_prefix = "20.0.20{switch_id}."
# so peer DPUs of DUT[i] live in 20.0.20{1-i}.0/24.
DIRECT_LINK_PEER_DPU_PA_PREFIX = {0: "20.0.201.0/24", 1: "20.0.200.0/24"}

# Peer-NPU Loopback0 /32 to redirect onto the direct inter-DUT link. When the local DPU
# is shut down, customer VxLAN traffic that landed on
# this NPU is re-encapsulated in a fresh VxLAN tunnel toward the *peer NPU's*
# Loopback0 so the peer DPU can service the flow. By default this prefix
# resolves via BGP through the T2 cEOS uplinks, which can drop packets under
# load (cEOS capacity limit). Steering it onto the direct inter-DUT link
# avoids that bottleneck.
#
#   DUT1 (MtFuji-dut01) Loopback0 = 10.1.0.32/32
#   DUT2 (MtFuji-dut02) Loopback0 = 10.1.0.33/32
DIRECT_LINK_PEER_NPU_LOOPBACK = {0: "10.1.0.33/32", 1: "10.1.0.32/32"}

# Default DASH HA channel ports (from generate_golden_config_db.py); used only
# in log messages and the suggested tcpdump filter below.
#   cp_data_channel_port = 11362  (control plane)
#   dp_channel_dst_port  = 11368  (data plane / flow-sync)

# ---------------------------------------------------------------------------
# IXIA STREAMS — what to configure manually in IxExplorer before continuing
# from breakpoint #1. The "expected RX" packet is what the Ixia capture port
# should observe after DASH NAT46+NVGRE encap on the DPU return path.
# ---------------------------------------------------------------------------
#
# TX stream (Ixia 3.1 -> DUT1 Eth96, VxLAN outbound to DPU)
# ---------------------------------------------------------
#   L2 mode:        Ethernet II  (NOT 802.3 — bytes 12-13 must be EtherType)
#   dst MAC:        24:d5:e4:35:09:40   (DUT1 Eth96 MAC)
#   src MAC:        00:11:22:33:44:55   (IXIA_GATEWAY_MAC; same value used as
#                                        the L2 next-hop MAC for the GRE return
#                                        — mirrors a real gateway upstream)
#   EtherType:      0x0800 (IPv4)
#   IPv4:
#     src:          1.9.1.1            (pl.VM1_PA)
#     dst:          3.2.1.0            (pl.APPLIANCE_VIP)
#     proto:        17 (UDP)
#     ttl:          64
#   UDP:
#     sport:        random in VxLAN sport range
#     dport:        4789               (VxLAN)
#   VxLAN:
#     vni:          2001               (pl.VNET1_VNI)
#   Inner Ethernet:
#     src:          ENI_MAC
#     dst:          REMOTE_MAC
#     type:         0x0800 (IPv4)
#   Inner IPv4:
#     src:          10.0.0.11          (pl.VM1_CA)
#     dst:          10.2.0.100         (pl.PE_CA)
#     proto:        17 (UDP)
#   Inner UDP:
#     sport/dport:  varied by UDF to create 10M flows in the DPU
#                   [Ixia UDF1: byte offset 84, mode counter, 32 bits,
#                    repeat count 5M, init 0, step 1]
#                   (5M unique 5-tuples × 2 bidirectional entries = 10M)
#   Payload:        56 bytes of incrementing pattern (00 01 02 ... 39)
#
#   Sample L3+ hex (what to paste into IxExplorer Protocol Pad):
#     450000880001000040115C611901010103020100142312B500740000
#     080000000007D10043BE6525FA67F4939FEFC47E08004500005600010000
#     401166260A00000B0A0200641A8511D700428F51
#     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
#     202122232425262728292A2B2C2D2E2F30313233343536373839
#
#   Rate:           10M pps
#
# Expected RX packet (Ixia 3.1 capture — same port)
# -----------------------------------------------------------------------
#   Outer Ethernet:
#     dst:          00:11:22:33:44:55  (IXIA_GATEWAY_MAC)
#     src:          24:d5:e4:35:09:40  (DUT1 Eth96 MAC)
#     type:         0x0800 (IPv4)
#   Outer IPv4:
#     src:          3.2.1.0            (pl.APPLIANCE_VIP)
#     dst:          101.1.2.3          (pl.PE_PA)
#     proto:        47 (GRE)
#     ttl:          63 (to mask - varies by platform)
#   GRE:
#     protocol:     0x6558             (Transparent Ethernet Bridging => NVGRE)
#     key present:  yes
#   NVGRE key/VSID:
#     VSID:         0x000064 = 100     (pl.ENCAP_VNI)
#     flow id:      0x00
#   Inner Ethernet:
#     src:          ENI_MAC
#     dst:          REMOTE_MAC         (to mask — varies by platform)
#     type:         0x86DD (IPv6)
#   Inner IPv6 (NAT46 result of the inner IPv4 above):
#     src:          fd41:108:20:d107:64:ff71:a00:b   (overlay-encoded VM1_CA)
#     dst:          2603:10e1:100:2::3401:203        (overlay-encoded PE_CA)
#     next hdr:     17 (UDP)
#   Inner UDP:
#     sport/dport:  preserved from TX (varies per flow via UDF)
#   Payload:        same 56-byte pattern as TX
#
#   Captured hex (from a real run; bytes 12-13 differ per platform/HA owner,
#   inner IPv6 addresses depend on overlay encoding constants, last 4 bytes
#   are Ethernet FCS appended by the Ixia receiver):
#     00 11 22 33 44 55 24 d5 e4 35 09 40 08 00 45 00     # outer Eth + IPv4 start
#     00 94 00 00 00 00 3f 2f 10 36 03 02 01 00 65 01     # IPv4 cont, GRE, src=3.2.1.0
#     02 03 20 00 65 58 00 00 64 00 43 be 65 25 fa 67     # dst=101.1.2.3, GRE flags+proto 6558, NVGRE VSID 100, inner Eth dst
#     f4 93 9f ef c4 7e 86 dd 60 00 00 00 00 42 11 40     # inner Eth src + type 86DD, IPv6 header
#     fd 41 01 08 00 20 d1 07 00 64 ff 71 0a 00 00 0b     # inner IPv6 src (overlay-encoded VM1_CA)
#     26 03 10 e1 01 00 00 02 00 00 00 00 34 01 02 03     # inner IPv6 dst (overlay-encoded PE_CA)
#     1a 85 11 d7 00 42 5c 85 00 01 02 03 04 05 06 07     # UDP sport=6789, dport=4567, len, csum, payload start
#     08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17
#     18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27
#     28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
#     38 39 3b 84 68 78                                   # payload tail + 4-byte FCS
#
# ---------------------------------------------------------------------------

FANOUT_VLAN_ID = 99  # VLAN on the fanout bridging DUT Eth96 ports and Ixia
FANOUT_IXIA_PORT = "Ethernet224"  # Fanout port facing Ixia 3.1

# Fanout switch connection info (SONiC-based fanout, direct paramiko SSH).
# Port mapping: fanout port -> what it connects to.
FANOUT_IP = "1.2.31.91"
FANOUT_USER = "admin"
FANOUT_PASSWORD = "password"
FANOUT_PORTS = {
    "Ethernet208": "DUT1 Ethernet96",
    "Ethernet216": "DUT2 Ethernet96",
    "Ethernet224": "Ixia 3.1 (TX + RX)",
}
# Ports that must be in VLAN 99 for the test to work (DUT1, DUT2, Ixia).
FANOUT_VLAN_PORTS = ["Ethernet208", "Ethernet216", "Ethernet224"]

# --- HA cycle pacing (purely time-based) ---
PRE_ACTION_SETTLE_S = 5     # let Ixia traffic flow before triggering shutdown
POST_ACTION_SETTLE_S = 10   # let traffic stabilize after each HA state change

# --- Breakpoint modes (BRK env var) ---
#   none:  No breakpoints; fully automated.
#   ends:  Break before Ixia start + after all iterations (default).
#   mid:   ends + once after primary-dead and once after secondary-dead
#          (first iteration only, not every iteration).
#
# Usage: BRK=mid ./run_tests.sh ...
#        BRK=none ./run_tests.sh ...
import os
BRK_MODE = os.environ.get("BRK", "ends")

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    skip_config,
    dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json,
    ha_owner,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    """Apply DASH/HA config on both DUT/DPU pairs."""
    if skip_config:
        return

    for i in range(len(duthosts)):
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]
        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG
        }
        logger.info(f"configure on {duthost.hostname} dpu {dpuhost.dpu_index} {base_config_messages}")
        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_CONFIG
        }
        if 'bluefield' in dpuhost.facts['asic_type']:
            route_and_mapping_messages.update({
                **pl.INBOUND_VNI_ROUTE_RULE_CONFIG
            })
        apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

        meter_rule_messages = {
            **pl.METER_RULE1_V4_CONFIG,
            **pl.METER_RULE2_V4_CONFIG,
        }
        apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    config_reload(dpuhost, safe_reload=True, yang_validate=False)


def _fanout_ssh_run(cmd):
    """Run a command on the fanout switch via paramiko SSH.
    Returns (stdout, stderr, exit_code).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(FANOUT_IP, port=22, username=FANOUT_USER,
                       password=FANOUT_PASSWORD, timeout=10)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='replace').strip()
        err = stderr.read().decode('utf-8', errors='replace').strip()
        return out, err, rc
    finally:
        client.close()


def _ensure_fanout_vlan():
    """Verify (and if necessary create) VLAN 99 on the fanout switch with
    all required ports (DUT1 Eth96, DUT2 Eth96, Ixia).

    Uses direct paramiko SSH to the fanout (FANOUT_IP). Returns a list of
    port names that were *added* by this call so they can be removed in
    teardown. Ports already in VLAN 99 are left untouched.
    """
    added = []

    # Get current VLAN 99 membership
    vlan_out, _, _ = _fanout_ssh_run("show vlan brief")

    for port in FANOUT_VLAN_PORTS:
        if port in vlan_out:
            logger.info(
                "Fanout %s: port %s already in VLAN %d — no change",
                FANOUT_IP, port, FANOUT_VLAN_ID,
            )
            continue

        logger.info(
            "Fanout %s: adding port %s to VLAN %d",
            FANOUT_IP, port, FANOUT_VLAN_ID,
        )
        # Create VLAN if it doesn't exist (idempotent)
        _fanout_ssh_run(f"sudo config vlan add {FANOUT_VLAN_ID}")
        out, err, rc = _fanout_ssh_run(
            f"sudo config vlan member add -u {FANOUT_VLAN_ID} {port}"
        )
        if rc != 0 and "already a member" not in (err + out):
            pytest.fail(
                f"Fanout {FANOUT_IP}: failed to add {port} to VLAN "
                f"{FANOUT_VLAN_ID}: {err or out}"
            )
        added.append(port)

    return added


def _remove_fanout_vlan(added_ports):
    """Remove fanout VLAN memberships that _ensure_fanout_vlan added,
    then delete VLAN 99 itself if it has no remaining members.
    """
    for port in added_ports:
        logger.info(
            "Fanout %s: removing port %s from VLAN %d",
            FANOUT_IP, port, FANOUT_VLAN_ID,
        )
        _fanout_ssh_run(f"sudo config vlan member del {FANOUT_VLAN_ID} {port}")

    # Delete the VLAN if no ports remain
    vlan_out, _, _ = _fanout_ssh_run("show vlan brief")
    # Check if any of our known ports are still in the VLAN
    remaining = [p for p in FANOUT_VLAN_PORTS if p in vlan_out]
    if not remaining:
        logger.info("Fanout %s: deleting empty VLAN %d", FANOUT_IP, FANOUT_VLAN_ID)
        _fanout_ssh_run(f"sudo config vlan del {FANOUT_VLAN_ID}")


def _apply_eth96_ips(duthosts):
    """Unconditionally (re)apply the Eth96 IP on each DUT via CONFIG_DB.

    This persists in CONFIG_DB until removed in teardown. Using ``ip add``
    rather than a presence-check keeps the code simple; ``config interface
    ip add`` returns non-zero if the IP is already present, which we tolerate
    via ``module_ignore_errors``.
    """
    for i, dh in enumerate(duthosts):
        want_ip = ETH96_IP_BY_DUT[i]
        logger.info("Configuring %s on %s of %s", want_ip, IXIA_DUT_INTF, dh.hostname)
        dh.shell(f"sudo config interface ip add {IXIA_DUT_INTF} {want_ip}",
                 module_ignore_errors=True)


def _remove_eth96_ips(duthosts):
    """Remove the Eth96 IPs that ``_apply_eth96_ips`` added. Errors ignored
    so cleanup is robust against partial setup.
    """
    for i, dh in enumerate(duthosts):
        want_ip = ETH96_IP_BY_DUT[i]
        logger.info("Removing %s from %s of %s", want_ip, IXIA_DUT_INTF, dh.hostname)
        dh.shell(f"sudo config interface ip remove {IXIA_DUT_INTF} {want_ip}",
                 module_ignore_errors=True)


def _apply_direct_link_ha_steering(duthosts):
    """Force HA flow-sync and DPU-down redirect traffic onto the direct
    inter-DUT link (DUT1 <-> Fanout VLAN 99 <-> DUT2) instead of the default
    uplink path through the T2 cEOS VMs.

    Two distinct prefixes are steered onto the direct link per DUT:

    Both prefixes normally resolve via BGP through the cEOS T2 uplink
    containers, which cannot sustain the high traffic rates in this stress
    test. The direct physical link bypasses cEOS entirely.

    1. Peer-DPU PA /24 (DIRECT_LINK_PEER_DPU_PA_PREFIX) — outer dst of the
       steady-state HA DP channel (UDP/11368) and CP channel (UDP/11362)
       used for inline flow-sync and BFD probes between the two DPUs.

    2. Peer-NPU Loopback0 /32 (DIRECT_LINK_PEER_NPU_LOOPBACK) — when the
       local DPU is in 'dead' state, the NPU re-encapsulates incoming
       customer VxLAN in a fresh VxLAN tunnel toward the peer NPU's
       Loopback0 so the peer DPU services the flow.

    Both are installed as kernel routes (distance 0 beats BGP's distance 20)
    pointing at the peer DUT's IP on the direct link.

    Returns the list of (prefix, hop) tuples installed per duthost index so
    the teardown helper can delete exactly what was added.
    """
    installed = []  # list[list[(prefix, hop)]] aligned with duthosts
    for i, dh in enumerate(duthosts):
        hop = DIRECT_LINK_PEER_NPU_IP[i]
        per_dut = []
        for prefix in (DIRECT_LINK_PEER_DPU_PA_PREFIX[i],
                       DIRECT_LINK_PEER_NPU_LOOPBACK[i]):
            logger.info("Direct-link HA steering on %s: %s via %s dev %s",
                        dh.hostname, prefix, hop, IXIA_DUT_INTF)
            dh.shell(f"ip route replace {prefix} via {hop} dev {IXIA_DUT_INTF}")
            # Probe the .1 host (or the bare /32) so we get a useful
            # 'ip route get' log line confirming the install.
            net, plen = prefix.split("/")
            probe_ip = net if plen == "32" else net.rsplit(".", 1)[0] + ".1"
            out = dh.shell(f"ip route get {probe_ip}",
                           module_ignore_errors=True)["stdout"]
            logger.info("%s: %s", dh.hostname, out.strip())
            per_dut.append((prefix, hop))
        installed.append(per_dut)
    return installed


def _remove_direct_link_ha_steering(duthosts, installed_prefixes):
    """Delete the kernel routes installed by
    ``_apply_direct_link_ha_steering`` so the BGP-installed route via
    PortChannel101..108 takes over again. Tolerates missing routes.
    """
    if not installed_prefixes:
        return
    for i, dh in enumerate(duthosts):
        if i >= len(installed_prefixes) or not installed_prefixes[i]:
            continue
        for prefix, hop in installed_prefixes[i]:
            logger.info("Removing direct-link HA steering on %s: %s via %s",
                        dh.hostname, prefix, hop)
            dh.shell(f"ip route del {prefix} via {hop} dev {IXIA_DUT_INTF}",
                     module_ignore_errors=True)


def _apply_ixia_steering(duthosts):
    """Override the route installed by add_npu_static_routes so the GRE return
    egresses Ethernet96 (visible to Ixia capture port) instead of the default
    nexthop. Also install the static ARP for the fake Ixia gateway.

    Idempotent — safe to call multiple times.
    """
    for dh in duthosts:
        logger.info("Applying Ixia steering on %s: route %s via %s dev %s",
                    dh.hostname, PE_PA_PREFIX, IXIA_GATEWAY_IP, IXIA_DUT_INTF)
        dh.shell(f"ip neigh replace {IXIA_GATEWAY_IP} lladdr {IXIA_GATEWAY_MAC} "
                 f"dev {IXIA_DUT_INTF} nud permanent")
        dh.shell(f"ip route replace {PE_PA_PREFIX} via {IXIA_GATEWAY_IP} dev {IXIA_DUT_INTF}")
        # Sanity log
        out = dh.shell(f"ip route get {PE_PA_PREFIX.split('/')[0]}", module_ignore_errors=True)['stdout']
        logger.info("%s: %s", dh.hostname, out.strip())


def _remove_ixia_steering(duthosts, dash_pl_config):
    """Restore the fixture-installed route so add_npu_static_routes' teardown
    can find its expected next-hop and succeed.

    add_npu_static_routes' teardown does:
        ip route del 101.1.2.3/32 via <pe_nexthop>
    If we leave the route pointing at our Ixia gateway (or delete it outright),
    that command fails with 'No such process'. So we 'ip route replace' it back
    to the value the fixture installed, then let the fixture's teardown delete
    it normally.

    Also remove the static ARP we added (the fixture doesn't care about that).
    Errors are ignored so this can run unconditionally during cleanup.
    """
    for i, dh in enumerate(duthosts):
        try:
            pe_nexthop_ip = get_interface_ip(dh, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1
            logger.info("Restoring fixture's route on %s: %s via %s",
                        dh.hostname, PE_PA_PREFIX, pe_nexthop_ip)
            dh.shell(f"ip route replace {PE_PA_PREFIX} via {pe_nexthop_ip}",
                     module_ignore_errors=True)
        except Exception as e:
            logger.warning("Could not restore fixture route on %s: %s", dh.hostname, e)
            dh.shell(f"ip route del {PE_PA_PREFIX} via {IXIA_GATEWAY_IP} dev {IXIA_DUT_INTF}",
                     module_ignore_errors=True)

        logger.info("Removing static ARP for %s on %s", IXIA_GATEWAY_IP, dh.hostname)
        dh.shell(f"ip neigh del {IXIA_GATEWAY_IP} dev {IXIA_DUT_INTF}",
                 module_ignore_errors=True)


def _planned_shutdown_cycle(
    localhost,
    duthosts,
    ptfhost,
    ha_owner,
    iteration,
    break_mode="none",
):
    """One HA planned shutdown cycle, time-paced. Ixia drives the data plane
    externally.

    If break_mode == 'mid' and iteration == 1, drops into pdb after each
    dead/standalone transition so you can inject new flows (e.g. SYN burst)
    while one side is down. Only pauses on the first iteration."""

    # --- Phase 1: shutdown primary ---
    logger.info("Iter %d: settle %ds, then set primary dead", iteration, PRE_ACTION_SETTLE_S)
    time.sleep(PRE_ACTION_SETTLE_S)

    set_dead_dash_ha_scope(localhost, duthosts[0], ptfhost, "vdpu0_0:haset0_0")
    time.sleep(POST_ACTION_SETTLE_S)

    pytest_assert(verify_ha_state(duthosts[0], "vdpu0_0:haset0_0", "dead"),
                  f"Iter {iteration}: Primary HA state is not dead")
    pytest_assert(verify_ha_state(duthosts[1], "vdpu1_0:haset0_0", "standalone"),
                  f"Iter {iteration}: Secondary HA state is not standalone")

    if break_mode == "mid" and iteration == 1:
        logger.info("=== PRIMARY is DEAD, SECONDARY is STANDALONE. ===")
        logger.info("    Inject new flows (SYN burst) or inspect state, then `c`.")
        breakpoint()

    pytest_assert(activate_primary_dash_ha(localhost, duthosts[0], ptfhost,
                                           "vdpu0_0:haset0_0", "activate_role",
                                           owner=ha_owner),
                  f"Iter {iteration}: Failed to re-activate HA on primary")
    time.sleep(POST_ACTION_SETTLE_S)

    # --- Phase 2: shutdown standby ---
    logger.info("Iter %d: settle %ds, then set standby dead", iteration, PRE_ACTION_SETTLE_S)
    time.sleep(PRE_ACTION_SETTLE_S)

    set_dead_dash_ha_scope(localhost, duthosts[1], ptfhost, "vdpu1_0:haset0_0")
    time.sleep(POST_ACTION_SETTLE_S)

    pytest_assert(verify_ha_state(duthosts[1], "vdpu1_0:haset0_0", "dead"),
                  f"Iter {iteration}: Secondary HA state is not dead")
    pytest_assert(verify_ha_state(duthosts[0], "vdpu0_0:haset0_0", "standalone"),
                  f"Iter {iteration}: Primary HA state is not standalone")

    if break_mode == "mid" and iteration == 1:
        logger.info("=== SECONDARY is DEAD, PRIMARY is STANDALONE. ===")
        logger.info("    Inject new flows (SYN burst) or inspect state, then `c`.")
        breakpoint()

    pytest_assert(activate_secondary_dash_ha(localhost, duthosts[1], ptfhost,
                                             "vdpu1_0:haset0_0", "activate_role",
                                             owner=ha_owner),
                  f"Iter {iteration}: Failed to re-activate HA on standby")
    time.sleep(POST_ACTION_SETTLE_S)


def test_ha_planned_shutdown_stress_ixia(
    localhost,
    duthosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
):
    """HA planned-shutdown stress driven by Ixia.

    Flow:
      1. _ensure_fanout_vlan(): Ensure VLAN 99 on the fanout (DUT Eth96
         ports + Ixia Ethernet224) — L2 bridge between Ixia, DUT1, DUT2.
      2. _apply_eth96_ips(): Configure Eth96 IPs on both DUTs
         (10.99.0.1/24, 10.99.0.2/24) on fanout VLAN 99.
      3. _apply_ixia_steering(): Route + static ARP for the fake Ixia
         gateway so GRE returns egress Eth96 toward Ixia capture.
      4. _apply_direct_link_ha_steering(): Steer HA-related prefixes onto
         the direct inter-DUT link to avoid cEOS bottlenecks:
           a. Peer DPU PA /24 — HA DP/CP channel (UDP/11368 + UDP/11362).
           b. Peer NPU Loopback0 /32 — DPU-down VxLAN re-encap to peer.
      5. [BRK != none] Breakpoint: user starts Ixia capture + stream,
         then `c` to continue.
      6. _planned_shutdown_cycle(): N HA shutdown/restart cycles,
         time-paced.
      7. [BRK != none] Breakpoint: user stops Ixia, reads TX/RX counters,
         then `c` to continue.
      8. Teardown: remove direct-link HA steering, Ixia steering, Eth96
         IPs, and fanout VLAN memberships (if added by the test).

    Breakpoint mode (BRK env var):
      none:  No breakpoints; fully automated (steps 5/7 skipped).
      ends:  Break before Ixia start + after iterations (default).
      mid:   ends + once after primary-dead and once after secondary-dead
             (first iteration only).
    """
    direct_link_ha_routes = []
    fanout_added_ports = []
    try:
        fanout_added_ports = _ensure_fanout_vlan()
        _apply_eth96_ips(duthosts)
        _apply_ixia_steering(duthosts)
        direct_link_ha_routes = _apply_direct_link_ha_steering(duthosts)
        # === BREAKPOINT #1: Start Ixia ===
        if BRK_MODE != "none":
            logger.info("=== IXIA START: DPU programmed, HA active, Eth96 + steering installed. ===")
            logger.info("    On the Ixia chassis: start capture on RX port, then start the TX stream.")
            logger.info("    Type `c` (continue) to begin %d HA iterations, or `q` to abort.", STRESS_ITERATIONS)
            breakpoint()

        for iteration in range(1, STRESS_ITERATIONS + 1):
            logger.info("=== Stress iteration %d / %d ===", iteration, STRESS_ITERATIONS)
            try:
                _planned_shutdown_cycle(
                    localhost,
                    duthosts,
                    ptfhost,
                    ha_owner,
                    iteration,
                    break_mode=BRK_MODE,
                )
            except BaseException as exc:
                # === BREAKPOINT (iteration failure): inspect live state ===
                logger.error(
                    "=== Iteration %d FAILED: %s: %s ===",
                    iteration, type(exc).__name__, exc,
                )
                logger.error(
                    "    Dropping to breakpoint BEFORE teardown so live state "
                    "is preserved. Type `c` to continue to teardown, `q` to abort."
                )
                breakpoint()
                raise
            logger.info("=== Completed iteration %d / %d ===", iteration, STRESS_ITERATIONS)

        logger.info("All %d HA iterations completed.", STRESS_ITERATIONS)

        # === BREAKPOINT #2: Stop Ixia and collect numbers (HA config still up) ===
        if BRK_MODE != "none":
            logger.info("=== IXIA STOP: HA iterations done; HA + DASH config still active. ===")
            logger.info("    On the Ixia chassis: stop the stream and capture, record TX/RX counts.")
            logger.info("    Type `c` (continue) to proceed to cleanup.")
            breakpoint()

    finally:
        # Tear down in reverse order of setup. All helpers tolerate missing
        # state, so partial setup still produces a clean teardown.
        _remove_direct_link_ha_steering(duthosts, direct_link_ha_routes)
        # Restore the route that add_npu_static_routes installed so its own
        # teardown can delete it cleanly; also drop our static ARP.
        # (Fixture teardown only reloads the DPU; NPU state would otherwise persist.)
        _remove_ixia_steering(duthosts, dash_pl_config)
        _remove_eth96_ips(duthosts)
        _remove_fanout_vlan(fanout_added_ports)

