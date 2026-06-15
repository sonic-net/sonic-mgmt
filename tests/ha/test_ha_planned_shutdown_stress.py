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

# See test_ha_stress.md ("Topology") for the full connection map

IXIA_DUT_INTF = "Ethernet96"
PE_PA_PREFIX = "101.1.2.3/32"           # GRE return outer dst — pl.PE_PA

# Fanout interface → IP mapping (fanout side of each /30)
FANOUT_INTF_IPS = {
    "Ethernet224": "10.99.1.1/30",   # → Ixia 3.1 (TX)
    "Ethernet208": "10.99.2.1/30",   # → DUT1 Eth96
    "Ethernet216": "10.99.3.1/30",   # → DUT2 Eth96
    "Ethernet240": "10.99.4.1/30",   # → Ixia 3.2 (RX)
}

# Ixia L3 emulation IPs (configured in IxNetwork topology)
IXIA_TX_IP = "10.99.1.2"            # Ixia 3.1 (TX port), gateway 10.99.1.1
IXIA_RX_IP = "10.99.4.2"            # Ixia 3.2 (RX port), gateway 10.99.4.1

# Eth96 L3 addressing on each DUT (indexed by duthosts position)
ETH96_IP_BY_DUT = {0: "10.99.2.2/30", 1: "10.99.3.2/30"}

# Each DUT's fanout gateway (next-hop for all steering routes out Eth96)
FANOUT_GATEWAY_BY_DUT = {0: "10.99.2.1", 1: "10.99.3.1"}

# Peer-DPU PA subnet to redirect through the fanout. This is the outer-dst
# of the steady-state HA DP/CP channel packets (UDP/11368 + UDP/11362).
# Pattern from generate_golden_config_db.py:
#   pa_prefix = "20.0.20{switch_id}."
# so peer DPUs of DUT[i] live in 20.0.20{1-i}.0/24.
DIRECT_LINK_PEER_DPU_PA_PREFIX = {0: "20.0.201.0/24", 1: "20.0.200.0/24"}

# Peer-NPU Loopback0 /32 to redirect through the fanout. When the local DPU
# is shut down, customer VxLAN traffic that landed on this NPU is
# re-encapsulated in a fresh VxLAN tunnel toward the *peer NPU's* Loopback0
# so the peer DPU can service the flow. By default this prefix resolves via
# BGP through the T2 cEOS uplinks, which can drop packets under load (cEOS
# capacity limit). Routing through the L3 fanout avoids that bottleneck.
#
#   DUT1 (MtFuji-dut01) Loopback0 = 10.1.0.32/32
#   DUT2 (MtFuji-dut02) Loopback0 = 10.1.0.33/32
DIRECT_LINK_PEER_NPU_LOOPBACK = {0: "10.1.0.33/32", 1: "10.1.0.32/32"}

# Routes to install on the fanout for L3 forwarding between all participants.
FANOUT_ROUTES = {
    # ECMP to both DUTs for inbound VxLAN traffic
    "3.2.1.0/32": ["10.99.2.2", "10.99.3.2"],   # APPLIANCE_VIP → DUT1 + DUT2
    # GRE return to Ixia RX port
    "101.1.2.3/32": ["10.99.4.2"],               # PE_PA → Ixia 3.2
    # HA inter-DUT: peer DPU PA subnets (flow-sync + BFD)
    "20.0.200.0/24": ["10.99.2.2"],              # DUT1's DPUs (HA from DUT2→DUT1)
    "20.0.201.0/24": ["10.99.3.2"],              # DUT2's DPUs (HA from DUT1→DUT2)
    # HA inter-DUT: peer NPU Loopback0 (DPU-dead VxLAN re-encap)
    "10.1.0.32/32": ["10.99.2.2"],               # DUT1 Loopback0
    "10.1.0.33/32": ["10.99.3.2"],               # DUT2 Loopback0
}

# Default DASH HA channel ports (from generate_golden_config_db.py); used only
# in log messages and the suggested tcpdump filter below.
#   cp_data_channel_port = 11362  (control plane)
#   dp_channel_dst_port  = 11368  (data plane / flow-sync)

# ---------------------------------------------------------------------------
# IXIA — configure in IxNetwork before continuing from breakpoint #1.
# Two ports: 3.1 (TX) and 3.2 (RX), each with an L3 topology:
#   Port 3.1 (TX): IP 10.99.1.2/30, gateway 10.99.1.1 (fanout Eth224)
#   Port 3.2 (RX): IP 10.99.4.2/30, gateway 10.99.4.1 (fanout Eth240)
# Build a VxLAN(VNI=2001) frame wrapping an inner Ethernet/IPv4/L4 packet
# (inner src 10.0.0.11 VM1_CA -> dst 10.2.0.100 PE_CA; outer dst 3.2.1.0
# APPLIANCE_VIP). Inner L4 may be UDP or TCP; vary inner L4 ports via a UDF
# to scale DPU flows. The DPU returns NVGRE (VSID 100) toward PE_PA
# (101.1.2.3), routed back to the Ixia RX port. See test_ha_stress.md
# (section 5) for the full frame layout, UDF, and send rates.
# ---------------------------------------------------------------------------

# Fanout switch connection info (SONiC-based fanout, direct paramiko SSH).
FANOUT_IP = "1.2.31.91"
FANOUT_USER = "admin"
FANOUT_PASSWORD = "password"
# Port mapping: fanout port → what it connects to.
FANOUT_PORTS = {
    "Ethernet208": "DUT1 Ethernet96",
    "Ethernet216": "DUT2 Ethernet96",
    "Ethernet224": "Ixia 3.1 (TX)",
    "Ethernet240": "Ixia 3.2 (RX)",
}

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
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 — lab fanout with hardcoded IP
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


def _configure_fanout_l3():
    """Configure L3 routing on the fanout: assign IPs to interfaces and
    install static routes (including ECMP for APPLIANCE_VIP).

    Idempotent — uses 'ip add' (tolerates "already assigned") and
    'ip route replace'.
    """
    # Assign IPs to fanout interfaces
    for intf, ip in FANOUT_INTF_IPS.items():
        logger.info("Fanout %s: assigning %s to %s", FANOUT_IP, ip, intf)
        _fanout_ssh_run(f"sudo config interface ip add {intf} {ip}")

    # Install routes
    for prefix, nexthops in FANOUT_ROUTES.items():
        if len(nexthops) > 1:
            # ECMP: multiple next-hops
            nh_args = " ".join(f"nexthop via {nh}" for nh in nexthops)
            logger.info("Fanout %s: ECMP route %s via %s",
                        FANOUT_IP, prefix, nexthops)
            _fanout_ssh_run(f"sudo ip route replace {prefix} {nh_args}")
        else:
            logger.info("Fanout %s: route %s via %s",
                        FANOUT_IP, prefix, nexthops[0])
            _fanout_ssh_run(f"sudo ip route replace {prefix} via {nexthops[0]}")

    # Ping Ixia IPs to bootstrap ARP (SONiC doesn't learn from gratuitous
    # ARPs, so the fanout needs to send a request to learn the Ixia MACs).
    for ip in (IXIA_TX_IP, IXIA_RX_IP):
        logger.info("Fanout %s: pinging %s to bootstrap ARP", FANOUT_IP, ip)
        _fanout_ssh_run(f"ping -c 1 -W 2 {ip}")


def _remove_fanout_l3():
    """Remove L3 config from the fanout: delete routes then IPs.
    Errors tolerated so cleanup is robust against partial setup.
    """
    for prefix in FANOUT_ROUTES:
        logger.info("Fanout %s: removing route %s", FANOUT_IP, prefix)
        _fanout_ssh_run(f"sudo ip route del {prefix}")

    for intf, ip in FANOUT_INTF_IPS.items():
        logger.info("Fanout %s: removing %s from %s", FANOUT_IP, ip, intf)
        _fanout_ssh_run(f"sudo config interface ip remove {intf} {ip}")


def _apply_eth96_ips(duthosts):
    """Unconditionally (re)apply the Eth96 IP on each DUT via CONFIG_DB.

    This persists in CONFIG_DB until removed in teardown. Using ``ip add``
    rather than a presence-check keeps the code simple; ``config interface
    ip add`` returns non-zero if the IP is already present, which we tolerate
    via ``module_ignore_errors``.
    """
    for i, dh in enumerate(duthosts):
        want_ip = ETH96_IP_BY_DUT[i]
        # Bring the port admin-up first
        logger.info("Bringing up %s on %s", IXIA_DUT_INTF, dh.hostname)
        dh.shell(f"sudo config interface startup {IXIA_DUT_INTF}",
                 module_ignore_errors=True)
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
    """Force HA flow-sync and DPU-down redirect traffic through the L3 fanout
    (DUT1 → Fanout → DUT2 and vice versa) instead of the default uplink path
    through the T2 cEOS VMs.

    Two distinct prefixes are steered per DUT:

    Both prefixes normally resolve via BGP through the cEOS T2 uplink
    containers, which cannot sustain the high traffic rates in this stress
    test. The L3 fanout bypasses cEOS entirely.

    1. Peer-DPU PA /24 (DIRECT_LINK_PEER_DPU_PA_PREFIX) — outer dst of the
       steady-state HA DP channel (UDP/11368) and CP channel (UDP/11362)
       used for inline flow-sync and BFD probes between the two DPUs.

    2. Peer-NPU Loopback0 /32 (DIRECT_LINK_PEER_NPU_LOOPBACK) — when the
       local DPU is in 'dead' state, the NPU re-encapsulates incoming
       customer VxLAN in a fresh VxLAN tunnel toward the peer NPU's
       Loopback0 so the peer DPU services the flow.

    Both are installed as kernel routes (distance 0 beats BGP's distance 20)
    pointing at the DUT's fanout gateway. The fanout then forwards to the
    peer DUT via its connected route.

    Returns the list of (prefix, hop) tuples installed per duthost index so
    the teardown helper can delete exactly what was added.
    """
    installed = []  # list[list[(prefix, hop)]] aligned with duthosts
    for i, dh in enumerate(duthosts):
        hop = FANOUT_GATEWAY_BY_DUT[i]
        per_dut = []
        for prefix in (DIRECT_LINK_PEER_DPU_PA_PREFIX[i],
                       DIRECT_LINK_PEER_NPU_LOOPBACK[i]):
            logger.info("HA steering on %s: %s via %s dev %s",
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
    egresses Ethernet96 toward the fanout (which then routes to Ixia RX port)
    instead of the default nexthop via PortChannel uplinks.

    Each DUT routes PE_PA via its fanout gateway. The fanout has a static
    route for PE_PA pointing at Ixia 3.2 (RX port). No static ARP needed —
    the fanout is a real L3 device and responds to ARP.

    Idempotent — safe to call multiple times.
    """
    for i, dh in enumerate(duthosts):
        gateway = FANOUT_GATEWAY_BY_DUT[i]
        logger.info("Applying Ixia steering on %s: route %s via %s dev %s",
                    dh.hostname, PE_PA_PREFIX, gateway, IXIA_DUT_INTF)
        dh.shell(f"ip route replace {PE_PA_PREFIX} via {gateway} dev {IXIA_DUT_INTF}")
        # Sanity log
        out = dh.shell(f"ip route get {PE_PA_PREFIX.split('/')[0]}", module_ignore_errors=True)['stdout']
        logger.info("%s: %s", dh.hostname, out.strip())


def _remove_ixia_steering(duthosts, dash_pl_config):
    """Restore the fixture-installed route so add_npu_static_routes' teardown
    can find its expected next-hop and succeed.

    add_npu_static_routes' teardown does:
        ip route del 101.1.2.3/32 via <pe_nexthop>
    If we leave the route pointing at the fanout (or delete it outright),
    that command fails with 'No such process'. So we 'ip route replace' it
    back to the value the fixture installed, then let the fixture's teardown
    delete it normally.

    Errors are ignored so this can run unconditionally during cleanup.
    """
    for i, dh in enumerate(duthosts):
        gateway = FANOUT_GATEWAY_BY_DUT[i]
        try:
            pe_nexthop_ip = get_interface_ip(dh, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1
            logger.info("Restoring fixture's route on %s: %s via %s",
                        dh.hostname, PE_PA_PREFIX, pe_nexthop_ip)
            dh.shell(f"ip route replace {PE_PA_PREFIX} via {pe_nexthop_ip}",
                     module_ignore_errors=True)
        except Exception as e:
            logger.warning("Could not restore fixture route on %s: %s", dh.hostname, e)
            dh.shell(f"ip route del {PE_PA_PREFIX} via {gateway} dev {IXIA_DUT_INTF}",
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
    """HA planned-shutdown stress driven by Ixia (IxNetwork).

    Flow:
      1. _configure_fanout_l3(): Assign IPs to fanout interfaces and
         install routes (ECMP for APPLIANCE_VIP, PE_PA → Ixia RX,
         peer DPU PA and Loopback0 for inter-DUT HA).
      2. _apply_eth96_ips(): Bring Eth96 admin-up and configure its IPs
         on both DUTs (10.99.2.2/30, 10.99.3.2/30).
      3. _apply_ixia_steering(): Route PE_PA via fanout gateway so GRE
         returns egress Eth96 → fanout → Ixia RX (port 3.2).
      4. _apply_direct_link_ha_steering(): Steer HA-related prefixes
         through the fanout to avoid cEOS bottlenecks:
           a. Peer DPU PA /24 — HA DP/CP channel (UDP/11368 + UDP/11362).
           b. Peer NPU Loopback0 /32 — DPU-down VxLAN re-encap to peer.
      5. [BRK != none] Breakpoint: user starts IxNetwork traffic
         (TX on 3.1, capture on 3.2), then `c` to continue.
      6. _planned_shutdown_cycle(): N HA shutdown/restart cycles,
         time-paced.
      7. [BRK != none] Breakpoint: user stops IxNetwork traffic, reads
         TX/RX counters, then `c` to continue.
      8. Teardown: remove HA steering, Ixia steering, Eth96 IPs, and
         fanout L3 config.

    Breakpoint mode (BRK env var):
      none:  No breakpoints; fully automated (steps 5/7 skipped).
      ends:  Break before Ixia start + after iterations (default).
      mid:   ends + once after primary-dead and once after secondary-dead
             (first iteration only).
    """
    direct_link_ha_routes = []
    try:
        _configure_fanout_l3()
        _apply_eth96_ips(duthosts)
        _apply_ixia_steering(duthosts)
        direct_link_ha_routes = _apply_direct_link_ha_steering(duthosts)
        # === BREAKPOINT #1: Start Ixia ===
        if BRK_MODE != "none":
            logger.info("=== IXIA START: DPU programmed, HA active, L3 fanout + steering installed. ===")
            logger.info("    In IxNetwork: start traffic on TX port (3.1), enable capture on RX port (3.2).")
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
            logger.info("    In IxNetwork: stop traffic, check TX/RX stats on ports 3.1 and 3.2.")
            logger.info("    Type `c` (continue) to proceed to cleanup.")
            breakpoint()

    finally:
        # Tear down in reverse order of setup. All helpers tolerate missing
        # state, so partial setup still produces a clean teardown.
        _remove_direct_link_ha_steering(duthosts, direct_link_ha_routes)
        # Restore the route that add_npu_static_routes installed so its own
        # teardown can delete it cleanly.
        # (Fixture teardown only reloads the DPU; NPU state would otherwise persist.)
        _remove_ixia_steering(duthosts, dash_pl_config)
        _remove_eth96_ips(duthosts)
        _remove_fanout_l3()
