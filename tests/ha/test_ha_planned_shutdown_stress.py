"""HA planned-shutdown stress test driven by external Ixia traffic.

See the matching test-plan doc for more details on how to run this test:
docs/testplan/smart-switch/high-availability/test_ha_planned_shutdown_stress.md
"""
import logging
import os
import time

import paramiko
import yaml
import configs.privatelink_config as pl
import pytest
from constants import REMOTE_DUT_INTF
from tests.common.helpers.assertions import pytest_assert, pytest_require
from gnmi_utils import apply_messages
from tests.common.config_reload import config_reload
from ha_utils import activate_primary_dash_ha, activate_secondary_dash_ha, \
         verify_ha_state, set_dead_dash_ha_scope
from conftest import get_interface_ip

logger = logging.getLogger(__name__)

# Bundled default config (also a template); overridable via --ha_stress_config.
DEFAULT_STRESS_CONFIG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "configs", "ha_stress_ixia.yaml")


class StressConfig:
    """Resolved, testbed-specific settings for the stress test.

    Built from the YAML config plus values derived from the DUTs. All
    DUT-indexed attributes are ordered to match ``duthosts`` (index 0 ==
    duthosts[0]). HA is a strict 2-DUT feature, so exactly two DUTs are
    required.
    """

    def __init__(self, raw, duthosts):
        n = len(duthosts)
        pytest_require(n == 2, "HA stress test requires exactly 2 DUTs")

        dl = raw["direct_link"]
        self.dut_interface = dl["dut_interface"]
        self.dut_ips = list(dl["dut_ips"])            # device side, with mask
        self.dut_gateways = list(dl["dut_gateways"])  # fanout side next-hop
        dut_dev_ips = [ip.split("/")[0] for ip in self.dut_ips]

        fan = raw["fanout"]
        self.fanout_ip = fan["ip"]
        self.fanout_user = fan["user"]
        self.fanout_password = fan["password"]
        self.fanout_intf_ips = {x["port"]: x["ip"] for x in fan["interfaces"]}

        ixia = raw["ixia"]
        self.ixia_tx_ip = ixia["tx_ip"]
        self.ixia_rx_ip = ixia["rx_ip"]

        addr = raw.get("addressing") or {}
        # APPLIANCE_VIP: inbound VxLAN outer-dst, ECMP'd to all DUTs.
        self.appliance_vip = addr.get("appliance_vip") or pl.APPLIANCE_VIP
        # PE_PA: GRE/NVGRE return outer-dst, routed to the Ixia RX port.
        self.pe_pa = addr.get("pe_pa") or pl.PE_PA
        self.pe_pa_prefix = f"{self.pe_pa}/32"

        # Peer-DPU PA /24: outer-dst of the steady-state HA DP/CP flow-sync
        # channel between the two DPUs. Explicit per-DUT list from the config;
        # entry i is duthosts[i]'s PEER subnet (its partner's DPU PA /24).
        self.peer_dpu_pa_prefixes = list(addr["peer_dpu_pa_prefixes"])
        # Each DUT's OWN DPU PA /24 is its partner's peer entry (1 - i in a
        # 2-DUT pair); the fanout routes flow-sync traffic back to its owner.
        own_dpu_pa = [self.peer_dpu_pa_prefixes[1 - i] for i in range(n)]

        # Each DUT's Loopback0 /32 (read live). The peer DUT (1 - i) is the one
        # whose traffic we steer over the direct link.
        own_loopbacks = [f"{get_interface_ip(duthosts[i], 'Loopback0').ip}/32"
                         for i in range(n)]
        # Peer-NPU Loopback0 /32: DPU-down VxLAN re-encap target. "auto" reads
        # each DUT's Loopback0 from CONFIG_DB.
        pnl = addr.get("peer_npu_loopbacks", "auto")
        if pnl in (None, "auto"):
            self.peer_npu_loopbacks = [own_loopbacks[1 - i] for i in range(n)]
        else:
            self.peer_npu_loopbacks = list(pnl)

        # Fanout static routing table, fully derived from the primitives above:
        #   APPLIANCE_VIP -> ECMP to every DUT (inbound VxLAN)
        #   PE_PA         -> Ixia RX port (GRE/NVGRE return)
        #   own DPU PA    -> the DUT that owns it (inter-DUT HA flow-sync)
        #   own Loopback0 -> the DUT that owns it (DPU-down re-encap)
        routes = {f"{self.appliance_vip}/32": list(dut_dev_ips),
                  self.pe_pa_prefix: [self.ixia_rx_ip]}
        for i in range(n):
            routes[own_dpu_pa[i]] = [dut_dev_ips[i]]
            routes[own_loopbacks[i]] = [dut_dev_ips[i]]
        self.fanout_routes = routes

        st = raw.get("stress") or {}
        self.iterations = int(st.get("iterations", 5))
        self.pre_action_settle_s = int(st.get("pre_action_settle_s", 5))
        self.post_action_settle_s = int(st.get("post_action_settle_s", 10))


@pytest.fixture(scope="module")
def ha_stress_config(request, duthosts):
    """Load and resolve the testbed-specific stress config (see StressConfig)."""
    path = request.config.getoption("--ha_stress_config") or DEFAULT_STRESS_CONFIG
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    pytest_require(os.path.isfile(path), f"HA stress config not found: {path}")
    logger.info("Loading HA stress config from %s", path)
    with open(path) as f:
        raw = yaml.safe_load(f)
    cfg = StressConfig(raw, duthosts)
    logger.info("Resolved HA stress config: fanout=%s dut_interface=%s "
                "fanout_routes=%s peer_dpu_pa=%s peer_npu_loopbacks=%s",
                cfg.fanout_ip, cfg.dut_interface, cfg.fanout_routes,
                cfg.peer_dpu_pa_prefixes, cfg.peer_npu_loopbacks)
    return cfg


# ---------------------------------------------------------------------------
# IXIA (manual) — configure in IxNetwork before continuing from breakpoint #1.
# Two ports (TX + RX), each with an L3 topology whose IP/gateway match the
# ``ixia`` and ``fanout`` sections of the YAML config. Build a VxLAN frame
# wrapping an inner Ethernet/IPv4/L4 packet (inner src VM1_CA -> dst PE_CA;
# outer dst = APPLIANCE_VIP); vary inner L4 ports via a UDF to scale DPU flows.
# The DPU returns NVGRE toward PE_PA, routed back to the Ixia RX port. See the
# test-plan doc (section 5) for the full frame layout, UDF, and send rates.
# ---------------------------------------------------------------------------

# --- Interactive pause modes (--ha_pause_mode option) ---
#   none:  No pauses; the test never blocks (default; for unattended/CI runs).
#   ends:  Pause before traffic start + after all iterations.
#   mid:   ends + once after primary-dead and once after secondary-dead
#          (first iteration only, not every iteration).
#
# Usage: pytest ... --ha_pause_mode=ends -s
#        pytest ... --ha_pause_mode=mid  -s
# Pausing requires `-s` so the debugger has a TTY.


@pytest.fixture(scope="module")
def ha_pause_mode(request):
    """Interactive pause mode for the stress test (see --ha_pause_mode)."""
    return request.config.getoption("--ha_pause_mode")


def _pause(*messages):
    """Pause the test for manual traffic-generator interaction.

    This test still relies on a human driving IxNetwork (start/stop traffic,
    read stats) at well-defined points, so we drop into the pytest debugger
    rather than asserting. We use ``pytest.set_trace()`` (not the builtin
    ``breakpoint()``) because it integrates with pytest's output capturing —
    it suspends capture while you are at the prompt and restores it on ``c``.

    Pauses only happen when ``--ha_pause_mode`` is ``ends`` or ``mid`` (the
    caller checks); the default ``none`` keeps unattended/CI runs from blocking
    on a TTY. Pausing also requires ``pytest -s``.

    NOTE: the long-term, fully-idiomatic sonic-mgmt approach is to drive the
    traffic generator programmatically via the ``snappi_api`` fixture
    (tests/common/snappi_tests/snappi_fixtures.py), which would remove these
    manual pauses and make the test CI-runnable end to end.
    """
    for msg in messages:
        logger.info(msg)
    pytest.set_trace()


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


def _fanout_ssh_run(cfg, cmd):
    """Run a command on the fanout switch via paramiko SSH.
    Returns (stdout, stderr, exit_code).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 — lab fanout, config-supplied IP
    try:
        client.connect(cfg.fanout_ip, port=22, username=cfg.fanout_user,
                       password=cfg.fanout_password, timeout=10)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='replace').strip()
        err = stderr.read().decode('utf-8', errors='replace').strip()
        return out, err, rc
    finally:
        client.close()


def _configure_fanout_l3(cfg):
    """Configure L3 routing on the fanout: assign IPs to interfaces and
    install static routes (including ECMP for APPLIANCE_VIP).

    Idempotent — uses 'ip add' (tolerates "already assigned") and
    'ip route replace'.
    """
    # Assign IPs to fanout interfaces
    for intf, ip in cfg.fanout_intf_ips.items():
        logger.info("Fanout %s: assigning %s to %s", cfg.fanout_ip, ip, intf)
        _fanout_ssh_run(cfg, f"sudo config interface ip add {intf} {ip}")

    # Install routes
    for prefix, nexthops in cfg.fanout_routes.items():
        if len(nexthops) > 1:
            # ECMP: multiple next-hops
            nh_args = " ".join(f"nexthop via {nh}" for nh in nexthops)
            logger.info("Fanout %s: ECMP route %s via %s",
                        cfg.fanout_ip, prefix, nexthops)
            _fanout_ssh_run(cfg, f"sudo ip route replace {prefix} {nh_args}")
        else:
            logger.info("Fanout %s: route %s via %s",
                        cfg.fanout_ip, prefix, nexthops[0])
            _fanout_ssh_run(cfg, f"sudo ip route replace {prefix} via {nexthops[0]}")

    # Ping Ixia IPs to bootstrap ARP (SONiC doesn't learn from gratuitous
    # ARPs, so the fanout needs to send a request to learn the Ixia MACs).
    for ip in (cfg.ixia_tx_ip, cfg.ixia_rx_ip):
        logger.info("Fanout %s: pinging %s to bootstrap ARP", cfg.fanout_ip, ip)
        _fanout_ssh_run(cfg, f"ping -c 1 -W 2 {ip}")


def _remove_fanout_l3(cfg):
    """Remove L3 config from the fanout: delete routes then IPs.
    Errors tolerated so cleanup is robust against partial setup.
    """
    for prefix in cfg.fanout_routes:
        logger.info("Fanout %s: removing route %s", cfg.fanout_ip, prefix)
        _fanout_ssh_run(cfg, f"sudo ip route del {prefix}")

    for intf, ip in cfg.fanout_intf_ips.items():
        logger.info("Fanout %s: removing %s from %s", cfg.fanout_ip, ip, intf)
        _fanout_ssh_run(cfg, f"sudo config interface ip remove {intf} {ip}")


def _apply_direct_link_ips(cfg, duthosts):
    """Unconditionally (re)apply the direct-link IP on each DUT via CONFIG_DB.

    This persists in CONFIG_DB until removed in teardown. Using ``ip add``
    rather than a presence-check keeps the code simple; ``config interface
    ip add`` returns non-zero if the IP is already present, which we tolerate
    via ``module_ignore_errors``.
    """
    for i, dh in enumerate(duthosts):
        want_ip = cfg.dut_ips[i]
        # Bring the port admin-up first
        logger.info("Bringing up %s on %s", cfg.dut_interface, dh.hostname)
        dh.shell(f"sudo config interface startup {cfg.dut_interface}",
                 module_ignore_errors=True)
        logger.info("Configuring %s on %s of %s", want_ip, cfg.dut_interface, dh.hostname)
        dh.shell(f"sudo config interface ip add {cfg.dut_interface} {want_ip}",
                 module_ignore_errors=True)


def _remove_direct_link_ips(cfg, duthosts):
    """Remove the direct-link IPs that ``_apply_direct_link_ips`` added. Errors
    ignored so cleanup is robust against partial setup.
    """
    for i, dh in enumerate(duthosts):
        want_ip = cfg.dut_ips[i]
        logger.info("Removing %s from %s of %s", want_ip, cfg.dut_interface, dh.hostname)
        dh.shell(f"sudo config interface ip remove {cfg.dut_interface} {want_ip}",
                 module_ignore_errors=True)


def _apply_direct_link_ha_steering(cfg, duthosts):
    """Force HA flow-sync and DPU-down redirect traffic through the L3 fanout
    (DUT1 → Fanout → DUT2 and vice versa) instead of the default uplink path
    through the T2 cEOS VMs.

    Two distinct prefixes are steered per DUT:

    Both prefixes normally resolve via BGP through the cEOS T2 uplink
    containers, which cannot sustain the high traffic rates in this stress
    test. The L3 fanout bypasses cEOS entirely.

    1. Peer-DPU PA /24 (cfg.peer_dpu_pa_prefixes) — outer dst of the
       steady-state HA DP channel (UDP/11368) and CP channel (UDP/11362)
       used for inline flow-sync and BFD probes between the two DPUs.

    2. Peer-NPU Loopback0 /32 (cfg.peer_npu_loopbacks) — when the
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
        hop = cfg.dut_gateways[i]
        per_dut = []
        for prefix in (cfg.peer_dpu_pa_prefixes[i],
                       cfg.peer_npu_loopbacks[i]):
            logger.info("HA steering on %s: %s via %s dev %s",
                        dh.hostname, prefix, hop, cfg.dut_interface)
            dh.shell(f"ip route replace {prefix} via {hop} dev {cfg.dut_interface}")
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


def _remove_direct_link_ha_steering(cfg, duthosts, installed_prefixes):
    """Delete the kernel routes installed by
    ``_apply_direct_link_ha_steering`` so the BGP-installed route via the
    regular uplinks takes over again. Tolerates missing routes.
    """
    if not installed_prefixes:
        return
    for i, dh in enumerate(duthosts):
        if i >= len(installed_prefixes) or not installed_prefixes[i]:
            continue
        for prefix, hop in installed_prefixes[i]:
            logger.info("Removing direct-link HA steering on %s: %s via %s",
                        dh.hostname, prefix, hop)
            dh.shell(f"ip route del {prefix} via {hop} dev {cfg.dut_interface}",
                     module_ignore_errors=True)


def _apply_ixia_steering(cfg, duthosts):
    """Override the route installed by add_npu_static_routes so the GRE return
    egresses the direct-link interface toward the fanout (which then routes to
    the Ixia RX port) instead of the default nexthop via PortChannel uplinks.

    Each DUT routes PE_PA via its fanout gateway. The fanout has a static
    route for PE_PA pointing at the Ixia RX port. No static ARP needed —
    the fanout is a real L3 device and responds to ARP.

    Idempotent — safe to call multiple times.
    """
    for i, dh in enumerate(duthosts):
        gateway = cfg.dut_gateways[i]
        logger.info("Applying Ixia steering on %s: route %s via %s dev %s",
                    dh.hostname, cfg.pe_pa_prefix, gateway, cfg.dut_interface)
        dh.shell(f"ip route replace {cfg.pe_pa_prefix} via {gateway} dev {cfg.dut_interface}")
        # Sanity log
        out = dh.shell(f"ip route get {cfg.pe_pa}", module_ignore_errors=True)['stdout']
        logger.info("%s: %s", dh.hostname, out.strip())


def _remove_ixia_steering(cfg, duthosts, dash_pl_config):
    """Restore the fixture-installed route so add_npu_static_routes' teardown
    can find its expected next-hop and succeed.

    add_npu_static_routes' teardown does:
        ip route del <pe_pa>/32 via <pe_nexthop>
    If we leave the route pointing at the fanout (or delete it outright),
    that command fails with 'No such process'. So we 'ip route replace' it
    back to the value the fixture installed, then let the fixture's teardown
    delete it normally.

    Errors are ignored so this can run unconditionally during cleanup.
    """
    for i, dh in enumerate(duthosts):
        gateway = cfg.dut_gateways[i]
        try:
            pe_nexthop_ip = get_interface_ip(dh, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1
            logger.info("Restoring fixture's route on %s: %s via %s",
                        dh.hostname, cfg.pe_pa_prefix, pe_nexthop_ip)
            dh.shell(f"ip route replace {cfg.pe_pa_prefix} via {pe_nexthop_ip}",
                     module_ignore_errors=True)
        except Exception as e:
            logger.warning("Could not restore fixture route on %s: %s", dh.hostname, e)
            dh.shell(f"ip route del {cfg.pe_pa_prefix} via {gateway} dev {cfg.dut_interface}",
                     module_ignore_errors=True)


def _planned_shutdown_cycle(
    localhost,
    duthosts,
    ptfhost,
    ha_owner,
    iteration,
    cfg,
    break_mode="none",
):
    """One HA planned shutdown cycle, time-paced. Ixia drives the data plane
    externally.

    If break_mode == 'mid' and iteration == 1, drops into pdb after each
    dead/standalone transition so you can inject new flows (e.g. SYN burst)
    while one side is down. Only pauses on the first iteration."""

    # --- Phase 1: shutdown primary ---
    logger.info("Iter %d: settle %ds, then set primary dead", iteration, cfg.pre_action_settle_s)
    time.sleep(cfg.pre_action_settle_s)

    set_dead_dash_ha_scope(localhost, duthosts[0], ptfhost, "vdpu0_0:haset0_0")
    time.sleep(cfg.post_action_settle_s)

    pytest_assert(verify_ha_state(duthosts[0], "vdpu0_0:haset0_0", "dead"),
                  f"Iter {iteration}: Primary HA state is not dead")
    pytest_assert(verify_ha_state(duthosts[1], "vdpu1_0:haset0_0", "standalone"),
                  f"Iter {iteration}: Secondary HA state is not standalone")

    if break_mode == "mid" and iteration == 1:
        _pause("=== PRIMARY is DEAD, SECONDARY is STANDALONE. ===",
               "    Inject new flows (SYN burst) or inspect state, then `c`.")

    pytest_assert(activate_primary_dash_ha(localhost, duthosts[0], ptfhost,
                                           "vdpu0_0:haset0_0", "activate_role",
                                           owner=ha_owner),
                  f"Iter {iteration}: Failed to re-activate HA on primary")
    time.sleep(cfg.post_action_settle_s)

    # --- Phase 2: shutdown standby ---
    logger.info("Iter %d: settle %ds, then set standby dead", iteration, cfg.pre_action_settle_s)
    time.sleep(cfg.pre_action_settle_s)

    set_dead_dash_ha_scope(localhost, duthosts[1], ptfhost, "vdpu1_0:haset0_0")
    time.sleep(cfg.post_action_settle_s)

    pytest_assert(verify_ha_state(duthosts[1], "vdpu1_0:haset0_0", "dead"),
                  f"Iter {iteration}: Secondary HA state is not dead")
    pytest_assert(verify_ha_state(duthosts[0], "vdpu0_0:haset0_0", "standalone"),
                  f"Iter {iteration}: Primary HA state is not standalone")

    if break_mode == "mid" and iteration == 1:
        _pause("=== SECONDARY is DEAD, PRIMARY is STANDALONE. ===",
               "    Inject new flows (SYN burst) or inspect state, then `c`.")

    pytest_assert(activate_secondary_dash_ha(localhost, duthosts[1], ptfhost,
                                             "vdpu1_0:haset0_0", "activate_role",
                                             owner=ha_owner),
                  f"Iter {iteration}: Failed to re-activate HA on standby")
    time.sleep(cfg.post_action_settle_s)


def test_ha_planned_shutdown_stress_ixia(
    localhost,
    duthosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    ha_stress_config,
    ha_pause_mode,
):
    """HA planned-shutdown stress driven by Ixia (IxNetwork).

    All testbed-specific values come from ``ha_stress_config`` (YAML, see
    --ha_stress_config). Flow:
      1. _configure_fanout_l3(): Assign IPs to fanout interfaces and
         install routes (ECMP for APPLIANCE_VIP, PE_PA → Ixia RX,
         peer DPU PA and Loopback0 for inter-DUT HA).
      2. _apply_direct_link_ips(): Bring the direct-link interface admin-up
         and configure its per-DUT IPs.
      3. _apply_ixia_steering(): Route PE_PA via fanout gateway so GRE
         returns egress the direct link → fanout → Ixia RX.
      4. _apply_direct_link_ha_steering(): Steer HA-related prefixes
         through the fanout to avoid cEOS bottlenecks:
           a. Peer DPU PA /24 — HA DP/CP channel (UDP/11368 + UDP/11362).
           b. Peer NPU Loopback0 /32 — DPU-down VxLAN re-encap to peer.
      5. [pause unless none] Pause: user starts the traffic generator (TX
         port, capture on RX port), then `c` to continue.
      6. _planned_shutdown_cycle(): N HA shutdown/restart cycles,
         time-paced.
      7. [pause unless none] Pause: user stops the traffic generator, reads
         TX/RX counters, then `c` to continue.
      8. Teardown: remove HA steering, Ixia steering, direct-link IPs, and
         fanout L3 config.

    Pause mode (--ha_pause_mode option, requires pytest -s):
      none:  No pauses; the test never blocks (default; steps 5/7 skipped).
      ends:  Pause before traffic start + after iterations.
      mid:   ends + once after primary-dead and once after secondary-dead
             (first iteration only).
    """
    cfg = ha_stress_config
    direct_link_ha_routes = []
    try:
        _configure_fanout_l3(cfg)
        _apply_direct_link_ips(cfg, duthosts)
        _apply_ixia_steering(cfg, duthosts)
        direct_link_ha_routes = _apply_direct_link_ha_steering(cfg, duthosts)
        # === PAUSE #1: Start the traffic generator ===
        if ha_pause_mode != "none":
            _pause("=== TRAFFIC START: DPU programmed, HA active, L3 fanout + steering installed. ===",
                   "    In the traffic generator: start traffic on the TX port, enable capture on the RX port.",
                   f"    Type `c` (continue) to begin {cfg.iterations} HA iterations, or `q` to abort.")

        for iteration in range(1, cfg.iterations + 1):
            logger.info("=== Stress iteration %d / %d ===", iteration, cfg.iterations)
            try:
                _planned_shutdown_cycle(
                    localhost,
                    duthosts,
                    ptfhost,
                    ha_owner,
                    iteration,
                    cfg,
                    break_mode=ha_pause_mode,
                )
            except BaseException as exc:
                # On failure, optionally drop to the debugger with live state
                # preserved (only when paused, so CI runs never hang).
                logger.error(
                    "=== Iteration %d FAILED: %s: %s ===",
                    iteration, type(exc).__name__, exc,
                )
                if ha_pause_mode != "none":
                    _pause(
                        "    Dropping to debugger BEFORE teardown so live state "
                        "is preserved. Type `c` to continue to teardown, `q` to abort."
                    )
                raise
            logger.info("=== Completed iteration %d / %d ===", iteration, cfg.iterations)

        logger.info("All %d HA iterations completed.", cfg.iterations)

        # === PAUSE #2: Stop the traffic generator and collect numbers ===
        if ha_pause_mode != "none":
            _pause("=== TRAFFIC STOP: HA iterations done; HA + DASH config still active. ===",
                   "    In the traffic generator: stop traffic, check TX/RX stats on both ports.",
                   "    Type `c` (continue) to proceed to cleanup.")

    finally:
        # Tear down in reverse order of setup. All helpers tolerate missing
        # state, so partial setup still produces a clean teardown.
        _remove_direct_link_ha_steering(cfg, duthosts, direct_link_ha_routes)
        # Restore the route that add_npu_static_routes installed so its own
        # teardown can delete it cleanly.
        # (Fixture teardown only reloads the DPU; NPU state would otherwise persist.)
        _remove_ixia_steering(cfg, duthosts, dash_pl_config)
        _remove_direct_link_ips(cfg, duthosts)
        _remove_fanout_l3(cfg)
