"""Shared helpers for dpdk-tgen / OTG throughput tests in sonic-mgmt."""

import logging
import os
import re
import time

from tests.common.snappi_tests.otg_metrics import poll_flow_metric, poll_port_metrics
logger = logging.getLogger(__name__)

FLOW_NAME = "otg_throughput"
_CARD_PORT_RE = re.compile(r"^Card(\d+)/Port(\d+)$", re.IGNORECASE)
_PROXY_ENV_KEYS = (
    "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ftp_proxy", "FTP_PROXY",
)
_NO_PROXY_KEYS = ("no_proxy", "NO_PROXY")


def configure_otg_client_environment(tbinfo):
    """
    Strip corporate proxy env, extend no_proxy, set TGEN_API for bridge -> host OTG.

    Returns a dict of prior env values for teardown (otg/conftest.py).
    """
    saved = {}
    api_host = str(tbinfo.get("ptf_ip", "")).split("/")[0]
    bypass_hosts = ["localhost", "127.0.0.1"]
    if api_host:
        bypass_hosts.append(api_host)
    docker_gw = os.environ.get("OTG_DOCKER_HOST_GATEWAY", "172.17.0.1")
    bypass_hosts.append(docker_gw)

    for key in _PROXY_ENV_KEYS:
        saved[key] = os.environ.pop(key, None)

    for key in _NO_PROXY_KEYS:
        saved[key] = os.environ.get(key)
        cur = saved[key] or ""
        parts = [p.strip() for p in cur.split(",") if p.strip()]
        for host in bypass_hosts:
            if host not in parts:
                parts.append(host)
        os.environ[key] = ",".join(parts)

    if os.environ.get("TGEN_API"):
        return saved

    port = 8443
    if tbinfo.get("tg_api_server") and ":" in str(tbinfo["tg_api_server"]):
        try:
            port = int(str(tbinfo["tg_api_server"]).rsplit(":", 1)[-1])
        except ValueError:
            pass

    otg_tb = "OTG" in (tbinfo.get("ptf_image_name") or "").upper()
    use_gw = otg_tb or os.environ.get("OTG_USE_DOCKER_HOST_GATEWAY", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if use_gw:
        saved["TGEN_API"] = os.environ.get("TGEN_API")
        scheme = os.environ.get("TGEN_API_SCHEME", "http")
        os.environ["TGEN_API"] = "%s://%s:%s" % (scheme, docker_gw, port)

    return saved


def build_snappi_ports_from_conn_graph(conn_graph_facts, dut_hostname, api_server_ip):
    """
    Build snappi port dicts from conn_graph_facts without fanout_graph_facts.

    ``get_snappi_ports_single_dut`` indexes SnappiFanoutManager with the position
    of the chassis in *all* fanout_graph_facts keys; on nokia graphs with many
    non-tgen fanouts that index is wrong and raises IndexError.
    """
    dev_conn = conn_graph_facts.get("device_conn", {}).get(dut_hostname, {})
    api_ip = str(api_server_ip).split("/")[0]
    ports = []
    for dut_port, link in dev_conn.items():
        peerport = (link.get("peerport") or "").strip()
        match = _CARD_PORT_RE.match(peerport)
        if not match:
            continue
        card_id, port_id = match.group(1), match.group(2)
        ports.append(
            {
                "peer_port": dut_port,
                "peer_device": dut_hostname,
                "peerdevice": link.get("peerdevice"),
                "ip": api_ip,
                "card_id": card_id,
                "port_id": port_id,
                "speed": str(link.get("speed", "100000")),
                # dpdk-tgen matches locations as CardN/PortM (see resources.Port.location).
                "location": "Card%s/Port%s" % (card_id, port_id),
            }
        )
    if len(ports) < 2:
        raise RuntimeError(
            "Need at least two Card*/Port* links on %s in conn_graph_facts; got %s"
            % (dut_hostname, [p["peer_port"] for p in ports])
        )
    return ports


def build_otg_api_base(tbinfo, snappi_api_serv_ip, snappi_api_serv_port):
    """REST base URL for metrics polling (matches snappi_api OTG branch)."""
    env = os.environ.get("TGEN_API")
    if env:
        return env.rstrip("/")
    name = (tbinfo.get("ptf_image_name") or "").upper()
    if "OTG" in name:
        scheme = os.environ.get("TGEN_API_SCHEME", "http")
        host = os.environ.get("OTG_DOCKER_HOST_GATEWAY", "172.17.0.1")
        return "%s://%s:%s" % (scheme, host, snappi_api_serv_port)
    return "https://%s:%s" % (snappi_api_serv_ip, snappi_api_serv_port)


def clear_dut_interface_counters(duthost):
    """Clear SONiC port counters before a measured iteration."""
    duthost.shell("sonic-clear counters", module_ignore_errors=False)
    time.sleep(1)


def pick_snappi_ports_for_dut_links(snappi_ports, ingress_peer, egress_peer):
    """Map DUT interfaces (generator tx / rx cabling) to snappi port dicts."""
    tx_port = None
    rx_port = None
    for port in snappi_ports:
        peer = port.get("peer_port")
        if peer == ingress_peer:
            tx_port = port
        elif peer == egress_peer:
            rx_port = port
    if tx_port is None or rx_port is None:
        peers = [p.get("peer_port") for p in snappi_ports]
        raise RuntimeError(
            "Could not find snappi ports for DUT %s / %s in %s"
            % (ingress_peer, egress_peer, peers)
        )
    return tx_port, rx_port


def build_throughput_config(
    api,
    tx_location,
    rx_location,
    frame_size,
    rate_gbps,
    duration_sec,
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    src_port=5001,
    dst_port=5002,
):
    config = api.config()

    tx = config.ports.port(name="tx", location=tx_location)[-1]
    rx = config.ports.port(name="rx", location=rx_location)[-1]

    flow = config.flows.flow(name=FLOW_NAME)[-1]
    flow.tx_rx.port.tx_name = tx.name
    flow.tx_rx.port.rx_names = [rx.name]
    flow.size.fixed = frame_size
    flow.duration.fixed_seconds.seconds = duration_sec
    flow.metrics.enable = True

    rate_gbps_int = int(rate_gbps)
    try:
        flow.rate.choice = flow.rate.GBPS
        # snappi Python bindings require uint32, not float (5.0 fails validation).
        flow.rate.gbps = rate_gbps_int
    except (AttributeError, TypeError, ValueError):
        flow.rate.choice = flow.rate.BPS
        flow.rate.bps = rate_gbps_int * 1_000_000_000

    eth, ipv4, udp = flow.packet.ethernet().ipv4().udp()
    eth.src.value = src_mac
    eth.dst.value = dst_mac
    ipv4.src.value = src_ip
    ipv4.dst.value = dst_ip
    udp.src_port.value = src_port
    udp.dst_port.value = dst_port

    return config


def wait_until_flow_stopped(api_base, flow_name, duration_sec, poll_sec=1.0):
    """Poll OTG until transmit stops after a fixed-duration flow."""
    timeout = duration_sec + 120
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = poll_flow_metric(api_base, flow_name)
        logger.info(
            "flow %s: tx=%d rx=%d transmit=%s",
            flow_name,
            last.frames_tx,
            last.frames_rx,
            getattr(last, "transmit", "?"),
        )
        if getattr(last, "transmit", None) == "stopped" and last.frames_tx > 0:
            return last
        time.sleep(poll_sec)
    raise TimeoutError(
        "flow %s did not stop within %ds (last tx=%s)"
        % (flow_name, timeout, getattr(last, "frames_tx", None))
    )


def _port_metric_by_name(port_metrics, name):
    for port in port_metrics:
        if port.name == name:
            return port
    return None


def verify_iteration(
    flow_metric,
    port_metrics,
    dut_ingress_rx,
    dut_egress_tx,
    dut_ingress_rx_drp,
    dut_egress_tx_drp,
    counter_tolerance=0,
):
    """
    Return (ok, list of (check, passed, detail)).

    Phase 1e: fail if OTG flow tx != rx. DUT: no drops; egress TX >= ingress RX.
    OTG_STRICT_DUT_COUNTERS=1 restores exact tgen?dut counter matching.
    """
    checks = []
    strict_dut = os.environ.get("OTG_STRICT_DUT_COUNTERS", "").lower() in (
        "1",
        "true",
        "yes",
    )
    lost = flow_metric.frames_tx - flow_metric.frames_rx
    checks.append(
        (
            "generator flow lossless",
            lost == 0,
            "tx=%d rx=%d lost=%d" % (flow_metric.frames_tx, flow_metric.frames_rx, lost),
        )
    )
    checks.append(
        ("generator transmitted", flow_metric.frames_tx > 0, "frames_tx=%d" % flow_metric.frames_tx)
    )

    tx_hw = _port_metric_by_name(port_metrics, "tx")
    rx_hw = _port_metric_by_name(port_metrics, "rx")
    if tx_hw is not None:
        checks.append(
            (
                "flow tx vs tx port hw opackets (info)",
                True,
                "flow=%d hw=%d" % (flow_metric.frames_tx, tx_hw.frames_tx),
            )
        )
    if rx_hw is not None:
        checks.append(
            (
                "flow rx vs rx port hw ipackets (info)",
                True,
                "flow=%d hw=%d" % (flow_metric.frames_rx, rx_hw.frames_rx),
            )
        )

    checks.append(
        (
            "DUT egress TX >= ingress RX",
            dut_egress_tx >= dut_ingress_rx,
            "ingress_rx=%d egress_tx=%d" % (dut_ingress_rx, dut_egress_tx),
        )
    )
    if strict_dut:
        delta_in = abs(flow_metric.frames_tx - dut_ingress_rx)
        checks.append(
            (
                "DUT ingress RX vs generator tx (strict)",
                delta_in <= counter_tolerance,
                "tgen_tx=%d dut_rx=%d delta=%d tol=%d"
                % (flow_metric.frames_tx, dut_ingress_rx, delta_in, counter_tolerance),
            )
        )
        delta_out = abs(flow_metric.frames_rx - dut_egress_tx)
        checks.append(
            (
                "DUT egress TX vs generator rx (strict)",
                delta_out <= counter_tolerance,
                "tgen_rx=%d dut_tx=%d delta=%d tol=%d"
                % (flow_metric.frames_rx, dut_egress_tx, delta_out, counter_tolerance),
            )
        )
    checks.append(
        ("DUT ingress RX_DRP", dut_ingress_rx_drp == 0, "RX_DRP=%d" % dut_ingress_rx_drp)
    )
    checks.append(
        ("DUT egress TX_DRP", dut_egress_tx_drp == 0, "TX_DRP=%d" % dut_egress_tx_drp)
    )

    ok = all(passed for _, passed, _ in checks)
    return ok, checks


def run_one_rate_step(
    api,
    api_base,
    tx_location,
    rx_location,
    duthost,
    dut_ingress_port,
    dut_egress_port,
    rate_gbps,
    frame_size,
    duration_sec,
    l2_l3,
    counter_tolerance=0,
):
    clear_dut_interface_counters(duthost)

    config = build_throughput_config(
        api,
        tx_location,
        rx_location,
        frame_size,
        rate_gbps,
        duration_sec,
        l2_l3["src_mac"],
        l2_l3["dst_mac"],
        l2_l3["src_ip"],
        l2_l3["dst_ip"],
        l2_l3.get("src_port", 5001),
        l2_l3.get("dst_port", 5002),
    )
    response = api.set_config(config)
    for warning in getattr(response, "warnings", None) or []:
        logger.warning("OTG set_config: %s", warning)

    state = api.control_state()
    state.traffic.flow_transmit.state = state.traffic.flow_transmit.START
    api.set_control_state(state)

    wait_until_flow_stopped(api_base, FLOW_NAME, duration_sec)
    time.sleep(1)

    flow = poll_flow_metric(api_base, FLOW_NAME)
    ports = poll_port_metrics(api_base, ["tx", "rx"])

    from tests.common.snappi_tests.common_helpers import get_port_stats

    dut_rx = get_port_stats(duthost, dut_ingress_port, "RX_OK")
    dut_tx = get_port_stats(duthost, dut_egress_port, "TX_OK")
    dut_rx_drp = get_port_stats(duthost, dut_ingress_port, "RX_DRP")
    dut_tx_drp = get_port_stats(duthost, dut_egress_port, "TX_DRP")

    ok, checks = verify_iteration(
        flow,
        ports,
        dut_rx,
        dut_tx,
        dut_rx_drp,
        dut_tx_drp,
        counter_tolerance=counter_tolerance,
    )
    return ok, checks, flow, ports, dut_rx, dut_tx


def otg_port_location(port):
    """OTG REST config: CardN/PortM (not Ixia ip;card;port from get_snappi_port_location)."""
    loc = port.get("location")
    if loc and loc.startswith("Card") and "/" in loc:
        return loc
    return "Card%s/Port%s" % (port["card_id"], port["port_id"])


def locations_from_snappi_ports(tx_port, rx_port):
    return otg_port_location(tx_port), otg_port_location(rx_port)
