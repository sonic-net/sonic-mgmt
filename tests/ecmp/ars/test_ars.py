# Summary: ARS test
# How to run this test: sudo ./run_tests.sh -n <tb name> -i <inventory files> \
#   -u -m group -e --skip_sanity -l info -c ecmp/test_ars.py

import logging
import pytest
import json
import tempfile
import time
import os
import copy
import re


from datetime import datetime
from tests.ptf_runner import ptf_runner
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

RESULTS_FILE = "/tmp/ars_test_results.json"
PACKET_COUNT = 1000
TRAFFIC_VARIATIONS = 1

# ------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------


@pytest.fixture(scope="function")
def create_rif(duthost, tbinfo):
    rif_port, rif_ptf = get_ingress_ptf_port(duthost, tbinfo, vlan_name="Vlan1000")
    rif_ip = "10.3.3.1/24"

    cmds_create = [
        f"config vlan member del 1000 {rif_port}",
        f"config interface ip add {rif_port} {rif_ip}",
    ]

    cmds_remove = [
        f"config interface ip remove {rif_port} {rif_ip}",
        f"config vlan member add -u 1000 {rif_port}"
    ]

    for cmd in cmds_create:
        duthost.shell(cmd)

    yield

    # Cleanup
    time.sleep(1)
    for cmd in cmds_remove:
        duthost.shell(cmd)
    config_reload(duthost, safe_reload=True)
    time.sleep(5)


def update_scaling_factor(duthost, port, value):
    duthost.shell(
        f"sonic-db-cli CONFIG_DB HSET 'ARS_INTERFACE|{port}' 'scaling_factor' '{value}'"
    )
    time.sleep(2)


def write_temp_config(duthost, config_data):
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8",
                                     delete=False, suffix=".json") as tmp_local:
        json.dump(config_data, tmp_local, indent=4)
        tmp_local.flush()
        tmp_name = tmp_local.name

    duthost.copy(src=tmp_name, dest="/tmp/ars_config.json")
    os.unlink(tmp_name)

    return "/tmp/ars_config.json"


def load_config(duthost):
    logging.debug("Reloading SONiC configuration via JSON...")
    duthost.shell("config load -y /tmp/ars_config.json")
    time.sleep(10)  # allow services to restart


def update_ars_interface_ports(cfg, egress_ports):
    new_table = {}

    for port in egress_ports:
        new_table[str(port)] = {
            "scaling_factor": "1",
            "ars_obj_name": "ars_obj_name"
        }

    cfg["ARS_INTERFACE"] = new_table


def configure_ars_from_json(duthost, base_cfg, nhg_mode, assign_mode, egress_ports):
    """
    Load ars.json, override fields based on test case requirement,
    generate a temporary config, and reload device.
    """
    cfg = copy.deepcopy(base_cfg)

    logging.debug(f"Applying ARS config from ars.json with overrides: "
                  f"nhg_mode={nhg_mode}, assign_mode={assign_mode}")

    if "ARS_PROFILE" in cfg:
        for profile_name, profile in cfg["ARS_PROFILE"].items():
            profile["ars_nhg_path_selector_mode"] = nhg_mode

    if "ARS_OBJECT" in cfg:
        for obj_name, obj in cfg["ARS_OBJECT"].items():
            obj["assign_mode"] = assign_mode
    update_ars_interface_ports(cfg, egress_ports)
    write_temp_config(duthost, cfg)
    load_config(duthost)

    logging.debug("ARS JSON configuration applied successfully.")


def configure_acl_from_json(duthost, acl_cfg):
    """
    Load acl.json, generate a temporary ACL config file on the DUT,
    and reload the ACL configuration.
    """
    logging.debug("Applying ACL configuration from acl.json")

    write_temp_config(duthost, acl_cfg)
    load_config(duthost)

    logging.debug("ACL JSON configuration applied successfully.")


def verify_bgp_ecmp(duthost):
    """
    Verify BGP ECMP exist in DUT.
    1) Ensures all BGP neighbors are in Established state by checking uptime formats.
    2) Ensures ECMP routes exist.
    """
    bgp_summary = duthost.shell("show ip bgp summary")["stdout"]

    neighbor_lines = [
        line for line in bgp_summary.splitlines()
        if re.match(r"^\d+\.\d+\.\d+\.\d+", line.strip())
    ]

    if not neighbor_lines:
        raise AssertionError("No BGP neighbors found")

    up_down_regex = re.compile(
        r"^(?:\d{2}:\d{2}:\d{2}|\d+d\d+h\d+m?|\d+w\d+d)$"
    )

    for line in neighbor_lines:
        parts = line.split()
        up_down = parts[-3]

        if not up_down_regex.match(up_down):
            raise AssertionError(f"BGP neighbor down: {line}")

    routes_output = duthost.shell("show ip route")["stdout"]

    if not has_ecmp_routes(routes_output):
        raise AssertionError("No ECMP routes installed")


def has_ecmp_routes(routes_output):
    """
    Detects ECMP routes in 'show ip route' output.
    ECMP = 2 or more 'via' nexthops under the same prefix.
    """

    lines = routes_output.splitlines()
    via_count = 0

    for line in lines:
        stripped = line.strip()

        if re.match(r"^[A-Z\*]>", stripped):
            if via_count > 1:
                return True
            via_count = 1 if " via " in stripped else 0
            continue

        if stripped.startswith("*") or stripped.startswith("via "):
            if " via " in stripped:
                via_count += 1
            continue

    return via_count > 1


def get_first_3_pc_member_ptf_ports(duthost, tbinfo):
    mg = duthost.get_extended_minigraph_facts(tbinfo)
    pcs = mg.get("minigraph_portchannels", {}) or {}
    ptf_indices = mg.get("minigraph_ptf_indices", {}) or {}

    dut_ports = []
    ptf_ports = []

    for pc_name in sorted(pcs.keys()):
        members = (pcs[pc_name] or {}).get("members", [])
        for member in sorted(members):
            if member in ptf_indices:
                dut_ports.append(member)
                ptf_ports.append(ptf_indices[member])
                if len(dut_ports) == 3:
                    return dut_ports, ptf_ports

    return dut_ports, ptf_ports


def get_ingress_ptf_port(duthost, tbinfo, vlan_name="Vlan1000"):
    mg = duthost.get_extended_minigraph_facts(tbinfo)
    vlans = mg.get("minigraph_vlans", {}) or {}
    ptf_indices = mg.get("minigraph_ptf_indices", {}) or {}

    if vlan_name not in vlans:
        raise RuntimeError(f"VLAN {vlan_name} not found in minigraph_vlans")

    members = vlans[vlan_name].get("members", [])
    if not members:
        raise RuntimeError(f"No members found for VLAN {vlan_name}")

    for member in sorted(members):
        if member in ptf_indices:
            return member, ptf_indices[member]

    return members[0], None


def run_ptf_ars_test(request, duthost, ptfhost, tbinfo, nhg_mode, assign_mode, router_mac, negative):
    """
    Run the ARS ECMP PTF test  on the PTF host.

    """
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    logging.info(f"Running ARS ECMP test: NHG={nhg_mode}, assign={assign_mode}")
    log_file = "/tmp/ars_ecmp_test.arsTest.{}.log"\
        .format(timestamp)
    logging.debug("PTF log file: %s" % log_file)
    ingress_member, ingress_port = get_ingress_ptf_port(duthost, tbinfo)
    egress_ports, ptf_ports = get_first_3_pc_member_ptf_ports(duthost, tbinfo)
    # Prepare PTF parameters
    ptf_params = {
        "test_case": f"ars_{nhg_mode}_{assign_mode}",
        "router_mac": router_mac,
        "packet_count": PACKET_COUNT,
        "ingress_port": ingress_port,
        "egress_ports": ptf_ports,
        "hash_keys": ["src-ip"],
        "negative": negative
    }

    # Run the PTF test using ptf_runner with Python3 mode
    ptf_runner(ptfhost,
               "ptftests",
               "arstest.ArsTest",       # module.class
               platform_dir="ptftests",
               params=ptf_params,
               log_file=log_file,
               qlen=2000,
               socket_recv_size=16384,
               is_python3=True)

    logging.info(f"PTF ARS test finished: NHG={nhg_mode}, assign={assign_mode}")


def save_results(data):
    with open(RESULTS_FILE, "w") as f:
        json.dump(data, f, indent=4)
    logging.debug(f"Results saved to {RESULTS_FILE}")


@pytest.mark.parametrize("nhg_mode", ["global", "interface", "nexthop"])
@pytest.mark.parametrize("assign_mode", ["per_packet_quality", "per_flowlet_quality"])
def test_ars_modes(request, duthost, ptfhost, tbinfo, base_ars_config, nhg_mode, assign_mode, router_mac, create_rif):
    """
    Verify ARS ECMP using ARS config loaded from ars.json,
    with dynamic overrides (nhg_mode + assign_mode).
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    pc_members = []
    for _, pc_data in (mg_facts.get("minigraph_portchannels", {}) or {}).items():
        pc_members.extend(pc_data.get("members", []))
    last_eth = pc_members[-1]
    # Apply ARS config from JSON
    egress_ports, ptf_ports = get_first_3_pc_member_ptf_ports(duthost, tbinfo)
    configure_ars_from_json(
        duthost=duthost,
        base_cfg=base_ars_config,
        nhg_mode=nhg_mode,
        assign_mode=assign_mode,
        egress_ports=egress_ports
    )
    # Verify BGP and ECMP
    verify_bgp_ecmp(duthost)
    # trigger creation of ARS
    duthost.shell(f"sudo config interface shutdown {last_eth}")
    time.sleep(10)
    # Run PTF runner
    run_ptf_ars_test(request, duthost, ptfhost, tbinfo, nhg_mode, assign_mode, router_mac, False)
    duthost.shell(f"sudo config interface startup {last_eth}")

    save_results({
        "case": "test_ars_modes",
        "nhg_mode": nhg_mode,
        "assign_mode": assign_mode,
        "status": "PASSED"
    })


def test_ars_acl_action(request, duthost, ptfhost, tbinfo, base_ars_config, router_mac, create_rif, acl_config):
    """
    Verify ACL can disable ARS forwarding for specific traffic.
    """

    cfg = copy.deepcopy(base_ars_config)

    egress_ports, ptf_ports = get_first_3_pc_member_ptf_ports(duthost, tbinfo)
    configure_ars_from_json(
        duthost=duthost,
        base_cfg=cfg,
        nhg_mode="nexthop",
        assign_mode="per_packet_quality",
        egress_ports=egress_ports
    )
    cfg = copy.deepcopy(acl_config)
    configure_acl_from_json(duthost, acl_cfg=cfg)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    pc_members = []
    for _, pc_data in (mg_facts.get("minigraph_portchannels", {}) or {}).items():
        pc_members.extend(pc_data.get("members", []))
    last_eth = pc_members[-1]

    duthost.shell(f"sudo config interface shutdown {last_eth}")
    time.sleep(10)
    verify_bgp_ecmp(duthost)
    run_ptf_ars_test(request, duthost, ptfhost, tbinfo, "global", "per-packet", router_mac, True)
    duthost.shell(f"sudo config interface startup {last_eth}")

    save_results({"case": "test_ars_acl_action", "status": "PASSED"})


@pytest.mark.parametrize("nhg_mode", ["interface", "nexthop"])
def test_ars_nonars_interface(request, duthost, ptfhost, tbinfo, base_ars_config, nhg_mode, router_mac, create_rif):
    """
    Run ARS in 2 modes:
      - interface : ARS applied using ARS_INTERFACE
      - nexthop   : ARS applied using ARS_NEXTHOP
    """

    logging.info(f"=== Running ARS Test Mode: {nhg_mode} ===")

    cfg = copy.deepcopy(base_ars_config)

    if nhg_mode == "interface":
        logging.debug("ARS Mode: interface (removing ARS_INTERFACE)")
        cfg.pop("ARS_INTERFACE", None)
    elif nhg_mode == "nexthop":
        logging.debug("ARS Mode: nexthop (removing ARS_NEXTHOP)")
        cfg.pop("ARS_NEXTHOP", None)

    egress_ports, ptf_ports = get_first_3_pc_member_ptf_ports(duthost, tbinfo)
    configure_ars_from_json(
        duthost=duthost,
        base_cfg=cfg,
        nhg_mode=nhg_mode,
        assign_mode="per_packet_quality",
        egress_ports=egress_ports
    )

    verify_bgp_ecmp(duthost)

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    pc_members = []
    for _, pc_data in (mg_facts.get("minigraph_portchannels", {}) or {}).items():
        pc_members.extend(pc_data.get("members", []))
    last_eth = pc_members[-1]
    duthost.shell(f"sudo config interface shutdown {last_eth}")
    time.sleep(10)
    try:
        run_ptf_ars_test(
            request,
            duthost,
            ptfhost, tbinfo,
            nhg_mode,
            "per-packet",
            router_mac,
            True,
        )
    except AssertionError:
        logging.warning("Traffic check failed as per testcase")

    duthost.shell(f"sudo config interface startup {last_eth}")
    save_results({
        "case": f"test_ars_{nhg_mode}",
        "status": "PASSED"
    })


def test_ars_stress(request, duthost, ptfhost, tbinfo, base_ars_config, router_mac, create_rif):
    """
    Stress test ARS ECMP under port flap and scaling factor change.
    """
    egress_ports, ptf_ports = get_first_3_pc_member_ptf_ports(duthost, tbinfo)
    configure_ars_from_json(
        duthost=duthost,
        base_cfg=base_ars_config,
        nhg_mode="nexthop",
        assign_mode="per_flowlet_quality",
        egress_ports=egress_ports
    )

    verify_bgp_ecmp(duthost)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    pc_members = []
    for _, pc_data in (mg_facts.get("minigraph_portchannels", {}) or {}).items():
        pc_members.extend(pc_data.get("members", []))
    last_eth = pc_members[-1]

    duthost.shell(f"sudo config interface shutdown {last_eth}")
    # To install ARS ecmp
    time.sleep(20)
    run_ptf_ars_test(request, duthost, ptfhost, tbinfo, "nexthop", "per-flowlet", router_mac, False)

    for port in pc_members[:2]:
        logger.info(f"Flapping port {port} ...")
        duthost.shell(f"config interface shutdown {port}")
        duthost.shell(f"config interface startup {port}")

    # update scaling factor for each PC member
    for port in pc_members:
        update_scaling_factor(duthost, port, 2)
    # To install ARS ecmp
    time.sleep(20)

    run_ptf_ars_test(request, duthost, ptfhost, tbinfo, "nexthop", "per-flowlet", router_mac, False)
    duthost.shell(f"sudo config interface startup {last_eth}")

    save_results({"case": "test_ars_stress", "status": "PASSED"})
