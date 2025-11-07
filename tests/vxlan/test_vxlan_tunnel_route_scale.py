import json
import sys
import time
import logging
import pytest
import traceback
from ipaddress import IPv4Address
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.reboot import reboot
from tests.ptf_runner import ptf_runner
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa:F401

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

PTF_VTEP = "100.0.1.10"
TUNNEL_NAME = "tunnel_v4"

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
]

# -------------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------------
def get_loopback_ip(cfg_facts):
    for key in cfg_facts.get("LOOPBACK_INTERFACE", {}):
        if key.startswith("Loopback0|") and "." in key:
            return key.split("|")[1].split("/")[0]

    pytest.fail("Cannot find IPv4 Loopback0 address in LOOPBACK_INTERFACE")


def generate_routes(vnet_id: int, count: int):
    base = int(IPv4Address(f"30.{vnet_id}.0.0"))
    return [f"{IPv4Address(base + i)}/32" for i in range(count)]


def apply_chunk(duthost, payload, config_name):
    content = json.dumps(payload, indent=2)
    file_dest = f"/tmp/{config_name}_chunk.json"
    duthost.copy(content=content, dest=file_dest)
    duthost.shell(f"sonic-cfggen -j {file_dest} --write-to-db")
    duthost.shell(f"cp {file_dest} /home/admin/")


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """
    Return vlan id and available ports in that vlan if there are enough ports available.

    Args:
        cfg_facts: DUT config facts
        num_ports_needed: number of available ports needed for test
    """
    port_status = cfg_facts["PORT"]
    vlan_id = -1
    available_ports = []
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        # Number of members in vlan is insufficient
        if len(members) < num_ports_needed:
            continue

        # Get available ports in vlan
        possible_ports = []
        for vlan_member in members:
            if port_status[vlan_member].get("admin_status", "down") != "up":
                continue

            possible_ports.append(vlan_member)
            if len(possible_ports) == num_ports_needed:
                available_ports = possible_ports[:]
                vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
                break

        if vlan_id != -1:
            break

    logger.debug(f"Vlan {vlan_id} has available ports: {available_ports}")
    return available_ports


def restore_config_db(localhost, duthost, ptfhost, setup_params=None):
    logger.info("Restoring DUT config DB from backup")
    try:
        if setup_params and "vnet_ptf_map" in setup_params and ptfhost:
            vnet_map = setup_params["vnet_ptf_map"]
            logger.info(f"Flushing IPs on {len(vnet_map)} PTF interfaces")
            for vnet, info in vnet_map.items():
                port_name = info.get("ptf_intf")
                if port_name:
                    logger.info(f"Flushing IP address on {port_name}")
                    try:
                        ptfhost.shell(f"ip addr flush dev {port_name}")
                    except Exception as e:
                        logger.warning(f"Failed to flush {port_name}: {e}")
                else:
                    logger.warning(f"No ptf_intf defined for {vnet}")
    except Exception as e:
        logger.warning(f"PTF interface cleanup failed: {e}")

    # Restore DUT config and reboot
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    reboot(duthost, localhost)


def vxlan_setup_config(config_facts, cfg_facts, duthost, dut_indx, ptfhost,
                       tbinfo, num_vnets, routes_per_vnet, vnet_base):
    ports = get_available_vlan_id_and_ports(config_facts, num_vnets)
    pytest_assert(ports and len(ports) >= num_vnets, "Not enough ports for VNET setup")

    port_indexes = config_facts["port_index_map"]

    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {host_interfaces[k]: f"eth{k}" for k in host_interfaces}
    logger.info(f"PTF port map: {ptf_ports_available_in_topo}")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    for p in ports:
        duthost.shell(f"config vlan member del all {p} || true")

    dut_vtep = get_loopback_ip(cfg_facts)
    ptf_vtep = PTF_VTEP
    vxlan_tun = TUNNEL_NAME
    apply_chunk(duthost, {"VXLAN_TUNNEL": {vxlan_tun: {"src_ip": dut_vtep}}}, "vxlan_tunnel")
    time.sleep(5)

    vnet_ptf_map = {}

    for idx in range(num_vnets):
        vnet_id = idx + 1
        vnet_name = f"Vnet{vnet_id}"
        vni = vnet_base + vnet_id
        iface = ports[idx]
        ptf_port_index = port_indexes[iface]
        port_name = ptf_ports_available_in_topo[ptf_port_index]

        dut_intf_ip = f"201.0.{vnet_id}.1"
        ingress_ptf_ip = f"201.0.{vnet_id}.101"

        vnet_ptf_map[vnet_name] = {
            "vnet_id": vnet_id,
            "dut_intf": iface,
            "ptf_intf": port_name,
            "ptf_ifindex": ptf_port_index,
        }

        logger.info(f"Configuring {vnet_name} on {iface} <-> {port_name}")

        ptfhost.shell(f"ip addr flush dev {port_name}")
        ptfhost.shell(f"ip addr add {ingress_ptf_ip}/24 dev {port_name}")
        ptfhost.shell(f"ip link set {port_name} up")

        duthost.shell(f"config vnet add {vnet_name} {vni} {vxlan_tun}")

        apply_chunk(
            duthost,
            {
                "VNET": {
                    vnet_name: {
                        "vni": str(vni),
                        "vxlan_tunnel": vxlan_tun
                    }
                }
            },
            f"vnet_{vnet_name}",
        )
        time.sleep(5)
        apply_chunk(
            duthost,
            {
                "INTERFACE": {
                    iface: {"vnet_name": vnet_name},
                    f"{iface}|{dut_intf_ip}/24": {},
                }
            },
            f"intf_{vnet_name}",
        )
    time.sleep(20)
    for idx in range(num_vnets):
        vnet_id = idx + 1
        vnet_name = f"Vnet{vnet_id}"
        vni = vnet_base + vnet_id
        logger.info(f"Generating {routes_per_vnet} routes for {vnet_name}")
        routes = generate_routes(vnet_id, routes_per_vnet)
        vnet_routes = {
            f"{vnet_name}|{r}": {"endpoint": ptf_vtep, "vni": str(vni)} for r in routes
        }

        logger.info(f"Applying {len(vnet_routes)} routes for {vnet_name}")
        apply_chunk(duthost, {"VNET_ROUTE_TUNNEL": vnet_routes}, f"vnet_routes_{vnet_name}")
        time.sleep(10)

    logger.info("Discovering PortChannel egress members ...")
    egress_ptf_if = []
    pc_members = cfg_facts.get("PORTCHANNEL_MEMBER", {})

    for pc_key in pc_members.keys():
        # key format: "PortChannel101|Ethernet0"
        _, member = pc_key.split("|")
        if member in port_indexes:
            ptf_index = port_indexes[member]
            if ptf_index in ptf_ports_available_in_topo:
                egress_ptf_if.append(ptf_index)

    pytest_assert(egress_ptf_if, "No egress PTF interfaces discovered from PortChannels")
    logger.info(f"Egress PTF interfaces: {egress_ptf_if}")

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=duthost.facts["router_mac"])

    time.sleep(10)

    setup_params = {
        "dut_vtep": dut_vtep,
        "ptf_vtep": ptf_vtep,
        "vnet_base": vnet_base,
        "num_vnets": num_vnets,
        "routes_per_vnet": routes_per_vnet,
        "vnet_ptf_map": vnet_ptf_map,
        "egress_ptf_if": egress_ptf_if,
        "router_mac": duthost.facts["router_mac"],
    }
    return setup_params


@pytest.fixture(scope="module", autouse=True)
def vxlan_scale_setup_teardown(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, scaled_vnet_params, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    logger.info(f"Starting VXLAN scale setup on DUT: {duthost.hostname}")
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("VXLAN scale test not supported on virtual SONiC (VS)")
    setup_params = {}

    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")
    try:
        cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        num_vnets = scaled_vnet_params.get("num_vnet") or 5
        routes_per_vnet = scaled_vnet_params.get("num_routes") or 100
        vnet_base = 10000
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]

        logger.info(f"Using num_vnets={num_vnets}, routes_per_vnet={routes_per_vnet}")

        setup_params = vxlan_setup_config(
            config_facts,
            cfg_facts,
            duthost,
            dut_indx,
            ptfhost,
            tbinfo,
            num_vnets,
            routes_per_vnet,
            vnet_base
        )
    except Exception as e:
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))
        restore_config_db(localhost, duthost, ptfhost, setup_params)
        pytest.fail("Vnet testing setup failed")

    yield setup_params, duthost

    restore_config_db(localhost, duthost, ptfhost, setup_params)
    logger.info("VXLAN scale setup and teardown completed")


# -------------------------------------------------------------------
# Testcases
# -------------------------------------------------------------------
def test_vxlan_route_programming(vxlan_scale_setup_teardown):
    """
    Fast validation: for each VNET, ensure APP_DB and ASIC_DB have expected
    route *counts* (e.g. 10K per VNET), rather than checking every route individually.
    """
    setup_params, duthost = vxlan_scale_setup_teardown
    num_vnets = setup_params["num_vnets"]
    routes_per_vnet = setup_params["routes_per_vnet"]

    logger.info(f"Validating route *counts* for {num_vnets} VNETs {routes_per_vnet} routes each")

    # --- APP_DB count check ---
    appdb_counts = {}
    for vnet_id in range(1, num_vnets + 1):
        vnet_name = f"Vnet{vnet_id}"
        key_prefix = f"VNET_ROUTE_TUNNEL_TABLE:{vnet_name}:30.{vnet_id}."
        # Count matching keys in APP_DB
        cmd = f"redis-cli -n 0 KEYS '{key_prefix}*' | wc -l"
        count = int(duthost.shell(cmd)["stdout"].strip())
        appdb_counts[vnet_name] = count
        logger.info(f"{vnet_name}: found {count} APP_DB routes")

    failed_appdb = [vn for vn, cnt in appdb_counts.items() if cnt != routes_per_vnet]
    pytest_assert(
        not failed_appdb,
        f"APP_DB route count mismatch for: {failed_appdb}. Counts: {appdb_counts}",
    )
    logger.info("All APP_DB route counts correct")

    # --- ASIC_DB count check ---
    logger.info("Counting ASIC_DB route entries per VNET prefix ...")
    asic_keys = "\n".join(
        duthost.shell("redis-cli -n 1 KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY*'")["stdout_lines"]
    )

    asic_counts = {}
    for vnet_id in range(1, num_vnets + 1):
        prefix = f"30.{vnet_id}."
        count = asic_keys.count(prefix)
        asic_counts[f"Vnet{vnet_id}"] = count
        logger.info(f"Vnet{vnet_id}: found {count} ASIC_DB routes")

    failed_asicdb = [vn for vn, cnt in asic_counts.items() if cnt < routes_per_vnet]
    pytest_assert(
        not failed_asicdb,
        f"ASIC_DB route count mismatch for: {failed_asicdb}. Counts: {asic_counts}",
    )

    logger.info("All ASIC_DB route counts correct")


def test_vxlan_scale_traffic(vxlan_scale_setup_teardown, ptfhost):
    """
    Run the full-scale VXLAN traffic test via PTF.
    """
    setup_params, duthost = vxlan_scale_setup_teardown
    logger.info("Launching PTF VXLANScaleTest with params: %s", setup_params)

    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_traffic_scale.VXLANScaleTest",
        platform_dir="ptftests",
        params=setup_params,
        qlen=1000,
        log_file="/tmp/vxlan_traffic_scale.log",
        is_python3=True
    )

    logger.info("VXLAN traffic test completed successfully")
