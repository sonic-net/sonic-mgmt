import json
import time
import logging
import sys
import traceback
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa:F401

logger = logging.getLogger(__name__)

BASE_VLAN_ID = 1100
PTF_EXABGP_BASE_PORT = 5100
VXLAN_TUNNEL_NAME = "vtep_v4"
PTF_BOND_IFACE = "bond1"
PORTCHANNEL_NAME = "PortChannel1"
PORTCHANNEL_SHORT_NAME = "Po1"

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000'),
    pytest.mark.disable_memory_utilization,
]


def get_cfg_facts(duthost):
    # return config db contents(running-config)
    tmp_facts = json.loads(duthost.shell(
        "sonic-cfggen -d --print-data")['stdout'])

    return tmp_facts


def calculate_wait_time(total_sessions):
    # previously was based on vnet_count; now scale with total BGP sessions
    return min(300, max(30, int(total_sessions * 0.25)))


def get_loopback_ip(cfg_facts):
    for key in cfg_facts.get("LOOPBACK_INTERFACE", {}):
        if key.startswith("Loopback0|") and "." in key:
            return key.split("|")[1].split("/")[0]
    pytest.fail("Cannot find IPv4 Loopback0 address in LOOPBACK_INTERFACE")


def get_one_ptf_port(config_facts, tbinfo, dut_index):
    port_index_map = config_facts["port_index_map"]
    ptf_map = tbinfo["topo"]["ptf_map"][str(dut_index)]
    dut_to_ptf = {}
    for dut_port, idx in port_index_map.items():
        if str(idx) in ptf_map:
            dut_to_ptf[dut_port] = f"eth{ptf_map[str(idx)]}"

    for vlan_name, members in config_facts.get("VLAN_MEMBER", {}).items():
        for dut_port in members:
            # Must be admin-up
            if config_facts["PORT"][dut_port].get("admin_status").lower() == "up":
                if dut_port in dut_to_ptf:
                    return dut_port, dut_to_ptf[dut_port]

    pytest_assert(False, "No usable DUT/PTF port found in VLAN_MEMBER")


def apply_config_to_dut(duthost, config, cfg_type):
    config_path = f"/tmp/dut_config_{cfg_type}.json"
    duthost.copy(content=json.dumps(config, indent=4), dest=config_path)
    result = duthost.shell(f"sonic-cfggen -j {config_path} --write-to-db")
    pytest_assert(result["rc"] == 0, f"Failed to apply config {config_path}: {result['stderr']}")


def generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet):
    """
    Generate a /30 block per (vnet, subinterface).
    """
    block_size = 4
    global_index = (vnet_id - 1) * subifs_per_vnet + subif_index
    base_offset = global_index * block_size

    third_octet = base_offset // 256
    fourth_octet = base_offset % 256

    # /30 uses block_size=4 ⇒ fourth_octet+3 must be <= 255
    if fourth_octet + 3 > 255:
        raise ValueError(f"IP range too large for vnet_id {vnet_id}, subif_index {subif_index}")

    network = f"10.1.{third_octet}.{fourth_octet}/30"
    dut_ip = f"10.1.{third_octet}.{fourth_octet + 1}"
    ptf_ip = f"10.1.{third_octet}.{fourth_octet + 2}"

    return dut_ip, ptf_ip, network


def generate_test_route(vnet_id, subif_index, subifs_per_vnet):
    """
    Create a unique /32 route per BGP session using 50.<high>.<low>.1/32.

    session_id is a global index across all (vnet, subif) pairs:
        session_id = (vnet_id - 1) * subifs_per_vnet + subif_index

    We then encode session_id into two bytes:
        high = session_id // 256
        low  = session_id % 256
    """
    session_id = (vnet_id - 1) * subifs_per_vnet + subif_index
    high = session_id // 256
    low = session_id % 256
    prefix = f"50.{high}.{low}.1/32"
    return prefix


def exabgp_batch_announce_routes(ptfhost, vnet_count, subifs_per_vnet):
    """
    Announce 1 route to each bgp neighbor.
    """
    script_lines = [
        "#!/bin/bash",
        "set -e",
        ""
    ]

    for vnet_id in range(1, vnet_count + 1):
        for subif_index in range(subifs_per_vnet):
            dut_ip, ptf_ip, _ = generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet)
            prefix = generate_test_route(vnet_id, subif_index, subifs_per_vnet)
            announce_cmd = (
                f"curl -s -X POST "
                f"-d \"command=neighbor {dut_ip} announce route {prefix} next-hop {ptf_ip}\" "
                f"http://localhost:{PTF_EXABGP_BASE_PORT}"
            )
            script_lines.append(announce_cmd)

    script_content = "\n".join(script_lines) + "\n"

    script_path = "/tmp/exabgp_batch_announce.sh"
    ptfhost.copy(content=script_content, dest=script_path)
    ptfhost.shell(f"chmod +x {script_path}")

    logger.info(f"[Batch-Announce] Announcing {vnet_count * subifs_per_vnet} routes individually to neighbors.")

    ptfhost.shell(script_path)

    logger.info("[Batch-Announce] Completed announcing all routes.")


def cleanup_ptf_config(ptfhost, base_iface, cfg_path="/etc/exabgp/all_vnets.conf"):
    kill_exabgp = f"""
MAIN_PID=$(pgrep -f "exabgp {cfg_path}")
if [ -n "$MAIN_PID" ]; then
    echo "Killing ExaBGP instance PID=$MAIN_PID"
    kill -9 $MAIN_PID 2>/dev/null
fi
"""
    ptfhost.shell(kill_exabgp, module_ignore_errors=True)

    kill_api = f"""
API_PID=$(pgrep -f "/usr/share/exabgp/http_api.py {PTF_EXABGP_BASE_PORT}")
if [ -n "$API_PID" ]; then
    echo "Killing ExaBGP HTTP API PID=$API_PID"
    kill -9 $API_PID 2>/dev/null
fi
"""
    ptfhost.shell(kill_api, module_ignore_errors=True)

    cleanup_script = f"""
echo "Deleting VLAN subinterfaces on {base_iface}"
for subif in $(ip -o link show | grep -o "{base_iface}\\\\.[0-9]\\\\+"); do
    echo "Deleting $subif"
    ip link delete $subif 2>/dev/null
done

echo "Detecting slaves of {base_iface}"
SLAVES=$(ip -o link show | awk '/master {base_iface}/ {{print $2}}' | sed -e 's/:$//' -e 's/@.*//')

for slave in $SLAVES; do
    echo "Detaching slave $slave from {base_iface}"
    ip link set $slave nomaster 2>/dev/null
done

echo "Deleting bond interface {base_iface}"
ip link delete {base_iface} 2>/dev/null

echo "Removing ExaBGP config file {cfg_path}"
rm -f {cfg_path}
"""
    ptfhost.shell(cleanup_script, module_ignore_errors=True)


def generate_dut_config_ptf(vnet_count, subifs_per_vnet, peer_asn, dut_port, cfg_facts):
    """
    DUT side:
    - Create one PortChannel (PORTCHANNEL_NAME) with member 'dut_port'
    - Create per-VNET PortChannel subinterfaces PortChannelVNET0.<vlan_id>
      and bind them to VNETs via VLAN_SUB_INTERFACE (with vnet_name on creation).
    - Create per-subinterface BGP_PEER_RANGE entries (dynamic neighbors).
    """
    dut_vtep = get_loopback_ip(cfg_facts)

    config_db = {
        "VXLAN_TUNNEL": {
            VXLAN_TUNNEL_NAME: {
                "src_ip": dut_vtep
            }
        },
        "VNET": {},
        "PORTCHANNEL": {
            PORTCHANNEL_NAME: {
                "admin_status": "up",
                "lacp_key": "auto",
                "min_links": "1",
                "mtu": "9100",
            }
        },
        "PORTCHANNEL_MEMBER": {
            f"{PORTCHANNEL_NAME}|{dut_port}": {}
        },
        "VLAN_SUB_INTERFACE": {}
    }

    bgp_config_db = {
        "BGP_PEER_RANGE": {}
    }

    for vnet_id in range(1, vnet_count + 1):
        vnet_name = f"Vnet{vnet_id}"

        # VNET itself (single VNI per VNET)
        config_db["VNET"][vnet_name] = {
            "vni": str(vnet_id),
            "vxlan_tunnel": VXLAN_TUNNEL_NAME
        }

        for subif_index in range(subifs_per_vnet):
            global_index = (vnet_id - 1) * subifs_per_vnet + subif_index
            vlan_id = BASE_VLAN_ID + global_index
            subif_name = f"{PORTCHANNEL_SHORT_NAME}.{vlan_id}"

            dut_ip, ptf_ip, network_str = generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet)

            # IMPORTANT: put vnet_name at creation time
            config_db["VLAN_SUB_INTERFACE"][subif_name] = {
                "admin_status": "up",
                "vlan": str(vlan_id),
                "vnet_name": vnet_name
            }
            config_db["VLAN_SUB_INTERFACE"][f"{subif_name}|{dut_ip}/30"] = {}

            dynpeer_name = f"dynpeer{vnet_name}_{subif_index + 1}"
            key = f"{vnet_name}|{dynpeer_name}"
            bgp_config_db["BGP_PEER_RANGE"][key] = {
                "ip_range": [network_str],
                "peer_asn": peer_asn,
                "src_address": dut_ip,
                "name": dynpeer_name
            }

    return config_db, bgp_config_db


def create_ptf_bond_and_subifs(ptfhost, vnet_count, subifs_per_vnet, ptf_port):
    """
    PTF side:
    - Create a bond interface (PTF_BOND_IFACE) and enslave 'ptf_port'
    - For each (vnet, subif) create bond subinterface BOND_IFACE.<vlan_id>
      with a single IP (ptf_ip) from the same /30 used on DUT.
    """
    logger.info(
        f"Creating bond {PTF_BOND_IFACE} and "
        f"{vnet_count * subifs_per_vnet} VLAN subinterfaces on PTF port {ptf_port}"
    )
    script = "#!/bin/bash\n"
    script += f"BASE_VLAN_ID={BASE_VLAN_ID}\n"
    script += f"VNET_COUNT={vnet_count}\n"
    script += f"SUBIFS_PER_VNET={subifs_per_vnet}\n"
    script += f"PTF_L2_IFACE={ptf_port}\n"
    script += f"BOND_IFACE={PTF_BOND_IFACE}\n\n"

    script += r"""
# Create bond interface and enslave PTF_L2_IFACE
ip link add ${BOND_IFACE} type bond 2>/dev/null
ip link set ${BOND_IFACE} type bond miimon 100 mode 802.3ad 2>/dev/null

ip link set ${PTF_L2_IFACE} down 2>/dev/null
ip link set ${PTF_L2_IFACE} master ${BOND_IFACE} 2>/dev/null

ip link set ${BOND_IFACE} up 2>/dev/null
ifconfig ${BOND_IFACE} mtu 9216 up

generate_vnet_ip_plan() {
    vnet_id=$1
    subif_index=$2

    block_size=4
    global_index=$(( (vnet_id - 1) * SUBIFS_PER_VNET + subif_index ))
    base_offset=$(( global_index * block_size ))

    third_octet=$(( base_offset / 256 ))
    fourth_octet=$(( base_offset % 256 ))

    dut_ip="10.1.${third_octet}.$((fourth_octet + 1))"
    ptf_ip="10.1.${third_octet}.$((fourth_octet + 2))"

    echo "$dut_ip $ptf_ip"
}

for vnet_id in $(seq 1 ${VNET_COUNT}); do
    for subif_index in $(seq 0 $((SUBIFS_PER_VNET - 1))); do
        global_index=$(( (vnet_id - 1) * SUBIFS_PER_VNET + subif_index ))
        vlan_id=$(( BASE_VLAN_ID + global_index ))
        subif="${BOND_IFACE}.${vlan_id}"

        read dut_ip ptf_ip <<< "$(generate_vnet_ip_plan ${vnet_id} ${subif_index})"

        ip link add link ${BOND_IFACE} name ${subif} type vlan id ${vlan_id} 2>/dev/null
        ip addr add ${ptf_ip}/30 dev ${subif} 2>/dev/null
        ip link set ${subif} up 2>/dev/null
    done
done
"""

    tmp = "/tmp/ptf_create_bond_subifs.sh"
    with open(tmp, "w") as f:
        f.write(script)

    ptfhost.copy(src=tmp, dest=tmp)
    ptfhost.shell(f"chmod +x {tmp}")
    ptfhost.shell(f"bash {tmp}")


def generate_single_exabgp_config(vnet_count, subifs_per_vnet, dut_asn, ptf_asn, cfg_path="/etc/exabgp/all_vnets.conf"):
    logger.info(f"Generating single ExaBGP config for {vnet_count} VNETs, {subifs_per_vnet} subifs/VNET")
    config = f"""
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {PTF_EXABGP_BASE_PORT};
    encoder json;
}}
"""

    for vnet_id in range(1, vnet_count + 1):
        for subif_index in range(subifs_per_vnet):
            dut_ip, ptf_ip, network = generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet)

            # One neighbor per subinterface
            config += f"""
neighbor {dut_ip} {{
    router-id {ptf_ip};
    local-address {ptf_ip};

    local-as {ptf_asn};
    peer-as {dut_asn};

    hold-time 10;

    api {{
        processes [ api-vnets ];
    }}

    family {{
        ipv4 unicast;
    }}
}}
"""

    tmp = "/tmp/all_vnets.conf"
    with open(tmp, "w") as f:
        f.write(config)

    return tmp, cfg_path


def apply_single_exabgp(ptfhost, vnet_count, subifs_per_vnet, dut_asn, ptf_asn, ptf_port):
    tmp, cfg_path = generate_single_exabgp_config(vnet_count, subifs_per_vnet, dut_asn, ptf_asn)
    ptfhost.copy(src=tmp, dest=cfg_path)
    ptfhost.shell(
        f"nohup exabgp {cfg_path} > /var/log/exabgp_all_vnets.log 2>&1 &"
    )
    time.sleep(120)
    exabgp_batch_announce_routes(ptfhost, vnet_count, subifs_per_vnet)


@pytest.fixture(scope="module", autouse=True)
def vnet_bgp_setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, vnet_count, subif_per_vnet):
    try:
        duthost = duthosts[rand_one_dut_hostname]
        dut_index = tbinfo["duts"].index(rand_one_dut_hostname)
        cfg_facts = get_cfg_facts(duthost)
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]

        dut_port, ptf_port = get_one_ptf_port(config_facts, tbinfo, dut_index)
        asic_index = config_facts["port_index_map"][dut_port]
        ptf_port_index = int(tbinfo["topo"]["ptf_map"][str(dut_index)][str(asic_index)])
        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")
        duthost.shell(f"config vlan member del all {dut_port}")

        logger.info("DUT_L2_IFACE: %s", dut_port)
        logger.info("PTF_L2_IFACE: %s", ptf_port)
        logger.info("PTF_L2_IFACE_INDEX: %s", ptf_port_index)

        dut_asn = cfg_facts['DEVICE_METADATA']['localhost']['bgp_asn']
        neighbors = cfg_facts['BGP_NEIGHBOR']
        peer_asn = list(neighbors.values())[0]["asn"]

        total_sessions = vnet_count * subif_per_vnet
        wait_time = calculate_wait_time(total_sessions)

        logger.info("Generate config DB for DUT")
        logger.info("vnet_count: %d, subifs_per_vnet: %d, expected BGP sessions: %d",
                    vnet_count, subif_per_vnet, total_sessions)

        vnet_config, bgp_config = generate_dut_config_ptf(
            vnet_count, subif_per_vnet, peer_asn, dut_port, cfg_facts
        )

        logger.info("Apply PortChannel subinterface and VNET config on DUT")
        apply_config_to_dut(duthost, vnet_config, "vnet")
        time.sleep(wait_time)  # Allow time for interfaces to come up

        create_ptf_bond_and_subifs(ptfhost, vnet_count, subif_per_vnet, ptf_port)
        time.sleep(wait_time)

        logger.info("Apply BGP dynamic peer-range config on DUT")
        apply_config_to_dut(duthost, bgp_config, "bgp")

        logger.info("Configuring PTF for VNET dynamic BGP peers via bond + subinterfaces")
        apply_single_exabgp(ptfhost, vnet_count, subif_per_vnet, dut_asn, peer_asn, ptf_port)
    except Exception as e:
        logger.error("vnet_bgp_setup failed: %s", str(e))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))
        cleanup_ptf_config(ptfhost, PTF_BOND_IFACE)
        config_reload(duthost, safe_reload=True, yang_validate=False)
        pytest.fail("Vnet testing setup failed")

    yield duthost, vnet_count, subif_per_vnet, wait_time, ptf_port_index
    # Teardown
    logger.info("Tearing down VNET BGP config")
    cleanup_ptf_config(ptfhost, PTF_BOND_IFACE)
    config_reload(duthost, safe_reload=True, yang_validate=False)


def validate_bgp_summary(duthost, vnet_count, subif_per_vnet):
    cmd = "vtysh -c 'show bgp vrf all summary json'"
    all_vrfs = json.loads(duthost.shell(cmd)["stdout"])

    failures = []
    expected_peers = subif_per_vnet

    for vnet_id in range(1, vnet_count + 1):
        vrf = f"Vnet{vnet_id}"
        try:
            peers = int(all_vrfs[vrf]["ipv4Unicast"]["dynamicPeers"])
            if peers != expected_peers:
                logger.warning(f"[DEBUG] {vrf}: dynamicPeers={peers} (expected {expected_peers})")
                failures.append(f"{vrf}: expected {expected_peers} peers, got {peers}")
        except Exception as e:
            logger.warning(f"[DEBUG] {vrf}: missing keys or invalid data ({type(e).__name__})")
            failures.append(f"{vrf}: unable to read dynamicPeers")

    if failures:
        logger.error("BGP validation failures:\n" + "\n".join(failures))
        pytest.fail("BGP validation failed. See logs for details.")


def test_vnet_bgp_scale_summary(vnet_bgp_setup):
    duthost, vnet_count, subif_per_vnet, _, _ = vnet_bgp_setup
    logger.info(f"Testing vnet bgp scale for {vnet_count} vnets, {subif_per_vnet} subifs/VNET")
    validate_bgp_summary(duthost, vnet_count, subif_per_vnet)


def test_vnet_bgp_scale_config_reload(vnet_bgp_setup):
    duthost, vnet_count, subif_per_vnet, wait_time, _ = vnet_bgp_setup
    logger.info(f"Testing vnet bgp scale config reload for {vnet_count} vnets, {subif_per_vnet} subifs/VNET")
    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")
    duthost.shell("config save -y")
    time.sleep(10)
    config_reload(duthost, safe_reload=True, yang_validate=False)
    time.sleep(wait_time)
    validate_bgp_summary(duthost, vnet_count, subif_per_vnet)
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")


def test_vnet_bgp_scale_dataplane(vnet_bgp_setup, ptfhost):
    duthost, vnet_count, subif_per_vnet, _, ptf_port_index = vnet_bgp_setup

    # Get DUT router MAC
    router_mac = duthost.facts["router_mac"]
    validate_bgp_summary(duthost, vnet_count, subif_per_vnet)

    ptf_params = {
        "vnet_count": vnet_count,
        "subif_per_vnet": subif_per_vnet,
        "base_vlan_id": BASE_VLAN_ID,
        "bond_iface": PTF_BOND_IFACE,
        "ptf_port_index": ptf_port_index,
        "router_mac": router_mac,
    }

    logger.info(
        "Starting PTF dataplane test for %d VNETs, %d subifs/VNET (total %d sessions)",
        vnet_count, subif_per_vnet, vnet_count * subif_per_vnet
    )

    ptf_runner(
        ptfhost,
        "ptftests",
        "vnet_bgp_scale_dataplane.VnetBgpScaleDataplane",
        platform_dir="ptftests",
        params=ptf_params,
        log_file="/tmp/vnet_bgp_scale_dp.log",
        is_python3=True
    )
