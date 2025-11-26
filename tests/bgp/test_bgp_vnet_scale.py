import json
import time
import logging
import sys
import traceback
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

BASE_VLAN_ID = 1100
PTF_EXABGP_BASE_PORT = 5100
VXLAN_TUNNEL_NAME = "vtep_v4"

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


def calculate_wait_time(vnet_count):
    return min(300, max(30, int(vnet_count * 0.25)))


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


def generate_vnet_ip_plan(vnet_id):
    block_size = 8
    base_offset = (vnet_id - 1) * block_size
    third_octet = base_offset // 256
    fourth_octet = base_offset % 256

    if fourth_octet + 7 > 255:
        raise ValueError(f"IP range too large for vnet_id {vnet_id}")

    dut_ip = f"10.1.{third_octet}.{fourth_octet + 1}"
    ptf_ip1 = f"10.1.{third_octet}.{fourth_octet + 2}"
    ptf_ip2 = f"10.1.{third_octet}.{fourth_octet + 3}"
    network = f"10.1.{third_octet}.{fourth_octet}/29"

    return dut_ip, ptf_ip1, ptf_ip2, network


def cleanup_ptf_config(ptfhost, base_iface, cfg_path="/etc/exabgp/all_vnets.conf"):
    kill_exabgp = f"""
MAIN_PID=$(pgrep -f "exabgp {cfg_path}")
if [ -n "$MAIN_PID" ]; then
    echo "Killing test ExaBGP instance PID=$MAIN_PID"
    kill -9 $MAIN_PID 2>/dev/null
fi
"""
    ptfhost.shell(kill_exabgp, module_ignore_errors=True)

    kill_http_api = f"""
API_PID=$(pgrep -f "/usr/share/exabgp/http_api.py {PTF_EXABGP_BASE_PORT}")
if [ -n "$API_PID" ]; then
    echo "Killing test http_api.py PID=$API_PID"
    kill -9 $API_PID 2>/dev/null
fi
"""
    ptfhost.shell(kill_http_api, module_ignore_errors=True)

    delete_subifs = f"""
for subif in $(ip -o link show | grep -o "{base_iface}\\.[0-9]\\+"); do
    echo "Deleting $subif"
    ip link delete $subif 2>/dev/null
done

rm -f {cfg_path}
"""
    ptfhost.shell(delete_subifs, module_ignore_errors=True)


def generate_dut_config_ptf(vnet_count, peer_asn, dut_port, cfg_facts):
    dut_vtep = get_loopback_ip(cfg_facts)
    config_db = {
        "VXLAN_TUNNEL": {
            VXLAN_TUNNEL_NAME: {
                "src_ip": dut_vtep
            }
        },
        "VNET": {},
        "VLAN": {},
        "VLAN_MEMBER": {},
        "VLAN_INTERFACE": {}
    }

    bgp_config_db = {
        "BGP_PEER_RANGE": {}
    }

    for vnet_id in range(1, vnet_count + 1):
        vnet_name = f"Vnet{vnet_id}"
        vlan_id = BASE_VLAN_ID + vnet_id
        vlan_name = f"Vlan{vlan_id}"
        dut_ip, ptf_ip1, ptf_ip2, network_str = generate_vnet_ip_plan(vnet_id)
        config_db["VLAN"][vlan_name] = {
            "vlanid": str(vlan_id)
        }
        config_db["VLAN_MEMBER"][f"{vlan_name}|{dut_port}"] = {
            "tagging_mode": "tagged"
        }
        config_db["VLAN_INTERFACE"][vlan_name] = {
            "vnet_name": vnet_name
        }
        config_db["VLAN_INTERFACE"][f"{vlan_name}|{dut_ip}/29"] = {}
        config_db["VNET"][vnet_name] = {
            "vni": str(vnet_id),
            "vxlan_tunnel": VXLAN_TUNNEL_NAME
        }
        bgp_config_db["BGP_PEER_RANGE"][f"{vnet_name}|dynpeer{vnet_name}"] = {
            "ip_range": [network_str],
            "peer_asn": peer_asn,
            "src_address": dut_ip,
            "name": f"dynpeer{vnet_name}"
        }

    return config_db, bgp_config_db


def create_ptf_vlans(ptfhost, vnet_count, ptf_port):
    logger.info(f"Creating {vnet_count} VLAN subinterfaces on PTF port {ptf_port}")
    script = "#!/bin/bash\n"
    script += f"BASE_VLAN_ID={BASE_VLAN_ID}\n"
    script += f"PTF_L2_IFACE={ptf_port}\n\n"

    script += r"""
generate_vnet_ip_plan() {
    vnet_id=$1
    block_size=8
    base_offset=$(( (vnet_id - 1) * block_size ))
    third_octet=$(( base_offset / 256 ))
    fourth_octet=$(( base_offset % 256 ))

    dut_ip="10.1.${third_octet}.$((fourth_octet + 1))"
    ptf_ip1="10.1.${third_octet}.$((fourth_octet + 2))"
    ptf_ip2="10.1.${third_octet}.$((fourth_octet + 3))"

    echo "$dut_ip $ptf_ip1 $ptf_ip2"
}
"""

    script += "\nfor vnet_id in $(seq 1 %d); do\n" % vnet_count
    script += """
    vlan_id=$(( BASE_VLAN_ID + vnet_id ))
    subif="${PTF_L2_IFACE}.${vlan_id}"

    read dut_ip ptf_ip1 ptf_ip2 <<< "$(generate_vnet_ip_plan $vnet_id)"

    ip link add link ${PTF_L2_IFACE} name ${subif} type vlan id ${vlan_id} 2>/dev/null
    ip addr add ${ptf_ip1}/29 dev ${subif} 2>/dev/null
    ip addr add ${ptf_ip2}/29 dev ${subif} 2>/dev/null
    ip link set ${subif} up 2>/dev/null
done
"""

    tmp = "/tmp/ptf_create_vlans.sh"
    with open(tmp, "w") as f:
        f.write(script)

    # Copy to PTF and run once
    ptfhost.copy(src=tmp, dest=tmp)
    ptfhost.shell(f"chmod +x {tmp}")
    ptfhost.shell(f"bash {tmp}")


def generate_single_exabgp_config(vnet_count, dut_asn, ptf_asn, cfg_path="/etc/exabgp/all_vnets.conf"):
    logger.info(f"Generating single ExaBGP config for {vnet_count} VNETs")
    config = f"""
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {PTF_EXABGP_BASE_PORT};
    encoder json;
}}
"""

    for vnet_id in range(1, vnet_count + 1):
        dut_ip, ptf_ip1, ptf_ip2, network = generate_vnet_ip_plan(vnet_id)

        for local_ip in (ptf_ip1, ptf_ip2):
            config += f"""
neighbor {dut_ip} {{
    router-id {local_ip};
    local-address {local_ip};

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


def apply_single_exabgp(ptfhost, vnet_count, dut_asn, ptf_asn, ptf_port):
    create_ptf_vlans(ptfhost, vnet_count, ptf_port)
    time.sleep(20)
    tmp, cfg_path = generate_single_exabgp_config(vnet_count, dut_asn, ptf_asn)
    ptfhost.copy(src=tmp, dest=cfg_path)
    ptfhost.shell(
        f"nohup exabgp {cfg_path} > /var/log/exabgp_all_vnets.log 2>&1 &"
    )


@pytest.fixture(scope="module", autouse=True)
def vnet_bgp_setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, vnet_count):
    try:
        ptf_port = None
        duthost = duthosts[rand_one_dut_hostname]
        dut_index = tbinfo["duts"].index(rand_one_dut_hostname)
        cfg_facts = get_cfg_facts(duthost)
        wait_time = calculate_wait_time(vnet_count)
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]

        dut_port, ptf_port = get_one_ptf_port(config_facts, tbinfo, dut_index)

        logger.info("DUT_L2_IFACE: %s", dut_port)
        logger.info("PTF_L2_IFACE: %s", ptf_port)

        dut_asn = cfg_facts['DEVICE_METADATA']['localhost']['bgp_asn']
        neighbors = cfg_facts['BGP_NEIGHBOR']
        peer_asn = list(neighbors.values())[0]["asn"]

        logger.info("Generate config DB for DUT")
        logger.info("vnet_count: %d", vnet_count)
        vnet_config, bgp_config = generate_dut_config_ptf(vnet_count, peer_asn, dut_port, cfg_facts)

        logger.info("Apply interface, vlan and vnet config on DUT")
        apply_config_to_dut(duthost, vnet_config, "vnet")
        time.sleep(wait_time)  # Allow time for interfaces to come up
        logger.info("Apply BGP config on DUT")
        apply_config_to_dut(duthost, bgp_config, "bgp")

        logger.info("Configuring PTF for VNET dynamic BGP peers")
        apply_single_exabgp(ptfhost, vnet_count, dut_asn, peer_asn, ptf_port)
        time.sleep(wait_time)
    except Exception as e:
        logger.error("vnet_bgp_setup failed: %s", str(e))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))
        if ptf_port is not None:
            cleanup_ptf_config(ptfhost, ptf_port)
        config_reload(duthost, safe_reload=True, yang_validate=False)
        pytest.fail("Vnet testing setup failed")

    yield duthost, vnet_count, wait_time
    # Teardown
    logger.info("Tearing down VNET BGP config")
    cleanup_ptf_config(ptfhost, ptf_port)
    config_reload(duthost, safe_reload=True, yang_validate=False)


def validate_bgp_summary(duthost, count):
    cmd = "vtysh -c 'show bgp vrf all summary json'"
    all_vrfs = json.loads(duthost.shell(cmd)["stdout"])

    failures = []

    for vnet_id in range(1, count + 1):
        vrf = f"Vnet{vnet_id}"
        try:
            peers = int(all_vrfs[vrf]["ipv4Unicast"]["dynamicPeers"])
            if peers != 2:
                logger.warning(f"[DEBUG] {vrf}: dynamicPeers={peers} (expected 2)")
                failures.append(f"{vrf}: expected 2 peers, got {peers}")
        except Exception as e:
            logger.warning(f"[DEBUG] {vrf}: missing keys or invalid data ({type(e).__name__})")
            failures.append(f"{vrf}: unable to read dynamicPeers")

    if failures:
        logger.error("BGP validation failures:\n" + "\n".join(failures))
        pytest.fail("BGP validation failed. See logs for details.")


def test_vnet_bgp_scale_summary(vnet_bgp_setup):
    duthost, vnet_count = vnet_bgp_setup
    logger.info(f"Testing vnet bgp scale for {vnet_count} vnets")
    validate_bgp_summary(duthost, vnet_count)


def test_vnet_bgp_scale_config_reload(vnet_bgp_setup):
    duthost, vnet_count, wait_time = vnet_bgp_setup
    logger.info(f"Testing vnet bgp scale config reload for {vnet_count} vnets")
    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")
    duthost.shell("config save -y")
    time.sleep(10)
    config_reload(duthost, safe_reload=True, yang_validate=False)
    time.sleep(wait_time)
    validate_bgp_summary(duthost, vnet_count)
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")