import json
import logging
import sys
import time
import traceback

import pytest

from tests.common.config_reload import config_reload
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa:F401
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner
from tests.common.vxlan_ecmp_utils import Ecmp_Utils

ecmp_utils = Ecmp_Utils()
logger = logging.getLogger(__name__)

BASE_VLAN_ID = 1100
PTF_EXABGP_BASE_PORT = 5100
VXLAN_TUNNEL_NAME = "vtep_v4"
PORTCHANNEL_NAME_FMT = "PortChannel{}"
PORTCHANNEL_SHORT_NAME_FMT = "Po{}"
VXLAN_PORT = 4789
VNI_BASE = 10000

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.device_type("physical"),
    pytest.mark.asic("cisco-8000"),
    pytest.mark.disable_memory_utilization,
]


def get_cfg_facts(duthost):
    return json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])


def calculate_wait_time(total_sessions):
    return min(300, max(30, int(total_sessions * 0.25)))


def get_loopback_ip(cfg_facts):
    for key in cfg_facts.get("LOOPBACK_INTERFACE", {}):
        if key.startswith("Loopback0|") and "." in key:
            return key.split("|")[1].split("/")[0]
    pytest.fail("Cannot find IPv4 Loopback0 address in LOOPBACK_INTERFACE")


def get_wl_and_one_t1_port_info(config_facts, tbinfo, dut_index, required_wl_count):
    port_index_map = config_facts["port_index_map"]
    ptf_map = tbinfo["topo"]["ptf_map"][str(dut_index)]
    portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})

    dut_to_ptf = {}
    for dut_port, idx in port_index_map.items():
        if str(idx) in ptf_map:
            dut_to_ptf[dut_port] = {
                "ptf_name": "eth{}".format(ptf_map[str(idx)]),
                "ptf_index": int(ptf_map[str(idx)]),
            }

    wl_bindings = []
    wl_dut_ports = set()

    for members in config_facts.get("VLAN_MEMBER", {}).values():
        for dut_port in members:
            if dut_port in wl_dut_ports:
                continue
            if config_facts["PORT"][dut_port].get("admin_status", "").lower() != "up":
                continue
            if dut_port not in dut_to_ptf:
                continue

            wl_bindings.append(
                {
                    "dut_port": dut_port,
                    "ptf_name": dut_to_ptf[dut_port]["ptf_name"],
                    "ptf_index": dut_to_ptf[dut_port]["ptf_index"],
                }
            )
            wl_dut_ports.add(dut_port)

            if len(wl_bindings) == required_wl_count:
                break
        if len(wl_bindings) == required_wl_count:
            break

    pytest_assert(
        len(wl_bindings) == required_wl_count,
        "Need {} usable WL DUT/PTF ports, found {}".format(required_wl_count, len(wl_bindings)),
    )

    t1_port_ptf_index = None
    for members in portchannel_members.values():
        for dut_port in members.keys():
            if dut_port not in dut_to_ptf:
                continue
            if config_facts["PORT"].get(dut_port, {}).get("admin_status", "").lower() != "up":
                continue

            t1_port_ptf_index = dut_to_ptf[dut_port]["ptf_index"]
            break
        if t1_port_ptf_index is not None:
            break

    pytest_assert(t1_port_ptf_index is not None, "Could not find one T1-facing portchannel member PTF port")
    return wl_bindings, t1_port_ptf_index


def apply_config_to_dut(duthost, config, cfg_type):
    config_path = "/tmp/dut_config_{}.json".format(cfg_type)
    duthost.copy(content=json.dumps(config, indent=4), dest=config_path)
    result = duthost.shell("sonic-cfggen -j {} --write-to-db".format(config_path))
    pytest_assert(
        result["rc"] == 0,
        "Failed to apply config {}: {}".format(config_path, result["stderr"]),
    )


def generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet):
    block_size = 4
    global_index = (vnet_id - 1) * subifs_per_vnet + subif_index
    base_offset = global_index * block_size
    third_octet = base_offset // 256
    fourth_octet = base_offset % 256

    if fourth_octet + 3 > 255:
        raise ValueError(
            "IP range too large for vnet_id {}, subif_index {}".format(vnet_id, subif_index)
        )

    network = "100.1.{}.{}".format(third_octet, fourth_octet)
    dut_ip = "100.1.{}.{}".format(third_octet, fourth_octet + 1)
    ptf_ip = "100.1.{}.{}".format(third_octet, fourth_octet + 2)
    return dut_ip, ptf_ip, "{}/30".format(network)


def generate_shared_vnet_route(vnet_id):
    route_id = vnet_id - 1
    high = route_id // 256
    low = route_id % 256
    return "50.{}.{}.1/32".format(high, low)


def exabgp_batch_announce_routes(ptfhost, vnet_count, subifs_per_vnet):
    script_lines = ["#!/bin/bash", "set -e", ""]

    for vnet_id in range(1, vnet_count + 1):
        prefix = generate_shared_vnet_route(vnet_id)
        for subif_index in range(subifs_per_vnet):
            dut_ip, ptf_ip, _ = generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet)
            announce_cmd = (
                "curl -s -X POST "
                "-d \"command=neighbor {dut_ip} announce route {prefix} next-hop {ptf_ip}\" "
                "http://localhost:{api_port}"
            ).format(
                dut_ip=dut_ip,
                prefix=prefix,
                ptf_ip=ptf_ip,
                api_port=PTF_EXABGP_BASE_PORT,
            )
            script_lines.append(announce_cmd)

    script_content = "\n".join(script_lines) + "\n"
    script_path = "/tmp/exabgp_batch_announce.sh"
    ptfhost.copy(content=script_content, dest=script_path)
    ptfhost.shell("chmod +x {}".format(script_path))
    ptfhost.shell(script_path)


def cleanup_ptf_config(ptfhost, ptf_ports, cfg_path="/etc/exabgp/all_vnets.conf"):
    cleanup_script = """
#!/bin/bash
set +e

CFG_PATH="{cfg_path}"
API_PORT="{api_port}"
PTF_PORTS="{ptf_ports}"

echo "==== PTF cleanup start ===="

echo "Killing custom ExaBGP instance for ${{CFG_PATH}}"
MAIN_PIDS=$(pgrep -f "exabgp ${{CFG_PATH}}")
if [ -n "${{MAIN_PIDS}}" ]; then
    echo "${{MAIN_PIDS}}" | xargs -r kill -9 2>/dev/null || true
fi

echo "Killing ExaBGP HTTP API on port ${{API_PORT}}"
API_PIDS=$(pgrep -f "/usr/share/exabgp/http_api.py ${{API_PORT}}")
if [ -n "${{API_PIDS}}" ]; then
    echo "${{API_PIDS}}" | xargs -r kill -9 2>/dev/null || true
fi

sleep 1

echo "Deleting all bond VLAN subinterfaces"
for subif in $(ip -o link show | awk -F': ' '{{print $2}}' | grep -E '^bond[0-9]+\\.[0-9]+(@|$)' | cut -d@ -f1); do
    echo "Deleting subinterface $subif"
    ip link delete "$subif" 2>/dev/null || true
done

echo "Detaching slaves from all bond interfaces"
for bond in $(ip -o link show | awk -F': ' '{{print $2}}' | grep -E '^bond[0-9]+(@|$)' | cut -d@ -f1); do
    SLAVES=$(ip -o link show | awk '/master '"$bond"'/ {{print $2}}' | sed -e 's/:$//' -e 's/@.*//')
    for slave in $SLAVES; do
        echo "Detaching slave $slave from $bond"
        ip link set "$slave" nomaster 2>/dev/null || true
    done
done

echo "Deleting all bond interfaces"
for bond in $(ip -o link show | awk -F': ' '{{print $2}}' | grep -E '^bond[0-9]+(@|$)' | cut -d@ -f1); do
    echo "Deleting bond $bond"
    ip link set "$bond" down 2>/dev/null || true
    ip link delete "$bond" type bond 2>/dev/null || true
done

echo "Cleaning physical PTF interfaces"
for port in ${{PTF_PORTS}}; do
    echo "Resetting $port"
    ip addr flush dev "$port" 2>/dev/null || true
    ip link set "$port" nomaster 2>/dev/null || true
    ip link set "$port" up 2>/dev/null || true
done

echo "Removing generated files"
rm -f "${{CFG_PATH}}" 2>/dev/null || true
rm -f /tmp/ptf_create_vnet_subifs.sh 2>/dev/null || true
rm -f /tmp/exabgp_batch_announce.sh 2>/dev/null || true
rm -f /var/log/exabgp_all_vnets.log 2>/dev/null || true

echo "==== PTF cleanup end ===="
""".format(
        cfg_path=cfg_path,
        api_port=PTF_EXABGP_BASE_PORT,
        ptf_ports=" ".join(ptf_ports),
    )

    script_path = "/tmp/ptf_cleanup_vnet.sh"
    ptfhost.copy(content=cleanup_script, dest=script_path)
    ptfhost.shell("chmod +x {}".format(script_path), module_ignore_errors=True)
    ptfhost.shell("bash {}".format(script_path), module_ignore_errors=True)


def generate_dut_config_ptf(vnet_count, subifs_per_vnet, peer_asn, port_bindings, cfg_facts):
    dut_vtep = get_loopback_ip(cfg_facts)

    config_db = {
        "VXLAN_TUNNEL": {
            VXLAN_TUNNEL_NAME: {
                "src_ip": dut_vtep,
            }
        },
        "VNET": {},
        "PORTCHANNEL": {},
        "PORTCHANNEL_MEMBER": {},
        "VLAN_SUB_INTERFACE": {},
    }
    bgp_config_db = {"BGP_PEER_RANGE": {}}

    for subif_index, binding in enumerate(port_bindings):
        pc_name = PORTCHANNEL_NAME_FMT.format(subif_index + 1)
        config_db["PORTCHANNEL"][pc_name] = {
            "admin_status": "up",
            "lacp_key": "auto",
            "min_links": "1",
            "mtu": "9100",
        }
        config_db["PORTCHANNEL_MEMBER"]["{}|{}".format(pc_name, binding["dut_port"])] = {}

    for vnet_id in range(1, vnet_count + 1):
        vnet_name = "Vnet{}".format(vnet_id)
        vlan_id = BASE_VLAN_ID + (vnet_id - 1)

        config_db["VNET"][vnet_name] = {
            "vni": str(VNI_BASE + vnet_id),
            "vxlan_tunnel": VXLAN_TUNNEL_NAME,
        }

        for subif_index in range(subifs_per_vnet):
            pc_short = PORTCHANNEL_SHORT_NAME_FMT.format(subif_index + 1)
            subif_name = "{}.{}".format(pc_short, vlan_id)
            dut_ip, _, network_str = generate_vnet_ip_plan(vnet_id, subif_index, subifs_per_vnet)

            config_db["VLAN_SUB_INTERFACE"][subif_name] = {
                "admin_status": "up",
                "vlan": str(vlan_id),
                "vnet_name": vnet_name,
            }
            config_db["VLAN_SUB_INTERFACE"]["{}|{}/30".format(subif_name, dut_ip)] = {}

            dynpeer_name = "dynpeer{}_{}".format(vnet_name, subif_index + 1)
            bgp_config_db["BGP_PEER_RANGE"]["{}|{}".format(vnet_name, dynpeer_name)] = {
                "ip_range": [network_str],
                "peer_asn": peer_asn,
                "src_address": dut_ip,
                "name": dynpeer_name,
            }

    return config_db, bgp_config_db


def create_ptf_vlan_subifs(ptfhost, vnet_count, subifs_per_vnet, port_bindings):
    script = [
        "#!/bin/bash",
        "set -e",
        "BASE_VLAN_ID={}".format(BASE_VLAN_ID),
        "VNET_COUNT={}".format(vnet_count),
        "SUBIFS_PER_VNET={}".format(subifs_per_vnet),
        "",
        "generate_vnet_ptf_ip() {",
        "    vnet_id=$1",
        "    subif_index=$2",
        "    block_size=4",
        "    global_index=$(( (vnet_id - 1) * SUBIFS_PER_VNET + subif_index ))",
        "    base_offset=$(( global_index * block_size ))",
        "    third_octet=$(( base_offset / 256 ))",
        "    fourth_octet=$(( base_offset % 256 ))",
        '    echo "100.1.${third_octet}.$((fourth_octet + 2))"',
        "}",
        "",
    ]

    for subif_index, binding in enumerate(port_bindings):
        script.append("PTF_PORT_{}={}".format(subif_index, binding["ptf_name"]))
        script.append("BOND_NAME_{}=bond{}".format(subif_index, subif_index + 1))

    script.extend(
        [
            "",
            "# Create one bond per selected PTF port to mirror DUT PortChannels",
            "for subif_index in $(seq 0 $((SUBIFS_PER_VNET - 1))); do",
            "    ptf_port_var=PTF_PORT_${subif_index}",
            "    bond_var=BOND_NAME_${subif_index}",
            '    ptf_port="${!ptf_port_var}"',
            '    bond_name="${!bond_var}"',
            "",
            "    ip link set ${ptf_port} down 2>/dev/null || true",
            "    ip addr flush dev ${ptf_port} 2>/dev/null || true",
            "",
            "    ip link add ${bond_name} type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4",
            "    ip link set ${ptf_port} master ${bond_name}",
            "    ip link set ${ptf_port} up",
            "    ip link set ${bond_name} up",
            "done",
            "",
            "# For each VNET use one VLAN, and create one bond subinterface per bond",
            "for vnet_id in $(seq 1 ${VNET_COUNT}); do",
            "    vlan_id=$(( BASE_VLAN_ID + vnet_id - 1 ))",
            "",
            "    for subif_index in $(seq 0 $((SUBIFS_PER_VNET - 1))); do",
            "        bond_var=BOND_NAME_${subif_index}",
            '        bond_name="${!bond_var}"',
            '        subif="${bond_name}.${vlan_id}"',
            '        ptf_ip="$(generate_vnet_ptf_ip ${vnet_id} ${subif_index})"',
            "",
            "        ip link add link ${bond_name} name ${subif} type vlan id ${vlan_id}",
            "        ip addr add ${ptf_ip}/30 dev ${subif}",
            "        ip link set ${subif} up",
            "    done",
            "done",
        ]
    )

    script_path = "/tmp/ptf_create_vnet_subifs.sh"
    ptfhost.copy(content="\n".join(script) + "\n", dest=script_path)
    ptfhost.shell("chmod +x {}".format(script_path))
    ptfhost.shell("bash {}".format(script_path))


def generate_single_exabgp_config(vnet_count, subifs_per_vnet, dut_asn, ptf_asn):
    config = """
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {api_port};
    encoder json;
}}
""".format(api_port=PTF_EXABGP_BASE_PORT)

    for vnet_id in range(1, vnet_count + 1):
        for subif_index in range(subifs_per_vnet):
            dut_ip, ptf_ip, _ = generate_vnet_ip_plan(
                vnet_id,
                subif_index,
                subifs_per_vnet
            )

            config += """
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
""".format(
                dut_ip=dut_ip,
                ptf_ip=ptf_ip,
                ptf_asn=ptf_asn,
                dut_asn=dut_asn,
            )

    tmp = "/tmp/all_vnets.conf"
    with open(tmp, "w") as fp:
        fp.write(config)

    return tmp, "/etc/exabgp/all_vnets.conf"


def apply_single_exabgp(ptfhost, vnet_count, subifs_per_vnet, dut_asn, ptf_asn):
    tmp, cfg_path = generate_single_exabgp_config(vnet_count, subifs_per_vnet, dut_asn, ptf_asn)
    ptfhost.copy(src=tmp, dest=cfg_path)
    ptfhost.shell("nohup exabgp {} > /var/log/exabgp_all_vnets.log 2>&1 &".format(cfg_path))
    time.sleep(120)
    exabgp_batch_announce_routes(ptfhost, vnet_count, subifs_per_vnet)


@pytest.fixture(scope="module", autouse=True)
def vnet_bgp_setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, vnet_count, subif_per_vnet):
    ptf_ports = []
    dut_vtep = None
    wl_ptf_port_indices = []
    t1_ptf_port_index = None

    duthost = None

    try:
        ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
        ecmp_utils.Constants["DEBUG"] = True
        duthost = duthosts[rand_one_dut_hostname]
        dut_index = tbinfo["duts"].index(rand_one_dut_hostname)

        cfg_facts = get_cfg_facts(duthost)
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]

        wl_bindings, t1_ptf_port_index = get_wl_and_one_t1_port_info(
            config_facts,
            tbinfo,
            dut_index,
            subif_per_vnet,
        )

        ptf_ports = [entry["ptf_name"] for entry in wl_bindings]
        wl_ptf_port_indices = [entry["ptf_index"] for entry in wl_bindings]

        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")
        for entry in wl_bindings:
            duthost.shell("config vlan member del all {}".format(entry["dut_port"]))

        dut_asn = cfg_facts["DEVICE_METADATA"]["localhost"]["bgp_asn"]
        neighbors = cfg_facts["BGP_NEIGHBOR"]
        peer_asn = list(neighbors.values())[0]["asn"]
        total_sessions = vnet_count * subif_per_vnet
        wait_time = calculate_wait_time(total_sessions)
        dut_vtep = get_loopback_ip(cfg_facts)

        vnet_config, bgp_config = generate_dut_config_ptf(
            vnet_count,
            subif_per_vnet,
            peer_asn,
            wl_bindings,
            cfg_facts,
        )

        apply_config_to_dut(duthost, vnet_config, "vnet")
        time.sleep(wait_time)
        ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

        create_ptf_vlan_subifs(ptfhost, vnet_count, subif_per_vnet, wl_bindings)
        time.sleep(wait_time)

        apply_config_to_dut(duthost, bgp_config, "bgp")
        apply_single_exabgp(ptfhost, vnet_count, subif_per_vnet, dut_asn, peer_asn)

    except Exception as exc:
        logger.error("vnet_bgp_setup failed: %s", str(exc))
        logger.error(json.dumps(traceback.format_exception(*sys.exc_info()), indent=2))
        cleanup_ptf_config(ptfhost, ptf_ports)
        if duthost is not None:
            config_reload(duthost, safe_reload=True, yang_validate=False)
        pytest.fail("Vnet testing setup failed")

    yield {
        "duthost": duthost,
        "vnet_count": vnet_count,
        "subif_per_vnet": subif_per_vnet,
        "wait_time": wait_time,
        "wl_ptf_port_indices": wl_ptf_port_indices,
        "t1_ptf_port_index": t1_ptf_port_index,
        "dut_vtep": dut_vtep,
    }

    cleanup_ptf_config(ptfhost, ptf_ports)
    config_reload(duthost, safe_reload=True, yang_validate=False)


def validate_bgp_summary(duthost, vnet_count, subif_per_vnet):
    all_vrfs = json.loads(duthost.shell("vtysh -c 'show bgp vrf all summary json'")["stdout"])
    failures = []
    expected_peers = subif_per_vnet

    for vnet_id in range(1, vnet_count + 1):
        vrf = "Vnet{}".format(vnet_id)
        try:
            peers = int(all_vrfs[vrf]["ipv4Unicast"]["dynamicPeers"])
            if peers != expected_peers:
                failures.append("{}: expected {} peers, got {}".format(vrf, expected_peers, peers))
        except Exception:
            failures.append("{}: unable to read dynamicPeers".format(vrf))

    if failures:
        pytest.fail("BGP validation failed:\n{}".format("\n".join(failures)))


def test_vnet_bgp_scale_summary(vnet_bgp_setup):
    setup = vnet_bgp_setup
    validate_bgp_summary(setup["duthost"], setup["vnet_count"], setup["subif_per_vnet"])


def test_vnet_bgp_scale_config_reload(vnet_bgp_setup):
    setup = vnet_bgp_setup
    duthost = setup["duthost"]

    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")
    duthost.shell("config save -y")

    config_reload(duthost, safe_reload=True, yang_validate=False)
    time.sleep(setup["wait_time"])

    validate_bgp_summary(duthost, setup["vnet_count"], setup["subif_per_vnet"])
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")


def test_vnet_bgp_scale_dataplane(vnet_bgp_setup, ptfhost):
    setup = vnet_bgp_setup
    duthost = setup["duthost"]

    validate_bgp_summary(duthost, setup["vnet_count"], setup["subif_per_vnet"])

    ptf_params = {
        "vnet_count": setup["vnet_count"],
        "subif_per_vnet": setup["subif_per_vnet"],
        "base_vlan_id": BASE_VLAN_ID,
        "wl_ptf_port_indices": ",".join(str(index) for index in setup["wl_ptf_port_indices"]),
        "t1_ptf_port_index": str(setup["t1_ptf_port_index"]),
        "router_mac": duthost.facts["router_mac"],
        "dut_vtep": setup["dut_vtep"],
        "vxlan_port": VXLAN_PORT,
    }

    ptf_runner(
        ptfhost,
        "ptftests",
        "vnet_bgp_scale_dataplane.VnetBgpScaleDataplane",
        platform_dir="ptftests",
        params=ptf_params,
        log_file="/tmp/vnet_bgp_scale_dp.log",
        is_python3=True,
    )
