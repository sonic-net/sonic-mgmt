import json
import time
import logging
import pytest
from tests.common.reboot import reboot

logger = logging.getLogger(__name__)

BASE_VLAN_ID = 1100
DUT_INTERFACE = "Po101"
DUT_IFACES = ["Po101", "Po102"]
NEIGH_INTERFACE = "Po1"
VXLAN_TUNNEL_NAME = "vtep_v4"
VXLAN_SRC_IP = "10.1.0.32"

pytestmark = [
    pytest.mark.topology('smartswitch')
]

def get_cfg_facts(duthost):
    # return config db contents(running-config)
    tmp_facts = json.loads(duthost.shell(
        "sonic-cfggen -d --print-data")['stdout'])

    return tmp_facts


def apply_config_to_dut(duthost, config, cfg_type):
    config_path = f"/tmp/dut_config_{cfg_type}.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=4)

    duthost.copy(src=config_path, dest=config_path)
    duthost.shell(f"sonic-cfggen -j {config_path} --write-to-db")


def generate_ip_pair(vnet_id, iface_index):
    # Each iface_index (0 or 1) gets a /30 block within the /29 range per VNET
    block_size = 4  # /30 block size
    base_offset = (vnet_id - 1) * 8  # each VNET gets 8 IPs (two /30s)
    subnet_offset = base_offset + (iface_index * block_size)

    third_octet = subnet_offset // 256
    fourth_octet = subnet_offset % 256

    if fourth_octet + 3 > 255:
        raise ValueError("IP range exceeds .255 in fourth octet")

    dut_ip = f"10.1.{third_octet}.{fourth_octet + 1}"
    nbr_ip = f"10.1.{third_octet}.{fourth_octet + 2}"
    network_str = f"10.1.{third_octet}.{fourth_octet}/30"

    return dut_ip, nbr_ip, network_str


def generate_dut_config(vnet_count, peer_asn):
    config_db = {
        "VXLAN_TUNNEL": {
            VXLAN_TUNNEL_NAME: {
                "src_ip": VXLAN_SRC_IP
            }
        },
        "VLAN": {},
        "VNET": {},
        "VLAN_SUB_INTERFACE": {}
    }

    bgp_config_db = {
        "BGP_PEER_RANGE": {}
    }

    for vnet_id in range(1, vnet_count + 1):
        vnet_name = f"Vnet{vnet_id}"
        vlan_id = BASE_VLAN_ID + vnet_id

        config_db["VLAN"][str(vlan_id)] = {}

        subinterfaces = []
        for idx, iface in enumerate(DUT_IFACES):
            subintf = f"{iface}.{vlan_id}"
            dut_ip, _, ip_range = generate_ip_pair(vnet_id, idx)

            config_db["VLAN_SUB_INTERFACE"][subintf] = {
                "admin_status": "up",
                "vlan": str(vlan_id),
                "vnet_name": vnet_name
            }
            config_db["VLAN_SUB_INTERFACE"][f"{subintf}|{dut_ip}/30"] = {}

            subinterfaces.append((subintf, dut_ip, ip_range))

        config_db["VNET"][vnet_name] = {
            "vni": str(vnet_id),
            "vxlan_tunnel": VXLAN_TUNNEL_NAME
        }

        # Combined /29 block covering both /30 subnets per VNET
        first_subnet_base = subinterfaces[0][2].split('/')[0]
        third_octet, fourth_octet = map(int, first_subnet_base.split('.')[2:4])
        combined_network = f"10.1.{third_octet}.{fourth_octet // 8 * 8}/29"

        bgp_config_db["BGP_PEER_RANGE"][f"{vnet_name}|dynpeer{vnet_name}"] = {
            "ip_range": [combined_network],
            "peer_asn": peer_asn,
            "src_address": subinterfaces[0][1],  # first subinterface IP
            "name": f"dynpeer{vnet_name}"
        }

    return config_db, bgp_config_db


def configure_neighbor(nbrhosts, neighbor_type, dut_asn, dut_name, peer_asn, count, base_vlan, iface_list):
    assert len(iface_list) == len(nbrhosts), "iface_list length must match nbrhosts"

    if neighbor_type == "sonic":
        nbr_subintf_configs = {nbr: {"VLAN": {}, "VLAN_SUB_INTERFACE": {}} for nbr in nbrhosts}
        nbr_bgp_configs = {nbr: {"BGP_NEIGHBOR": {}} for nbr in nbrhosts}
    else:
        for nbr in nbrhosts:
            nbrhosts[nbr].shell(
                "iptables -nL BGPSACL || iptables -N BGPSACL; "
                "iptables -C BGP -s 10.1.0.0/16 -j BGPSACL || "
                "iptables -I BGP 1 -s 10.1.0.0/16 -j BGPSACL"
            )

    for vnet_id in range(1, count + 1):
        vlan_id = base_vlan + vnet_id

        for idx, (nbr_name, nbrhost) in enumerate(nbrhosts.items()):
            iface = iface_list[idx]
            subintf = f"{iface}.{vlan_id}"
            dut_ip, nbr_ip, _ = generate_ip_pair(vnet_id, idx)
            nbr_ip_with_mask = f"{nbr_ip}/30"

            if neighbor_type == "sonic":
                subintf_cfg = nbr_subintf_configs[nbr_name]
                subintf_cfg["VLAN"][str(vlan_id)] = {}

                subintf_cfg["VLAN_SUB_INTERFACE"][subintf] = {
                    "admin_status": "up",
                    "vlan": str(vlan_id)
                }
                subintf_cfg["VLAN_SUB_INTERFACE"][f"{subintf}|{nbr_ip_with_mask}"] = {}

                bgp_cfg = nbr_bgp_configs[nbr_name]
                bgp_cfg["BGP_NEIGHBOR"][dut_ip] = {
                    "admin_status": "up",
                    "asn": dut_asn,
                    "holdtime": "10",
                    "keepalive": "3",
                    "local_addr": nbr_ip,
                    "name": dut_name,
                    "nhopself": "0",
                    "rrclient": "0"
                }
            else:
                intf_cmds = [
                    f"interface {iface}.{vlan_id}",
                    f"encapsulation dot1q vlan {vlan_id}",
                    f"ip address {nbr_ip_with_mask}",
                    f"interface {iface}",
                    f"switchport trunk allowed vlan add {vlan_id}"
                ]
                nbrhosts[nbr_name].config(intf_cmds, module_ignore_errors=True)
                dut_ip, _, _ = generate_ip_pair(vnet_id, idx)
                bgp_cmds = [
                    f"neighbor {dut_ip} remote-as {dut_asn}"
                ]
                nbrhosts[nbr_name].config(bgp_cmds, parents=f"router bgp {peer_asn}", module_ignore_errors=True)

    if neighbor_type == "sonic":
        for nbr_name, cfg in nbr_subintf_configs.items():
            subintf_path = f"/tmp/{nbr_name}_subintf.json"
            with open(subintf_path, "w") as f:
                json.dump(cfg, f, indent=4)

            nbrhosts[nbr_name].copy(src=subintf_path, dest=subintf_path)
            nbrhosts[nbr_name].shell(f"sonic-cfggen -j {subintf_path} --write-to-db")

        # Give time for interfaces to come up before BGP config
        time.sleep(2)

        for nbr_name, cfg in nbr_bgp_configs.items():
            bgp_path = f"/tmp/{nbr_name}_bgp.json"
            with open(bgp_path, "w") as f:
                json.dump(cfg, f, indent=4)

            nbrhosts[nbr_name].copy(src=bgp_path, dest=bgp_path)
            nbrhosts[nbr_name].shell(f"sonic-cfggen -j {bgp_path} --write-to-db")


def validate_bgp_summary(duthost, count):
    for vnet_id in range(1, count + 1):
        # Validate BGP summary for each VNET
        command = f"vtysh -c 'show bgp vrf Vnet{vnet_id} summary json'"
        bgp_summary_string = duthost.shell(command)["stdout"]
        bgp_summary = json.loads(bgp_summary_string)
        total_peers = bgp_summary['ipv4Unicast']['dynamicPeers']
        assert int(total_peers) == 2, "There should be 2 dynamic peers. Found {}".format(total_peers)


def test_vnet_bulk_configure(duthost, nbrhosts, localhost, vnet_count, request):
    cfg_facts = get_cfg_facts(duthost)
    dut_asn = cfg_facts['DEVICE_METADATA']['localhost']['bgp_asn']
    dut_name = cfg_facts['DEVICE_METADATA']['localhost']['hostname']
    neighbors = cfg_facts['BGP_NEIGHBOR']
    peer_asn = list(neighbors.values())[0]["asn"]

    logger.info("Generate config DB for DUT")
    vnet_config, bgp_config = generate_dut_config(vnet_count, peer_asn)

    logger.info("Apply interface, vlan and vnet config on DUT")
    apply_config_to_dut(duthost, vnet_config, "vnet")
    time.sleep(5)  # Allow time for interfaces to come up
    logger.info("Apply BGP config on DUT")
    apply_config_to_dut(duthost, bgp_config, "bgp")

    logger.info("Step 3: Configure neighbor device")
    logger.info("nbrhosts: %s", nbrhosts)
    neighbor_type = request.config.getoption("--neighbor_type")
    logger.info("Neighbor type: %s", neighbor_type)

    selected_nbrhosts = {
        'ARISTA01T1': nbrhosts['ARISTA01T1']['host'],
        'ARISTA02T1': nbrhosts['ARISTA02T1']['host'],
    }

    # Corresponding interfaces on DUT for these neighbors
    interfaces = ["Po1", "Po1"]

    configure_neighbor(
        selected_nbrhosts, neighbor_type, dut_asn, dut_name, peer_asn,
        count=vnet_count, base_vlan=BASE_VLAN_ID, iface_list=interfaces
    )

    time.sleep(60)

    validate_bgp_summary(duthost, vnet_count)

    duthost.shell("cp /etc/sonic/config_db.json /home/admin/config_db_backup.json")

    # Validate config persistence after config reload.
    duthost.shell("config save -y", module_ignore_errors=True)
    time.sleep(5)

    duthost.shell("config reload -y", module_ignore_errors=True)
    time.sleep(60)
    validate_bgp_summary(duthost, vnet_count)

    # cleanup
    duthost.shell("cp /home/admin/config_db_backup.json /etc/sonic/config_db.json")
    duthost.shell("config reload -y", module_ignore_errors=True)
