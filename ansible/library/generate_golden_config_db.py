#!/usr/bin/python

# This ansible module is for generate golden_config_db.json
# Currently, only enable dhcp_server feature and generated related configuration in MX device
# which has dhcp_server feature.


import copy
from jinja2 import Template
import logging
import json
import re
import ipaddress

from ansible.module_utils.basic import AnsibleModule
from sonic_py_common import device_info, multi_asic
from ansible.module_utils.smartswitch_utils import smartswitch_hwsku_config, smartswitch_vlan_config

DOCUMENTATION = '''
module: generate_golden_config_db.py
author: Yaqiang Zhu (yaqiangzhu@microsoft.com)
short_description:   Generate golden_config_db.json
Description:
        When load_minigraph, SONiC support to use parameter --override_config to add configuration via
        golden_config_db.json. This module is to generate required /etc/sonic/golden_config_db.json
    Input:
        topo_name: Name of current topo
'''

GOLDEN_CONFIG_DB_PATH = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_DB_PATH_ORI = "/etc/sonic/golden_config_db.json.origin.backup"
TEMP_DHCP_SERVER_CONFIG_PATH = "/tmp/dhcp_server.json"
TEMP_SMARTSWITCH_CONFIG_PATH = "/tmp/smartswitch.json"
DUMMY_QUOTA = "dummy_single_quota"
MACSEC_PROFILE_PATH = '/tmp/profile.json'
GOLDEN_CONFIG_TEMPLATE = 'golden_config_db_t2.j2'
GOLDEN_CONFIG_TEMPLATE_PATH = '/tmp/golden_config_db_t2.j2'
DNS_CONFIG_PATH = '/tmp/dns_config.json'

logger = logging.getLogger(__name__)

LOSSY_HWSKU = frozenset({'Arista-7060X6-64PE-C256S2', 'Arista-7060X6-64PE-C224O8',
                         'Mellanox-SN5600-C256S1', 'Mellanox-SN5600-C224O8',
                         'Arista-7060X6-64PE-B-C512S2', 'Arista-7060X6-64PE-B-C448O16',
                         'Mellanox-SN5640-C512S2', 'Mellanox-SN5640-C448O16'})

DEVICE_PATH = '/usr/share/sonic/device'


def _resolve_base_hwsku_dir(hwsku, platform):
    """
    Resolve the base HwSku directory for generic HwSku support.
    If the exact hwsku directory exists, return it.
    Otherwise, strip breakout suffixes (e.g., -C222O9, -O128S2) to find the base directory.
    """
    import os
    platform_dir = os.path.join(DEVICE_PATH, platform)
    exact_dir = os.path.join(platform_dir, hwsku)
    if os.path.isdir(exact_dir):
        return exact_dir

    # Strip breakout suffix patterns: -C256S2, -O128S2, -C224O8, -C222O9, etc.
    base = re.sub(r'-([A-Z]\d+)+$', '', hwsku)
    base_dir = os.path.join(platform_dir, base)
    if base != hwsku and os.path.isdir(base_dir):
        return base_dir

    # Try stripping -B- variants (e.g., Arista-7060X6-64PE-B-C512S2)
    base2 = re.sub(r'(-B)?-([A-Z]\d+)+$', '', hwsku)
    base2_dir = os.path.join(platform_dir, base2)
    if base2 != hwsku and os.path.isdir(base2_dir):
        return base2_dir

    return exact_dir  # Return original path even if not found


def generate_port_table_from_hwsku_json(platform, hwsku, minigraph_ports=None):
    """
    Generate a PORT table dict from hwsku.json + platform.json for generic HwSku support.
    Derives the breakout mode by comparing minigraph port names against hwsku.json cages.

    Args:
        platform: Platform name (e.g., 'x86_64-arista_7060x6_64pe')
        hwsku: Target HwSku name (e.g., 'Arista-7060X6-64PE')
        minigraph_ports: Set of port names from minigraph (e.g., {'Ethernet0', 'Ethernet4', ...})

    Returns:
        dict: PORT table suitable for config_db / golden_config override, or None if not applicable
    """
    import os

    hwsku_dir = _resolve_base_hwsku_dir(hwsku, platform)

    hwsku_json_path = os.path.join(hwsku_dir, 'hwsku.json')
    if not os.path.exists(hwsku_json_path):
        return None

    with open(hwsku_json_path) as f:
        hwsku_data = json.load(f)

    # Load platform.json for lane info and alias patterns
    platform_json_path = os.path.join(DEVICE_PATH, platform, 'platform.json')
    platform_data = None
    if os.path.exists(platform_json_path):
        with open(platform_json_path) as f:
            platform_data = json.load(f)

    interfaces = hwsku_data.get('interfaces', {})
    port_table = {}

    for port_name, port_info in sorted(interfaces.items(), key=lambda x: int(x[0].replace('Ethernet', ''))):
        base_num = int(port_name.replace('Ethernet', ''))

        # Get lane info from platform.json
        if platform_data and 'interfaces' in platform_data:
            plat_port = platform_data['interfaces'].get(port_name, {})
            all_lanes = plat_port.get('lanes', '')
            base_alias = plat_port.get('alias', '')
            base_index = str(plat_port.get('index', base_num // 8 + 1)).split(',')[0].strip()
            lane_list = all_lanes.split(',') if all_lanes else []
            total_lanes = len(lane_list) if lane_list else 8
        else:
            lane_list = []
            total_lanes = 8
            base_alias = ''
            base_index = str(base_num // 8 + 1)

        # Derive breakout by counting how many minigraph ports fall within this cage
        if minigraph_ports and base_num < 512:
            # Count ports in this cage's range [base_num, base_num + total_lanes)
            ports_in_cage = [p for p in minigraph_ports
                             if p.startswith('Ethernet') and p[8:].isdigit()
                             and base_num <= int(p[8:]) < base_num + total_lanes]
            num_ports = len(ports_in_cage) if ports_in_cage else 1
        else:
            # Management ports or no minigraph info — use hwsku.json default
            brkout_mode = port_info.get('default_brkout_mode', '1x400G')
            brkout_clean = re.sub(r'\[.*\]', '', brkout_mode)
            m = re.match(r'(\d+)x(\d+)G', brkout_clean)
            num_ports = int(m.group(1)) if m else 1

        lanes_per_subport = total_lanes // num_ports if num_ports > 0 else total_lanes
        # Speed = lanes_per_subport * 100G (PAM4: 1 lane = 100Gbps)
        speed = lanes_per_subport * 100000
        step = lanes_per_subport

        for sub_idx in range(num_ports):
            sub_port_num = base_num + sub_idx * step
            sub_port_name = 'Ethernet{}'.format(sub_port_num)

            # Assign lanes for this sub-port
            if lane_list:
                start_lane = sub_idx * lanes_per_subport
                end_lane = start_lane + lanes_per_subport
                sub_lanes = ','.join(lane_list[start_lane:end_lane])
            else:
                sub_lanes = ','.join([str(base_num + sub_idx * step + l) for l in range(lanes_per_subport)])

            # Generate alias
            if base_alias:
                if num_ports > 1:
                    suffix = chr(ord('a') + sub_idx)
                    alias = '{}{}'.format(re.sub(r'[a-z]$', '', base_alias), suffix)
                else:
                    alias = base_alias
            else:
                cage_num = base_num // 8 + 1
                if num_ports > 1:
                    alias = 'etp{}{}'.format(cage_num, chr(ord('a') + sub_idx))
                else:
                    alias = 'etp{}'.format(cage_num)
                    alias = 'etp{}'.format(cage_num)

            # Build PORT entry
            port_entry = {
                'alias': alias,
                'lanes': sub_lanes,
                'speed': str(speed),
                'index': base_index,
                'admin_status': 'up',
                'mtu': '9100'
            }

            # Add FEC for high-speed ports
            if speed >= 200000:
                port_entry['fec'] = 'rs'

            port_table[sub_port_name] = port_entry

    return port_table if port_table else None


def is_full_lossy_hwsku(hwsku):
    """
    Return True if the platform is lossy-only and PFCWD should default to 'disable'.
    """
    return hwsku in LOSSY_HWSKU


class GenerateGoldenConfigDBModule(object):
    def __init__(self):
        self.module = AnsibleModule(argument_spec=dict(topo_name=dict(required=True, type='str'),
                                    port_index_map=dict(required=False, type='dict', default=None),
                                    macsec_profile=dict(required=False, type='str', default=None),
                                    num_asics=dict(required=False, type='int', default=1),
                                    hwsku=dict(required=False, type='str', default=None),
                                    vm_configuration=dict(required=False, type='dict', default={}),
                                    is_lit_mode=dict(required=False, type='bool', default=True),
                                    npu_index=dict(required=False, type='int', default=0)),
                                    supports_check_mode=True)
        self.topo_name = self.module.params['topo_name']
        self.port_index_map = self.module.params['port_index_map']
        self.macsec_profile = self.module.params['macsec_profile']
        self.num_asics = self.module.params['num_asics']
        self.hwsku = self.module.params['hwsku']
        self.platform, _ = device_info.get_platform_and_hwsku()

        self.vm_configuration = self.module.params['vm_configuration']
        self.is_lit_mode = self.module.params['is_lit_mode']
        self.npu_index = self.module.params['npu_index']

    def generate_mgfx_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate config table from init_cfg.ini
        ori_config_db = json.loads(out)

        golden_config_db = {}
        if "DEVICE_METADATA" in ori_config_db:
            golden_config_db["DEVICE_METADATA"] = ori_config_db["DEVICE_METADATA"]
            if ("localhost" in golden_config_db["DEVICE_METADATA"] and
               "default_pfcwd_status" in golden_config_db["DEVICE_METADATA"]["localhost"]):
                golden_config_db["DEVICE_METADATA"]["localhost"]["default_pfcwd_status"] = "disable"

        if self.topo_name == "mx":
            golden_config_db.update(self.generate_mx_golden_config_db())
        return json.dumps(golden_config_db, indent=4)

    def generate_mx_golden_config_db(self):
        """
        If FEATURE table in init_cfg.json contains dhcp_server, enable it.
        And add dhcp_server related configuration
        """
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate FEATURE table from init_cfg.ini
        ori_config_db = json.loads(out)
        if "FEATURE" not in ori_config_db or "dhcp_server" not in ori_config_db["FEATURE"]:
            return {}

        ori_config_db["FEATURE"]["dhcp_server"]["state"] = "enabled"
        gold_config_db = {
            "FEATURE": copy.deepcopy(ori_config_db["FEATURE"]),
            "PORT": copy.deepcopy(ori_config_db["PORT"])
        }

        # Generate dhcp_server related configuration
        rc, out, err = self.module.run_command("cat {}".format(TEMP_DHCP_SERVER_CONFIG_PATH))
        if rc != 0:
            self.module.fail_json(msg="Failed to get dhcp_server config: {}".format(err))
        if self.port_index_map is None or self.port_index_map == {}:
            self.module.fail_json(msg="port_index_map is missing")
        dhcp_server_config_obj = json.loads(out)
        # Update DHCP_SERVER_IPV4_PORT based on port index map
        dhcp_server_port_config = {}
        for key, value in dhcp_server_config_obj["DHCP_SERVER_IPV4_PORT"].items():
            splits = key.split("|")
            new_key = "{}|{}".format(splits[0], self.port_index_map[splits[1]])
            dhcp_server_port_config[new_key] = value
        dhcp_server_config_obj["DHCP_SERVER_IPV4_PORT"] = dhcp_server_port_config

        gold_config_db.update(dhcp_server_config_obj)
        return gold_config_db

    def generate_full_lossy_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate config table from init_cfg.ini
        ori_config_db = json.loads(out)

        golden_config_db = {}
        if "DEVICE_METADATA" in ori_config_db:
            golden_config_db["DEVICE_METADATA"] = ori_config_db["DEVICE_METADATA"]
            if ("localhost" in golden_config_db["DEVICE_METADATA"] and
               "default_pfcwd_status" in golden_config_db["DEVICE_METADATA"]["localhost"]):
                golden_config_db["DEVICE_METADATA"]["localhost"]["default_pfcwd_status"] = "disable"
                golden_config_db["DEVICE_METADATA"]["localhost"]["buffer_model"] = "traditional"

        # set counterpoll interval to 2000ms as workaround for Slowness observed in nexthop group and member programming
        if "FLEX_COUNTER_TABLE" in ori_config_db and 'sn5640' in self.platform:
            golden_config_db["FLEX_COUNTER_TABLE"] = ori_config_db["FLEX_COUNTER_TABLE"]
            golden_config_db["FLEX_COUNTER_TABLE"]["PORT"]["POLL_INTERVAL"] = "2000"

        return json.dumps(golden_config_db, indent=4)

    def check_version_for_bmp(self):
        output_version = device_info.get_sonic_version_info()
        build_version = output_version['build_version']

        if re.match(r'^(\d{6})', build_version):
            version_number = int(re.findall(r'\d{6}', build_version)[0])
            if version_number < 202411:
                return False
        elif re.match(r'^internal-(\d{6})', build_version):
            internal_version_number = int(re.findall(r'\d{6}', build_version)[0])
            if internal_version_number < 202411:
                return False
        else:
            return True
        return True

    def has_otel_image(self):
        rc, out, _ = self.module.run_command("docker images --format '{{.Repository}}'")
        if rc != 0:
            return False
        repos = [line.strip().lower() for line in out.splitlines() if line.strip()]
        return "docker-sonic-otel" in repos

    def get_config_from_minigraph(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))
        return out

    def get_multiasic_feature_config(self):
        rc, out, err = self.module.run_command("show runningconfiguration all")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from runningconfiguration: {}".format(err))
        config = json.loads(out)
        # From the running configure, only keep the key "FEATURE"
        for namespace, ns_data in config.items():
            config[namespace] = {k: ns_data[k] for k in ns_data if k == "FEATURE"}
        return config

    def overwrite_feature_golden_config_db_multiasic(self, config, feature_key, auto_restart="enabled",
                                                     state="enabled", feature_data=None):
        full_config = json.loads(config)
        if full_config == {} or "FEATURE" not in full_config.get("localhost", {}):
            # need dump running config FEATURE + selected feature
            gold_config_db = self.get_multiasic_feature_config()
        else:
            # need existing config + selected feature
            gold_config_db = full_config

        if feature_data is None:
            feature_data = {
                feature_key: {
                    "auto_restart": auto_restart,
                    "check_up_status": "false",
                    "delayed": "False",
                    "has_global_scope": "False",
                    "has_per_asic_scope": "True",
                    "high_mem_alert": "disabled",
                    "set_owner": "local",
                    "state": state,
                    "support_syslog_rate_limit": "false"
                }
            }

        for namespace, ns_data in gold_config_db.items():
            if "FEATURE" in ns_data:
                feature_section = ns_data["FEATURE"]
                feature_section.update(feature_data)
                ns_data["FEATURE"] = feature_section
            else:
                ns_data["FEATURE"] = feature_data

        return json.dumps(gold_config_db, indent=4)

    def overwrite_feature_golden_config_db_singleasic(self, config, feature_key,
                                                      auto_restart="enabled", state="enabled"):
        full_config = config
        onlyFeature = config == "{}"  # FEATURE needs special handling since it does not support incremental update.
        if config == "{}":
            full_config = self.get_config_from_minigraph()

        ori_config_db = json.loads(full_config)
        if "FEATURE" not in ori_config_db:
            full_config = self.get_config_from_minigraph()
            feature_config_db = json.loads(full_config)
            ori_config_db["FEATURE"] = feature_config_db.get("FEATURE", {})

        # Append the specified feature section to the original "FEATURE" section
        ori_config_db.setdefault("FEATURE", {}).setdefault(feature_key, {}).update({
            "auto_restart": auto_restart,
            "check_up_status": "false",
            "delayed": "False",
            "has_global_scope": "True",
            "has_per_asic_scope": "False",
            "high_mem_alert": "disabled",
            "set_owner": "local",
            "state": state,
            "support_syslog_rate_limit": "false"
        })

        # Create the gold_config_db dictionary with both "FEATURE" and the specified feature section
        if onlyFeature:
            gold_config_db = {
                "FEATURE": copy.deepcopy(ori_config_db["FEATURE"])
            }
        else:
            gold_config_db = ori_config_db

        return json.dumps(gold_config_db, indent=4)

    def get_portchannle_config(self, vm_configuration):
        portchannel_configs = []

        for device_name, device_data in vm_configuration.items():
            # Only process T0 neighbors
            if not device_name.endswith("T0"):
                continue

            interfaces = device_data.get("interfaces", {})
            for intf_name, intf_config in interfaces.items():
                if "Port-Channel" in intf_name and '.' in intf_name:
                    base, sub_id = intf_name.split('.')
                    base = base.replace("Port-Channel", "PortChannel")

                    # Handle IPv4
                    ipv4_addr = intf_config.get("ipv4")
                    if ipv4_addr:
                        try:
                            network_v4 = ipaddress.IPv4Interface(ipv4_addr).network
                            subinterface_ipv4 = str(network_v4)
                            portchannel_configs.append((device_name, base, sub_id, subinterface_ipv4))
                        except Exception as e:
                            raise ValueError("Error parsing IPv4 on {}: {}".format(intf_name, e))

                    # Handle IPv6
                    ipv6_addr = intf_config.get("ipv6")
                    if ipv6_addr:
                        try:
                            iface_v6 = ipaddress.IPv6Interface(ipv6_addr)
                            new_ip = str(iface_v6.ip - 1)
                            subnet = "{}/{}".format(new_ip, iface_v6.network.prefixlen)
                            portchannel_configs.append((device_name, base, sub_id, subnet))
                        except Exception as e:
                            raise ValueError("Error parsing IPv6 on {}: {}".format(intf_name, e))

        if not portchannel_configs:
            raise ValueError("No valid Port-Channel subinterface found in any T0 neighbor")

        return portchannel_configs

    def get_bgp_config(self, vm_configuration):

        vrf_name = "Vrf_Q10DDOS"
        bgp_neighbors = {}
        for device_name, config in self.vm_configuration.items():
            if not device_name.endswith("T0"):
                continue  # Skip non-T0 devices
            interfaces = config.get("interfaces", {})
            subintf_exists = any(
                "Port-Channel" in intf_name and '.' in intf_name
                for intf_name in interfaces
            )
            if not subintf_exists:
                continue  # Skip if no Port-Channel subinterfaces

            bgp = config.get("bgp", {})
            local_asn = bgp.get("asn")
            peers = bgp.get("peers", {})
            if not peers:
                continue  # Skip if no BGP peers
            ipv4_count = 0
            ipv6_count = 0

            for peer_asn, neighbor_list in peers.items():
                for idx, ip in enumerate(neighbor_list):
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        local_ip = str(ip_obj)
                        neighbor_ip = str(ip_obj + 1)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            if ipv4_count == 0:
                                neighbor_key = neighbor_ip
                            else:
                                neighbor_key = "{}|{}".format(vrf_name, neighbor_ip)
                            ipv4_count += 1

                        else:
                            if ipv6_count == 0:
                                neighbor_key = neighbor_ip
                            else:
                                neighbor_key = "{}|{}".format(vrf_name, neighbor_ip)
                            ipv6_count += 1

                        bgp_neighbors[neighbor_key] = {
                            "admin_status": "up",
                            "name": device_name,
                            "holdtime": "10",
                            "keepalive": "3",
                            "rrclient": "0",
                            "local_addr": local_ip,
                            "asn": local_asn,
                            "nhopself": "0"
                        }
                    except ipaddress.AddressValueError:
                        print("[ERROR] Invalid IPv4 address in {}: {}".format(device_name, ip))
        return bgp_neighbors

    def generate_filterleaf_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate FEATURE table from init_cfg.ini
        ori_config_db = json.loads(out)
        if "DEVICE_METADATA" not in ori_config_db or "localhost" not in ori_config_db["DEVICE_METADATA"]:
            return "{}"

        if "FEATURE" not in ori_config_db \
                or "dhcp_relay" not in ori_config_db["FEATURE"]:
            return "{}"
        ori_config_db["FEATURE"]["dhcp_relay"]["state"] = "disabled"

        if "VRF" not in ori_config_db:
            ori_config_db["VRF"] = {}
        ori_config_db["VRF"]["Vrf_Q10DDOS"] = {}

        if "VLAN_SUB_INTERFACE" not in ori_config_db:
            ori_config_db["VLAN_SUB_INTERFACE"] = {}

        portchannel_configs = self.get_portchannle_config(self.vm_configuration)

        for device_name, base_interface, vlan, ip_subnet in portchannel_configs:
            base_interface = base_interface + '.' + vlan
            if vlan in ['7', '9', '11', '13']:
                ori_config_db["VLAN_SUB_INTERFACE"][base_interface] = {}
                ori_config_db["VLAN_SUB_INTERFACE"]["{}|{}".format(base_interface, ip_subnet)] = {}
            else:
                ori_config_db["VLAN_SUB_INTERFACE"][base_interface] = {
                    "vrf_name": "Vrf_Q10DDOS"
                }
                ori_config_db["VLAN_SUB_INTERFACE"]["{}|{}".format(base_interface, ip_subnet)] = {}

        bgp_neighbors = self.get_bgp_config(self.vm_configuration)
        ori_config_db["BGP_NEIGHBOR"] = bgp_neighbors

        gold_config_db = {
            "DEVICE_METADATA": copy.deepcopy(ori_config_db["DEVICE_METADATA"]),
            "FEATURE": copy.deepcopy(ori_config_db["FEATURE"]),
            "VRF": copy.deepcopy(ori_config_db["VRF"]),
            "VLAN_SUB_INTERFACE": copy.deepcopy(ori_config_db["VLAN_SUB_INTERFACE"]),
            "BGP_NEIGHBOR": copy.deepcopy(ori_config_db["BGP_NEIGHBOR"]),
        }

        return json.dumps(gold_config_db, indent=4)

    def generate_smartswitch_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        ori_config_db = json.loads(out)
        if "DEVICE_METADATA" not in ori_config_db or "localhost" not in ori_config_db["DEVICE_METADATA"]:
            return "{}"
        ori_config_db["DEVICE_METADATA"]["localhost"]["subtype"] = "SmartSwitch"
        hwsku = ori_config_db["DEVICE_METADATA"]["localhost"].get("hwsku", None)

        if "FEATURE" not in ori_config_db \
                or "dhcp_server" not in ori_config_db["FEATURE"] \
                or "dhcp_relay" not in ori_config_db["FEATURE"]:
            return "{}"
        ori_config_db["FEATURE"]["dhcp_server"]["state"] = "enabled"
        ori_config_db["FEATURE"]["dhcp_relay"]["state"] = "enabled"

        if "PORT" not in ori_config_db or "INTERFACE" not in ori_config_db:
            return "{}"

        if hwsku not in smartswitch_hwsku_config:
            return "{}"

        if "DPUS" not in ori_config_db:
            ori_config_db["DPUS"] = {}

        if "CHASSIS_MODULE" not in ori_config_db:
            ori_config_db["CHASSIS_MODULE"] = {}

        if "DHCP_SERVER_IPV4_PORT" not in ori_config_db:
            ori_config_db["DHCP_SERVER_IPV4_PORT"] = {}

        hwsku_config = smartswitch_hwsku_config[hwsku]
        dpu_num = hwsku_config["dpu_num"]

        vlan_cfg = smartswitch_vlan_config.get(self.npu_index, smartswitch_vlan_config[0])
        vlan_name = vlan_cfg["vlan_name"]

        ori_config_db["VLAN"] = {
            vlan_name: {"vlanid": vlan_cfg["vlanid"]}
        }
        ori_config_db["VLAN_INTERFACE"] = {
            vlan_name: {},
            "{}|{}".format(vlan_name, vlan_cfg["vlan_interface_ip"]): {}
        }
        ori_config_db["VLAN_MEMBER"] = {}

        for i in range(dpu_num):
            port_index = hwsku_config["base"] + i * hwsku_config["step"] \
                if "base" in hwsku_config and "step" in hwsku_config else i
            port_key = hwsku_config["port_key"].format(port_index)
            dpu_key = hwsku_config["dpu_key"].format(i)

            if port_key in ori_config_db["PORT"]:
                ori_config_db["PORT"][port_key]["admin_status"] = "up"

            # Remove any minigraph-generated INTERFACE entries for DPU dataplane ports
            keys_to_remove = [k for k in ori_config_db["INTERFACE"]
                              if k == port_key or k.startswith(port_key + "|")]
            for k in keys_to_remove:
                del ori_config_db["INTERFACE"][k]

            vlan_member_key = "{}|{}".format(vlan_name, port_key)
            ori_config_db["VLAN_MEMBER"][vlan_member_key] = {"tagging_mode": "untagged"}

            ori_config_db["CHASSIS_MODULE"]["DPU{}".format(i)] = {"admin_status": "up"}

            if dpu_key not in ori_config_db["DPUS"]:
                ori_config_db["DPUS"][dpu_key] = {}
            ori_config_db["DPUS"][dpu_key]["midplane_interface"] = dpu_key

            key = "bridge-midplane|dpu{}".format(i)
            if key not in ori_config_db["DHCP_SERVER_IPV4_PORT"]:
                ori_config_db["DHCP_SERVER_IPV4_PORT"][key] = {}
            ori_config_db["DHCP_SERVER_IPV4_PORT"][key]["ips"] = ["169.254.200.{}".format(i + 1)]

        mid_plane_bridge_config = {
                "GLOBAL": {
                    "bridge": "bridge-midplane",
                    "ip_prefix": "169.254.200.254/24"
                }
            }

        ori_config_db["MID_PLANE_BRIDGE"] = mid_plane_bridge_config

        dhcp_server_ipv4_config = {
            "DHCP_SERVER_IPV4": {
                "bridge-midplane": {
                    "lease_time": "600000000",
                    "mode": "PORT",
                    "netmask": "255.255.255.0",
                    "state": "enabled"
                }
            }
        }
        ori_config_db["DHCP_SERVER_IPV4"] = dhcp_server_ipv4_config["DHCP_SERVER_IPV4"]
        gold_config_db = {
            "DEVICE_METADATA": copy.deepcopy(ori_config_db["DEVICE_METADATA"]),
            "FEATURE": copy.deepcopy(ori_config_db["FEATURE"]),
            "INTERFACE": copy.deepcopy(ori_config_db["INTERFACE"]),
            "PORT": copy.deepcopy(ori_config_db["PORT"]),
            "VLAN": copy.deepcopy(ori_config_db["VLAN"]),
            "VLAN_INTERFACE": copy.deepcopy(ori_config_db["VLAN_INTERFACE"]),
            "VLAN_MEMBER": copy.deepcopy(ori_config_db["VLAN_MEMBER"]),
            "CHASSIS_MODULE": copy.deepcopy(ori_config_db["CHASSIS_MODULE"]),
            "DPUS": copy.deepcopy(ori_config_db["DPUS"]),
            "DHCP_SERVER_IPV4_PORT": copy.deepcopy(ori_config_db["DHCP_SERVER_IPV4_PORT"]),
            "MID_PLANE_BRIDGE": copy.deepcopy(ori_config_db["MID_PLANE_BRIDGE"]),
            "DHCP_SERVER_IPV4": copy.deepcopy(ori_config_db["DHCP_SERVER_IPV4"])
        }

        gold_config_db["DEVICE_METADATA"]["localhost"]["buffer_model"] = "traditional"
        if self.topo_name == "t1-smartswitch-ha":
            gold_config_db["DEVICE_METADATA"]["localhost"]["cluster"] = "cluster1"
            gold_config_db["DEVICE_METADATA"]["localhost"]["region"] = "west"

        rc, out, err = self.module.run_command("cat {}".format(TEMP_SMARTSWITCH_CONFIG_PATH))
        if rc != 0:
            self.module.fail_json(msg="Failed to get smartswitch config: {}".format(err))
        smartswitch_config_obj = json.loads(out)
        gold_config_db.update(smartswitch_config_obj)
        return json.dumps(gold_config_db, indent=4)

    def generate_t2_golden_config_db(self):
        with open(MACSEC_PROFILE_PATH) as f:
            macsec_profiles = json.load(f)

            profile = macsec_profiles.get(self.macsec_profile)
            if profile:
                profile['macsec_profile'] = self.macsec_profile

            # Update the profile context with the asic count
            profile['asic_cnt'] = self.num_asics

            def safe_open_template(template_path):
                with open(template_path) as template_file:
                    return Template(template_file.read())

            # Render the template using the profile
            rendered_json = safe_open_template(GOLDEN_CONFIG_TEMPLATE_PATH).render(profile)

        return rendered_json

    def update_dns_config(self, config):
        # Generate dns_server related configuration
        rc, out, err = self.module.run_command("cat {}".format(DNS_CONFIG_PATH))
        if rc != 0:
            self.module.fail_json(msg="Failed to get dns config: {}".format(err))
        try:
            dns_config_obj = json.loads(out)
        except json.JSONDecodeError:
            self.module.fail_json(msg="Invalid JSON in DNS config: {}".format(out))
        if "DNS_NAMESERVER" in dns_config_obj:
            ori_config_db = json.loads(config)
            if multi_asic.is_multi_asic():
                for key, value in ori_config_db.items():
                    value.update(dns_config_obj)
            else:
                ori_config_db.update(dns_config_obj)
            return json.dumps(ori_config_db, indent=4)
        else:
            return config
        
    def generate_generic_hwsku_port_override(self):
        """
        Generate golden_config with PORT table override for generic HwSku support.
        Derives breakout mode by reading minigraph port names and comparing against
        hwsku.json physical cages. No breakout_mode parameter needed.
        """
        import os
        from lxml import etree

        platform, _ = device_info.get_platform_and_hwsku()

        hwsku_dir = os.path.join(DEVICE_PATH, platform, self.hwsku)
        port_config_path = os.path.join(hwsku_dir, 'port_config.ini')

        # If port_config.ini exists, sonic-cfggen handles PORT table — no override needed
        if os.path.exists(port_config_path):
            return None

        # Read port names from minigraph
        minigraph_ports = set()
        minigraph_path = '/etc/sonic/minigraph.xml'
        if os.path.exists(minigraph_path):
            try:
                tree = etree.parse(minigraph_path)
                root = tree.getroot()
                ns = 'Microsoft.Search.Autopilot.Evolution'
                # Find all InterfaceName elements in DeviceInterfaceLinks
                for elem in root.iter():
                    if 'InterfaceName' in elem.tag and elem.text and elem.text.startswith('Ethernet'):
                        minigraph_ports.add(elem.text)
                # Also find port names from EthernetInterfaces
                for elem in root.iter():
                    if 'EthernetInterface' in elem.tag:
                        for child in elem:
                            if 'InterfaceName' in child.tag and child.text and child.text.startswith('Ethernet'):
                                minigraph_ports.add(child.text)
            except Exception:
                pass

        if not minigraph_ports:
            return None

        port_table = generate_port_table_from_hwsku_json(platform, self.hwsku, minigraph_ports)
        if port_table is None:
            return None

        golden_config_db = {"PORT": port_table}

        # Also update DEVICE_METADATA with the target hwsku name
        golden_config_db["DEVICE_METADATA"] = {
            "localhost": {
                "hwsku": self.hwsku
            }
        }

        return golden_config_db

    def generate_default_init_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate config table from init_cfg.ini
        ori_config_db = json.loads(out)

        golden_config_db = {}
        if "DEVICE_METADATA" in ori_config_db:
            golden_config_db["DEVICE_METADATA"] = ori_config_db["DEVICE_METADATA"]

        # Set buffer_model to traditional to prevent regression, as it is currently hardcoded here:
        #     https://github.com/sonic-net/sonic-utilities/blob/19594b99129f3c881d500ff65d4955d077accb25/config/main.py#L2216
        golden_config_db["DEVICE_METADATA"]["localhost"]["buffer_model"] = "traditional"

        return json.dumps(golden_config_db, indent=4)

    def update_zmq_config(self, config):
        ori_config_db = json.loads(config)
        if "DEVICE_METADATA" not in ori_config_db:
            ori_config_db["DEVICE_METADATA"] = {}
        if "localhost" not in ori_config_db["DEVICE_METADATA"]:
            ori_config_db["DEVICE_METADATA"]["localhost"] = {}

        # Older version image may not support ZMQ feature flag
        rc, out, err = self.module.run_command("sudo cat /usr/local/yang-models/sonic-device_metadata.yang")
        if "orch_northbond_route_zmq_enabled" in out:
            ori_config_db["DEVICE_METADATA"]["localhost"]["orch_northbond_route_zmq_enabled"] = "true"

        return json.dumps(ori_config_db, indent=4)

    def generate_lt2_ft2_golden_config_db(self):
        """
        Generate golden_config for FT2 to enable FEC.
        **Only PORT table is updated**.
        """
        SUPPORTED_TOPO = ["ft2-64", "lt2-p32o64", "lt2-o128"]
        if self.topo_name not in SUPPORTED_TOPO:
            return "{}"
        SUPPORTED_PORT_SPEED = ["200000", "400000", "800000"]
        ori_config = json.loads(self.get_config_from_minigraph())
        port_config = ori_config.get("PORT", {})
        for name, config in port_config.items():
            # Enable FEC for ports with supported speed
            if config["speed"] in SUPPORTED_PORT_SPEED and "fec" not in config:
                config["fec"] = "rs"

        return json.dumps({"PORT": port_config}, indent=4)

    def generate(self):
        module_msg = "Success to generate golden_config_db.json"
        # topo check
        if self.topo_name == "mx" or "m0" in self.topo_name:
            config = self.generate_mgfx_golden_config_db()
            module_msg = module_msg + " for mgfx"
            self.module.run_command("sudo rm -f {}".format(TEMP_DHCP_SERVER_CONFIG_PATH))
        elif self.topo_name in ["t1-smartswitch-ha", "t1-28-lag", "smartswitch-t1", "t1-48-lag"] \
                and self.is_lit_mode:
            config = self.generate_smartswitch_golden_config_db()
            module_msg = module_msg + " for smartswitch"
            self.module.run_command("sudo rm -f {}".format(TEMP_SMARTSWITCH_CONFIG_PATH))
        elif "ft2" in self.topo_name or "lt2" in self.topo_name:
            config = self.generate_lt2_ft2_golden_config_db()
        elif "t2" in self.topo_name and self.macsec_profile:
            config = self.generate_t2_golden_config_db()
            module_msg = module_msg + " for t2"
            self.module.run_command("sudo rm -f {}".format(MACSEC_PROFILE_PATH))
            self.module.run_command("sudo rm -f {}".format(GOLDEN_CONFIG_TEMPLATE_PATH))
        elif self.hwsku and is_full_lossy_hwsku(self.hwsku):
            module_msg = module_msg + " for full lossy hwsku"
            config = self.generate_full_lossy_golden_config_db()
        elif self.topo_name in ["t1-filterleaf-lag"]:
            config = self.generate_filterleaf_golden_config_db()
        else:
            config = self.generate_default_init_config_db()

        # update ZMQ config
        config = self.update_zmq_config(config)

        # update dns config
        config = self.update_dns_config(config)

        # Apply generic HwSku PORT table override if applicable
        port_override = self.generate_generic_hwsku_port_override()
        if port_override is not None:
            config_dict = json.loads(config)
            if isinstance(config_dict, dict):
                # Merge PORT table override into golden config
                for table_name, table_data in port_override.items():
                    if table_name in config_dict and isinstance(config_dict[table_name], dict):
                        config_dict[table_name].update(table_data)
                    else:
                        config_dict[table_name] = table_data
                config = json.dumps(config_dict, indent=4)

        # To enable bmp feature when the image version is >= 202411 and the device is not supervisor
        # Note: the Chassis supervisor is not holding any BGP sessions so the BMP feature is not needed
        if self.check_version_for_bmp() is True and device_info.is_supervisor() is False:
            if multi_asic.is_multi_asic():
                config = self.overwrite_feature_golden_config_db_multiasic(config, "frr_bmp", "disabled", "enabled")
                config = self.overwrite_feature_golden_config_db_multiasic(config, "bmp")
            else:
                config = self.overwrite_feature_golden_config_db_singleasic(config, "frr_bmp", "disabled", "enabled")
                config = self.overwrite_feature_golden_config_db_singleasic(config, "bmp")

        # Enable otel feature when docker-sonic-otel image exists
        if self.has_otel_image():
            config = self.overwrite_feature_golden_config_db_singleasic(config, "otel", "enabled", "enabled")

        # Disable dash-ha feature for all multi-asic platforms
        if multi_asic.is_multi_asic():
            config = self.overwrite_feature_golden_config_db_multiasic(config, "dash-ha", feature_data={
                "dash-ha": {
                    "auto_restart": "disabled",
                    "state": "disabled",
                    "has_per_asic_scope": "True",
                }
            })

        with open(GOLDEN_CONFIG_DB_PATH, "w") as temp_file:
            temp_file.write(config)
        with open(GOLDEN_CONFIG_DB_PATH_ORI, "w") as temp_file:
            temp_file.write(config)
        self.module.exit_json(change=True, msg=module_msg)


def main():
    generate_golden_config_db = GenerateGoldenConfigDBModule()
    generate_golden_config_db.generate()


if __name__ == '__main__':
    main()
