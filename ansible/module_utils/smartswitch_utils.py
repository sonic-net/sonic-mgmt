common_cisco_hwsku_config = {
    "dpu_num": 8,
    "port_key": "Ethernet{}",
    "base": 224,
    "step": 8,
    "dpu_key": "dpu{}"
}

common_mellanox_hwsku_config = {
    "dpu_num": 4,
    "port_key": "Ethernet{}",
    "base": 224,
    "step": 8,
    "dpu_key": "dpu{}"
}

smartswitch_hwsku_config = {
    # Cisco SKUs
    hwsku: common_cisco_hwsku_config.copy() for hwsku in [
        "Cisco-8102-28FH-DPU-O",
        "Cisco-8102-28FH-DPU-C28",
        "Cisco-8102-28FH-DPU-O8C20",
        "Cisco-8102-28FH-DPU-O12C16",
        "Cisco-8102-28FH-DPU-O8C40",
        "Cisco-8102-28FH-DPU-O8V40"
    ]
}

# Mellanox SKUs
smartswitch_hwsku_config.update({
    "Mellanox-SN4280-O28": common_mellanox_hwsku_config.copy(),
    "Mellanox-SN4280-O8C40": common_mellanox_hwsku_config.copy()
})

# VLAN configuration for NPU-DPU dataplane connectivity.
# Both NPUs use Vlan55 with different subnets: NPU 0 → 20.0.200.0/24, NPU 1 → 20.0.201.0/24 (HA testbeds).
smartswitch_vlan_config = {
    0: {
        "vlan_name": "Vlan55",
        "vlanid": "55",
        "vlan_interface_ip": "20.0.200.254/24",
        "dpu_ip_prefix": "20.0.200.",
    },
    1: {
        "vlan_name": "Vlan55",
        "vlanid": "55",
        "vlan_interface_ip": "20.0.201.254/24",
        "dpu_ip_prefix": "20.0.201.",
    }
}
