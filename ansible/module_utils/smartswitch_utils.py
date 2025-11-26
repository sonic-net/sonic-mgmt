common_cisco_hwsku_config = {
    "dpu_num": 8,
    "port_key": "Ethernet{}",
    "interface_key": "Ethernet{}|18.{}.202.0/31",
    "base": 224,
    "step": 8,
    "dpu_key": "dpu{}"
}

common_mellanox_hwsku_config = {
    "dpu_num": 4,
    "port_key": "Ethernet{}",
    "interface_key": "Ethernet{}|18.{}.202.0/31",
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
