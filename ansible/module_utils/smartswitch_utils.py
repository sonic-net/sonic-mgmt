common_hwsku_config = {
    "dpu_num": {},
    "port_key": "Ethernet{}",
    "interface_key": "Ethernet{}|18.{}.202.0/31",
    "base": 224,
    "step": 8
}

smartswitch_hwsku_config = {
    hwsku: common_hwsku_config.copy() for hwsku in [
        "Cisco-8102-28FH-DPU-O",
        "Cisco-8102-28FH-DPU-C28",
        "Cisco-8102-28FH-DPU-O8C20",
        "Cisco-8102-28FH-DPU-O12C16",
        "Cisco-8102-28FH-DPU-O8C40",
        "Cisco-8102-28FH-DPU-O8V40",
    ]
}
