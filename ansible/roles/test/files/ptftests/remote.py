"""
Remote platform

This platform uses physical ethernet interfaces.
"""

# Update this dictionary to suit your environment.
remote_port_map = {
    (0, 0) : "eth0",
    (0, 1) : "eth1",
    (0, 2) : "eth2",
    (0, 3) : "eth3",
    (0, 4) : "eth4",
    (0, 5) : "eth5",
    (0, 6) : "eth6",
    (0, 7) : "eth7",
    (0, 8) : "eth8",
    (0, 9) : "eth9",
    (0, 10) : "eth10",
    (0, 11) : "eth11",
    (0, 12) : "eth12",
    (0, 13) : "eth13",
    (0, 14) : "eth14",
    (0, 15) : "eth15",
    (0, 16) : "eth16",
    (0, 17) : "eth17",
    (0, 18) : "eth18",
    (0, 19) : "eth19",
    (0, 20) : "eth20",
    (0, 21) : "eth21",
    (0, 22) : "eth22",
    (0, 23) : "eth23",
    (0, 24) : "eth24",
    (0, 25) : "eth25",
    (0, 26) : "eth26",
    (0, 27) : "eth27",
    (0, 28) : "eth28",
    (0, 29) : "eth29",
    (0, 30) : "eth30",
    (0, 31) : "eth31",
    (0, 32) : "eth32",
    (0, 33) : "eth33",
    (0, 34) : "eth34",
    (0, 35) : "eth35",
    (0, 36) : "eth36",
    (0, 37) : "eth37",
    (0, 38) : "eth38",
    (0, 39) : "eth39",
    (0, 40) : "eth40",
    (0, 41) : "eth41",
    (0, 42) : "eth42",
    (0, 43) : "eth43",
    (0, 44) : "eth44",
    (0, 45) : "eth45",
    (0, 46) : "eth46",
    (0, 47) : "eth47",
    (0, 48) : "eth48",
    (0, 49) : "eth49",
    (0, 50) : "eth50",
    (0, 51) : "eth51",
    (0, 52) : "eth52",
    (0, 53) : "eth53",
    (0, 54) : "eth54",
    (0, 55) : "eth55",
    (0, 56) : "eth56",
    (0, 57) : "eth57",
    (0, 58) : "eth58",
    (0, 59) : "eth59",
    (0, 60) : "eth60",
    (0, 61) : "eth61",
    (0, 62) : "eth62",
    (0, 63) : "eth63",    
}

def platform_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    """
    global remote_port_map
    config["port_map"] = remote_port_map.copy()
    config["caps_table_idx"] = 0

