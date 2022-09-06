
PRINT_LOGS = {
    "version": "show version",
    "images": "sonic_installer list",
    "docker": "docker ps -a",
    "interfaces": "show interface status",
    "ip": "show ip interface",
    "neigh": "ip neigh",
    "bgpv4": "show ip bgp summary",
    "bgpv6": "show ipv6 bgp summary",
    "routes": "ip route | wc -l",
    "mux_status": "show mux status",
    "mux_config": "show mux config",
}

# Check items for testbed infrastructure that are not
# controlled by the DUT
INFRA_CHECK_ITEMS = [
    "mux_simulator"
]

# Recover related definitions
RECOVER_METHODS = {
    "config_reload": {"cmd": "bash -c 'config reload -y &>/dev/null'", "reboot": False, "adaptive": False, 'recover_wait': 120},
    "config_reload_f": {"cmd": "bash -c 'config reload -f -y &>/dev/null'", "reboot": False, "adaptive": False, 'recover_wait': 120},
    "load_minigraph": {"cmd": "bash -c 'config load_minigraph -y &>/dev/null'", "reboot": False, "adaptive": False, 'recover_wait': 60},
    "reboot": {"cmd": "reboot", "reboot": True, "adaptive": False, 'recover_wait': 120},
    "warm_reboot": {"cmd": "warm-reboot", "reboot": True, "adaptive": False, 'recover_wait': 120},
    "fast_reboot": {"cmd": "fast_reboot", "reboot": True, "adaptive": False, 'recover_wait': 120},
    "adaptive": {"cmd": None, "reboot": False, "adaptive": True, 'recover_wait': 30},
}       # All supported recover methods

STAGE_PRE_TEST = 'stage_pre_test'
STAGE_POST_TEST = 'stage_post_test'
SANITY_CHECK_FAILED_RC = 10
