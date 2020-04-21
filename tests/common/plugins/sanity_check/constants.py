
PRINT_LOGS = {
    "version": "show version",
    "images": "sonic_installer list",
    "docker": "docker ps -a",
    "interfaces": "show interface status",
    "ip": "show ip interface",
    "neigh": "ip neigh",
    "bgp": "show bgp summary",
    "routes": "ip route | wc -l"
}

# Recover related definitions
RECOVER_METHODS = {
    "config_reload": {"cmd": "config reload -y", "reboot": False, "adaptive": False, 'recover_wait': 60},
    "load_minigraph": {"cmd": "config load_minigraph -y", "reboot": False, "adaptive": False, 'recover_wait': 60},
    "reboot": {"cmd": "reboot", "reboot": True, "adaptive": False, 'recover_wait': 120},
    "warm_reboot": {"cmd": "warm-reboot", "reboot": True, "adaptive": False, 'recover_wait': 120},
    "fast_reboot": {"cmd": "fast_reboot", "reboot": True, "adaptive": False, 'recover_wait': 120},
    "adaptive": {"cmd": None, "reboot": False, "adaptive": True, 'recover_wait': 30},
}       # All supported recover methods

SUPPORTED_CHECK_ITEMS = ["services", "interfaces", "dbmemory"]          # Supported checks
