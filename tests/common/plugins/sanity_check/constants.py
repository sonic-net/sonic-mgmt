
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
    "config_reload": {"cmd": "config reload -y", "reboot": False, "adaptive": False},
    "load_minigraph": {"cmd": "config load_minigraph -y", "reboot": False, "adaptive": False},
    "reboot": {"cmd": "reboot", "reboot": True, "adaptive": False},
    "warm_reboot": {"cmd": "warm-reboot", "reboot": True, "adaptive": False},
    "fast_reboot": {"cmd": "fast_reboot", "reboot": True, "adaptive": False},
    "adaptive": {"cmd": None, "reboot": False, "adaptive": True},
}       # All supported recover methods

SUPPORTED_CHECK_ITEMS = ["services", "interfaces", "dbmemory"]          # Supported checks
