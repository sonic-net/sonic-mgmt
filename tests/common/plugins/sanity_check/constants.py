
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
    "config_reload": {"cmd": "config reload -y", "reboot": False},
    "load_minigraph": {"cmd": "config load_minigraph -y", "reboot": False},
    "reboot": {"cmd": "reboot", "reboot": True},
    "warm_reboot": {"cmd": "warm-reboot", "reboot": True},
    "fast_reboot": {"cmd": "fast_reboot", "reboot": True}
}       # All supported recover methods

SUPPORTED_CHECK_ITEMS = ["services", "interfaces", "dbmemory"]          # Supported checks
