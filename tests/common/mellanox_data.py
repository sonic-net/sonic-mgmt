
SPC1_HWSKUS = ["ACS-MSN2700", "Mellanox-SN2700", "ACS-MSN2740", "ACS-MSN2100", "ACS-MSN2410", "ACS-MSN2010"]
SPC2_HWSKUS = ["ACS-MSN3700", "ACS-MSN3700C", "ACS-MSN3800"]
SWITCH_HWSKUS = SPC1_HWSKUS + SPC2_HWSKUS

SWITCH_MODELS = {
    "ACS-MSN2700": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 4,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    },
    "ACS-MSN2740": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 4,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    },
    "ACS-MSN2410": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 4,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    },
    "ACS-MSN2010": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 4,
            "hot_swappable": False
        },
        "psus": {
            "number": 2,
            "hot_swappable": False
        }
    },
    "ACS-MSN2100": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 4,
            "hot_swappable": False
        },
        "psus": {
            "number": 2,
            "hot_swappable": False
        }
    },
    "ACS-MSN3800": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 3,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    },
    "ACS-MSN3700": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 6,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    },
    "ACS-MSN3700C": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 4,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    },
    "ACS-MSN3510": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": False
        },
        "fans": {
            "number": 6,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        }
    }
}
