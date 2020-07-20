
SPC1_HWSKUS = ["ACS-MSN2700", "Mellanox-SN2700", "Mellanox-SN2700-D48C8", "ACS-MSN2740", "ACS-MSN2100", "ACS-MSN2410", "ACS-MSN2010"]
SPC2_HWSKUS = ["ACS-MSN3700", "ACS-MSN3700C", "ACS-MSN3800", "Mellanox-SN3800-D112C8", "ACS-MSN3420"]
SPC3_HWSKUS = ["ACS-MSN4700", "ACS-MSN4600C"]
SWITCH_HWSKUS = SPC1_HWSKUS + SPC2_HWSKUS + SPC3_HWSKUS

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
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
        }
    },
    "Mellanox-SN2700": {
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
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
        }
    },
    "Mellanox-SN2700-D48C8": {
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
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN2740": {
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
        },
        "cpu_pack": {
            "number": 0
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
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
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 56
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 56
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN2010": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 4,
            "hot_swappable": False
        },
        "psus": {
            "number": 2,
            "hot_swappable": False
        },
        "cpu_pack": {
            "number": 0
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 22
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 22
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN2100": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 4,
            "hot_swappable": False
        },
        "psus": {
            "number": 2,
            "hot_swappable": False
        },
        "cpu_pack": {
            "number": 0
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 16
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 16
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN3800": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 3,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 64
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 64
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "gearbox": {
                "start": 1,
                "number": 32
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    },
    "Mellanox-SN3800-D112C8": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 3,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 64
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 64
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "gearbox": {
                "start": 1,
                "number": 32
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN3700": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 6,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN3700C": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 4,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN4700": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 6,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 4
            },
            "module": {
                "start": 1,
                "number": 32
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN4600C": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 1,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 4
        },
        "ports": {
            "number": 64
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 60
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    },
    "ACS-MSN3420": {
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": False,
            "warm_reboot": True
        },
        "fans": {
            "number": 5,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 60
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 1,
                "number": 60
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "asic_ambient": {
                "number": 1
            },
            "port_ambient": {
                "number": 1
            },
            "fan_ambient": {
                "number": 1
            },
            "comex_ambient": {
                "number": 1
            }
        }
    }
}

def is_mellanox_device(dut):
    return dut.facts["asic_type"] == "mellanox"
