
SPC1_HWSKUS = ["ACS-MSN2700", "Mellanox-SN2700", "Mellanox-SN2700-D48C8", "ACS-MSN2740", "ACS-MSN2100", "ACS-MSN2410", "ACS-MSN2010"]
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
            "warm_reboot": False
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
            "warm_reboot": False
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
            "warm_reboot": False
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
    }
}

THERMAL_NAMING_RULE = {
    "cpu_core": {
        "name": "CPU Core {} Temp",
        "temperature": "cpu_core{}",
        "high_threshold": "cpu_core{}_max",
        "high_critical_threshold": "cpu_core{}_crit"
    },
    "module": {
        "name": "xSFP module {} Temp",
        "temperature": "module{}_temp_input",
        "high_threshold": "module{}_temp_crit",
        "high_critical_threshold": "module{}_temp_emergency"
    },
    "psu": {
        "name": "PSU-{} Temp",
        "temperature": "psu{}_temp",
        "high_threshold": "psu{}_temp_max"
    },
    "cpu_pack": {
        "name": "CPU Pack Temp",
        "temperature": "cpu_pack",
        "high_threshold": "cpu_pack_max",
        "high_critical_threshold": "cpu_pack_crit"
    },
    "gearbox": {
        "name": "CPU Pack Temp",
        "temperature": "temp_input_gearbox{}"
    },
    "asic_ambient": {
        "name": "Ambient ASIC Temp",
        "temperature": "asic"
    },
    "port_ambient": {
        "name": "Ambient Port Side Temp",
        "temperature": "port_amb"
    },
    "fan_ambient": {
        "name": "Ambient Fan Side Temp",
        "temperature": "fan_amb"
    },
    "comex_ambient": {
        "name": "Ambient COMEX Temp",
        "temperature": "comex_amb"
    },
    "board_ambient": {
        "name": "Ambient Board Temp",
        "temperature": "board_amb"
    }
}

FAN_NAMING_RULE = {
    "fan": {
        "name": "fan{}",
        "speed": "fan{}_speed_get",
        "presence": "fan{}_status",
        "target_speed": "fan{}_speed_set",
        "max_speed": "fan{}_max",
        "status": "fan{}_fault",
        "led_capability": "led_fan{}_capability",
        "led_green": "led_fan{}_green",
        "led_red": "led_fan{}_red",
        "led_orange": "led_fan{}_orange"
    },
    "psu_fan": {
        "name": "psu_{}_fan_1",
        "speed": "psu{}_fan1_speed_get",
        "power_status": "psu{}_pwr_status"
    }
}

