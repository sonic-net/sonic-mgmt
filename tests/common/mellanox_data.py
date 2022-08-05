
SPC1_HWSKUS = ["ACS-MSN2700", "Mellanox-SN2700", "Mellanox-SN2700-D48C8", "ACS-MSN2740", "ACS-MSN2100", "ACS-MSN2410",
               "ACS-MSN2010", "ACS-SN2201"]
SPC2_HWSKUS = ["ACS-MSN3700", "ACS-MSN3700C", "ACS-MSN3800", "Mellanox-SN3800-D112C8", "ACS-MSN3420"]
SPC3_HWSKUS = ["ACS-MSN4700", "ACS-MSN4600C", "ACS-MSN4410", "ACS-MSN4600", "Mellanox-SN4600C-D112C8", "Mellanox-SN4600C-C64"]
SWITCH_HWSKUS = SPC1_HWSKUS + SPC2_HWSKUS + SPC3_HWSKUS

PSU_CAPABILITIES = [
    ['psu{}_curr', 'psu{}_curr_in', 'psu{}_power', 'psu{}_power_in', 'psu{}_volt', 'psu{}_volt_in', 'psu{}_volt_out'],
    ['psu{}_curr', 'psu{}_curr_in', 'psu{}_power', 'psu{}_power_in', 'psu{}_volt', 'psu{}_volt_out2']
]
SWITCH_MODELS = {
    "x86_64-nvidia_sn2201-r0": {
        "chip_type": "spectrum1",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 2
        },
        "ports": {
            "number": 52
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 2
            },
            "module": {
                "start": 49,
                "number": 4
            },
            "psu": {
                "start": 1,
                "number": 2
            },
            "cpu_pack": {
                "number": 1
            },
            "cpu_ambient": {
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
    "x86_64-mlnx_msn2700-r0": {
        "chip_type": "spectrum1",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[0]
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
    "x86_64-mlnx_msn2740-r0": {
        "chip_type": "spectrum1",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[0]
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
    "x86_64-mlnx_msn2410-r0": {
        "chip_type": "spectrum1",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[0]
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
    "x86_64-mlnx_msn2010-r0": {
        "chip_type": "spectrum1",
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
    "x86_64-mlnx_msn2100-r0": {
        "chip_type": "spectrum1",
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
    "x86_64-mlnx_msn3800-r0": {
        "chip_type": "spectrum2",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-mlnx_msn3700-r0": {
        "chip_type": "spectrum2",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-mlnx_msn3700c-r0": {
        "chip_type": "spectrum2",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-mlnx_msn4700-r0": {
        "chip_type": "spectrum3",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-mlnx_msn4600c-r0": {
        "chip_type": "spectrum3",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-mlnx_msn3420-r0": {
        "chip_type": "spectrum2",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[0]
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
    },
    "x86_64-mlnx_msn4410-r0": {
        "chip_type": "spectrum3",
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
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-mlnx_msn4600-r0": {
        "chip_type": "spectrum3",
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 3,
            "hot_swappable": True
        },
        "psus": {
            "number": 2,
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
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
    "x86_64-nvidia_sn4800-r0": {
        "chip_type": "spectrum3",
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 6,
            "hot_swappable": True
        },
        "psus": {
            "number": 4,
            "hot_swappable": True
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 6
        },
        "ports": {
            "number": 0
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 6
            },
            "psu": {
                "start": 1,
                "number": 4
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
    }
}


def is_mellanox_device(dut):
    return dut.facts["asic_type"] == "mellanox"


def get_platform_data(dut):
    """
    Get the platform physical data for the given dut object
    :param dut: dut object
    :return: A dictionary contains the platform physical data
    """
    dut_platform = dut.facts["platform"]
    return SWITCH_MODELS[dut_platform]


def get_chip_type(dut):
    platform_data = get_platform_data(dut)
    return platform_data.get("chip_type")
