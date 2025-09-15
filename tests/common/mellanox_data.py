import functools
import pytest
import logging
logger = logging.getLogger(__name__)


SPC1_HWSKUS = ["ACS-MSN2700", "Mellanox-SN2700", "Mellanox-SN2700-D48C8", "ACS-MSN2740", "ACS-MSN2100", "ACS-MSN2410",
               "ACS-MSN2010", "ACS-SN2201", "Mellanox-SN2700-C28D8", "Mellanox-SN2700-A1-C28D8"]
SPC2_HWSKUS = ["ACS-MSN3700", "ACS-MSN3700C", "ACS-MSN3800", "Mellanox-SN3800-D112C8", "ACS-MSN3420"]
SPC3_HWSKUS = ["ACS-MSN4700", "Mellanox-SN4700-O28", "ACS-MSN4600C", "ACS-MSN4410", "ACS-MSN4600",
               "Mellanox-SN4600C-D112C8", "Mellanox-SN4600C-C64", "ACS-SN4280", "Mellanox-SN4280-O28",
               "Mellanox-SN4280-O8C40", "Mellanox-SN4280-C48", "Mellanox-SN4280-O8V40", "Mellanox-SN4280-O8C80"]
SPC4_HWSKUS = ["ACS-SN5600", "Mellanox-SN5600-V256", "Mellanox-SN5600-C256S1", "Mellanox-SN5600-C224O8",
               'Mellanox-SN5610N-C256S2', 'Mellanox-SN5610N-C224O8']
SPC5_HWSKUS = ["Mellanox-SN5640-C512S2", "Mellanox-SN5640-C448O16"]
SWITCH_HWSKUS = SPC1_HWSKUS + SPC2_HWSKUS + SPC3_HWSKUS + SPC4_HWSKUS + SPC5_HWSKUS

LOSSY_ONLY_HWSKUS = ['Mellanox-SN5600-C256S1', 'Mellanox-SN5600-C224O8', 'Mellanox-SN5640-C512S2',
                     'Mellanox-SN5640-C448O16']

PSU_CAPABILITIES = [
    ['psu{}_curr', 'psu{}_curr_in', 'psu{}_power', 'psu{}_power_in', 'psu{}_volt', 'psu{}_volt_in', 'psu{}_volt_out'],
    ['psu{}_curr', 'psu{}_curr_in', 'psu{}_power', 'psu{}_power_in', 'psu{}_volt', 'psu{}_volt_in', 'psu{}_volt_out2']
]
MULTI_HARDWARE_TYPE_PLATFORMS = ['x86_64-mlnx_msn4700-r0',
                                 'x86_64-mlnx_msn4410-r0',
                                 'x86_64-mlnx_msn4600c-r0',
                                 'x86_64-mlnx_msn3700-r0',
                                 'x86_64-mlnx_msn3700c-r0']
SWITCH_MODELS = {
    "x86_64-nvidia_sn5600-r0": {
        "chip_type": "spectrum4",
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
            "number": 6
        },
        "ports": {
            "number": 64
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 6
            },
            "module": {
                "start": 1,
                "number": 65
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
            },
            "pch": {
                "number": 1
            },
            "sodimm": {
                "start": 1,
                "number": 2
            }
        }
    },
    "x86_64-nvidia_sn5640-r0": {
        "chip_type": "spectrum5",
        "reboot": {
            "cold_reboot": True,
            "fast_reboot": True,
            "warm_reboot": True
        },
        "fans": {
            "number": 5,
            "hot_swappable": True
        },
        "psus": {
            "number": 4,
            "hot_swappable": True,
            "capabilities": PSU_CAPABILITIES[1]
        },
        "cpu_pack": {
            "number": 1
        },
        "cpu_cores": {
            "number": 0
        },
        "ports": {
            "number": 64
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 6
            },
            "module": {
                "start": 1,
                "number": 65
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
            },
            "pch": {
                "number": 1
            },
            "sodimm": {
                "start": 1,
                "number": 2
            }
        }
    },
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
            },
            "sodimm": {
                "start": 1,
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
            },
            "sodimm": {
                "start": 1,
                "number": 1
            }
        }
    },
    "x86_64-mlnx_msn2700a1-r0": {
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
            },
            "comex_ambient": {
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
            },
            "sodimm": {
                "start": 1,
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
            },
            "sodimm": {
                "start": 1,
                "number": 2
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
            },
            "sodimm": {
                "start": 1,
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
    "x86_64-nvidia_sn4280-r0": {
        "chip_type": "spectrum3",
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
            "number": 0
        },
        "ports": {
            "number": 32
        },
        "thermals": {
            "cpu_core": {
                "start": 0,
                "number": 0
            },
            "module": {
                "start": 1,
                "number": 28
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
    "x86_64-nvidia_sn4280_simx-r0": {
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
                "number": 0
            },
            "cpu_cores": {
                "number": 0
            },
            "ports": {
                "number": 32
            },
            "thermals": {
                "cpu_core": {
                    "start": 0,
                    "number": 0
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
                    "number": 0
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
    "x86_64-mlnx_msn4700_simx-r0": {
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
                "number": 0
            },
            "cpu_cores": {
                "number": 0
            },
            "ports": {
                "number": 32
            },
            "thermals": {
                "cpu_core": {
                    "start": 0,
                    "number": 0
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
                    "number": 0
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


def read_only_cache():
    """Decorator to cache return value for a method/function once.
       This decorator should be used for method/function when:
       1. Executing the method/function takes time. e.g. reading sysfs.
       2. The return value of this method/function never changes.
    """
    def decorator(method):
        method.return_value = None

        @functools.wraps(method)
        def _impl(*args, **kwargs):
            if not method.return_value:
                method.return_value = method(*args, **kwargs)
            return method.return_value
        return _impl
    return decorator


@read_only_cache()
def is_mellanox_device(dut):
    return dut.facts["asic_type"] == "mellanox"


@read_only_cache()
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


@read_only_cache()
def get_hardware_version(duthost, platform):
    if platform in MULTI_HARDWARE_TYPE_PLATFORMS:
        config1 = duthost.command('cat /run/hw-management/system/config1', module_ignore_errors=True)
        config3 = duthost.command('cat /run/hw-management/system/config3', module_ignore_errors=True)
        if platform in ('x86_64-mlnx_msn4700-r0', 'x86_64-mlnx_msn4410-r0'):
            return 'a1' if config1['rc'] == 0 and config1['stdout'] == '1' else ''
        elif platform == 'x86_64-mlnx_msn4600c-r0':
            if config1['rc'] == 0:
                if config1['stdout'] == '1':
                    if config3['rc'] == 0 and config3['stdout'] == '1':
                        return 'a1-respined'
                    else:
                        return 'a1'
                else:
                    if config3['rc'] == 0 and config3['stdout'] == '1':
                        return 'respined'
            return ''
        elif platform in ('x86_64-mlnx_msn3700-r0', 'x86_64-mlnx_msn3700c-r0'):
            if config1['rc'] == 0 and (config1['stdout'] == '2' or config1['stdout'] == '6'):
                return 'swb-respined'
            if config3['rc'] == 0 and config3['stdout'] == '1':
                return 'respined'
            return ''
    else:
        return ''


@read_only_cache()
def get_hw_management_version(duthost):
    full_version = duthost.shell('dpkg-query --showformat=\'${Version}\' --show hw-management')['stdout']
    return full_version[len('1.mlnx.'):]


def is_innolight_cable(port_info):
    """ Check if the given port info indicates an Innolight cable and handle known issues """
    return 'PINEWAVE' in port_info.get('manufacturer', '')


def is_unsupported_module(port_info, port_number):
    if is_innolight_cable(port_info):
        logger.info(f"Port {port_number} has an unsupported module, skipping it and continue to check other ports")
        return True
    return False


def skip_on_unsupported_module():
    pytest.skip("All ports are with unsupported modules, skipping the test due to Github issue #21878")


def is_cmis_version_supported(cmis_version, min_required_version=5.0, failed_api_ports=None, port_name=None):
    """
    Check if a CMIS version supports a specific feature by comparing it to a minimum required version
    @param: cmis_version: CMIS version string (e.g., "5.0", "4.0", etc.)
    @param: min_required_version: Minimum required CMIS version (default: 5.0)
    @param: failed_api_ports: List to append failed ports to (optional)
    @param: port_name: Port name to append to failed list if version check fails (optional)
    @return: bool: True if CMIS version is supported, False otherwise
    """
    try:
        cmis_version_float = float(cmis_version)
        return cmis_version_float >= min_required_version
    except (ValueError, TypeError):
        if failed_api_ports is not None and port_name is not None:
            failed_api_ports.append(port_name)
        return False


def get_supported_available_optical_interfaces(eeprom_infos, parsed_presence,
                                               min_cmis_version=5.0, return_failed_api_ports=False):
    """
    Filter available optical interfaces based on presence, EEPROM detection, media type, and CMIS version support
    @param: eeprom_infos: Dictionary containing EEPROM information for each port
    @param: parsed_presence: Dictionary containing presence status for each port
    @param: min_cmis_version: Minimum required CMIS version (default: 5.0)
    @param: return_failed_api_ports: If True, return both available_optical_interfaces and failed_api_ports.
                                     If False, return only available_optical_interfaces (default: False)
    @return: list or tuple: If return_failed_api_ports=False, returns list of available optical interface names. 
                            If return_failed_api_ports=True, returns (available_optical_interfaces, failed_api_ports)
    """
    available_optical_interfaces = []
    failed_api_ports = []

    for port_name, eeprom_info in eeprom_infos.items():
        if parsed_presence.get(port_name) != "Present":
            continue
        if "SFP EEPROM detected" not in eeprom_info[port_name]:
            continue
        media_technology = eeprom_info.get("Media Interface Technology", "N/A").upper()
        if "COPPER" in media_technology:
            continue
        if "N/A" in media_technology:
            failed_api_ports.append(port_name)
            continue
        cmis_version = eeprom_info.get("CMIS Revision", "N/A")
        if "N/A" in cmis_version:
            failed_api_ports.append(port_name)
            continue
        elif not is_cmis_version_supported(cmis_version, min_cmis_version, failed_api_ports, port_name):
            logging.info(f"Port {port_name} skipped: CMIS not supported on this port.")
            continue

        available_optical_interfaces.append(port_name)

    if return_failed_api_ports:
        return available_optical_interfaces, failed_api_ports
    else:
        return available_optical_interfaces
