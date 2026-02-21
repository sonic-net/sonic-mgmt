import functools
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sed_password_helper import SED_Change_Password_General

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
NO_QOS_HWSKUS = []

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
    "x86_64-nvidia_sn5600_simx-r0": {
        "chip_type": "spectrum4"
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
    "x86_64-mlnx_msn2700_simx-r0": {
        "chip_type": "spectrum1"
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


class SED_Change_Password_Mellanox(SED_Change_Password_General):
    PRIMARY_SED_TPM_BANK = '0x81010001'
    SECONDARY_SED_TPM_BANK = '0x81010002'
    THIRD_SED_TPM_BANK = '0x81010003'
    SED_AUTH_PASS = (
        "$(dd if=/sys/firmware/efi/efivars/TpmSealCtx-36bfcbde-d710-4903-ba2e-c03ec245dcee "
        "bs=1 skip=4 2>/dev/null | base64 -d)"
    )

    MINIMAL_PASSWORD_LENGTH = 8
    MAXIMUM_PASSWORD_LENGTH = 124

    def get_disk_name(self, duthost):
        """
        Return The disk device path
        """
        result = duthost.shell("sudo sedutil-cli --scan", module_ignore_errors=True)
        pytest_assert(result['rc'] == 0, f"Failed to scan for SED disks: {result['stderr']}")

        output = result['stdout']
        if '/dev/' in output:
            # Find /dev/xxx pattern
            start = output.find("/dev/")
            if start != -1:
                end = output.find(" ", start)
                if end != -1:
                    return output[start:end]
                return output[start:].split()[0]

        pytest_assert(False, "Cannot find SED-enabled disk device")

    def verify_default_pass(self, duthost, localhost, verify_sed_pass_works):
        """
        Verify that the default SED password is set correctly.
        """
        real_default_pass = self.get_sed_pass_from_tpm_bank(duthost, self.THIRD_SED_TPM_BANK)

        if (not self.verify_pass_saved(duthost, real_default_pass) or
                not self.verify_sed_pass_works(duthost, real_default_pass)):
            logger.warning(
                "TPM banks/SED password mismatch with the default SED password. "
                "Attempting cold reboot to recover."
            )
            from tests.common.reboot import reboot
            reboot(duthost, localhost, reboot_type='cold', safe_reboot=True)
            raise Exception("TPM banks/SED password mismatch with the default SED password.")

        return real_default_pass

    def set_sed_pass_in_tpm_bank(self, duthost, tpm_bank, password):
        """
        Store a new SED password in the specified TPM bank.
        """
        logger.info(f"Setting SED password in TPM bank {tpm_bank}")
        tpm_create_cmd = (
            f'echo "{password}" | sudo tpm2_create -g sha256 -u seal.pub -r seal.priv '
            f'-C prim.ctx -p "{self.SED_AUTH_PASS}" -i - > /dev/null 2>&1'
        )
        commands = [
            'sudo rm -f seal.* prim.ctx',
            f'sudo tpm2_evictcontrol -C o -c "{tpm_bank}" > /dev/null 2>&1',
            'sudo tpm2_createprimary -C o --key-algorithm=rsa --key-context=prim.ctx > /dev/null 2>&1',
            tpm_create_cmd,
            'sudo tpm2_load -C prim.ctx -u seal.pub -r seal.priv -n seal.name -c seal.ctx',
            f'sudo tpm2_evictcontrol -C o -c seal.ctx "{tpm_bank}"',
            'sudo rm -f seal.* prim.ctx',
        ]
        for command in commands:
            result = duthost.shell(command, module_ignore_errors=True)
            pytest_assert(
                result['rc'] == 0,
                f"Failed to execute command: {command}\nError: {result['stderr']}"
            )

    def get_primary_sed_tpm_bank(self):
        return self.PRIMARY_SED_TPM_BANK

    def get_sed_pass_from_tpm_bank(self, duthost, tpm_bank):
        """
        Retrieve the SED password from the specified TPM bank.
        """
        result = duthost.shell(
            f"sudo tpm2_unseal -c '{tpm_bank}' -p \"{self.SED_AUTH_PASS}\"",
            module_ignore_errors=True
        )
        if result['rc'] == 0:
            return result['stdout'].strip()
        logger.warning(
            f"Failed to get SED password from TPM bank {tpm_bank}: {result['stderr']}"
        )
        return None

    def verify_pass_saved(self, duthost, expected_pass):
        """
        Verify that both TPM banks (primary and secondary) have the expected password.
        """
        logger.info(f"Verifying TPM banks have password: {expected_pass}")

        password_primary = self.get_sed_pass_from_tpm_bank(duthost, self.PRIMARY_SED_TPM_BANK)
        assert password_primary == expected_pass, (
            f"Primary TPM bank password mismatch. Expected: '{expected_pass}', "
            f"Got: '{password_primary}'"
        )

        password_secondary = self.get_sed_pass_from_tpm_bank(
            duthost, self.SECONDARY_SED_TPM_BANK
        )
        assert password_secondary == expected_pass, (
            f"Secondary TPM bank password mismatch. Expected: '{expected_pass}', "
            f"Got: '{password_secondary}'"
        )
        return True

    def get_min_and_max_pass_len(self, duthost):
        """
        Get the minimal and maximum password length for Mellanox devices.
        """
        return (self.MINIMAL_PASSWORD_LENGTH, self.MAXIMUM_PASSWORD_LENGTH)

    def verify_sed_pass_change_feature_enabled(self, duthost):
        """Verify SED password change feature is enabled.
            1. Check SED-enabled NVME disk exists
            2. Check LockingEnabled=Y
            3. Check both TPM banks configured
            Skips test if not.
        """
        logger.info("Check SED-enabled NVME disk exists")
        scan = duthost.shell("sedutil-cli --scan | grep -q '/dev/nvme'", module_ignore_errors=True)
        if scan['rc'] != 0:
            pytest.skip("No SED-enabled NVME disk found")

        logger.info("Check LockingEnabled=Y")
        disk = self.get_disk_name(duthost)
        locking = duthost.shell(f"sedutil-cli --query {disk} | grep 'LockingEnabled = Y'",
                                module_ignore_errors=True)
        if locking['rc'] != 0:
            pytest.skip("SED LockingEnabled is not Y")

        logger.info("Check both TPM banks configured")
        tpm = duthost.shell("tpm2_getcap handles-persistent", module_ignore_errors=True)
        if tpm['rc'] != 0:
            pytest.skip("Failed to query TPM handles")

        if any(bank not in tpm['stdout'] for bank in (
            self.PRIMARY_SED_TPM_BANK,
            self.SECONDARY_SED_TPM_BANK,
            self.THIRD_SED_TPM_BANK
        )):
            pytest.skip("Required TPM banks not configured")
