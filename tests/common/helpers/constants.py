
DEFAULT_ASIC_ID = None
DEFAULT_NAMESPACE = None
NAMESPACE_PREFIX = 'asic'
ASIC_PARAM_TYPE_ALL = 'num_asics'
ASIC_PARAM_TYPE_FRONTEND = 'frontend_asics'
ASICS_PRESENT = 'asics_present'
RANDOM_SEED = 'random_seed'
CUSTOM_MSG_PREFIX = "sonic_custom_msg"
DUT_CHECK_NAMESPACE = "dut_check_result"
PTF_TIMEOUT = 60

# Describe upstream neighbor of dut in different topos
UPSTREAM_NEIGHBOR_MAP = {
    "t0": "t1",
    "t1": "t2",
    "m1": "ma",
    "m0": "m1",
    "mx": "m0",
    "t2": "t3",
    "m0_vlan": "m1",
    "m0_l3": "m1",
    "ft2": "lt2",
    "lt2": "ut2",
    "t1-isolated-d128": "t0",
    "t1-isolated-d32": "t0",
}

# Describe ALL upstream neighbor of dut in different topos
UPSTREAM_ALL_NEIGHBOR_MAP = {
    "t0": ["t1", "pt0"],
    "t1": ["t2"],
    "m1": ["ma", "mb"],
    "m0": ["m1"],
    "mx": ["m0"],
    "t2": ["t3"],
    "m0_vlan": ["m1"],
    "m0_l3": ["m1"],
    'lt2': ['ut2'],
    'ft2': ['ut2']
}

# Describe downstream neighbor of dut in different topos
DOWNSTREAM_NEIGHBOR_MAP = {
    "t0": "server",
    "t1": "t0",
    "m1": "m0",
    "m0": "mx",
    "mx": "server",
    "t2": "t1, lt2",
    "m0_vlan": "server",
    "m0_l3": "mx",
    "ft2": "lt2",
    "lt2": "t1"
}

# Describe downstream neighbor of dut in different topos
DOWNSTREAM_ALL_NEIGHBOR_MAP = {
    "t0": ["server"],
    "t1": ["t0"],
    "m1": ["m0", "c0"],
    "m0": ["mx", "server"],
    "mx": ["server"],
    "t2": ["t1"],
    "m0_vlan": ["mx", "server"],
    "m0_l3": ["mx", "server"],
    "ft2": "lt2",
    "lt2": "t1"
}
