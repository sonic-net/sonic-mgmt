
DEFAULT_ASIC_ID = None
DEFAULT_NAMESPACE = None
NAMESPACE_PREFIX = 'asic'
ASIC_PARAM_TYPE_ALL = 'num_asics'
ASIC_PARAM_TYPE_FRONTEND = 'frontend_asics'
ASICS_PRESENT = 'asics_present'
RANDOM_SEED = 'random_seed'
CUSTOM_MSG_PREFIX = "sonic_custom_msg"
DUT_CHECK_NAMESPACE = "dut_check_result"

# Describe upstream neighbor of dut in different topos
UPSTREAM_NEIGHBOR_MAP = {
    "t0": "t1",
    "t1": "t2",
    "m0": "m1",
    "mx": "m0",
    "t2": "t3",
    "m0_vlan": "m1",
    "m0_l3": "m1"
}
# Describe downstream neighbor of dut in different topos
DOWNSTREAM_NEIGHBOR_MAP = {
    "t0": "server",
    "t1": "t0",
    "m0": "mx",
    "mx": "server",
    "t2": "t1",
    "m0_vlan": "server",
    "m0_l3": "mx"
}
