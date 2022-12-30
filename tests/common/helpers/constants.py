
DEFAULT_ASIC_ID = None
DEFAULT_NAMESPACE = None
NAMESPACE_PREFIX = 'asic'
ASIC_PARAM_TYPE_ALL = 'num_asics'
ASIC_PARAM_TYPE_FRONTEND = 'frontend_asics'
ASICS_PRESENT = 'asics_present'

# Describe upstream neighbor of dut in different topos
UPSTREAM_NEIGHBOR_MAP = {
    "t0": "t1",
    "t1": "t2",
    "m0": "m1",
    "t2": "t3"
}
# Describe downstream neighbor of dut in different topos
DOWNSTREAM_NEIGHBOR_MAP = {
    "t0": "server",
    "t1": "t0",
    "m0": "mx",
    "t2": "t1"
}
