
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

# Canonical default config path for the PTF arp_responder helper
# (ansible/roles/test/files/helpers/arp_responder.py and tests/scripts/arp_responder.py).
# It is the argparse default for the responder's --conf flag, so any test fixture that
# pre-renders the responder config without overriding --conf must write to exactly this
# path on the PTF. Use this constant in test-side code instead of hardcoding the literal
# so the canonical value lives in one place.
ARP_RESPONDER_DEFAULT_CONFIG = "/tmp/from_t1.json"

# Per-suffix variant used by the advanced-reboot family of tests when a logfile suffix
# differentiates one run's responder config from another (e.g. preboot/inboot operations).
# The format takes a single %s placeholder for the suffix and is consumed both inside the
# PTF runner (ansible/roles/test/files/ptftests/py3/advanced-reboot.py) and by the host-
# side fixture that passes `-c <path>` to the responder. Update both sides together if
# the file naming scheme ever changes; the PTF runner keeps a module-local mirror.
ARP_RESPONDER_PER_SUFFIX_CONFIG_FMT = "/tmp/from_t1_%s.json"

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
    "c0": "m1"
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
    "c0": ["m1"],
    'ft2': ['lt2']
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
    "t2": ["t1", "lt2"],
    "m0_vlan": ["mx", "server"],
    "m0_l3": ["mx", "server"],
    "ft2": ["lt2"],
    "lt2": ["t1"]
}
