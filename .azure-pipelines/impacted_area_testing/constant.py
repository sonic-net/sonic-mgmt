# Now, we only have below types of PR checker
# - dpu
# - dualtor-t0
# - multi-asic-t1-lag
# - t0
# - t0-2vlans
# - t0-sonic
# - t1- lag
PR_TOPOLOGY_TYPE = ["t0", "t0-2vlans", "t0-sonic", "t1", "t1-multi-asic", "dpu", "dualtor"]

EXCLUDE_TEST_SCRIPTS = [
    "test_posttest.py",
    "test_pretest.py"
]

# The mapping of topology type in PR test and topology recorded in kusto and the name of PR test.
PR_CHECKER_TOPOLOGY_NAME = {
    "t0": ["t0", "_kvmtest-t0_"],
    "t0-2vlans": ["t0", "_kvmtest-t0-2vlans_"],
    "t0-sonic": ["t0-64-32", "_kvmtest-t0-sonic_"],
    "t1": ["t1-lag", "_kvmtest-t1-lag_"],
    "t1-multi-asic": ["t1-8-lag", "_kvmtest-multi-asic-t1-lag_"],
    "dpu": ["dpu", "_kvmtest-dpu_"],
    "dualtor": ["dualtor", "_kvmtest-dualtor-t0_"]
}

MAX_INSTANCE_NUMBER = 25
