# Now, we only have below types of PR checker
# - dpu
# - dualtor-t0
# - multi-asic-t1-lag
# - t0
# - t0-2vlans
# - t0-sonic
# - t1- lag
PR_TOPOLOGY_TYPE = ["t0_checker", "t0-2vlans_checker", "t0-sonic_checker", "t1_checker",
                    "t1-multi-asic_checker", "dpu_checker", "dualtor_checker", "t2_checker"]

EXCLUDE_TEST_SCRIPTS = [
    "test_posttest.py",
    "test_pretest.py"
]

# The mapping of topology type in PR test and topology recorded in kusto and the name of PR test.
PR_CHECKER_TOPOLOGY_NAME = {
    "t0": ["t0", "kvmtest-t0_"],
    "t0-2vlans": ["t0", "kvmtest-t0-2vlans_"],
    "t0-sonic": ["t0-64-32", "kvmtest-t0-sonic_"],
    "t1": ["t1-lag", "kvmtest-t1-lag_"],
    "t1-multi-asic": ["t1-8-lag", "kvmtest-multi-asic-t1-lag_"],
    "dpu": ["dpu", "kvmtest-dpu_"],
    "dualtor": ["dualtor", "kvmtest-dualtor-t0_"],
    "t2": ["t2", "kvmtest-t2_"]
}

MAX_INSTANCE_NUMBER = 40
MAX_GET_TOKEN_RETRY_TIMES = 3
