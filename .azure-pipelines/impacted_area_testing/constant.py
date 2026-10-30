# Now, we only have below types of PR checker
# - dpu
# - dualtor-t0
# - dualtor-aa-vpp
# - multi-asic-t1-lag
# - t0
# - t0-2vlans
# - t0-sonic
# - t0-vpp
# - t1-lag
# - t1-lag-vpp
PR_TOPOLOGY_TYPE = ["t0_checker", "t0-2vlans_checker", "t0-sonic_checker", "t0-vpp_checker",
                    "t1_checker", "t1-multi-asic_checker", "t1-lag-vpp_checker", "dpu_checker",
                    "dualtor_checker", "dualtor-aa-vpp_checker", "t2_checker"]

EXCLUDE_TEST_SCRIPTS = [
    "test_posttest.py",
    "test_pretest.py"
]

# The mapping of topology type in PR test and topology recorded in kusto and the name of PR test.
PR_CHECKER_TOPOLOGY_NAME = {
    "t0": ["t0", "kvmtest-t0_"],
    "t0-2vlans": ["t0", "kvmtest-t0-2vlans_"],
    "t0-sonic": ["t0-64-32", "kvmtest-t0-sonic_"],
    "t0-vpp": ["t0-vpp", "kvmtest-t0-vpp_"],
    "t1": ["t1-lag", "kvmtest-t1-lag_"],
    "t1-multi-asic": ["t1-8-lag", "kvmtest-multi-asic-t1-lag_"],
    "t1-lag-vpp": ["t1-lag-vpp", "kvmtest-t1-lag-vpp_"],
    "dpu": ["dpu", "kvmtest-dpu_"],
    "dualtor": ["dualtor", "kvmtest-dualtor-t0_"],
    "dualtor-aa-vpp": ["dualtor-aa-vpp", "kvmtest-dualtor-aa-vpp_"],
    "t2": ["t2", "kvmtest-t2_"]
}

# Dedup rules: for each (keep_in, remove_from) pair, control-plane tests
# that appear in both checkers will be removed from 'remove_from'.
# Data-plane tests (detected automatically via traffic-pattern scanning)
# are always kept in both.
# Rules are evaluated against the *original* checker contents
# (order-independent).
# Only PR builds apply these rules (get_test_scripts.py --dedup-control-plane);
# the baseline keeps every script.
# A rule is skipped unless INCLUDE_JOBS enables a job in PR_CHECKER_JOBS for
# its keep_in checker, so a script is never dropped in favour of a job that
# will not run.
#
# To extend: add more pairs to cover additional topology overlaps,
# e.g. ("t1_checker", "t2_checker") once t2 tests are stable.
CONTROL_PLANE_DEDUP_RULES = [
    ("t0_checker", "t1_checker"),
]

# The multi-asic-t1 job also reads t1_checker, but the dedup only targets the
# t1-lag job. When the dedup removes scripts from t1_checker, the original list
# is kept under this key, which the multi-asic-t1 job reads before t1_checker.
MULTI_ASIC_T1_CHECKER = "multi-asic-t1-lag_checker"

# Jobs in pr_test_template.yml, by their INCLUDE_JOBS name, that run each
# checker's scripts. Keep in sync with the job conditions in that template.
PR_CHECKER_JOBS = {
    "t0_checker": ["t0_job"],
    "t0-2vlans_checker": ["t0_2vlans_job"],
    "t0-sonic_checker": ["t0_sonic_job"],
    "t0-vpp_checker": ["t0_vpp_job"],
    "t1_checker": ["t1_job", "t1_multi_asic_job"],
    MULTI_ASIC_T1_CHECKER: ["t1_multi_asic_job"],
    "t1-lag-vpp_checker": ["t1_lag_vpp_job"],
    "dpu_checker": ["dpu_job"],
    "dualtor_checker": ["dualtor_job"],
    "dualtor-aa-vpp_checker": ["dualtor_aa_vpp_job"],
    "t2_checker": ["t2_job"],
}

MAX_INSTANCE_NUMBER = 40
MAX_GET_TOKEN_RETRY_TIMES = 3
