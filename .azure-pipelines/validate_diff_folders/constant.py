# Now, we only have below types of PR checker
# - dpu
# - dualtor-t0
# - multi-asic-t1-lag
# - t0
# - t0-2vlans
# - t0-sonic
# - t1- lag
PR_TOPOLOGY_TYPE = ["t0", "t0_2vlans", "t0_sonic", "t1", "multi_asic", "dpu", "dualtor"]

EXCLUDE_TEST_SCRIPTS = [
    "test_posttest.py",
    "test_pretest.py"
]

