# We temporarily set four types of PR checker here
PR_TOPOLOGY_TYPE = ["t0", "t1", "t2", "dpu", "tgen", "snappi", "ptf"]

# Map the topology name and topology type in pr_test_scripts.yaml
# Key is the topology name in pr_test_scripts.yaml and the value is topology type
PR_TOPOLOGY_MAPPING = {
        "t0": "t0",
        "t0-2vlans": "t0",
        "t0-sonic": "t0",
        "dualtor": "t0",
        "t1-lag": "t1",
        "multi-asic-t1-lag": "t1",
        "t2": "t2",
        "dpu": "dpu",
        "tgen": "tgen",
        "multidut-tgen": "tgen",
        "snappi": "snappi",
        "ptf": "ptf"
}
