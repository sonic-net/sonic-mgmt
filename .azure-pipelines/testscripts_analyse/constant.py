DATAPLANE_FEATURES = {
        "acl", "arp", "bfd", "copp", "crm", "dash", "decap", "drop_packets", "dualtor", "dualtor_io",
        "ecmp", "everflow", "fdb", "fib", "flow_counter", "ip", "ipfwd", "ixia", "macsec", "mclag",
        "mpls", "nat", "pfc_asym", "pfcwd", "qos", "radv", "read_mac", "route", "sai_qualify", "sflow",
        "snappi_tests", "span", "stress", "upgrade_path", "vlan", "voq", "vrf", "vs_voq_cfgs", "vxlan", "wan"
}

# We temporarily set four types of PR checker here
PR_TOPOLOGY_TYPE = ["t0", "t1", "t2", "wan", "dpu", "tgen", "snappi", "ptf"]

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
        "wan-pub": "wan",
        "dpu": "dpu",
        "tgen": "tgen",
        "multidut-tgen": "tgen",
        "snappi": "snappi",
        "ptf": "ptf"
}
