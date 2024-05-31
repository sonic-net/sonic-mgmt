DATAPLANE_FEATURES = set([
        "acl", "arp", "bfd", "copp", "crm", "dash", "decap", "drop_packets", "dualtor", "dualtor_io",
        "ecmp", "everflow", "fdb", "fib", "flow_counter", "ip", "ipfwd", "ixia", "macsec", "mclag",
        "mpls", "nat", "pfc_asym", "qos", "radv", "read_mac", "route", "sai_qualify", "sflow",
        "snappi_tests", "span", "stress", "upgrade_path", "vlan", "voq", "vrf", "vs_voq_cfgs", "vxlan", "wan"
])
TOPOLOGY_TYPE = ["wan", "t0", "t1", "ptf", "fullmesh", "dualtor", "t2", "tgen", "mgmttor", "m0", "mc0", "mx", "dpu"]
