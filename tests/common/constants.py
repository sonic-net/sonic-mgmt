VLAN_SUB_INTERFACE_SEPARATOR = "."
# default port mapping mode for storage backend testbeds
PTF_PORT_MAPPING_MODE_DEFAULT = "use_sub_interface"
TOPO_KEY = "topo"
NAME_KEY = "name"
# field in mg_facts to flag whether it's a backend topology or not
IS_BACKEND_TOPOLOGY_KEY = "is_backend_topology"
# a topology whos name contains the indicator 'backend' will be considered as a backend topology
BACKEND_TOPOLOGY_IND = "backend"
# ssh connect default username and password
DEFAULT_SSH_CONNECT_PARAMS = {
    "public": {
        "username": "admin",
        "password": "YourPaSsWoRd"
    },
    "microsoft":{
        "username": "admin",
        "password": "password"
    }
}
# resolv.conf expected nameservers
#
# For public images tested with internal sonic-mgmt, expect the internal DNS server to be set. This is because there
# are some test cases (involving swapping syncd container) that need DNS to work, and we set the DNS server at pretest.
# If this is changed to set the DNS server only for those test cases that need DNS resolution, then this list can be
# empty for public images.
RESOLV_CONF_NAMESERVERS = {
    "public": ["10.64.5.5"],
    "microsoft": ["10.64.5.5"]
}
KVM_PLATFORM = 'x86_64-kvm_x86_64-r0'
