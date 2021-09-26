__all__ = ["CLEANUP_KEY", "IPV6_VXLAN_TEST_KEY", "APPLY_NEW_CONFIG_KEY", "NUM_VNET_KEY", "NUM_ROUTES_KEY", "NUM_ENDPOINTS_KEY", "NUM_INTF_PER_VNET_KEY",
            "DUT_VNET_SWITCH_JSON", "DUT_VNET_CONF_JSON", "DUT_VNET_ROUTE_JSON", "DUT_VNET_INTF_JSON", "DUT_VNET_NBR_JSON",
            "TEMPLATE_DIR", "LOWER_BOUND_UDP_PORT_KEY", "UPPER_BOUND_UDP_PORT_KEY", "TOTAL_NUMBER_OF_ENDPOINTS", "ECMP_NHS_PER_DESTINATION", "TOTAL_NUMBER_OF_NEXTHOPS",
            "IPV4_IN_IPV4", "IPV6_IN_IPV4", "IPV4_IN_IPV6", "IPV6_IN_IPV6"]

VXLAN_PORT = "13330"
VXLAN_MAC = "00:aa:bb:cc:78:9a"
DUT_VNET_SWITCH_JSON = "/tmp/vnet.switch.json"
DUT_VNET_CONF_JSON = "/tmp/vnet.conf.json"
DUT_VNET_ROUTE_JSON = "/tmp/vnet.route.json"
DUT_VNET_INTF_JSON = "/tmp/vnet.intf.json"
DUT_VNET_NBR_JSON = "/tmp/vnet.nbr.json"
DUT_VXLAN_PORT_JSON = "/tmp/vxlan_switch.json"
TEMPLATE_DIR = "vxlan/templates"

CLEANUP_KEY = "cleanup"
IPV6_VXLAN_TEST_KEY = "ipv6_vxlan_test"
APPLY_NEW_CONFIG_KEY = "apply_new_config"
NUM_VNET_KEY = "num_vnet"
NUM_ROUTES_KEY = "num_routes"
NUM_ENDPOINTS_KEY = "num_endpoints"
NUM_INTF_PER_VNET_KEY = "num_intf_per_vnet"
LOWER_BOUND_UDP_PORT_KEY = "lower_bound_udp_port"
UPPER_BOUND_UDP_PORT_KEY = "upper_bound_udp_port"
IPV6_IN_IPV4 = "ipv6_in_ipv4"

#ECMP
TOTAL_NUMBER_OF_ENDPOINTS = "total_number_of_endpoints"
ECMP_NHS_PER_DESTINATION = "ecmp_nhs_per_destination"
TOTAL_NUMBER_OF_NEXTHOPS = "total_number_of_nexthops"

# Various flavours
IPV4_IN_IPV4 = "ipv4_in_ipv4"
IPV6_IN_IPV4 = "ipv6_in_ipv4"
IPV4_IN_IPV6 = "ipv4_in_ipv6"
IPV6_IN_IPV6 = "ipv6_in_ipv6"
