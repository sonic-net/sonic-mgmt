__all__ = ["CLEANUP_KEY", "IPV6_VXLAN_TEST_KEY", "APPLY_NEW_CONFIG_KEY", "NUM_VNET_KEY", "NUM_ROUTES_KEY", "NUM_ENDPOINTS_KEY", "NUM_INTF_PER_VNET_KEY",
            "DUT_VNET_SWITCH_JSON", "DUT_VNET_CONF_JSON", "DUT_VNET_ROUTE_JSON", "DUT_VNET_INTF_JSON", "DUT_VNET_NBR_JSON",
            "TEMPLATE_DIR"]

VXLAN_PORT = "13330"
VXLAN_MAC = "00:aa:bb:cc:78:9a"
DUT_VNET_SWITCH_JSON = "/tmp/vnet.switch.json"
DUT_VNET_CONF_JSON = "/tmp/vnet.conf.json"
DUT_VNET_ROUTE_JSON = "/tmp/vnet.route.json"
DUT_VNET_INTF_JSON = "/tmp/vnet.intf.json"
DUT_VNET_NBR_JSON = "/tmp/vnet.nbr.json"
TEMPLATE_DIR = "vxlan/templates"

CLEANUP_KEY = "cleanup"
IPV6_VXLAN_TEST_KEY = "ipv6_vxlan_test"
APPLY_NEW_CONFIG_KEY = "apply_new_config"
NUM_VNET_KEY = "num_vnet"
NUM_ROUTES_KEY = "num_routes"
NUM_ENDPOINTS_KEY = "num_endpoints"
NUM_INTF_PER_VNET_KEY = "num_intf_per_vnet"
