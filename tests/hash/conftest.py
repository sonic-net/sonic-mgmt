"""
    Pytest configuration used by the generic hash tests.
"""

from tests.common.dualtor.dual_tor_utils import toggle_all_aa_ports_to_rand_selected_tor
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory

# Import fixtures for pytest discovery (pytest_plugins in a nested conftest is not
# supported in pytest 9+; see https://docs.pytest.org/en/stable/deprecations.html).
from generic_hash_helper import (  # noqa: F401
    get_supported_hash_algorithms,
    global_hash_capabilities,
    global_packet_type_capabilities,
    mg_facts,
    reload,
    restore_configuration,
    restore_init_hash_config,
    restore_interfaces,
    restore_vxlan_port,
    skip_lag_tests_on_no_lag_topos,
    skip_tests_on_isolated_topos,
    skip_vs_setups,
    toggle_all_simulator_ports_to_upper_tor,
)

# Referenced so pytest discovers these fixtures from other modules.
_FIXTURES = (
    toggle_all_aa_ports_to_rand_selected_tor,
    copy_ptftests_directory,
)


def pytest_addoption(parser):
    parser.addoption("--algorithm", action="store", default="random",
                     help="The hash algorithm to test, can be 'all', 'random' or a designated one or algorithms "
                          "separated by comma, such as 'CRC,CRC_CCITT'")
    parser.addoption("--hash_field", action="store", default="random",
                     help="The hash field to test, can be 'all', 'random' or a designated one or hash fields "
                          "separated by comma, such as 'SRC_IP,DST_IP,L4_SRC_PORT'")
    parser.addoption("--ip_version", action="store", default="random", choices=('all', 'random', 'ipv4', 'ipv6'),
                     help="The outer ip version to test.")
    parser.addoption("--inner_ip_version", action="store", default="random", choices=('all', 'random', 'ipv4', 'ipv6'),
                     help="The inner ip version to test, only needed when hash field is an inner field.")
    parser.addoption("--encap_type", action="store", default="random",
                     choices=('random', 'all', 'ipinip', 'vxlan', 'nvgre'),
                     help="The encapsulation type for the inner fields, "
                          "only needed when hash field is an inner field.")
    parser.addoption("--reboot", action="store", default="random",
                     choices=('random', 'all', 'cold', 'fast', 'warm', 'reload'),
                     help="The reboot type for the reboot test, only needed for the reboot test case.")
