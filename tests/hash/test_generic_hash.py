import pytest
import random
import time

from tests.common.helpers.assertions import pytest_assert
from generic_hash_helper import get_hash_fields_from_option, get_ip_version_from_option, get_encap_type_from_option, \
    get_reboot_type_from_option, HASH_CAPABILITIES, check_global_hash_config, startup_interface, \
    get_interfaces_for_test, get_ptf_port_indices, check_default_route, generate_test_params, flap_interfaces, \
    PTF_QLEN, remove_ip_interface_and_config_vlan, config_custom_vxlan_port, shutdown_interface, \
    remove_add_portchannel_member, get_hash_algorithm_from_option, check_global_hash_algorithm, get_diff_hash_algorithm
from generic_hash_helper import restore_configuration, reload, global_hash_capabilities, restore_interfaces  # noqa:F401
from generic_hash_helper import mg_facts, restore_init_hash_config, restore_vxlan_port, \
    get_supported_hash_algorithms, toggle_all_simulator_ports_to_upper_tor   # noqa:F401
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa F401
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

DEFAULT_VXLAN_PORT = 4789
PTF_LOG_PATH = "/tmp/generic_hash_test.GenericHashTest.log"

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]


def pytest_generate_tests(metafunc):
    """
    Use the random hash field to generate the pytest test case,
    this provides possibility to skip some hash field when there is some issue.
    """
    params = []
    params_tuple = []
    if 'lag' in metafunc.function.__name__:
        hash_fields = get_hash_fields_from_option(metafunc, 'lag', metafunc.config.getoption("--hash_field"))
    else:
        hash_fields = get_hash_fields_from_option(metafunc, 'ecmp', metafunc.config.getoption("--hash_field"))
    hash_algorithms = get_hash_algorithm_from_option(metafunc, metafunc.config.getoption("--algorithm"))
    outer_ip_versions = get_ip_version_from_option(metafunc.config.getoption("--ip_version"))
    inner_ip_versions = get_ip_version_from_option(metafunc.config.getoption("--inner_ip_version"))
    encap_types = get_encap_type_from_option(metafunc.config.getoption("--encap_type"))
    for field in hash_fields:
        if 'INNER' not in field:
            params_tuple.extend([(algorithm, field, ip_version, 'None', 'None')
                                 for algorithm in hash_algorithms
                                 for ip_version in outer_ip_versions])
        elif 'INNER_ETHERTYPE' in field:
            params_tuple.extend([(algorithm, field, ip_version, 'None', encap_type)
                                 for algorithm in hash_algorithms
                                 for ip_version in outer_ip_versions
                                 for encap_type in encap_types])
        else:
            params_tuple.extend([(algorithm, field, ip_version, inner_ip_version, encap_type)
                                 for algorithm in hash_algorithms
                                 for ip_version in outer_ip_versions
                                 for inner_ip_version in inner_ip_versions
                                 for encap_type in encap_types])
    for param in params_tuple:
        params.append('-'.join(param))
    if 'params' in metafunc.fixturenames:
        metafunc.parametrize("params", params)

    reboot_types = get_reboot_type_from_option(metafunc.config.getoption("--reboot"))
    if 'reboot_type' in metafunc.fixturenames:
        metafunc.parametrize("reboot_type", reboot_types)


@pytest.fixture(scope='function')
def fine_params(params, global_hash_capabilities):  # noqa:F811
    hash_algorithm, _, _, _, _ = params.split('-')
    all_supported_hash_algorithms = set(global_hash_capabilities['ecmp_algo']).\
        union(set(global_hash_capabilities['ecmp_algo']))
    if hash_algorithm not in all_supported_hash_algorithms:
        pytest.skip(f"{hash_algorithm} is not supported on current platform, "
                    f"the supported algorithms: {all_supported_hash_algorithms}")
    return params


def skip_unsupported_packet(hash_field, encap_type):
    if hash_field in ['INNER_SRC_MAC', 'INNER_DST_MAC', 'INNER_ETHERTYPE'] and encap_type == 'ipinip':
        pytest.skip(f"The field {hash_field} is not supported in ipinip encapsulation.")


def skip_unsupported_field_for_ecmp_test(field, encap_type):
    if field in ['DST_MAC', 'ETHERTYPE', 'VLAN_ID']:
        pytest.skip(f"The field {field} is not supported by the ecmp test case.")
    skip_unsupported_packet(field, encap_type)


def skip_single_member_lag_topology(uplink_portchannels, field, encap_type):
    lag_member_count = len(list(uplink_portchannels.values())[0])
    if lag_member_count < 2:
        pytest.skip("Skip the test_lag_member_flap case on setups without multi-member uplink portchannels.")
    skip_unsupported_packet(field, encap_type)


def config_validate_algorithm(duthost, algorithm_type, supported_algorithms):
    for algorithm in supported_algorithms:
        with allure.step(f"Configure algorithm: {algorithm} from supported algorithms: {supported_algorithms}"):
            if 'ecmp' == algorithm_type:
                duthost.set_switch_hash_global_algorithm('ecmp', algorithm)
                check_global_hash_algorithm(duthost, ecmp_hash_algo=algorithm)
            if 'lag' == algorithm_type:
                duthost.set_switch_hash_global_algorithm('lag', algorithm)
                check_global_hash_algorithm(duthost, lag_hash_algo=algorithm)


def test_hash_capability(duthost, global_hash_capabilities):  # noqa:F811
    """
    Test case to verify the 'show switch-hash capabilities' command.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    with allure.step('Check the dut hash capabilities are as expected'):
        ecmp_hash_capability, lag_hash_capability = global_hash_capabilities['ecmp'], global_hash_capabilities['lag']
        asic_type = duthost.facts["asic_type"]
        expected_hash_capabilities = HASH_CAPABILITIES.get(asic_type, HASH_CAPABILITIES['default'])
        expected_ecmp_hash_capability = expected_hash_capabilities['ecmp']
        expected_lag_hash_capability = expected_hash_capabilities['lag']
        pytest_assert(sorted(ecmp_hash_capability) == sorted(expected_ecmp_hash_capability),
                      'The ecmp hash capability is not as expected.')
        pytest_assert(sorted(lag_hash_capability) == sorted(expected_lag_hash_capability),
                      'The lag hash capability is not as expected.')


def test_ecmp_hash(duthost, tbinfo, ptfhost, fine_params, mg_facts, global_hash_capabilities,  # noqa:F811
                   restore_vxlan_port, toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the ecmp hash. The hash field to test is randomly chosen from the supported hash fields.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        mg_facts: minigraph facts
        hash_algorithm: randomly generated hash algorithm
        ecmp_test_hash_field: randomly generated ecmp hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    hash_algorithm, ecmp_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field, encap_type)
    with allure.step('Randomly select an ecmp hash field to test and configure the global ecmp and lag hash'):
        lag_hash_fields = global_hash_capabilities['lag']
        lag_hash_fields = lag_hash_fields[:]
        lag_hash_fields.remove(ecmp_test_hash_field)
        # Config the hash fields
        duthost.set_switch_hash_global('ecmp', [ecmp_test_hash_field])
        duthost.set_switch_hash_global('lag', lag_hash_fields)
    with allure.step(f'Configure ecmp hash algorithm: {hash_algorithm}'):
        duthost.set_switch_hash_global_algorithm('ecmp', hash_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(
            duthost, ecmp_hash_fields=[ecmp_test_hash_field], lag_hash_fields=lag_hash_fields)
        check_global_hash_algorithm(duthost, hash_algorithm)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=False)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])

    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_lag_hash(duthost, ptfhost, tbinfo, fine_params, mg_facts, restore_configuration,  # noqa:F811
                  restore_vxlan_port, global_hash_capabilities, toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the lag hash. The hash field to test is randomly chosen from the supported hash fields.
    When hash field is in [DST_MAC, ETHERTYPE, VLAN_ID], need to re-configure the dut for L2 traffic.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        mg_facts: minigraph facts
        tbinfo: testbed info fixture
        restore_configuration: fixture to restore the interface and vlan configurations after L2 test
        hash_algorithm: randomly generated hash algorithm
        lag_test_hash_field: randomly generated lag hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    hash_algorithm, lag_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    with allure.step('Randomly select a lag hash field to test and configure the global ecmp and lag hash'):
        ecmp_hash_fields = global_hash_capabilities['ecmp']
        ecmp_hash_fields = ecmp_hash_fields[:]
        ecmp_hash_fields.remove(lag_test_hash_field)
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, lag_test_hash_field)
        # If the uplinks are not multi-member portchannels, skip the test
        skip_single_member_lag_topology(uplink_interfaces, lag_test_hash_field, encap_type)
        # Config the hash fields
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', [lag_test_hash_field])
    with allure.step(f'Configure lag hash algorithm: {hash_algorithm}'):
        duthost.set_switch_hash_global_algorithm('lag', hash_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(
            duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=[lag_test_hash_field])
        check_global_hash_algorithm(duthost, lag_hash_algo=hash_algorithm)
    with allure.step('Change topology for L2 test if hash field in DST_MAC, ETHERTYPE, VLAN_ID'):
        # Need to send l2 traffic to validate SRC_MAC, DST_MAC, ETHERTYPE, VLAN_ID keys, changing topology is required
        is_l2_test = False
        if lag_test_hash_field in ['DST_MAC', 'ETHERTYPE', 'VLAN_ID']:
            # For L2 test, only one uplink portchannel interface is needed
            is_l2_test = True
            for _ in range(len(uplink_interfaces) - 1):
                uplink_interfaces.popitem()
            remove_ip_interface_and_config_vlan(
                duthost, mg_facts, tbinfo, downlink_interfaces[0], uplink_interfaces, lag_test_hash_field)
    with allure.step('Prepare test parameters'):
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, lag_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=False, lag_hash=True, is_l2_test=is_l2_test)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        if not is_l2_test:
            pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                          'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def config_all_hash_fields(duthost, global_hash_capabilities):  # noqa:F811
    duthost.set_switch_hash_global('ecmp', global_hash_capabilities['ecmp'])
    duthost.set_switch_hash_global('lag', global_hash_capabilities['lag'])


def config_all_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm):  # noqa:F811
    duthost.set_switch_hash_global_algorithm('ecmp', ecmp_algorithm)
    duthost.set_switch_hash_global_algorithm('lag', lag_algorithm)


def test_ecmp_and_lag_hash(duthost, tbinfo, ptfhost, fine_params, mg_facts, global_hash_capabilities,  # noqa:F811
                           restore_vxlan_port, get_supported_hash_algorithms,  # noqa:F811
                           toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the hash behavior when both ecmp and lag hash are configured with a same field.
    The hash field to test is randomly chosen from the supported hash fields.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        mg_facts: minigraph facts
        ecmp_algorithm: randomly generated ecmp hash algorithm
        ecmp_test_hash_field: randomly generated ecmp hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_algorithm, ecmp_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field, encap_type)
    with allure.step('Randomly select an ecmp hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        config_all_hash_fields(duthost, global_hash_capabilities)
        lag_algorithm = get_diff_hash_algorithm(ecmp_algorithm, get_supported_hash_algorithms)
    with allure.step(f'Configure ecmp hash algorithm: {ecmp_algorithm} - lag hash algorithm: {lag_algorithm}'):
        config_all_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(duthost, global_hash_capabilities['ecmp'], global_hash_capabilities['lag'])
        check_global_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_nexthop_flap(duthost, tbinfo, ptfhost, fine_params, mg_facts, restore_interfaces,  # noqa:F811
                      restore_vxlan_port, global_hash_capabilities, get_supported_hash_algorithms,  # noqa:F811
                      toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the ecmp hash when there is nexthop flapping.
    The hash field to test is randomly chosen from the supported hash fields.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        mg_facts: minigraph facts
        restore_interfaces: fixture to restore the interfaces used in the test
        ecmp_algorithm: randomly generated ecmp hash algorithm
        ecmp_test_hash_field: randomly generated ecmp hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_algorithm, ecmp_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field, encap_type)
    with allure.step('Randomly select an ecmp hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        config_all_hash_fields(duthost, global_hash_capabilities)
        lag_algorithm = get_diff_hash_algorithm(ecmp_algorithm, get_supported_hash_algorithms)
    with allure.step(f'Configure ecmp hash algorithm: {ecmp_algorithm} - lag hash algorithm: {lag_algorithm}'):
        config_all_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(duthost, global_hash_capabilities['ecmp'], global_hash_capabilities['lag'])
        check_global_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )
    with allure.step('Randomly shutdown 1 nexthop interface'):
        interface = random.choice(list(uplink_interfaces.keys()))
        remaining_uplink_interfaces = uplink_interfaces.copy()
        remaining_uplink_interfaces.pop(interface)
        origin_ptf_expected_port_groups = ptf_params['expected_port_groups']
        _, ptf_params['expected_port_groups'] = get_ptf_port_indices(
            mg_facts, downlink_interfaces=[], uplink_interfaces=remaining_uplink_interfaces)
        shutdown_interface(duthost, interface)
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )
    with allure.step('Startup the interface, and then flap it 3 more times'):
        startup_interface(duthost, interface)
        flap_interfaces(duthost, [interface], times=3)
        pytest_assert(wait_until(10, 2, 0, check_default_route, duthost, uplink_interfaces.keys()),
                      'The default route is not restored after the flapping.')
        ptf_params['expected_port_groups'] = origin_ptf_expected_port_groups
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_lag_member_flap(duthost, tbinfo, ptfhost, fine_params, mg_facts, restore_configuration,  # noqa:F811
                         restore_interfaces, global_hash_capabilities, restore_vxlan_port,  # noqa:F811
                         get_supported_hash_algorithms, toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the lag hash when there is lag member flapping.
    The hash field to test is randomly chosen from the supported hash fields.
    When hash field is in [DST_MAC, ETHERTYPE, VLAN_ID], need to re-configure the dut for L2 traffic.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        tbinfo: testbed info fixture
        mg_facts: minigraph facts
        restore_configuration: fixture to restore the interface and vlan configurations after L2 test
        restore_interfaces: fixture to restore the interfaces used in the test
        ecmp_algorithm: randomly generated ecmp hash algorithm
        lag_test_hash_fields: randomly generated lag hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_algorithm, lag_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    with allure.step('Randomly select an lag hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, lag_test_hash_field)
        # If the uplinks are not multi-member portchannels, skip the test
        skip_single_member_lag_topology(uplink_interfaces, lag_test_hash_field, encap_type)
        config_all_hash_fields(duthost, global_hash_capabilities)
        lag_algorithm = get_diff_hash_algorithm(ecmp_algorithm, get_supported_hash_algorithms)
    with allure.step(f'Configure ecmp hash algorithm: {ecmp_algorithm} - lag hash algorithm: {lag_algorithm}'):
        config_all_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(duthost, global_hash_capabilities['ecmp'], global_hash_capabilities['lag'])
        check_global_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step('Change topology for L2 test if hash field in DST_MAC, ETHERTYPE, VLAN_ID'):
        # Need to send l2 traffic to validate SRC_MAC, DST_MAC, ETHERTYPE, VLAN_ID fields, changing topology is required
        is_l2_test = False
        if lag_test_hash_field in ['DST_MAC', 'ETHERTYPE', 'VLAN_ID']:
            with allure.step('Change the topology for L2 test'):
                # For l2 test, only one uplink portchannel interface is needed
                is_l2_test = True
                for _ in range(len(uplink_interfaces) - 1):
                    uplink_interfaces.popitem()
                remove_ip_interface_and_config_vlan(duthost, mg_facts, tbinfo, downlink_interfaces[0],
                                                    uplink_interfaces,
                                                    lag_test_hash_field)
    with allure.step('Prepare test parameters'):
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, lag_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True, is_l2_test=is_l2_test)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        if not is_l2_test:
            pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                          'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )

    with allure.step('Randomly select one member in each portchannel and flap them 3 times'):
        # Randomly choose the members to flap
        interfaces = []
        for portchannel in uplink_interfaces:
            interface = random.choice(uplink_interfaces[portchannel])
            interfaces.append(interface)
        # Flap the members 3 more times
        flap_interfaces(duthost, interfaces, uplink_interfaces.keys(), times=3)

    if not is_l2_test:
        with allure.step('Wait for the default route to recover'):
            pytest_assert(wait_until(30, 5, 0, check_default_route, duthost, uplink_interfaces.keys()),
                          'The default route is not available or some nexthops are missing.')

    with allure.step('Start the ptf test, send traffic and check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_lag_member_remove_add(duthost, tbinfo, ptfhost, fine_params, mg_facts, restore_configuration,  # noqa:F811
                               restore_interfaces, global_hash_capabilities, restore_vxlan_port,  # noqa:F811
                               get_supported_hash_algorithms, toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the lag hash when a lag member is removed from the lag and added back for
    a few times.
    The hash field to test is randomly chosen from the supported hash fields.
    When hash field is in [DST_MAC, ETHERTYPE, VLAN_ID], need to re-configure the dut for L2 traffic.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        tbinfo: testbed info fixture
        mg_facts: minigraph facts
        restore_configuration: fixture to restore the interface and vlan configurations after L2 test
        restore_interfaces: fixture to restore the interfaces used in the test
        ecmp_algorithm: randomly generated ecmp hash algorithm
        lag_test_hash_fields: randomly generated lag hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_algorithm, lag_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    with allure.step('Randomly select an lag hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, lag_test_hash_field)
        # If the uplinks are not multi-member portchannels, skip the test
        skip_single_member_lag_topology(uplink_interfaces, lag_test_hash_field, encap_type)
        config_all_hash_fields(duthost, global_hash_capabilities)
        lag_algorithm = get_diff_hash_algorithm(ecmp_algorithm, get_supported_hash_algorithms)
    with allure.step(f'Configure ecmp hash algorithm: {ecmp_algorithm} - lag hash algorithm: {lag_algorithm}'):
        config_all_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(duthost, global_hash_capabilities['ecmp'], global_hash_capabilities['lag'])
        check_global_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step('Change topology for L2 test if hash field in DST_MAC, ETHERTYPE, VLAN_ID'):
        # Need to send l2 traffic to validate SRC_MAC, DST_MAC, ETHERTYPE, VLAN_ID fields, changing topology is required
        is_l2_test = False
        if lag_test_hash_field in ['DST_MAC', 'ETHERTYPE', 'VLAN_ID']:
            with allure.step('Change the topology for L2 test'):
                # For l2 test, only one uplink portchannel interface is needed
                is_l2_test = True
                for _ in range(len(uplink_interfaces) - 1):
                    uplink_interfaces.popitem()
                remove_ip_interface_and_config_vlan(duthost, mg_facts, tbinfo, downlink_interfaces[0],
                                                    uplink_interfaces,
                                                    lag_test_hash_field)
    with allure.step('Prepare test parameters'):
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, lag_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True, is_l2_test=is_l2_test)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        if not is_l2_test:
            pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                          'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )

    with allure.step('Randomly select one member in each portchannel and remove it from the lag and add it back'):
        # Randomly choose the members to remove/add
        for portchannel in uplink_interfaces:
            interface = random.choice(uplink_interfaces[portchannel])
            remove_add_portchannel_member(duthost, interface, portchannel)

    if not is_l2_test:
        with allure.step('Wait for the default route to recover'):
            pytest_assert(wait_until(30, 5, 0, check_default_route, duthost, uplink_interfaces.keys()),
                          'The default route is not available or some nexthops are missing.')

    with allure.step('Start the ptf test, send traffic and check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_reboot(duthost, tbinfo, ptfhost, localhost, fine_params, mg_facts, restore_vxlan_port,  # noqa:F811
                global_hash_capabilities, reboot_type, get_supported_hash_algorithms,  # noqa:F811
                toggle_all_simulator_ports_to_upper_tor):  # noqa:F811
    """
    Test case to validate the hash behavior after fast/warm/cold reboot.
    The hash field to test is randomly chosen from the supported hash fields.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        ptfhost (AnsibleHost): Packet Test Framework (PTF)
        mg_facts: minigraph facts
        localhost: local host object
        ecmp_algorithm: randomly generated ecmp hash algorithm
        ecmp_test_hash_field: randomly generated ecmp hash field parameter
        ipver: randomly generated outer frame ip version
        inner_ipver: randomly generated inner frame ip version
        encap_type: randomly generated encapsulation type
        restore_vxlan_port: fixture to restore vxlan port to default
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_algorithm, ecmp_test_hash_field, ipver, inner_ipver, encap_type = fine_params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field, encap_type)
    with allure.step('Randomly select an ecmp hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        config_all_hash_fields(duthost, global_hash_capabilities)
        lag_algorithm = get_diff_hash_algorithm(ecmp_algorithm, get_supported_hash_algorithms)
    with allure.step(f'Configure ecmp hash algorithm: {ecmp_algorithm} - lag hash algorithm: {lag_algorithm}'):
        config_all_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step("Check the config result"):
        check_global_hash_config(duthost, global_hash_capabilities['ecmp'], global_hash_capabilities['lag'])
        check_global_hash_algorithm(duthost, ecmp_algorithm, lag_algorithm)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, tbinfo, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )

    with allure.step(f'Randomly choose a reboot type: {reboot_type}, and reboot'):
        # Save config if reboot type is config reload or cold reboot
        if reboot_type in ['cold', 'reload']:
            duthost.shell('config save -y')
        # Reload/Reboot the dut
        if reboot_type == 'reload':
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        else:
            reboot(duthost, localhost, reboot_type=reboot_type)
        # Wait for the dut to recover
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started.")
    with allure.step('Check the generic hash config after the reboot'):
        check_global_hash_config(duthost, global_hash_capabilities['ecmp'], global_hash_capabilities['lag'])
    with allure.step('Check the route is established'):
        pytest_assert(wait_until(60, 10, 0, check_default_route, duthost, uplink_interfaces.keys()),
                      "The default route is not established after the cold reboot.")
    with allure.step('Start the ptf test, send traffic and check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


@pytest.mark.disable_loganalyzer
def test_backend_error_messages(duthost, reload, global_hash_capabilities):  # noqa:F811
    """
    Test case to validate there are backend errors printed in the syslog when
    the hash config is removed or updated with invalid values via redis cli.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        reload: fixture to reload the configuration after the test
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    test_data = [
        {'info': 'Remove the ecmp_hash entry via redis cli and check if there is an error in the log',
         'command': "redis-cli -n 4 HDEL 'SWITCH_HASH|GLOBAL' 'ecmp_hash@'",
         'expected_regex': [
             'ERR swss#orchagent:.*setSwitchHash: Failed to remove switch ECMP hash configuration: '
             'operation is not supported.*',
             # noqa:E501
             'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to set switch hash: ASIC and CONFIG DB are '
             'diverged.*']},
        # noqa:E501
        {'info': 'Remove the lag_hash entry via redis cli and check if there is an error in the log',
         'command': "redis-cli -n 4 HDEL 'SWITCH_HASH|GLOBAL' 'lag_hash@'",
         'expected_regex': [
             'ERR swss#orchagent:.*setSwitchHash: Failed to remove switch LAG hash configuration: '
             'operation is not supported.*',
             # noqa:E501
             'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to set switch hash: ASIC and CONFIG DB are '
             'diverged.*']},
        # noqa:E501
        {'info': 'Remove the ecmp_hash_algorithm entry via redis cli and check if there is an error in the log',
         'command': "redis-cli -n 4 HDEL 'SWITCH_HASH|GLOBAL' 'ecmp_hash_algorithm'",
         'expected_regex': [
             'ERR swss#orchagent:.*setSwitchHash: Failed to remove switch ECMP hash algorithm configuration: '
             'operation is not supported.*',
             # noqa:E501
             'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to set switch hash: ASIC and CONFIG DB are '
             'diverged.*']},
        # noqa:E501
        {'info': 'Remove the lag_hash_algorithm entry via redis cli and check if there is an error in the log',
         'command': "redis-cli -n 4 HDEL 'SWITCH_HASH|GLOBAL' 'lag_hash_algorithm'",
         'expected_regex': [
             'ERR swss#orchagent:.*setSwitchHash: Failed to remove switch LAG hash algorithm configuration: '
             'operation is not supported.*',
             # noqa:E501
             'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to set switch hash: ASIC and CONFIG DB are '
             'diverged.*']},
        # noqa:E501
        {'info': 'Update the ecmp hash fields with an invalid value via redis cli and check if there '
                 'is an error in the log.',
         'command': "redis-cli -n 4 HSET 'SWITCH_HASH|GLOBAL' 'ecmp_hash@' 'INVALID_FIELD'",
         'expected_regex': [
             'ERR swss#orchagent:.*parseSwHashFieldList: Failed to parse field\\(ecmp_hash\\): '
             'invalid value\\(INVALID_FIELD\\).*']},
        # noqa:E501
        {'info': 'Update the lag hash fields with an invalid value via redis cli and check if there '
                 'is an error in the log.',
         'command': "redis-cli -n 4 HSET 'SWITCH_HASH|GLOBAL' 'lag_hash@' 'INVALID_FIELD'",
         'expected_regex': [
             'ERR swss#orchagent:.*parseSwHashFieldList: Failed to parse field\\(lag_hash\\): '
             'invalid value\\(INVALID_FIELD\\).*']
         # noqa:E501
         },
        {'info': 'Update the ecmp hash algorithm with an invalid value via redis cli and check if there '
                 'is an error in the log.',
         'command': "redis-cli -n 4 HSET 'SWITCH_HASH|GLOBAL' 'ecmp_hash_algorithm' 'INVALID_FIELD'",
         'expected_regex': [
             'ERR swss#orchagent:.*parseSwHashAlgorithm: Failed to parse field\\(ecmp_hash_algorithm\\): '
             'invalid value\\(INVALID_FIELD\\).*']
         # noqa:E501
         },
        {'info': 'Update the lag hash algorithm with an invalid value via redis cli and check if there '
                 'is an error in the log.',
         'command': "redis-cli -n 4 HSET 'SWITCH_HASH|GLOBAL' 'lag_hash_algorithm' 'INVALID_FIELD'",
         'expected_regex': [
             'ERR swss#orchagent:.*parseSwHashAlgorithm: Failed to parse field\\(lag_hash_algorithm\\): '
             'invalid value\\(INVALID_FIELD\\).*']
         # noqa:E501
         },
        {'info': 'Remove the SWITCH_HASH|GLOBAL key via redis cli and check if there is an error in the log.',
         'command': "redis-cli -n 4 DEL 'SWITCH_HASH|GLOBAL'",
         'expected_regex': [
             'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to remove switch hash: '
             'operation is not supported: ASIC and CONFIG DB are diverged.*']
         # noqa:E501
         }
    ]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="test_backend_error_msgs:")
    for item in test_data:
        random_ecmp_algo = random.choice(global_hash_capabilities['ecmp_algo'])
        random_lag_algo = random.choice(global_hash_capabilities['lag_algo'])
        with allure.step('Configure all supported fields to the global ecmp and lag hash'):
            config_all_hash_fields(duthost, global_hash_capabilities)

        with allure.step(f"Random chose algorithm: {random_ecmp_algo} from supported ecmp hash "
                         f"algorithms: {global_hash_capabilities['ecmp_algo']}"):
            duthost.set_switch_hash_global_algorithm('ecmp', random_ecmp_algo)

        with allure.step(f"Random chose algorithm: {random_lag_algo} from supported lag hash "
                         f"algorithms: {global_hash_capabilities['lag_algo']}"):
            duthost.set_switch_hash_global_algorithm('lag', random_lag_algo)

        with allure.step(item['info']):
            loganalyzer.expect_regex = item['expected_regex']
            marker = loganalyzer.init()
            duthost.shell(item['command'])
            time.sleep(1)
            loganalyzer.analyze(marker)


def test_algorithm_config(duthost, global_hash_capabilities):  # noqa:F811
    """
    Test case to validate the hash algorithm configuration.
    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    with allure.step('Test ECMP hash algorithm configuration'):
        config_validate_algorithm(duthost, 'ecmp', global_hash_capabilities['ecmp_algo'])
    with allure.step('Test LAG hash algorithm configuration'):
        config_validate_algorithm(duthost, 'lag', global_hash_capabilities['lag_algo'])
