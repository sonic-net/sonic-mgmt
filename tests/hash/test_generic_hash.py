import pytest
import random
import time

from tests.common.helpers.assertions import pytest_assert
from generic_hash_helper import get_hash_fields_from_option, get_ip_version_from_option, get_encap_type_from_option,\
    get_reboot_type_from_option, HASH_CAPABILITIES, check_global_hash_config, startup_interface, \
    get_interfaces_for_test, get_ptf_port_indices, check_default_route, generate_test_params, flap_interfaces, \
    PTF_QLEN, remove_ip_interface_and_config_vlan, config_custom_vxlan_port, shutdown_interface, \
    remove_add_portchannel_member
from generic_hash_helper import restore_configuration, reload, global_hash_capabilities, restore_interfaces  # noqa:F401
from generic_hash_helper import mg_facts, restore_init_hash_config, restore_vxlan_port  # noqa:F401
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory # noqa F401
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

DEFAULT_VXLAN_PORT = 4789

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]


def pytest_generate_tests(metafunc):
    """
        Use the random hash field to generate the pytets test case,
        this provides possibility to skip some hash field when there is some issue.
    """
    params = []
    params_tuple = []
    if 'lag' in metafunc.function.__name__:
        hash_fields = get_hash_fields_from_option(metafunc, 'lag', metafunc.config.getoption("--hash_field"))
    else:
        hash_fields = get_hash_fields_from_option(metafunc, 'ecmp', metafunc.config.getoption("--hash_field"))
    outer_ip_versions = get_ip_version_from_option(metafunc.config.getoption("--ip_version"))
    inner_ip_versions = get_ip_version_from_option(metafunc.config.getoption("--inner_ip_version"))
    encap_types = get_encap_type_from_option(metafunc.config.getoption("--encap_type"))
    for field in hash_fields:
        if 'INNER' not in field:
            params_tuple.extend([(field, ip_version, 'None', 'None') for ip_version in outer_ip_versions])
        else:
            params_tuple.extend([(field, ip_version, inner_ip_version, encap_type)
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


def skip_unsupported_field_for_ecmp_test(field):
    if field in ['DST_MAC', 'ETHERTYPE', 'VLAN_ID']:
        pytest.skip(f"The field {field} is not supported by the ecmp test case.")


def skip_single_member_lag_topology(uplink_portchannels):
    lag_member_count = len(list(uplink_portchannels.values())[0])
    if lag_member_count < 2:
        pytest.skip("Skip the test_lag_member_flap case on setups without multi-member uplink portchannels.")


def test_hash_capability(duthost, global_hash_capabilities):  # noqa:F811
    """
        Test case to verify the 'show switch-hash capabilities' command.
        Args:
            duthost (AnsibleHost): Device Under Test (DUT)
            global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    with allure.step('Check the dut hash capabilities are as expected'):
        ecmp_hash_capability, lag_hash_capability = global_hash_capabilities
        asic_type = duthost.facts["asic_type"]
        if asic_type in HASH_CAPABILITIES.keys():
            expected_ecmp_hash_capability = HASH_CAPABILITIES[asic_type]['ecmp']
            expected_lag_hash_capability = HASH_CAPABILITIES[asic_type]['lag']
        else:
            expected_ecmp_hash_capability = HASH_CAPABILITIES['default']['ecmp']
            expected_lag_hash_capability = HASH_CAPABILITIES['default']['lag']
        pytest_assert(sorted(ecmp_hash_capability) == sorted(expected_ecmp_hash_capability),
                      'The ecmp hash capability is not as expected.')
        pytest_assert(sorted(lag_hash_capability) == sorted(expected_lag_hash_capability),
                      'The lag hash capability is not as expected.')


def test_ecmp_hash(duthost, ptfhost, params, mg_facts, global_hash_capabilities, restore_vxlan_port):  # noqa:F811
    """
        Test case to validate the ecmp hash. The hash field to test is randomly chosen from the supported hash fields.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                mg_facts: minigraph facts
                ecmp_test_hash_field: randomly generated ecmp hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field)
    with allure.step('Randomly select an ecmp hash field to test and configure the global ecmp and lag hash'):
        _, lag_hash_fields = global_hash_capabilities
        lag_hash_fields = lag_hash_fields[:]
        lag_hash_fields.remove(ecmp_test_hash_field)
        # Config the hash fields
        duthost.set_switch_hash_global('ecmp', [ecmp_test_hash_field])
        duthost.set_switch_hash_global('lag', lag_hash_fields)
        # Check the config result
        check_global_hash_config(
            duthost, ecmp_hash_fields=[ecmp_test_hash_field], lag_hash_fields=lag_hash_fields)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=False)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])

    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_lag_hash(duthost, ptfhost, tbinfo, params, mg_facts, restore_configuration, restore_vxlan_port,  # noqa:F811
                  global_hash_capabilities):  # noqa:F811
    """
        Test case to validate the lag hash. The hash field to test is randomly chosen from the supported hash fields.
        When hash field is in [DST_MAC, ETHERTYPE, VLAN_ID], need to re-configure the dut for L2 traffic.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                mg_facts: minigraph facts
                tbinfo: testbed info fixture
                restore_configuration: fixture to restore the interface and vlan configurations after L2 test
                lag_test_hash_field: randomly generated lag hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    lag_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    with allure.step('Randomly select a lag hash field to test and configure the global ecmp and lag hash'):
        ecmp_hash_fields, _ = global_hash_capabilities
        ecmp_hash_fields = ecmp_hash_fields[:]
        ecmp_hash_fields.remove(lag_test_hash_field)
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, lag_test_hash_field)
        # If the uplinks are not multi-member portchannels, skip the test
        skip_single_member_lag_topology(uplink_interfaces)
        # Config the hash fields
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', [lag_test_hash_field])
        # Check the config result
        check_global_hash_config(
            duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=[lag_test_hash_field])
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
            duthost, mg_facts, lag_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=False, lag_hash=True, is_l2_test=is_l2_test)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
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
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_ecmp_and_lag_hash(duthost, ptfhost, params, mg_facts, global_hash_capabilities,  # noqa:F811
                           restore_vxlan_port):  # noqa:F811
    """
        Test case to validate the hash behavior when both ecmp and lag hash are configured with a same field.
        The hash field to test is randomly chosen from the supported hash fields.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                mg_facts: minigraph facts
                ecmp_test_hash_field: randomly generated ecmp hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field)
    with allure.step('Randomly select an ecmp hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Config the hash fields
        ecmp_hash_fields, lag_hash_fields = global_hash_capabilities
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', lag_hash_fields)
        # Check the config result
        check_global_hash_config(duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=lag_hash_fields)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_nexthop_flap(duthost, ptfhost, params, mg_facts, restore_interfaces, restore_vxlan_port,  # noqa:F811
                      global_hash_capabilities):  # noqa:F811
    """
        Test case to validate the ecmp hash when there is nexthop flapping.
        The hash field to test is randomly chosen from the supported hash fields.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                mg_facts: minigraph facts
                restore_interfaces: fixture to restore the interfaces used in the test
                ecmp_test_hash_field: randomly generated ecmp hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field)
    with allure.step('Randomly select an ecmp hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Config the hash fields
        ecmp_hash_fields, lag_hash_fields = global_hash_capabilities
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', lag_hash_fields)
        # Check the config result
        check_global_hash_config(duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=lag_hash_fields)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
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
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
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
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_lag_member_flap(duthost, tbinfo, ptfhost, params, mg_facts, restore_configuration,  # noqa:F811
                         restore_interfaces,  global_hash_capabilities, restore_vxlan_port):  # noqa:F811
    """
        Test case to validate the lag hash when there is lag member flapping.
        The hash field to test is randomly chosen from the supported hash fields.
        When hash field is in [DST_MAC, ETHERTYPE, VLAN_ID], need to re-configure the dut for L2 traffic.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                tbinfo: testbed info fisture
                mg_facts: minigraph facts
                restore_configuration: fixture to restore the interface and vlan configurations after L2 test
                restore_interfaces: fixture to restore the interfaces used in the test
                lag_test_hash_fields: randomly generated lag hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    lag_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    with allure.step('Randomly select an lag hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, lag_test_hash_field)
        # If the uplinks are not multi-member portchannels, skip the test
        skip_single_member_lag_topology(uplink_interfaces)
        # Config the hash fields
        ecmp_hash_fields, lag_hash_fields = global_hash_capabilities
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', lag_hash_fields)
        # Check the config result
        check_global_hash_config(duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=lag_hash_fields)
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
            duthost, mg_facts, lag_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True, is_l2_test=is_l2_test)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
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
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
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

    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_lag_member_remove_add(duthost, tbinfo, ptfhost, params, mg_facts, restore_configuration,  # noqa:F811
                               restore_interfaces, global_hash_capabilities, restore_vxlan_port):  # noqa:F811
    """
        Test case to validate the lag hash when there is lag member flapping.
        The hash field to test is randomly chosen from the supported hash fields.
        When hash field is in [DST_MAC, ETHERTYPE, VLAN_ID], need to re-configure the dut for L2 traffic.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                tbinfo: testbed info fisture
                mg_facts: minigraph facts
                restore_configuration: fixture to restore the interface and vlan configurations after L2 test
                restore_interfaces: fixture to restore the interfaces used in the test
                lag_test_hash_fields: randomly generated lag hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    lag_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    with allure.step('Randomly select an lag hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, lag_test_hash_field)
        # If the uplinks are not multi-member portchannels, skip the test
        skip_single_member_lag_topology(uplink_interfaces)
        # Config the hash fields
        ecmp_hash_fields, lag_hash_fields = global_hash_capabilities
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', lag_hash_fields)
        # Check the config result
        check_global_hash_config(duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=lag_hash_fields)
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
            duthost, mg_facts, lag_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True, is_l2_test=is_l2_test)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
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
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
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

    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )


def test_reboot(duthost, ptfhost, localhost, params, mg_facts, restore_vxlan_port,  # noqa:F811
                global_hash_capabilities, reboot_type):  # noqa:F811
    """
        Test case to validate the hash behavior after fast/warm/cold reboot.
        The hash field to test is randomly chosen from the supported hash fields.
            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                mg_facts: minigraph facts
                localhost: local host object
                ecmp_test_hash_field: randomly generated ecmp hash field parameter
                ipver: randomly generated outer frame ip version
                inner_ipver: randomly generated inner frame ip version
                restore_vxlan_port: fixture to restore vxlan port to default
                global_hash_capabilities: module level fixture to get the dut hash capabilities
    """
    ecmp_test_hash_field, ipver, inner_ipver, encap_type = params.split('-')
    skip_unsupported_field_for_ecmp_test(ecmp_test_hash_field)
    with allure.step('Randomly select an ecmp hash field to test '
                     'and configure all supported fields to the global ecmp and lag hash'):
        # Config the hash fields
        ecmp_hash_fields, lag_hash_fields = global_hash_capabilities
        duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
        duthost.set_switch_hash_global('lag', lag_hash_fields)
        # Check the config result
        check_global_hash_config(duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=lag_hash_fields)
    with allure.step('Prepare test parameters'):
        # Get the interfaces for the test, downlink interface is selected randomly
        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(duthost, mg_facts, ecmp_test_hash_field)
        ptf_params = generate_test_params(
            duthost, mg_facts, ecmp_test_hash_field, ipver, inner_ipver, encap_type, uplink_interfaces,
            downlink_interfaces, ecmp_hash=True, lag_hash=True)
        if ptf_params.get('vxlan_port') and ptf_params['vxlan_port'] != DEFAULT_VXLAN_PORT:
            config_custom_vxlan_port(duthost, ptf_params['vxlan_port'])
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        # Check the default route before the ptf test
        pytest_assert(check_default_route(duthost, uplink_interfaces.keys()),
                      'The default route is not available or some nexthops are missing.')
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True
        )

    with allure.step('Randomly choose a reboot type: {}, and reboot'.format(reboot_type)):
        # Save config if reboot type is cold reboot
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
        # Check the generic hash config after the reboot
        check_global_hash_config(duthost, ecmp_hash_fields=ecmp_hash_fields, lag_hash_fields=lag_hash_fields)
        # Check the route is established
        pytest_assert(wait_until(60, 10, 0, check_default_route, duthost, uplink_interfaces.keys()),
                      "The default route is not established after the cold reboot.")
    with allure.step('Start the ptf test, send traffic anc check the balancing'):
        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file="/tmp/generic_hash_test.GenericHashTest.log",
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
         'expected_regex': ['ERR swss#orchagent:.*setSwitchHash: Failed to remove switch ECMP hash configuration: operation is not supported.*',  # noqa:E501
                            'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to set switch hash: ASIC and CONFIG DB are diverged.*']},  # noqa:E501
        {'info': 'Remove the lag_hash entry via redis cli and check if there is an error in the log',
         'command': "redis-cli -n 4 HDEL 'SWITCH_HASH|GLOBAL' 'lag_hash@'",
         'expected_regex': ['ERR swss#orchagent:.*setSwitchHash: Failed to remove switch LAG hash configuration: operation is not supported.*',  # noqa:E501
                            'ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to set switch hash: ASIC and CONFIG DB are diverged.*']},  # noqa:E501
        {'info': 'Update the ecmp hash fields with an invalid value via redis cli and check if there '
                 'is an error in the log.',
         'command': "redis-cli -n 4 HSET 'SWITCH_HASH|GLOBAL' 'ecmp_hash@' 'INVALID_FIELD'",
         'expected_regex': ['ERR swss#orchagent:.*parseSwHashFieldList: Failed to parse field\\(ecmp_hash\\): invalid value\\(INVALID_FIELD\\).*']},  # noqa:E501
        {'info': 'Update the lag hash fields with an invalid value via redis cli and check if there '
                 'is an error in the log.',
         'command': "redis-cli -n 4 HSET 'SWITCH_HASH|GLOBAL' 'lag_hash@' 'INVALID_FIELD'",
         'expected_regex': ['ERR swss#orchagent:.*parseSwHashFieldList: Failed to parse field\\(lag_hash\\): invalid value\\(INVALID_FIELD\\).*']  # noqa:E501
         },
        {'info': 'Remove the SWITCH_HASH|GLOBAL key via redis cli and check if there is an error in the log.',
         'command': "redis-cli -n 4 DEL 'SWITCH_HASH|GLOBAL'",
         'expected_regex': ['ERR swss#orchagent:.*doCfgSwitchHashTableTask: Failed to remove switch hash: operation is not supported: ASIC and CONFIG DB are diverged.*']  # noqa:E501
         }
    ]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="test_backend_error_msgs:")
    ecmp_hash_fields, lag_hash_fields = global_hash_capabilities
    for item in test_data:
        with allure.step('Configure all supported fields to the global ecmp and lag hash'):
            duthost.set_switch_hash_global('ecmp', ecmp_hash_fields)
            duthost.set_switch_hash_global('lag', lag_hash_fields)

        with allure.step(item['info']):
            loganalyzer.expect_regex = item['expected_regex']
            marker = loganalyzer.init()
            duthost.shell(item['command'])
            time.sleep(1)
            loganalyzer.analyze(marker)
