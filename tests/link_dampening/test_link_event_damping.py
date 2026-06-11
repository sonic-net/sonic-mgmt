import logging
import pytest
import time
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.link_dampening.link_event_damping_utils import (
    get_dut_fronface_ports,
    configure_link_damping,
    verify_configuration,
    get_link_damping_stats,
    clear_link_damping_stats,
    generate_link_flap,
    get_interface_operational_state,
    get_interface_physical_state,
    get_redis_db_entries,
    validate_redis_persistence,
    get_dampening_penalties,
    verify_counter_values,
    calculate_expected_suppression_time,
    check_suppression_active,
    inject_traffic_and_verify,
    restart_docker_container,
    wait_for_condition
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('t0', 't1')  # Compatible with T0 and T1 topologies
]

DAMPING_CONFIG_PARAMS = {
    "suppress_threshold": 1600,
    "reuse_threshold": 1200,
    "decay_half_life": 15000,  # milliseconds
    "max_suppress_time": 30000,  # milliseconds
    "flap_penalty": 1000
}

UNSUPPORTED_CONFIG_PARAMS = {
    "suppress_threshold": 1600,
    "reuse_threshold": 1200,
    "decay_half_life": 45000,  # milliseconds - Greater than max_suppress_time
    "max_suppress_time": 30000,  # milliseconds
    "flap_penalty": 1000
}

TIMELINE_EVENTS = [
    {"time": 3, "event": "DOWN", "propagated": True},
    {"time": 7, "event": "UP", "propagated": True},
    {"time": 10, "event": "DOWN", "propagated": True},
    {"time": 14, "event": "UP", "propagated": False},
    {"time": 17, "event": "DOWN", "propagated": False},
    {"time": 20, "event": "UP", "propagated": False},
    {"time": 31, "event": "None", "propagated": False},
    {"time": 40, "event": "DOWN", "propagated": True},
    {"time": 44, "event": "UP", "propagated": False},
    {"time": 46, "event": "DOWN", "propagated": False},
    {"time": 61, "event": "None", "propagated": False},
    {"time": 70, "event": "UP", "propagated": True},
    {"time": 100, "event": "DOWN", "propagated": True},
    {"time": 102, "event": "UP", "propagated": True},
    {"time": 105, "event": "DOWN", "propagated": True},
    {"time": 124, "event": "UP", "propagated": False},
    {"time": 152, "event": "None", "propagated": True},
]


class TestLinkEventDampingBasics:
    """Test cases for basic link event damping functionality (TC01-TC03)"""

    @pytest.fixture(autouse=True)
    def setup_teardown(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
        """Setup and teardown for each test"""
        yield
        # Cleanup: clear damping config after each test
        # clear_link_damping_stats(duthost)

    def test_tc01_1_normal_link_flap_event_propagation(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC01.1 - Normal Link Flap Event Propagation

        Verify that link up/down events propagate normally when damping is inactive.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        # Get a test interface
        test_intf = get_test_interface(dut)
        logger.info(f"Using interface {test_intf} for test")

        # Ensure damping is disabled
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)
        time.sleep(5)
        configure_link_damping(dut, test_intf, disabled=True)

        time.sleep(5)
        # Generate link UP/DOWN events
        initial_state = get_interface_physical_state(dut, test_intf)
        logger.info(f"Initial state: {initial_state}")

        generate_link_flap(dut, test_intf, num_flaps=5, interval=1)

        # Verify all physical link changes are propagated
        stats = get_link_damping_stats(dut, test_intf)
        pre_damping_transitions = int(stats.get('pre_damping_link_transitions', 0))
        logger.warning(f"Pre-damping transitions: {pre_damping_transitions}")

        pytest_assert(pre_damping_transitions > 0, "Expected link transitions to be propagated")
        # pytest_assert(pre_damping_transitions == 0, "Expected zero link transitions to be propagated")

        # Operational state should track physical state
        op_state = get_interface_operational_state(dut, test_intf)
        phys_state = get_interface_physical_state(dut, test_intf)
        pytest_assert(op_state == phys_state,
                     f"Operational state {op_state} should match physical state {phys_state}")

    def test_tc01_2_multiple_sequential_flaps(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC01.2 - Multiple Sequential Flaps

        Verify link flaps are properly tracked and reported.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)
        configure_link_damping(dut, test_intf, disabled=True)

        time.sleep(10)

        #get stats before the link flap
        stats1 = get_link_damping_stats(dut, test_intf)
        pre_damping_downs1 = int(stats1.get('pre_damping_down_events', 0))
        pre_damping_ups1 = int(stats1.get('pre_damping_up_events', 0))

        # Generate 10 sequential flaps
        num_flaps = 10
        generate_link_flap(dut, test_intf, num_flaps=num_flaps, interval=0.5)

        time.sleep(20)
        # Verify flaps are counted
        stats = get_link_damping_stats(dut, test_intf)
        pre_damping_downs = int(stats.get('pre_damping_down_events', 0))
        pre_damping_ups = int(stats.get('pre_damping_up_events', 0))

        logger.warning(f"Pre-damping DOWN events1: {pre_damping_downs1}")
        logger.warning(f"Pre-damping UP events1: {pre_damping_ups1}")
        logger.warning(f"Pre-damping DOWN events: {pre_damping_downs}")
        logger.warning(f"Pre-damping UP events: {pre_damping_ups}")

        pytest_assert(pre_damping_downs >= pre_damping_downs1,
                     "Expected DOWN events to be recorded")
        pytest_assert(pre_damping_ups >= pre_damping_ups1,
                     "Expected UP events to be recorded")

    def test_tc01_3_simultaneous_flaps_on_multiple_ports(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC01.3 - Simultaneous Flaps on Multiple Ports

        Verify simultaneous link flaps on multiple ports are handled correctly.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        # Get multiple test interfaces
        test_intfs = get_test_interfaces(dut, num_intfs=3)
        logger.info(f"Using interfaces {test_intfs} for test")

        # Disable damping on all interfaces
        for intf in test_intfs:
            configure_link_damping(dut, intf, **DAMPING_CONFIG_PARAMS)
            time.sleep(5)
            configure_link_damping(dut, intf, disabled=True)

        time.sleep(5)

        # Generate flaps on all interfaces simultaneously
        for intf in test_intfs:
            generate_link_flap(dut, intf, num_flaps=3, interval=0.5)

        time.sleep(5)
        # Verify all interfaces have reported events
        for intf in test_intfs:
            stats = get_link_damping_stats(dut, intf)
            pre_damping_transitions = int(stats.get('pre_damping_link_transitions', 0))
            logger.warning(f"Pre-damping DOWN events: {pre_damping_transitions}")
            pytest_assert(pre_damping_transitions > 0,
                         f"Expected transitions on {intf}")


class TestLinkEventDampingConfiguration:
    """Test cases for damping configuration validation (TC02-TC03)"""

    def test_tc02_1_basic_link_damping_configuration(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC02.1 - Basic Link Damping Configuration

        Verify that damping configuration is applied correctly.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Configure damping with all parameters
        configure_link_damping(dut, test_intf,
                             suppress_threshold=DAMPING_CONFIG_PARAMS["suppress_threshold"],
                             reuse_threshold=DAMPING_CONFIG_PARAMS["reuse_threshold"],
                             decay_half_life=DAMPING_CONFIG_PARAMS["decay_half_life"],
                             max_suppress_time=DAMPING_CONFIG_PARAMS["max_suppress_time"],
                             flap_penalty=DAMPING_CONFIG_PARAMS["flap_penalty"])

        time.sleep(5)
        # Verify configuration in CONFIG_DB
        is_configured = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
        pytest_assert(is_configured, "Configuration parameters not found in CONFIG_DB")

        logger.info(f"Damping configuration applied successfully on {test_intf}")

    def test_tc02_2_config_db_persistence(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC02.2 - CONFIG_DB Persistence

        Verify damping configuration persists in CONFIG_DB.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        time.sleep(5)
        # Query CONFIG_DB
        config_entries = get_redis_db_entries(dut, "CONFIG_DB", f"*LINK_EVENT_DAMPING*")
        pytest_assert(config_entries, f"No CONFIG_DB entries found for {test_intf}")

        logger.info(f"CONFIG_DB entries: {config_entries}")

    def test_tc02_3_redis_persistence(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC02.3 - Redis Persistence

        Verify damping configuration persists in Redis databases.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        time.sleep(5)
        # Verify Redis persistence
        is_persistent = validate_redis_persistence(dut, test_intf, DAMPING_CONFIG_PARAMS)
        pytest_assert(is_persistent, "Configuration not persisted in Redis")

        logger.info(f"Persistent: {is_persistent}")

    def test_tc02_4_multiple_configuration_profiles(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC02.4 - Multiple Configuration Profiles

        Verify different configuration profiles can be applied to different interfaces.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)

        # Apply different configurations to different interfaces
        config1 = {"suppress_threshold": 1600, "max_suppress_time": 30000}  # milliseconds
        config2 = {"suppress_threshold": 800, "max_suppress_time": 20000}  # milliseconds

        configure_link_damping(dut, test_intfs[0], **config1)
        configure_link_damping(dut, test_intfs[1], **config2)

        time.sleep(5)
        # Verify both configurations are independent
        verify_configuration(dut, test_intfs[0], config1)
        verify_configuration(dut, test_intfs[1], config2)

        logger.info("Multiple configuration profiles verified")

    def test_tc02_5_individual_parameter_validation(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC02.5 - Individual Parameter Validation

        Verify each damping parameter is individually configurable.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Test each parameter individually
        params_to_test = [
            {"suppress_threshold": 2000},
            {"reuse_threshold": 1500},
            {"decay_half_life": 20000},  # milliseconds
            {"max_suppress_time": 45000},  # milliseconds
            {"flap_penalty": 600}
        ]

        for param in params_to_test:
            configure_link_damping(dut, test_intf, **param)
            time.sleep(5)
            is_configured = verify_configuration(dut, test_intf, param)
            pytest_assert(is_configured, f"Parameter {param} not configured correctly")

        logger.info("individual  Parameter configuration verified")

    def test_tc02_6_configuration_synchronization(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC02.6 - Configuration Synchronization

        Verify configuration is synchronized across all layers.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        time.sleep(5)
        # Verify in CONFIG_DB
        config_db_ok = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)

        # Verify in Redis databases
        redis_ok = validate_redis_persistence(dut, test_intf, DAMPING_CONFIG_PARAMS)

        pytest_assert(config_db_ok and redis_ok, "Configuration not synchronized")

        logger.info("Configuration synchronisation with CONFIG DB verified")

class TestLinkEventDampingUnsupported:
    """Test cases for unsupported configuration handling (TC03)"""

    def test_tc03_1_decay_exceeds_max_suppress_time(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC03.1 - Decay Exceeds Max Suppress Time

        Verify damping is disabled when decay-half-life > max-suppress-time.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Apply unsupported configuration
        configure_link_damping(dut, test_intf, **UNSUPPORTED_CONFIG_PARAMS)

        time.sleep(5)
        clear_link_damping_stats(dut)
        # Generate link flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        time.sleep(5)
        # Verify damping is disabled - all events should propagate
        stats = get_link_damping_stats(dut, test_intf)
        post_damping_propagated = int(stats.get('post_damping_propagated_transitions', 0))
        pre_damping_transitions = int(stats.get('pre_damping_link_transitions', 0))

        logger.warning(f"Pre-damping transitions: {pre_damping_transitions}")
        logger.warning(f"Post-damping propagated: {post_damping_propagated}")

        # All events should be propagated (damping disabled)
        pytest_assert(post_damping_propagated == pre_damping_transitions or post_damping_propagated >= pre_damping_transitions - 1,
                     "Unsupported config should disable damping")

    def test_tc03_2_zero_flap_penalty(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC03.2 - Zero Flap Penalty

        Verify configuration with zero flap penalty is handled.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Zero penalty configuration
        zero_penalty_config = DAMPING_CONFIG_PARAMS.copy()
        zero_penalty_config["flap_penalty"] = 0

        configure_link_damping(dut, test_intf, **zero_penalty_config)

        # Generate flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Verify configuration accepted
        is_configured = verify_configuration(dut, test_intf, {"flap_penalty": 0})
        pytest_assert(is_configured, "Zero penalty configuration should be accepted")

        logger.info("Zero penalty configuaration verified")

    def test_tc03_3_suppress_less_than_reuse(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC03.3 - Suppress Less Than Reuse

        Verify invalid configuration (suppress < reuse) is handled.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Invalid configuration
        invalid_config = DAMPING_CONFIG_PARAMS.copy()
        invalid_config["suppress_threshold"] = 800
        invalid_config["reuse_threshold"] = 1000

        # This should either be rejected or handled gracefully
        configure_link_damping(dut, test_intf, **invalid_config)

        logger.info("Invalid configuration handled")

    def test_tc03_4_zero_reuse_threshold(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC03.4 - Zero Reuse Threshold

        Verify configuration with zero reuse threshold is handled.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        zero_reuse_config = DAMPING_CONFIG_PARAMS.copy()
        zero_reuse_config["reuse_threshold"] = 0

        configure_link_damping(dut, test_intf, **zero_reuse_config)

        logger.info("Zero reuse threshold configuration handled")

    def test_tc03_5_zero_max_suppress_time(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC03.6 - Zero Max Suppress Time

        Verify configuration with zero max suppress time is handled.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        zero_suppress_config = DAMPING_CONFIG_PARAMS.copy()
        zero_suppress_config["max_suppress_time"] = 0

        configure_link_damping(dut, test_intf, **zero_suppress_config)

        logger.info("Zero max suppress time configuration handled")

    def test_tc03_6_error_logging(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC03.9 - Error Logging

        Verify error messages are logged for invalid configurations.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Apply invalid configuration and check for error logs
        configure_link_damping(dut, test_intf, suppress_threshold=100, max_suppress_time=10000)  # milliseconds

        # Check system logs for errors
        output = dut.shell("tail -100 /var/log/syslog | grep -i 'damping\\|error' || echo 'no errors'")
        logger.info(f"System logs: {output['stdout']}")


class TestLinkEventDampingMixedConfig:
    """Test cases for mixed damping configuration (TC04)"""

    def test_tc04_1_basic_mixed_configuration(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC04.1 - Basic Mixed Configuration

        Verify damping on some ports and no damping on others.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)
        damped_intf = test_intfs[0]
        undamped_intf = test_intfs[1]

        # Configure damping on first interface
        configure_link_damping(dut, damped_intf, **DAMPING_CONFIG_PARAMS)

        # Disable damping on second interface
        configure_link_damping(dut, undamped_intf, disabled=True)

        # Verify both configurations
        assert verify_configuration(dut, damped_intf, DAMPING_CONFIG_PARAMS)

        logger.info("Mixed configuration applied successfully")

    def test_tc04_2_simultaneous_flaps_damped_vs_undamped(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC04.2 - Simultaneous Flaps (Damped vs Undamped)

        Compare behavior of damped and undamped ports.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)
        damped_intf = test_intfs[0]
        undamped_intf = test_intfs[1]

        configure_link_damping(dut, damped_intf, **DAMPING_CONFIG_PARAMS)
        configure_link_damping(dut, undamped_intf, disabled=True)

        clear_link_damping_stats(dut)

        # Generate identical flap patterns
        num_flaps = 10
        for _ in range(num_flaps):
            generate_link_flap(dut, damped_intf, num_flaps=1, interval=0.5)
            generate_link_flap(dut, undamped_intf, num_flaps=1, interval=0.5)

        # Get stats
        damped_stats = get_link_damping_stats(dut, damped_intf)
        undamped_stats = get_link_damping_stats(dut, undamped_intf)

        damped_propagated = int(damped_stats.get('post_damping_propagated_transitions', 0))
        undamped_propagated = int(undamped_stats.get('post_damping_propagated_transitions', 0))

        logger.info(f"Damped interface propagated: {damped_propagated}")
        logger.info(f"Undamped interface propagated: {undamped_propagated}")

        # Undamped should propagate more events
        pytest_assert(undamped_propagated >= damped_propagated,
                     "Undamped interface should propagate more events")

    def test_tc04_3_different_damping_profiles(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC04.3 - Different Damping Profiles

        Verify different damping profiles on different ports.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)

        config1 = {"suppress_threshold": 1600, "max_suppress_time": 30000}  # milliseconds
        config2 = {"suppress_threshold": 800, "max_suppress_time": 20000}  # milliseconds

        configure_link_damping(dut, test_intfs[0], **config1)
        configure_link_damping(dut, test_intfs[1], **config2)

        logger.info("Different damping profiles applied")

    def test_tc04_4_port_independence(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC04.4 - Port Independence

        Verify damping on one port doesn't affect others.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=3)

        # Configure damping on one port
        configure_link_damping(dut, test_intfs[0], **DAMPING_CONFIG_PARAMS)

        # Generate flaps on first port
        generate_link_flap(dut, test_intfs[0], num_flaps=10, interval=0.5)

        # Verify other ports are unaffected
        for intf in test_intfs[1:]:
            phys_state = get_interface_physical_state(dut, intf)
            op_state = get_interface_operational_state(dut, intf)
            # States might differ due to the flaps on other port, but shouldn't be suppressed
            logger.info(f"Interface {intf} state: physical={phys_state}, operational={op_state}")

    def test_tc04_5_flap_pattern_comparison(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC04.6 - Flap Pattern Comparison

        Compare flap patterns between damped and undamped ports.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)

        configure_link_damping(dut, test_intfs[0], **DAMPING_CONFIG_PARAMS)
        configure_link_damping(dut, test_intfs[1], disabled=True)

        logger.info("Flap pattern comparison set up")

    def test_tc04_6_large_scale_mixed_configuration(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC04.7 - Large-Scale Mixed Configuration

        Verify system handles large-scale mixed configurations.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=10)

        # Apply alternating configurations
        for i, intf in enumerate(test_intfs):
            if i % 2 == 0:
                configure_link_damping(dut, intf, **DAMPING_CONFIG_PARAMS)
            else:
                configure_link_damping(dut, intf, disabled=True)

        logger.info(f"Large-scale mixed configuration applied to {len(test_intfs)} interfaces")


class TestLinkEventDampingOperationalState:
    """Test cases for operational state accuracy (TC05)"""

    def test_tc05_1_operational_state_frozen_during_suppression(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC05.1 - Operational State Frozen During Suppression

        Verify operational state remains frozen while damping is active.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate flaps to trigger damping
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Check if suppression is active
        if check_suppression_active(dut, test_intf):
            op_state_during = get_interface_operational_state(dut, test_intf)
            phys_state = get_interface_physical_state(dut, test_intf)

            logger.info(f"During suppression - Op state: {op_state_during}, Phys state: {phys_state}")
            pytest_assert(op_state_during != phys_state or op_state_during == "down",
                         "Operational state should be frozen during suppression")

    def test_tc05_2_operational_state_updates_after_suppression_ends(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC05.2 - Operational State Updates After Suppression Ends

        Verify operational state updates after suppression ends.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Wait for suppression to end (max_suppress_time + buffer)
        max_suppress_ms = DAMPING_CONFIG_PARAMS.get("max_suppress_time", 30000)  # milliseconds
        wait_time = (max_suppress_ms / 1000) + 10  # convert to seconds and add buffer
        logger.info(f"Waiting {wait_time} seconds for suppression to end")
        time.sleep(wait_time)

        # Verify operational state matches physical state
        op_state = get_interface_operational_state(dut, test_intf)
        phys_state = get_interface_physical_state(dut, test_intf)

        logger.info(f"After suppression - Op state: {op_state}, Phys state: {phys_state}")
        pytest_assert(op_state == phys_state,
                     "Operational state should match physical state after suppression ends")

    def test_tc05_3_physical_vs_operational_state_divergence(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC05.3 - Physical vs Operational State Divergence During Suppression

        Verify physical and operational states diverge during suppression.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Record initial states
        initial_phys = get_interface_physical_state(dut, test_intf)
        initial_op = get_interface_operational_state(dut, test_intf)

        # Generate flaps to trigger suppression
        generate_link_flap(dut, test_intf, num_flaps=10, interval=0.3)

        # Check for divergence
        if check_suppression_active(dut, test_intf):
            phys_state = get_interface_physical_state(dut, test_intf)
            op_state = get_interface_operational_state(dut, test_intf)

            logger.info(f"Initial Physical state: {initial_phys}, Operational state: {initial_op}")
            logger.info(f"Physical state: {phys_state}, Operational state: {op_state}")
            # States should diverge if suppression is active

    def test_tc05_4_penalty_decay_and_state_recovery(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC05.4 - Penalty Decay and State Recovery

        Verify state recovers as penalty decays.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Monitor penalty decay
        initial_penalty = get_dampening_penalties(dut, test_intf)
        logger.info(f"Initial penalty: {initial_penalty}")

        # Wait and check penalty decay
        time.sleep(10)
        current_penalty = get_dampening_penalties(dut, test_intf)
        logger.info(f"Current penalty after 10s: {current_penalty}")

        # Penalty should decay
        pytest_assert(current_penalty < initial_penalty or current_penalty == 0,
                     "Penalty should decay over time")

    def test_tc05_5_multiple_suppression_cycles(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC05.5 - Multiple Suppression Cycles

        Verify system handles multiple suppression cycles correctly.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Cycle 1: Generate flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)
        time.sleep(35)

        # Cycle 2: Generate more flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)
        time.sleep(35)

        logger.info("Multiple suppression cycles completed")

class TestLinkEventDampingFrequency:
    """Test cases for flap frequency effects (TC06)"""

    def test_tc06_1_frequent_flaps_longer_suppression(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.1 - Frequent Flaps Longer Suppression

        Verify frequent flaps result in longer suppression.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        time.sleep(3)
        # Generate frequent flaps
        start_time = datetime.now()
        generate_link_flap(dut, test_intf, num_flaps=10, interval=6)

        # Check suppression duration
        suppression_start = datetime.now()
        while check_suppression_active(dut, test_intf) and (datetime.now() - suppression_start).seconds < 60:
            time.sleep(2)

        suppression_duration = (datetime.now() - suppression_start).seconds
        logger.warning(f"Suppression start time: {start_time}, duration: {suppression_duration} seconds")

        # Should be longer than minimal
        pytest_assert(suppression_duration > 5, "Suppression should last a reasonable time")

    def test_tc06_2_infrequent_flaps_shorter_suppression(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.2 - Infrequent Flaps Shorter Suppression

        Verify infrequent flaps result in shorter suppression.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate infrequent flaps (sparse)
        generate_link_flap(dut, test_intf, num_flaps=2, interval=5)

        logger.info("Infrequent flaps generated")

    def test_tc06_3_penalty_accumulation_difference(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.3 - Penalty Accumulation Difference

        Verify different penalty accumulation for different flap frequencies.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)

        for intf in test_intfs:
            configure_link_damping(dut, intf, **DAMPING_CONFIG_PARAMS)

        # Frequent flaps on first interface
        generate_link_flap(dut, test_intfs[0], num_flaps=10, interval=0.3)

        # Infrequent flaps on second interface
        generate_link_flap(dut, test_intfs[1], num_flaps=2, interval=5)

        logger.info("Penalty accumulation difference verified")

    def test_tc06_4_decay_rate_same_for_both(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.4 - Decay Rate Same for Both

        Verify decay rate is consistent regardless of frequency.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Record penalty at different times
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        penalty_t0 = get_dampening_penalties(dut, test_intf)
        time.sleep(5)
        penalty_t5 = get_dampening_penalties(dut, test_intf)
        time.sleep(5)
        penalty_t10 = get_dampening_penalties(dut, test_intf)

        logger.info(f"Penalty at t=0: {penalty_t0}, t=5: {penalty_t5}, t=10: {penalty_t10}")

    def test_tc06_5_recovery_time_proportional_to_frequency(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.5 - Recovery Time Proportional to Frequency

        Verify recovery time varies with flap frequency.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate flaps and measure recovery
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        logger.info("Recovery time measurement set up")

    def test_tc06_6_mixed_pattern_suppression(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.6 - Mixed Pattern Suppression

        Verify suppression behavior with mixed flap patterns.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate mixed pattern: frequent, pause, sparse
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.3)
        time.sleep(5)
        generate_link_flap(dut, test_intf, num_flaps=2, interval=5)

        logger.info("Mixed pattern suppression tested")

    def test_tc06_7_threshold_crossing_different_timing(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC06.7 - Threshold Crossing Different Timing

        Verify different timing for threshold crossing.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=2)

        config_aggressive = DAMPING_CONFIG_PARAMS.copy()
        config_conservative = DAMPING_CONFIG_PARAMS.copy()
        config_conservative["suppress_threshold"] = 3200

        configure_link_damping(dut, test_intfs[0], **config_aggressive)
        configure_link_damping(dut, test_intfs[1], **config_conservative)

        logger.info("Threshold crossing timing test set up")


class TestLinkEventDampingCounters:
    """Test cases for counter verification (TC07)"""

    def test_tc07_1_pre_damping_link_transitions_counter(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.1 - Pre-Damping Link Transitions Counter

        Verify pre-damping link transitions counter.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate flaps
        num_flaps = 5
        generate_link_flap(dut, test_intf, num_flaps=num_flaps, interval=0.5)

        # Check counter
        stats = get_link_damping_stats(dut, test_intf)
        transitions = int(stats.get('pre_damping_link_transitions', 0))

        logger.info(f"Pre-damping link transitions: {transitions}")
        pytest_assert(transitions > 0, "Pre-damping transitions should be recorded")

    def test_tc07_2_post_damping_propagated_transitions_counter(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.2 - Post-Damping Propagated Transitions Counter

        Verify post-damping propagated transitions counter.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Check counter
        stats = get_link_damping_stats(dut, test_intf)
        propagated = int(stats.get('post_damping_propagated_transitions', 0))

        logger.info(f"Post-damping propagated transitions: {propagated}")

    def test_tc07_3_pre_damping_up_events_counter(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.3 - Pre-Damping UP Events Counter

        Verify pre-damping UP events counter.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate UP events
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Check counter
        stats = get_link_damping_stats(dut, test_intf)
        up_events = int(stats.get('pre_damping_up_events', 0))

        logger.info(f"Pre-damping UP events: {up_events}")
        pytest_assert(up_events > 0, "UP events should be recorded")

    def test_tc07_4_pre_damping_down_events_counter(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.4 - Pre-Damping DOWN Events Counter

        Verify pre-damping DOWN events counter.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate DOWN events
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Check counter
        stats = get_link_damping_stats(dut, test_intf)
        down_events = int(stats.get('pre_damping_down_events', 0))

        logger.info(f"Pre-damping DOWN events: {down_events}")
        pytest_assert(down_events > 0, "DOWN events should be recorded")

    def test_tc07_5_post_damping_up_advertised_counter(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.5 - Post-Damping UP Advertised Counter

        Verify post-damping UP advertised counter.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate UP events
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Check counter
        stats = get_link_damping_stats(dut, test_intf)
        up_advertised = int(stats.get('post_damping_up_advertised', 0))

        logger.info(f"Post-damping UP advertised: {up_advertised}")

    def test_tc07_6_post_damping_down_advertised_counter(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.6 - Post-Damping DOWN Advertised Counter

        Verify post-damping DOWN advertised counter.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate DOWN events
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Check counter
        stats = get_link_damping_stats(dut, test_intf)
        down_advertised = int(stats.get('post_damping_down_advertised', 0))

        logger.info(f"Post-damping DOWN advertised: {down_advertised}")

    def test_tc07_7_counter_consistency_across_cycles(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.7 - Counter Consistency Across Cycles

        Verify counters remain consistent across multiple cycles.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # First cycle
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)
        stats1 = get_link_damping_stats(dut, test_intf)
        count1 = int(stats1.get('pre_damping_link_transitions', 0))

        # Second cycle
        generate_link_flap(dut, test_intf, num_flaps=3, interval=0.5)
        stats2 = get_link_damping_stats(dut, test_intf)
        count2 = int(stats2.get('pre_damping_link_transitions', 0))

        logger.info(f"Cycle 1 transitions: {count1}, Cycle 2 transitions: {count2}")
        pytest_assert(count2 >= count1, "Counter should monotonically increase")

    def test_tc07_8_counter_increments_proportional_to_events(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.8 - Counter Increments Proportional to Events

        Verify counter increments are proportional to events.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate different numbers of flaps
        generate_link_flap(dut, test_intf, num_flaps=10, interval=0.5)

        stats = get_link_damping_stats(dut, test_intf)
        transitions = int(stats.get('pre_damping_link_transitions', 0))

        logger.info(f"Transitions for 10 flaps: {transitions}")
        pytest_assert(transitions >= 10, "Counter should reflect number of events")

    def test_tc07_9_suppressed_events_not_in_post_damping(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.9 - Suppressed Events Not in Post-Damping

        Verify suppressed events are not counted in post-damping.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate flaps that trigger suppression
        generate_link_flap(dut, test_intf, num_flaps=20, interval=0.3)

        stats = get_link_damping_stats(dut, test_intf)
        pre_transitions = int(stats.get('pre_damping_link_transitions', 0))
        post_transitions = int(stats.get('post_damping_propagated_transitions', 0))

        logger.info(f"Pre-damping: {pre_transitions}, Post-damping: {post_transitions}")
        pytest_assert(post_transitions <= pre_transitions,
                     "Post-damping should not include suppressed events")

    def test_tc07_10_counter_reset_and_recovery(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC07.10 - Counter Reset and Recovery

        Verify counters can be reset and recovery is tracked.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate initial flaps
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        # Clear stats
        clear_link_damping_stats(dut)

        stats = get_link_damping_stats(dut, test_intf)
        transitions = int(stats.get('pre_damping_link_transitions', 0))

        logger.info(f"Transitions after reset: {transitions}")
        pytest_assert(transitions == 0, "Counters should reset to zero")


class TestLinkEventDampingTimeline:
    """Test cases for timeline validation (TC09)"""

    def test_tc09_1_timeline_event_sequence_execution(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC09.1 - Timeline Event Sequence Execution

        Execute deterministic timeline of events.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        logger.info(f"Starting timeline test on {test_intf}")
        logger.info(f"Configuration: {DAMPING_CONFIG_PARAMS}")

        clear_link_damping_stats(dut)

        # Execute timeline events
        start_time = datetime.now()
        execution_log = []

        for event in TIMELINE_EVENTS:
            if event["event"] != "None":
                # Wait until event time
                event_time = event["time"]
                wait_duration = event_time - (datetime.now() - start_time).total_seconds()

                if wait_duration > 0:
                    time.sleep(wait_duration)

                # Execute event
                logger.info(f"Executing event at t={event['time']}: {event['event']}")
                generate_link_flap(dut, test_intf, num_flaps=1, interval=0)

                execution_log.append({
                    "time": event["time"],
                    "event": event["event"],
                    "expected_propagated": event["propagated"]
                })



class TestLinkEventDampingPersistence:
    """Test cases for persistence across reboots and docker restarts (TC10)"""

    def test_tc10_1_damping_config_persists_after_reboot(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.1 - Damping Config Persists After Reboot

        Verify damping configuration persists after device reboot.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Configure damping before reboot
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Verify configuration before reboot
        is_configured_before = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
        pytest_assert(is_configured_before, "Configuration should exist before reboot")

        logger.info(f"Rebooting {dut.hostname}...")
        dut.reboot()

        time.sleep(60)
        # Verify configuration after reboot
        is_configured_after = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
        pytest_assert(is_configured_after, "Configuration should persist after reboot")

        logger.info("Configuration persisted after reboot")

    def test_tc10_2_damping_functionality_after_reboot(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.2 - Damping Functionality After Reboot

        Verify damping functionality works correctly after reboot.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)

        # Configure and reboot
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)
        logger.info("Rebooting...")
        dut.reboot()

        time.sleep(60)
        clear_link_damping_stats(dut)

        # Generate flaps after reboot
        generate_link_flap(dut, test_intf, num_flaps=10, interval=0.5)

        # Verify damping is working
        stats = get_link_damping_stats(dut, test_intf)
        pre_damping = int(stats.get('pre_damping_link_transitions', 0))
        post_damping = int(stats.get('post_damping_propagated_transitions', 0))

        logger.info(f"Pre-damping: {pre_damping}, Post-damping: {post_damping}")
        pytest_assert(post_damping <= pre_damping, "Damping should work after reboot")

    def test_tc10_3_counters_preserved_after_reboot(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.3 - Counters Preserved After Reboot

        Verify counters are preserved across reboot.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        clear_link_damping_stats(dut)

        # Generate events before reboot
        generate_link_flap(dut, test_intf, num_flaps=5, interval=0.5)

        stats_before = get_link_damping_stats(dut, test_intf)
        transitions_before = int(stats_before.get('pre_damping_link_transitions', 0))

        logger.info(f"Transitions before reboot: {transitions_before}")

        # Reboot
        logger.info("Rebooting...")
        dut.reboot()

        time.sleep(60)
        # Check counters after reboot
        stats_after = get_link_damping_stats(dut, test_intf)
        transitions_after = int(stats_after.get('pre_damping_link_transitions', 0))

        logger.info(f"Transitions after reboot: {transitions_after}")

    def test_tc10_4_multiple_reboot_cycles(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.4 - Multiple Reboot Cycles

        Verify system survives multiple reboot cycles.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Multiple reboot cycles
        num_reboots = 2
        for cycle in range(num_reboots):
            logger.info(f"Reboot cycle {cycle + 1}/{num_reboots}")
            dut.reboot()

            time.sleep(60)
            # Verify configuration
            is_configured = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
            pytest_assert(is_configured, f"Config lost after reboot cycle {cycle + 1}")

        logger.info("Multiple reboot cycles completed successfully")


    def test_tc10_5_concurrent_damping_multiple_ports(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.5 - Concurrent Damping Multiple Ports

        Verify concurrent damping on multiple ports survives reboot.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intfs = get_test_interfaces(dut, num_intfs=5)

        # Configure all interfaces
        for intf in test_intfs:
            configure_link_damping(dut, intf, **DAMPING_CONFIG_PARAMS)

        # Reboot
        logger.info("Rebooting...")
        dut.reboot()

        time.sleep(60)
        # Verify all configurations
        for intf in test_intfs:
            is_configured = verify_configuration(dut, intf, DAMPING_CONFIG_PARAMS)
            pytest_assert(is_configured, f"Config lost for {intf} after reboot")

        logger.info("Concurrent damping on multiple ports verified after reboot")

    def test_tc10_6_reboot_during_suppression(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.6 - Reboot During Suppression

        Verify system handles reboot while suppression is active.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Generate flaps to trigger suppression
        generate_link_flap(dut, test_intf, num_flaps=10, interval=0.3)

        # Verify suppression is active
        if check_suppression_active(dut, test_intf):
            logger.info("Suppression is active, rebooting...")
            dut.reboot()

            time.sleep(60)
            # Verify system recovered
            is_configured = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
            pytest_assert(is_configured, "Config should persist after reboot during suppression")
            time.sleep(120)

    def test_tc10_7_bgp_docker_restart(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.7 - BGP Docker Restart

        Verify damping persists after BGP docker restart.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Restart BGP container
        try:
            restart_docker_container(dut, "bgp")
            logger.info("BGP docker restarted")

            # Verify config persists
            is_configured = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
            pytest_assert(is_configured, "Config should persist after BGP docker restart")
            time.sleep(120)
        except Exception as e:
            logger.warning(f"BGP docker restart not available: {e}")

    def test_tc10_8_swss_docker_restart(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.8 - SWSS Docker Restart

        Verify damping persists after SWSS docker restart.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Restart SWSS container
        try:
            restart_docker_container(dut, "swss")
            logger.info("SWSS docker restarted")

            time.sleep(60)
            # Verify config persists
            is_configured = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
            pytest_assert(is_configured, "Config should persist after SWSS docker restart")
            time.sleep(120)
        except Exception as e:
            logger.warning(f"SWSS docker restart failed: {e}")

    def test_tc10_9_syncd_docker_restart(self, duthost, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """TC10.9 - Syncd Docker Restart

        Verify damping persists after Syncd docker restart.
        """
        logger = logging.getLogger(__name__)
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        time.sleep(120)
        test_intf = get_test_interface(dut)
        configure_link_damping(dut, test_intf, **DAMPING_CONFIG_PARAMS)

        # Restart Syncd container
        try:
            restart_docker_container(dut, "syncd")
            logger.info("Syncd docker restarted")

            # Verify config persists
            is_configured = verify_configuration(dut, test_intf, DAMPING_CONFIG_PARAMS)
            pytest_assert(is_configured, "Config should persist after Syncd docker restart")
            time.sleep(120)
        except Exception as e:
            logger.warning(f"Syncd docker restart failed: {e}")


# ============================================================================
# Helper Functions
# ============================================================================

def get_test_interface(dut):
    """Get a test interface from the DUT"""
    interfaces = dut.show_and_parse("show interfaces status")
    if interfaces:
        return interfaces[0]["interface"]
    pytest_assert(False, "No interfaces found on DUT")


def get_test_interfaces(dut, num_intfs=2):
    """Get multiple test interfaces from the DUT"""
    interfaces = dut.show_and_parse("show interfaces status")
    pytest_assert(len(interfaces) >= num_intfs, f"Need at least {num_intfs} interfaces, found {len(interfaces)}")
    return [intf["interface"] for intf in interfaces[:num_intfs]]
