# Dual ToR Test Plan Action Items

This document is subject to change as the project evolves.

Not covered in this doc:

1. Method of interacting with/controlling OVS bridge

## Test Structure

The test structure includes the following files, each corresponding to a section/action item below:

### Non-Test Files

* `cli_config_utils.py`
* `control_plane_utils.py`
* `data_plane_utils.py`
* `link_config_utils.py`
* `dual_tor_test_utils.py`
* `tor_config_utils.py`

### Test Files

All of the following test files are dependent on `control_plane_utils.py` and `data_plane_utils.py`. Dependencies on other specific files are listed:

* `test_normal_op.py -> cli_config_utils.py`
* `test_link_failures.py -> link_config_utils.py`
* `test_other_cases.py`
* `test_tor_component_failures.py -> tor_config_utils.py`
* `test_tor_failures.py -> tor_config_utils.py`

## Non-Test Items

To make the tests cases themselves as simple to write as possible, much of the work in the tests will be offloaded to these helper methods/fixtures that should be used within the body of each test case.

### Dual ToR Test Utilities

General test support methods/fixtures

Need to also add fixtures/methods to get the IPs associated with each port/interface

```python
def check_ovs_bridges():
    """
    Verifies that the OVS bridge is operating correctly as part of the sanity check

    Should call the PTF helper method `ping_server_from_tor`

    Returns:
        True if the PTF helper returns true, False otherwise
    """

def ping_server_from_tors():
    """
    Helper method for `check_ovs_bridge` to be run on the PTF

    This function should perform the following steps for all servers under the ToR set:
        1. Ping the server from each ToR
        2. Verify the server receives only the ping from the active ToR
        3. Send a reply from the server
        4. Verify both ToRs receive the reply

    Returns:
        True if the check passes, False otherwise
    """

@pytest.fixture
def tor_mux_intf():
    """
    Returns the interface/port name on the ToR that the mux cable used for testing is connected to (this should be consistent/deterministic between runs)

    Returns:
        The interface name as a string
    """

@pytest.fixture
def ptf_server_intf():
    """
    Returns the port corresponding to the server on the PTF used during the test run (this should be consistent/deterministic between test runs, probably by just using the first server every time)

    Returns:
        The interface name of the server
    """
@pytest.fixture
def t1_upper_tor_intfs():
    """
    Returns the PTF interface(s) that the upper ToR is connected to on the T1 (this should be consistent/deterministic between test runs, probably by just using the first T1 every time)

    The upper ToR may also be known as ToR A

    Returns:
        List containing the interface names on the T1 corresponding to the upper ToR
    """

@pytest.fixture
def t1_lower_tor_intfs():
    """
    Returns the PTF interface(s) that the lower ToR is connected to on the T1 (this should be consistent/deterministic between test runs, probaobly by just using the first T1 every time)

    The lower ToR may also be known as ToR B

    Returns:
        List containing the interface names on the T1 corresponding to the lower ToR
    """
    
def apply_dual_tor_config(duthost, active=True):
    """
    Applies dual ToR configurations to a regular ToR device
    
    Allows mocking/testing parts of a dual ToR system without requiring a dual ToR testbed
    See dual ToR orchagent test plan for details.
    Args:
        duthost: The host on which to apply the config
        active: if True, simulate apply an active ToR. If False, apply standby ToR configs
    """
```

### CLI Configuration Utilities

```python
def change_configs_and_config_reload(tor_host):
    """
    Make some dual ToR config changes (exact changes pending CLI being finalized) and config reload after (on both ToRs)

    Args:
        tor_host: DUT host object from duthosts fixture
    """

def force_active_tor(tor_host, intf):
    """
    Manually set `tor_host` to the active ToR for `intf`

    Args:
        tor_host: DUT host object which will become the active ToR (passed by calling function from duthosts fixture)
        intf: The interface name to set `tor_host` as active on, or 'all'
    """
```

### Link Configuration Utilities

Need to create a fixture to interact with the OVS bridge and add as a parameter to the following methods

```python
def shutdown_active_tor_mux_link():
    """
    Shutdown the link between the OVS bridge and the active ToR
    """

def shutdown_standby_tor_mux_link():
    """
    Shutdown the link between the OVS bridge and the standby ToR
    """

def drop_active_tor_mux_link(): # No longer needed, this behavior is included in the mux simulator client
    """
    Configure the OVS bridge to drop packets between the bridge and the active ToR
    """

def drop_standby_tor_mux_link(): # No longer needed, this behavior is included in the mux simulator client
    """
    Configure the OVS bridge to drop packets between the bridge and the standby ToR
    """
```

### ToR Configuration Utilities

```python
def shutdown_tor_bgp(tor_host):
    """
    Shutdown all BGP sessions on `tor_host`

    Args:
        tor_host: A ToR host object (should be passed by the calling function, from the duthosts fixture)
    """

def shutdown_tor_heartbeat(tor_host):
    """
    Shutdown the LinkProber on `tor_host`
    """

def simulate_tor_failure(tor_host):
    """
    Configure `tor_host` to blackhole all traffic
    """

def reboot_tor(tor_host):
    """
    Reboot `tor_host`
    """
```

### Control Plane Utilities

Methods/fixtures used to verify control plane (APP DB/STATE DB) values

```python
def expect_app_db_values(tor_host, intf_name, state):
    """
    Query APP_DB on `tor_host` and check if mux cable fields match the given parameters

    The following tables/fields are checked:

    MUX_CABLE|PORTNAME:
        - state: <active|standby|unknown>

    HW_MUX_CABLE|PORTNAME
        - state: <active|standby|unknown>

    MUX_CABLE_RESPONSE|PORTNAME:
        - response <active|standby|unknown>

    Args:
        tor_host: DUT host object (needs to be passed by calling function from duthosts fixture)
        intf_name: The PORTNAME to check in each table
        state: The expected value for each field in each table listed above.

    Returns:
        True if actual values match expected, False if not (also should have some mechanism to show the values that don't match, maybe calling `pytest.fail()` with a message)
    """

def expect_state_db_values(tor_host, intf_name, state, health):
    """
    Query STATE_DB on `tor_host` and check if mux cable fields match the given parameters

    The following tables/fields are checked:

    MUX_CABLE_TABLE|PORTNAME:
        - state: <active|standby|unknown>
        - health: <healthy|unhealthy>

    HW_MUX_CABLE_TABLE|PORTNAME:
        - state: <active|standby|unknown>

    Args:
        tor_host: DUT host object (needs to be passed by calling function from duthosts fixture)
        intf_name: The PORTNAME to check in each table
        state: The expected value for each of the `state` fields in both tables
        health: The expected value for the `health` field in the MUX_CABLE_TABLE table

    Returns:
        True if actual values match expected, False if not (also should have some mechanism to show the values that don't match, maybe calling `pytest.fail()` with a message)
    """
```

### Data Plane Utilities

Methods/fixtures used to support data plane operations/verifications

```python
def send_t1_to_server_after_action(server_port, tor_port, expect_tunnel_packet=False, delay=1, timeout=5, action=None, *args):
    """
    Performs `action`, then continuously sends a packet from the T1 to the server every 100ms until timeout or packet is received

    The `delay` is also the maximum allowable traffic interruption time. If after the `delay` the packet cannot be successfully sent, the ToR switchover process is taking too long.

    Should call PTF helper method `send_t1_to_server`

    Args:
        server_port: Corresponds to the destination server
        tor_port: Corresponds to the ToR used to send the packet
        expect_tunnel_packet: Whether or not the T1 should expect to receive a packet through the IP-in-IP tunnel
        delay: Maximum acceptable delay for traffic to continue flowing again
        timeout: Time to wait for packet to be transmitted
        action: Some function which performs the desired action, or `None` if no action/delay is desired
        *args: Any arguments to be passed to `action`
    """

def send_t1_to_server(server_port, tor_port, delay=1, timeout=5, expect_tunnel_packet=False):
    """
    Helper method for `send_t1_to_server_after_action` to be run on PTF

    Send a packet via `tor_port` to the server, and check for an IP-in-IP packet according to `expect_tunnel_packet`. Also check that the server receives the packet.

    If `expect_tunnel_packet` is `True`, check that the T1 receives an IP-in-IP packet from `tor_port`, and no other ports. If `False`, check that no IP-in-IP packets are received from any port.

    Args:
        server_port: The port intended to receive the packet
        tor_port: The port through which to send the packet. Connected to either the upper or lower ToR
        delay: Maximum acceptable delay for traffic to continue flowing again
        timeout: Time to wait for packet to be transmitted
        expect_tunnel_packet: `True` or `False` whether to expect an IP-in-IP tunnel packet
    """

def send_server_to_t1_after_action(server_port, tor_port, delay=1, timeout=5, action=None, *args):
    """
    Performs `action`, then continuously sends a packet from the server to the T1 every 100ms until timeout or packet is received

    The `delay` is also the maximum allowable traffic interruption time. If after the `delay` the packet cannot be successfully sent, the ToR switchover process is taking too long.

    Should call PTF helper method "send_server_to_t1"

    Args:
        server_port: The port to send the packet through
        tor_port: The port on the T1 the packet is expected to be received by
        delay: Maximum acceptable delay for traffic to continue flowing again
        timeout: Timeout to wait for packet to be received
        action: Some function which performs the desired action, or `None` if no action/delay is desired
        *args: Any arguments to be passed to `action`
    """

def send_server_to_t1(server_port, tor_port, delay=1, timeout=5):
    """
    Helper method for `send_server_to_t1_after_action` to be run on PTF

    Send a packet from the server port to the T1, and verify that the packet is received from tor_port and no other ports on the T1

    Args:
        server_port: The port to send the packet through
        tor_port: The port to expect the packet from
        delay: Maximum acceptable delay for traffic to continue flowing again
        timeout: Time to wait for packet to be transmitted
    """
```

## Test Scenarios

All test cases should use either `send_server_to_t1_after_action` or `send_t1_to_server_after_action` to send/verify packets on the data plane, since these methods automatically verify the traffic interruption interval.

The test cases are named according the following format:

```test_<failure/test scenario>_<traffic direction>_<ToR used (for downstream traffic only)>```

It's important to note that for consistency, any time the active or standby ToR (and their respective links/ports) are mentioned, they refer to the state of the ToR prior to the test being run. Please check the test plan HLD for clarification.

So a method testing what happens to downstream traffic (T1->server) passing through the standby ToR when the active ToR reboots would be named:

```test_active_tor_reboot_downstream_standby```

And a method testing what happens to upstream traffic (server->T1) when the active ToR loses its BGP sessions would be named:

```test_active_tor_bgp_down_upstream```

For testing purposes, the upper ToR will be set to the active ToR at the beginning of the test (via the mux simulator, not the SONiC CLI command).

Note that the upper/lower ToR designations do not change throughout the test.

### Normal Operation

```python
def test_normal_oper_upstream(ptf_server_port, t1_upper_tor_port, duthosts, tor_mux_intf):
    """
    Verify normal operation of dual ToR setup by sending traffic from the server to the T1

    Calls `send_server_to_t1_after_action(ptf_server_port, t1_upper_tor_port)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby', 'healthy')
    """

def test_normal_oper_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Verify normal operation of dual ToR setup by sending traffic from the T1 to the server via the active ToR

    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby', 'healthy')
    """

def test_normal_oper_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Verify normal operation of dual ToR setup by sending traffic from the T1 to the server via the standby ToR

    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, expect_tunnel_packet=True)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby', 'healthy')
    """

def test_active_config_reload_upstream(ptf_server_port, t1_lower_tor_port, duthosts):
    """
    Verify operation of dual ToR setup after active ToR config reload by sending traffic from the server to the T1

    Calls `send_server_to_t1_after_action(ptf_server_port, t1_lower_tor_port, action=change_configs_and_config_reload, upper_tor)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'standby')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'standby', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_standby_config_reload_upstream(ptf_server_port, t1_upper_tor_port, duthosts):
    """
    Verify operation of dual ToR setup after standby ToR config reload by sending traffic from the server to the T1

    Calls `send_server_to_t1_after_action(ptf_server_port, t1_upper_tor_port, action=change_configs_and_config_reload, upper_tor)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby', 'healthy')
    """

def test_standby_config_reload_downstream_active(ptf_server_port, t1_upper_tor_port, duthosts):
    """
    Verify operation of dual ToR setup after standby ToR config reload by sending traffic from the T1 to the server via the active ToR

    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, action=change_configs_and_config_reload, duthosts)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'standby', 'healthy')
    """

def test_active_config_reload_downstream_standby(ptf_server_port, t1_lower_tor_port, duthosts):
    """
    Verify operation of dual ToR setup after standby ToR config reload by sending traffic from the T1 to the server via the standby ToR

    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, expect_tunnel_packet=True, action=change_configs_and_config_reload, duthosts)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'standby')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'standby', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_tor_switch_upstream(ptf_server_port, t1_lower_tor_port, duthosts):
    """
    Verify operation of dual ToR setup after switching the active ToR by sending traffic from the server to the T1

    Select the current standby ToR (should be the lower ToR) from duthosts

    Calls `send_server_to_t1_after_action(ptf_server_port, t1_lower_tor_port, action=force_active_tor, current_standby_tor)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'standby')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'standby', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_tor_switch_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Verify operation of dual ToR setup after switching the active ToR by sending traffic from the T1 to the server via the original active ToR

    Select the current standby ToR (should be the lower ToR) from duthosts

    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, expected_tunnel_packet=True, action=force_active_tor, current_standby_tor)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'standby')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'standby', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_tor_switch_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Verify operation of dual ToR setup after switching the active ToR by sending traffic from the T1 to the server via the original standby ToR

    Select the current standby ToR (should be the lower ToR) from duthosts

    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=force_active_tor, current_standby_tor)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'standby')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'standby', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """
```

### Link Failures

```python
def test_active_link_down_upstream(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_lower_tor_port, action=shutdown_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_active_link_down_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, expect_tunnel_packet=True, action=shutdown_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_active_link_down_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_port, action=shutdown_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_standby_link_down_upstream(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_upper_tor_port, action=shutdown_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """

def test_standby_link_down_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, action=shutdown_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """

def test_standby_link_down_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=shutdown_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """

def test_active_link_drop_upstream(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_lower_tor_port, action=drop_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_active_link_drop_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, expect_tunnel_packet=True, action=drop_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_active_link_drop_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=drop_active_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'unknown')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'active')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'unknown', 'unhealthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'active', 'healthy')
    """

def test_standby_link_drop_upstream(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_server_to_t1_after_action(ptf_server_port, t1_upper_tor_port, action=drop_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """

def test_standby_link_drop_downstream_active(ptf_server_port, t1_upper_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_upper_tor_port, action=drop_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """

def test_standby_link_drop_downstream_standby(ptf_server_port, t1_lower_tor_port):
    """
    Calls `send_t1_to_server_after_action(ptf_server_port, t1_lower_tor_port, action=drop_standby_tor_mux_link)`
    Expects `expect_app_db_values(upper_tor, tor_mux_intf, 'active')` and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown')`
    Expects `expect_state_db_values(upper_tor, tor_mux_intf, 'active', 'healthy') and `expect_app_db_values(lower_tor, tor_mux_intf, 'unknown', 'unhealthy')
    """


```

### ToR Component Failures

Failure of individual components on the ToR (see HLD for test steps and expected results)

```python
def test_active_tor_bgp_down_upstream():
def test_active_tor_bgp_down_downstream_active(): # Out of scope, method included for completeness
def test_active_tor_bgp_down_downstream_standby():

def test_standby_tor_bgp_down_upstream():
def test_standby_tor_bgp_down_downstream_active():
def test_standby_tor_bgp_down_downstream_standby(): # Out of scope, method included for completeness

def test_active_tor_heartbeat_loss_upstream():
def test_active_tor_heartbeat_loss_downstream_active():
def test_active_tor_heartbeat_loss_downstream_standby():

def test_standby_tor_heartbeat_loss_upstream():
def test_standby_tor_heartbeat_loss_downstream_active():
def test_standby_tor_heartbeat_loss_downstream_standby():
```

### ToR Failures

Failure of the entire ToR (see HLD for test steps and expected results)

```python
def test_active_tor_failure_upstream():
def test_active_tor_failure_downstream_active(): # Out of scope, method included for completeness
def test_active_tor_failure_downstream_standby():

def test_standby_tor_failure_upstream():
def test_standby_tor_failure_downstream_active():
def test_standby_tor_failure_downstream_standby(): # Out of scope, method included for completeness

def test_active_tor_reboot_upstream():
def test_active_tor_reboot_downstream_active(): # Out of scope, method included for completeness
def test_active_tor_reboot_downstream_standby():

def test_standby_tor_reboot_upstream():
def test_standby_tor_reboot_downstream_active():
def test_standby_tor_reboot_downstream_standby(): # Out of scope, method included for completeness
```

### Other Test Cases

```python
def test_grat_arp():
    """
    Sends an ARP request from the active ToR to the server. Checks that both ToRs learned the reply

    No data plane operations/checks
    """

def test_proxy_arp():
    """
    For servers A and B, with server A having active ToR A and server B having active ToR B, send an ARP request from server A for server B's IP. Then send a packet from server A to server B.

    Control plane: Checks that server A receives an ARP reply with ToR A's MAC for server B's IP
    Data plane: Verify T1 receives IP-in-IP packet from ToR A to ToR B, and that server B receives the packet.
    """
def test_server_down():
    """
    Server stops sending all traffic.

    Verify that the ToR states do not excessively flap between active/standby (check APP DB/STATE DB values at several intervals)

    No data plane operations/checks
    """

def test_tunnel(): 
    """
    This test will no longer be planned. Explicitly checking encap/decap of tunnel packets is reserved for the orchagent tests. Test cases listed in this document will still verify correct tunnel packets.
    
    ~~Send encapped server traffic from ToR A to ToR B, and ToR B to ToR A~~

    ~~Verify that the T1 switch sees the expected IP-in-IP packet, and that each ToR receives the packet~~
    """
```
