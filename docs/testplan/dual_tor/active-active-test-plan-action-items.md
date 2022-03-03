# active-active dualtor test plan action items
This document is served as a blueprint to briefly descibe the roadmap to support active-active dualtor tests and list out all possible active-active test items.
This document is subject to change as the project evolves.
**NOTE**: the scope/detail of server NiC simulator is not within the scope of this document.

## test infrastructure roadmap
1. Add topo definition changes to support per-port cable types:
   - `active-standby`
   - `active-active`
2. Implement server NiC simulator(please refer the server NiC simulator doc for more detail)
3. Add testbed deployment support: `add-topo`, `remove-topo`, `restart-ptf`, and `deploy-mg`.
    3.1. minigraph generation/parsing support for the introduction of `active-active` cable type.
    3.2. support starting either server NiC simulator or mux simulator selectively based on the port cable type.
    3.3. changes to `vm_topology` to configure ovs bridge based on the port cable type.
4. Add utilities modules/functions to interact with the server NiC simulator.
5. Add sanity check support to verify the `active-active` port and its corresponding server NiC simulator service health.

## test infrastrucure items
The test infrastructure items listed here serves the following purposes:
- common utilities to interacts with server NiC simulator service that runs on the test server.
- common utilities to retrieve ToRs' or ports' related data including port mapping, port forwarding state, DB state, etc.
- common utilities to interact with ToRs to change specific settings(forwarding state, port state, etc).
- common utilities to send/verify traffic(Vxlan tunnel traffic checker).

**NOTE**: the original dualtor project had already implemented some of the test infrastructure items, those parts could simply be reused.

### server nic related items
```python
@pytest.fixture(scope="session")
def nic_simulator_server_info(request, tbinfo):
    """Return a tuple of (nic simulator IP, nic simulator port, vmset name)."""
    pass

@pytest.fixture(scope="session")
def restart_nic_simulator(nic_simulator_server_info, vminfo):
    """Restart server nic simulator."""
    pass

@pytest.fixture(scope='module')
def url(mux_server_url, duthost, tbinfo):
    """A helper fixture to return url for a given port and request to the server NiC simulator."""
    pass

@pytest.fixture(scope="module")
def recover_all_directions(url):
    """Recover the ovs bridge flows."""
    pass

@pytest.fixture(scope='function')
def set_drop(url, recover_all_directions):
    """A fixture to set drop for a certain direction on a bridge."""
    pass
```

### CLi related items
```python
@pytest.fixture
def show_forwarding_state():
    """Return a function to show the forwarding state for a port."""
    pass

@pytest.fixture
def force_tor_forwarding_state():
    """Return a function that to set the port forwarding state."""
    pass

@pytest.fixture
def force_all_tors_forwarding_state_active(force_tor_forwarding_state, recover_all_directions):
    """Ensure both ToRs are operated under `active` state."""
    pass
```

### link configuration utilities
```python
@pytest.fixture
def shutdown_fanout_upper_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo):
    """Fixture to shutdown the fanout that connects to the upper ToR's downstream ports."""
    pass

@pytest.fixture
def shutdown_fanout_lower_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo):
    """Fixture to shutdown the fanout that connects to the lower ToR's downstream ports."""
    pass

@pytest.fixture(scope="function")
def drop_flow_upper_tor(set_drop):
    """Remove the flow in the ovs bridge to simulator link drop on the upper tor."""
    pass

@pytest.fixture(scope="function")
def drop_flow_lower_tor(set_drop):
    """Remove the flow in the ovs bridge to simulator link drop on the lower tor."""
    pass
```

### ToR configuration utilities
```python
@pytest.fixture(scope="function")
def shutdown_tor_heartbeat():
    """Return a function to shutdown the LinkProber to simulate heartbeat loss on a ToR."""
    pass
```

### control plane utilties
```python
def verify_tor_state(duthost, expected_forwarding_state, expected_peer_forwarding_state, expected_health):
    """Verify ToR's forwarding state and link manager state."""
    pass
```

### data plane utilities
```python
@pytest.fixture
def vxlan_tunnel_traffic_checker(...):
    """
    Utility to check if there is expected Vxlan tunnel traffic from the standby ToR to the active ToR.
    """
    pass

@pytest.fixture
def send_server_to_t1_with_action(duthosts, ptfhost, ptfadapter, tbinfo):
    """
    Return a function that starts sender to send upstream traffic and sniffer before performing the action on the tor host.
    The returned function should perform the action, then continuously send a packet from the server to T1 every 100s until timeout or packet is received.
    NOTE: For upstream traffic, it should verify that the traffic is balanced across active ToRs.
    """
    pass

@pytest.fixture
def send_t1_to_server_with_action(duthosts, ptfhost, ptfadapter, tbinfo, vxlan_tunnel_traffic_checker):
    """
    Return a function that starts sender to send downstream traffic and sniffer before performing the action on the tor host.
    The returned function should perform the action, then continuously send a packet from a T1 to the server every 100s until timeout or packet is received.
    """
    pass
```

## test case structure
The testcases are meant to cover all the scenarios listed in the `active-active-test-plan`, and it basically follows the same naming convention as exisiting dualtor testcases:
```
test_<dualtor ToR state: active_active|active_standby>_<action>_<traffic direction: upstream|downstream>_<traffic target: self|standby>
```
It's important to note that `traffic target` is only used only for downstream traffic testcases:
    - `self` means the traffic is sent to the ToR that undergoes `action`. 
    - `standby` means the traffic is sent to the standby ToR only when dualtor state is `active_standby`
During test setup, fixture `recover_all_directions` and `force_all_tors_forwarding_state_active` to ensure both ToRs should operate in `active` state.

### upstream traffic verification
```python
def test_active_active_normal_op_upstream(...):
    """
    Verify normal upstream traffic by sending some packets from the server to T1.

    Steps:
        - send_server_to_t1_with_action with NOOP action
            - ensure no traffic interruption
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two active ToRs
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure both ToRs are active
    """
    pass

def test_active_standby_normal_op_upstream(...):
    """
    Verify normal upstream traffic by sending some packets from the server to T1.

    Steps:
        - force_tor_forwarding_state(lower_tor)
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR is toggled to standby
        - send_server_to_t1_with_action with NOOP action
            - ensure no traffic interruption
            - ensure traffic is received on the T1 side
            - ensure traffic is forwarded by the upper_tor
    """
    pass

def test_active_active_link_down_upstream(...):
    """
    Verify upstream traffic if a link between one of the dual ToRs and the server goes down.

    Steps:
        - send_server_to_t1_with_action with link down action to shutdown the link between lower_tor and server.
            - ensure no traffic interruption
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two ToRs before link down
            - ensure traffic is only forwarded by the active ToR after link down
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR switches to standby
    """
    pass

def test_active_active_link_drop_upstream(...):
    """
    Verify upstream traffic if a link between one of the dual ToRs and the server starts dropping packet.

    Steps:
        - send_server_to_t1_with_action with link drop action to drop packets on the link between lower_tor and server.
            - ensure only one traffic interruption after link drop
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two ToRs before link drop
            - ensure traffic is only forwarded by the active ToR after link drop
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR switches to standby
    """
    pass

def test_active_active_tor_heartbeat_loss_upstream(...):
    """
    Verify upstream traffic if link prober on one ToR is stopped.

    Steps:
        - send_server_to_t1_with_action with stop link prober action on the lower_tor.
            - ensure no traffic interruption
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two ToRs before heartbeat loss
            - ensure traffic is only forwarded by the active ToR after heartbeat loss
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR switches to standby
    """
    pass

def test_active_active_tor_failure_upstream(...):
    """
    Verify the upstream traffic if lower_tor goes through ToR failure.

    Steps:
        - send_server_to_t1_with_action with ToR failure action to the lower ToR.
            - ensure only one traffic interruption after ToR failure
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two ToRs before ToR failure
            - ensure traffic is only forwarded by the active ToR after ToR failure
        - verify_tor_state(upper_tor)
            - ensure upper ToR stays active
            - ensure peer admin forwarding state from upper ToR is standby
    """
    pass

def test_active_active_tor_reboot_upstream(...):
    """
    Verify the upstream traffic if lower_tor goes through reboot.

    Steps:
        - send_server_to_t1_with_action with ToR reboot the lower_tor.
            - ensure only one traffic interruption after lower_tor reboot
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two ToRs before lower_tor reboot
            - ensure traffic is only forwarded by the active ToR during lower_tor reboot
            - ensure traffic is balanced across two ToRs after lower_tor recovers from reboot
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure both ToRs are active
    """
    pass

def test_active_active_tor_config_reload_upstream(...):
    """
    Verify the upstream traffic if lower_tor goes through config reload.

    Steps:
        - send_server_to_t1_with_action with ToR config reload the lower_tor.
            - ensure only one traffic interruption after lower_tor config reload
            - ensure traffic is received on the T1 side
            - ensure traffic is balanced across two ToRs before lower_tor config reload
            - ensure traffic is only forwarded by the active ToR during lower_tor config reload
            - ensure traffic is balanced across two ToRs after lower_tor config reload
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure both ToRs are active
    """
    pass
```
### downstream traffic verification
```python
def test_active_active_normal_op_downstream_active(...):
    """
    Verify normal downstream traffic by sending some packets from T1 to server via the active ToR.

    Steps:
        - send_t1_to_server_with_action with NOOP action
            - ensure no traffic interruption
            - ensure traffic is received on the server side
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure both ToRs are active
    """
    pass

def test_active_standby_normal_op_downstream_standby(...):
    """
    Verify normal downstream traffic by sending some packets from T1 to server via the standby ToR.

    Steps:
        - force_tor_forwarding_state(lower_tor)
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR is toggled to standby
        - send_t1_to_server_with_action with NOOP action
            - ensure no traffic interruption
            - ensure traffic is received on the server side
            - ensure the traffic is vxvlan-tunneled from the standby ToR to the active ToR.
    """
    pass

def test_active_active_link_down_downstream_self():
    """
    Verify downstream traffic if a link between one of the dual ToRs and the server goes down.

    Steps:
        - send_t1_to_server_with_action with link down action to shutdown the link between lower_tor and server.
            - ensure only one traffic interruption
            - ensure traffic is received on the server side
            - ensure traffic is forwarded directly to the server by the lower_tor before link down
            - ensure traffic is vxlan-tunneled from the lower_tor to the upper_tor after link down
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR switches to standby
    """
    pass

def test_active_active_link_drop_downstream_self():
    """
    Verify downstream traffic if a link between one of the dual ToRs and the server starts dropping packet.

    Steps:
        - send_t1_to_server_with_action with link drop action on the link between lower_tor and server.
            - ensure only one traffic interruption
            - ensure traffic is received on the server side
            - ensure traffic is forwarded directly to the server by the lower_tor before link drop
            - ensure traffic is vxlan-tunneled from the lower_tor to the upper_tor after link drop
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR switches to standby
    """
    pass

def test_active_active_heartbeat_loss_downstream_self():
    """
    Verify downstream traffic if link prober on one ToR is stopped.

    Steps:
        - send_t1_to_server_with_action with stop link prober action on the lower_tor.
            - ensure only one traffic interruption
            - ensure traffic is received on the server side
            - ensure traffic is forwarded directly to the server by the lower_tor before heartbeat loss
            - ensure traffic is vxlan-tunneled from the lower_tor to the upper_tor after heartbeat loss
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure upper ToR stays active
            - ensure lower ToR switches to standby
    """
    pass

def test_active_active_reboot_self():
    """
    Verify the downstream traffic if lower_tor goes through reboot.

    Steps:
        - send_t1_to_server_with_action with ToR reboot the lower_tor.
            - ensure traffic is forwarded to the server before lower_tor reboot
            - ensure traffic is not forwarded to the server during lower_tor reboot
            - ensure traffic is forwarded to the server after lower_tor recovers from reboot
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure both ToRs are active
    """
    pass

def test_active_active_config_reload_self():
    """
    Verify the downstream traffic if lower_tor goes through config reload.

    Steps:
        - send_t1_to_server_with_action with ToR config reload the lower_tor.
            - ensure traffic is forwarded to the server before lower_tor config reload
            - ensure traffic is not forwarded to the server during lower_tor config reload
            - ensure traffic is forwarded to the server after lower_tor recovers from config reload
        - verify_tor_state(upper_tor) and verify_tor_state(lower_tor)
            - ensure both ToRs are active
    """
    pass
```