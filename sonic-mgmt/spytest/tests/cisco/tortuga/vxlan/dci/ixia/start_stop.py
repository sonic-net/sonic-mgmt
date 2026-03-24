from ixnetwork_restpy import SessionAssistant

def start_all_protocols(sess_assistant: SessionAssistant):
    """
    Start all protocols on the Ixia chassis synchronously.
    
    This function initiates all configured protocols (e.g., BGP, OSPF) on the Ixia
    traffic generator to ensure they are operational before traffic generation.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        
    Raises:
        SystemExit: If starting protocols fails
        
    Example:
        start_all_protocols(sess)
    """
    from spytest import st

    st.log("Starting all IXIA protocols...")
    try:
        # Start all configured protocols (BGP, OSPF, etc.) synchronously
        sess_assistant.Ixnetwork.StartAllProtocols("sync")
        st.log("Successfully started all IXIA protocols")
    except Exception as e:
        st.error(f"Failed to start all protocols on IXIA: {e}")
        return False
    return True


def stop_all_protocols(sess_assistant: SessionAssistant):
    """
    Stop all protocols on the Ixia chassis synchronously.
    
    This function halts all running protocols on the Ixia traffic generator,
    effectively stopping all network emulation activities.
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
    Raises:
        SystemExit: If stopping protocols fails
    Example:
        stop_all_protocols(sess)
    """
    from spytest import st

    st.log("Stopping all IXIA protocols...")
    try:
        # Stop all running protocols synchronously
        sess_assistant.Ixnetwork.StopAllProtocols("sync")
        st.log("Successfully stopped all IXIA protocols")
    except Exception as e:
        st.error(f"Failed to stop all protocols on IXIA: {e}")
        return False
    return True


def send_arp_and_regenerate_traffic(sess_assistant: SessionAssistant) -> bool:
    """
    Send ARP/ND and regenerate traffic to resolve destination MAC addresses.
    
    This function should be called after protocols are started and before applying
    traffic to ensure all destination MAC addresses are properly resolved.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        
    Returns:
        bool: True if ARP resolution and regeneration succeeded, False otherwise
        
    Example:
        send_arp_and_regenerate_traffic(sess)
    """
    from spytest import st
    
    st.log("Resolving destination MAC addresses for traffic items...")
    try:
        # Send ARP/ND to resolve MAC addresses
        st.log("Sending ARP to all interfaces...")
        try:
            sess_assistant.Ixnetwork.SendArpAll()
            st.wait(5, "waiting for ARP resolution to complete")
        except Exception as arp_error:
            st.warn(f"SendArpAll failed or not supported: {arp_error}")
            # Try alternative method for L2/L3 interface ARP
            try:
                st.log("Attempting alternative ARP method via interface protocol...")
                topology = sess_assistant.Ixnetwork.Topology.find()
                for topo in topology:
                    device_groups = topo.DeviceGroup.find()
                    for dg in device_groups:
                        try:
                            # Send ARP from IPv4 interfaces
                            ipv4 = dg.Ethernet.find().Ipv4.find()
                            if ipv4:
                                ipv4.SendArp()
                        except:
                            pass
                        try:
                            # Send Neighbor Discovery from IPv6 interfaces
                            ipv6 = dg.Ethernet.find().Ipv6.find()
                            if ipv6:
                                ipv6.SendNs()
                        except:
                            pass
                st.wait(5, "waiting for ARP/ND resolution to complete")
            except Exception as alt_error:
                st.error(f"Alternative ARP method also failed: {alt_error}")
                return False
        
        # Regenerate all traffic items to pick up resolved MAC addresses
        st.log("Regenerating traffic items with resolved MAC addresses...")
        traffic = sess_assistant.Ixnetwork.Traffic
        traffic_items = traffic.TrafficItem.find()
        
        if not traffic_items:
            st.warn("No traffic items found to regenerate")
            return False
        
        for item in traffic_items:
            st.log(f"Regenerating traffic item: {item.Name}")
            try:
                item.Generate()
            except Exception as gen_error:
                st.error(f"Failed to regenerate traffic item {item.Name}: {gen_error}")
                return False
        
        st.wait(3, "waiting for traffic regeneration to complete")
        st.log("Successfully resolved MAC addresses and regenerated traffic")
        return True
        
    except Exception as e:
        st.error(f"Failed to resolve MAC addresses and regenerate traffic: {e}")
        return False


def cleanup_ixia_session(sess_assistant: SessionAssistant):
    """
    Clean up the Ixia session by stopping protocols and clearing configuration.
    
    This function stops all protocols and clears the configuration, releasing
    all resources including port ownership.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object to cleanup
        
    Example:
        cleanup_ixia_session(sess)
    """
    from spytest import st
    
    try:
        st.log("Stopping all IXIA protocols...")
        stop_all_protocols(sess_assistant)
        st.log("Clearing IXIA configuration...")
        sess_assistant.Ixnetwork.NewConfig()
        st.log("IXIA session cleaned up successfully")
    except Exception as e:
        st.error(f"Error during IXIA session cleanup: {e}")
    

def start_all_traffic_items(sess_assistant: SessionAssistant) -> bool:
    """
    Start all traffic items configured in the Ixia session.
    
    This function resolves MAC addresses, regenerates traffic, and starts all 
    traffic items defined in the Ixia configuration.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
    Returns:
        bool: True if traffic items started successfully, False otherwise
    Example:
        start_all_traffic_items(sess)
    """
    from spytest import st

    st.log("Starting all IXIA traffic items...")
    try:
        # First resolve MAC addresses and regenerate traffic
        if not send_arp_and_regenerate_traffic(sess_assistant):
            st.error("Failed to resolve MAC addresses, traffic may not work properly")
            # Continue anyway to see if it works
        
        # Apply and start all traffic items
        st.log("Applying traffic configuration...")
        sess_assistant.Ixnetwork.Traffic.Apply(async_operation=False)
        st.log("Starting stateless traffic...")
        sess_assistant.Ixnetwork.Traffic.StartStatelessTraffic(async_operation=False)
        st.log("Successfully started all IXIA traffic items")
    except Exception as e:
        st.error(f"Failed to start all traffic items on IXIA: {e}")
        return False
    return True


def stop_all_traffic_items(sess_assistant: SessionAssistant) -> bool:
    """
    Stop all traffic items configured in the Ixia session.
    
    This function halts all ongoing traffic generation activities in the Ixia
    configuration.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
    Returns:
        bool: True if traffic items stopped successfully, False otherwise
    Example:
        stop_all_traffic_items(sess)
    """
    from spytest import st

    st.log("Stopping all IXIA traffic items...")
    try:
        # Stop all traffic items
        sess_assistant.Ixnetwork.Traffic.StopStatelessTraffic(async_operation=False)
        st.log("Successfully stopped all IXIA traffic items")
    except Exception as e:
        st.error(f"Failed to stop all traffic items on IXIA: {e}")
        return False
    return True


def start_device_group(sess_assistant: SessionAssistant, device_group_name: str = None) -> bool:
    """
    Start a specific device group or all device groups; fall back to IPv4-only on failure.
    
    Tries to start the full device group first. If that fails, starts only the IPv4
    stack so ARP and host traffic can still work without BGP or other protocols.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        device_group_name (str, optional): Name of the device group to start.
                                          If None, starts all device groups.
    Returns:
        bool: True if device group or IPv4 stack started successfully, False otherwise
        
    Example:
        # Start a specific device group (or IPv4 only if full start fails)
        start_device_group(sess, device_group_name="DG1")
        
        # Start all device groups (or IPv4 only if full start fails)
        start_device_group(sess)
    """
    from spytest import st

    try:
        ixnetwork = sess_assistant.Ixnetwork
        if device_group_name:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find(Name=device_group_name)
            if not device_groups:
                st.error(f"Device group '{device_group_name}' not found")
                return False
        else:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find()

        if len(device_groups) == 0:
            st.error("No device groups found to start")
            return False

        for device_group in device_groups:
            st.log(f"Starting device group: {device_group.Name}")
            device_group.Start()
            st.log(f"Successfully started device group: {device_group.Name}")
        st.log(f"Successfully started {len(device_groups)} device group(s)")
        return True
    except Exception as e:
        st.warn(f"Starting full device group failed: {e}; falling back to IPv4 stack only")
        return start_protocol_stack(sess_assistant, "ipv4", device_group_name)


def stop_device_group(sess_assistant: SessionAssistant, device_group_name: str = None) -> bool:
    """
    Stop a specific device group or all device groups.
    
    This function stops protocols in a specific device group, allowing for granular
    control over which emulated devices are deactivated.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        device_group_name (str, optional): Name of the device group to stop. 
                                          If None, stops all device groups.
    Returns:
        bool: True if device group(s) stopped successfully, False otherwise
        
    Example:
        # Stop a specific device group
        stop_device_group(sess, device_group_name="DG1")
        
        # Stop all device groups
        stop_device_group(sess)
    """
    from spytest import st

    try:
        ixnetwork = sess_assistant.Ixnetwork
        
        # Direct access to device groups across all topologies
        if device_group_name:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find(Name=device_group_name)
            if not device_groups:
                st.error(f"Device group '{device_group_name}' not found")
                return False
        else:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find()
        
        if len(device_groups) == 0:
            st.error("No device groups found to stop")
            return False
        
        # Stop device groups
        for device_group in device_groups:
            st.log(f"Stopping device group: {device_group.Name}")
            device_group.Stop()
            st.log(f"Successfully stopped device group: {device_group.Name}")
        
        st.log(f"Successfully stopped {len(device_groups)} device group(s)")
        return True
        
    except Exception as e:
        st.error(f"Failed to stop device group(s): {e}")
        return False


def start_protocol_stack(sess_assistant: SessionAssistant, protocol_type: str, 
                        device_group_name: str = None) -> bool:
    """
    Start a specific protocol stack (Ethernet, IPv4, IPv6, BGP) in device groups.
    
    This function provides fine-grained control to start only specific protocol stacks
    within device groups, allowing partial activation of emulated devices.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        protocol_type (str): Type of protocol to start. Options: 'ethernet', 'ipv4', 'ipv6', 
                            'bgpIpv4', 'bgpIpv6'
        device_group_name (str, optional): Name of device group. If None, applies to all.
        
    Returns:
        bool: True if protocol stack(s) started successfully, False otherwise
        
    Example:
        # Start BGP in a specific device group
        start_protocol_stack(sess, "bgpIpv4", device_group_name="DG1")
        
        # Start IPv4 in all device groups
        start_protocol_stack(sess, "ipv4")
    """
    from spytest import st

    try:
        ixnetwork = sess_assistant.Ixnetwork
        
        # Supported protocol types
        supported_protocols = ['ethernet', 'ipv4', 'ipv6', 'bgpipv4', 'bgpipv6']
        
        protocol_type_lower = protocol_type.lower()
        if protocol_type_lower not in supported_protocols:
            st.error(f"Unsupported protocol type: {protocol_type}. "
                    f"Supported types: {', '.join(supported_protocols)}")
            return False
        
        # Direct access to device groups
        if device_group_name:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find(Name=device_group_name)
            if not device_groups:
                st.error(f"Device group '{device_group_name}' not found")
                return False
        else:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find()
        
        if len(device_groups) == 0:
            st.error("No device groups found")
            return False
        
        protocols_started = 0
        for device_group in device_groups:
            try:
                # Navigate protocol stack based on protocol type
                if protocol_type_lower == 'ethernet':
                    protocols = device_group.Ethernet.find()
                elif protocol_type_lower == 'ipv4':
                    protocols = device_group.Ethernet.find().Ipv4.find()
                elif protocol_type_lower == 'ipv6':
                    protocols = device_group.Ethernet.find().Ipv6.find()
                elif protocol_type_lower == 'bgpipv4':
                    protocols = device_group.Ethernet.find().Ipv4.find().BgpIpv4Peer.find()
                elif protocol_type_lower == 'bgpipv6':
                    protocols = device_group.Ethernet.find().Ipv6.find().BgpIpv6Peer.find()
                else:
                    continue
                
                if protocols:
                    st.log(f"Starting {protocol_type} in device group: {device_group.Name}")
                    protocols.Start()
                    protocols_started += 1
                    st.log(f"Successfully started {protocol_type} in {device_group.Name}")
                    
            except AttributeError:
                st.log(f"Protocol {protocol_type} not found in device group: {device_group.Name}")
                continue
        
        if protocols_started == 0:
            st.error(f"No {protocol_type} protocol stacks found to start")
            return False
            
        st.log(f"Successfully started {protocol_type} in {protocols_started} device group(s)")
        return True
        
    except Exception as e:
        st.error(f"Failed to start protocol stack '{protocol_type}': {e}")
        return False


def stop_protocol_stack(sess_assistant: SessionAssistant, protocol_type: str, 
                       device_group_name: str = None) -> bool:
    """
    Stop a specific protocol stack (Ethernet, IPv4, IPv6, BGP) in device groups.
    
    This function provides fine-grained control to stop only specific protocol stacks
    within device groups, allowing partial deactivation of emulated devices.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        protocol_type (str): Type of protocol to stop. Options: 'ethernet', 'ipv4', 'ipv6', 
                            'bgpIpv4', 'bgpIpv6'
        device_group_name (str, optional): Name of device group. If None, applies to all.
        
    Returns:
        bool: True if protocol stack(s) stopped successfully, False otherwise
        
    Example:
        # Stop BGP in a specific device group
        stop_protocol_stack(sess, "bgpIpv4", device_group_name="DG1")
        
        # Stop IPv4 in all device groups
        stop_protocol_stack(sess, "ipv4")
    """
    from spytest import st

    try:
        ixnetwork = sess_assistant.Ixnetwork
        
        # Supported protocol types
        supported_protocols = ['ethernet', 'ipv4', 'ipv6', 'bgpipv4', 'bgpipv6']
        
        protocol_type_lower = protocol_type.lower()
        if protocol_type_lower not in supported_protocols:
            st.error(f"Unsupported protocol type: {protocol_type}. "
                    f"Supported types: {', '.join(supported_protocols)}")
            return False
        
        # Direct access to device groups
        if device_group_name:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find(Name=device_group_name)
            if not device_groups:
                st.error(f"Device group '{device_group_name}' not found")
                return False
        else:
            device_groups = ixnetwork.Topology.find().DeviceGroup.find()
        
        if len(device_groups) == 0:
            st.error("No device groups found")
            return False
        
        protocols_stopped = 0
        for device_group in device_groups:
            try:
                # Navigate protocol stack based on protocol type
                if protocol_type_lower == 'ethernet':
                    protocols = device_group.Ethernet.find()
                elif protocol_type_lower == 'ipv4':
                    protocols = device_group.Ethernet.find().Ipv4.find()
                elif protocol_type_lower == 'ipv6':
                    protocols = device_group.Ethernet.find().Ipv6.find()
                elif protocol_type_lower == 'bgpipv4':
                    protocols = device_group.Ethernet.find().Ipv4.find().BgpIpv4Peer.find()
                elif protocol_type_lower == 'bgpipv6':
                    protocols = device_group.Ethernet.find().Ipv6.find().BgpIpv6Peer.find()
                else:
                    continue
                
                if protocols:
                    st.log(f"Stopping {protocol_type} in device group: {device_group.Name}")
                    protocols.Stop()
                    protocols_stopped += 1
                    st.log(f"Successfully stopped {protocol_type} in {device_group.Name}")
                    
            except AttributeError:
                st.log(f"Protocol {protocol_type} not found in device group: {device_group.Name}")
                continue
        
        if protocols_stopped == 0:
            st.error(f"No {protocol_type} protocol stacks found to stop")
            return False
            
        st.log(f"Successfully stopped {protocol_type} in {protocols_stopped} device group(s)")
        return True
        
    except Exception as e:
        st.error(f"Failed to stop protocol stack '{protocol_type}': {e}")
        return False


def list_device_groups(sess_assistant: SessionAssistant) -> list:
    """
    List all device groups across all topologies.
    
    Args:
        sess_assistant (SessionAssistant): The Ixia session object
        
    Returns:
        list: List of device group names
        
    Example:
        device_groups = list_device_groups(sess)
        # Returns: ['DG1', 'DG2', 'DG3']
    """
    from spytest import st

    try:
        ixnetwork = sess_assistant.Ixnetwork
        
        # Direct access to all device groups
        device_groups = ixnetwork.Topology.find().DeviceGroup.find()
        dg_names = [dg.Name for dg in device_groups]
        
        st.log(f"Found {len(dg_names)} device groups: {', '.join(dg_names)}")
        
        return dg_names
    except Exception as e:
        st.error(f"Failed to list device groups: {e}")
        return []
