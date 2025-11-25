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
    
    This function enables and starts all traffic items defined in the Ixia
    configuration, allowing for traffic generation between emulated devices.
    
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
        # Enable and start all traffic items
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
