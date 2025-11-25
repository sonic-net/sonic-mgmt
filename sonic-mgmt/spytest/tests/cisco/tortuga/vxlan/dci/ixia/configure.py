import os
from typing import Optional
from ixnetwork_restpy import Files, SessionAssistant
from dci.ixia.session import session_assistant
from dci.ixia.const import CHASSIS_IP_DEFAULT

from spytest import st

def setup_ixia_session(session_assistant: SessionAssistant) -> bool:
    """
    Map physical IXIA ports to virtual ports and establish connections.
    
    Maps physical ports to their corresponding virtual ports based on the vport name
    in the loaded configuration file, then connects with force ownership.
    
    Args:
        session_assistant: The SessionAssistant object
    
    Returns:
        bool: True if setup is successful, False otherwise
    """
    port_map = session_assistant.PortMapAssistant()
    chassis_ip = os.getenv("IXIA_CHASSIS_IP", CHASSIS_IP_DEFAULT)
    
    # Remove any existing chassis entries to avoid duplicates
    st.log("Removing any existing chassis entries...")
    try:
        existing_chassis = session_assistant.Ixnetwork.AvailableHardware.Chassis.find()
        for chassis in existing_chassis:
            st.log(f"Removing existing chassis: {chassis.Hostname}")
            chassis.remove()
            st.log(f"Successfully removed chassis: {chassis.Hostname}")
    except Exception as e:
        st.log(f"No existing chassis to remove or error occurred: {e}")
    
    # Add the chassis
    st.log(f"Adding chassis: {chassis_ip}")
    session_assistant.Ixnetwork.AvailableHardware.Chassis.add(Hostname=chassis_ip)
    st.log(f"Successfully added chassis: {chassis_ip}")
    
    # Get all virtual ports from the loaded configuration
    vports = session_assistant.Ixnetwork.Vport.find()
    st.log(f"Found {len(vports)} virtual ports in configuration")
    
    # Map each virtual port to its corresponding physical port (limit to 6 ports)
    # Extract port number from vport name (e.g., "1/1/6" -> port 6)
    for vport in vports[:6]:  # Limit to first 6 ports
        # Vport name format: "card/slot/port" (e.g., "1/1/6")
        port_parts = vport.Name.split('/')
        if len(port_parts) == 3:
            card_id = int(port_parts[0])
            port_id = int(port_parts[2])
            st.log(f"Mapping chassis {chassis_ip} card {card_id} port {port_id} to vport {vport.Name}")
            port_map.Map(IpAddress=chassis_ip, CardId=card_id, PortId=port_id, Name=vport.Name)
        else:
            st.warn(f"Unexpected vport name format: {vport.Name}, skipping")
    
    # Connect all ports with force ownership to clear any existing ownership
    st.log("Connecting ports with ForceOwnership=True...")
    port_map.Connect(ForceOwnership=True)
    st.log("All ports connected successfully")
    return True


def configure_ixia_session(config_file, ixia_vm_ip, api_key) -> Optional[SessionAssistant]:
    """
    Configure and initialize an Ixia traffic generator session for DCI testing.
    
    This function loads a pre-configured Ixia configuration file, establishes a session
    with the Ixia chassis, and starts all protocols needed for traffic generation.
    Used primarily for HOST traffic emulation in multi-datacenter scenarios.
    
    Args:
        config_file (str): Name of the Ixia configuration file in ixia_config/ directory
        ixia_vm_ip (str): IP address of the Ixia Virtual Machine/Chassis
        api_key (str): API key for authentication with Ixia Web API
        
    Returns:
        SessionAssistant: Configured Ixia session object for traffic operations
        
    Raises:
        SystemExit: If configuration loading or protocol startup fails
        
    Example:
        sess = configure_ixia_session(
            "dci_3dc_6d.ixncfg", 
            "192.168.1.100", 
            "my-api-key"
        )
    """
    # Construct absolute path to Ixia configuration file in ixia subdirectory
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.abspath(os.path.join(script_dir, config_file))
    
    st.log(f"Loading IXIA config file from: {config_path}")
    
    # Establish authenticated session with Ixia chassis using provided credentials
    sess_assistant: SessionAssistant = session_assistant(ixia_vm_ip, api_key)
    
    try:
        # Load the Ixia configuration file (.ixncfg) containing topology and protocol settings
        st.log("Loading IXIA configuration file...")
        sess_assistant.Ixnetwork.LoadConfig(Files(config_path, local_file=True))
        st.log(f"IXIA configuration file {config_path} loaded successfully.")
    except Exception as e:
        st.error(f"Failed to load IXIA config file: {e}")
        return None
    # Allow time for configuration to be fully loaded and applied to the chassis
    st.wait(30, "waiting for IXIA configuration to apply")
    try:
        st.log("Setting up IXIA ports...")
        setup_ixia_session(sess_assistant)
        st.log("IXIA ports setup successfully")
    except Exception as e:
        st.error(f"Failed to setup ports in new IXIA session: {e}")
        return None
    # Return the configured session for traffic generation and control operations
    return sess_assistant