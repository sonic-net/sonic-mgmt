import os
from ixnetwork_restpy import Files, SessionAssistant
from dci.ixia.session import session_assistant

from spytest import st


def configure_ixia_session(config_file, ixia_vm_ip, api_key, session_id):
    """
    Configure and initialize an Ixia traffic generator session for DCI testing.
    
    This function loads a pre-configured Ixia configuration file, establishes a session
    with the Ixia chassis, and starts all protocols needed for traffic generation.
    Used primarily for HOST traffic emulation in multi-datacenter scenarios.
    
    Args:
        config_file (str): Name of the Ixia configuration file in ixia_config/ directory
        ixia_vm_ip (str): IP address of the Ixia Virtual Machine/Chassis
        api_key (str): API key for authentication with Ixia Web API
        session_id (str): Unique session identifier for this test run
        
    Returns:
        SessionAssistant: Configured Ixia session object for traffic operations
        
    Raises:
        SystemExit: If configuration loading or protocol startup fails
        
    Example:
        sess = configure_ixia_session(
            "dci_3dc_6d.ixncfg", 
            "192.168.1.100", 
            "my-api-key", 
            "12345"
        )
    """
    # Construct absolute path to Ixia configuration file in ixia_config subdirectory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "ixia", config_file)
    
    # Establish authenticated session with Ixia chassis using provided credentials
    sess_assistant: SessionAssistant = session_assistant(ixia_vm_ip, api_key, session_id)
    try:
        # Load the Ixia configuration file (.ixncfg) containing topology and protocol settings
        sess_assistant.Ixnetwork.LoadConfig(Files(config_path, local_file=True))
    except Exception as e:
        st.error(f"failed to load IXIA config file: {e}")
        st.abort_module("module_config_failed", "failed to load IXIA config file")
    
    # Allow time for configuration to be fully loaded and applied to the chassis
    st.wait(60)
    try:
        # Start all configured protocols (BGP, OSPF, etc.) synchronously
        # This ensures protocol sessions are established before traffic generation
        sess_assistant.Ixnetwork.StartAllProtocols("sync")
    except Exception as e:
        st.error(f"failed to start all protocols on IXIA: {e}")
        st.abort_module("module_config_failed", "failed to start protocols on IXIA")
    
    # Return the configured session for traffic generation and control operations
    return sess_assistant