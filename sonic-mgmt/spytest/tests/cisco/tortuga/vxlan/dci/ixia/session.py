from ixnetwork_restpy import SessionAssistant
from spytest import st
import requests


def get_session_id(ixia_vm_ip, api_key):
    """
    Dynamically retrieve active Ixia session ID from the traffic generator.
    
    Queries the Ixia Web API to discover existing sessions and returns the first
    active session ID. This enables automatic session discovery without requiring
    manual session ID specification.
    
    Args:
        ixia_vm_ip (str): IP address of the Ixia Virtual Machine/Chassis
        api_key (str): API key for authentication with Ixia Web API
        
    Returns:
        str: Session ID of the first active Ixia session, or None if no sessions found
        
    Note:
        Returns None if no active sessions exist, allowing SessionAssistant to create new session
    """
    # Construct REST API URL for session discovery on Ixia chassis
    session_url = f"https://{ixia_vm_ip}:443/api/v1/sessions"
    # Configure HTTP headers for authenticated API request
    headers = {
        "content-type": "application/json",
        "x-api-key": f"{api_key}",
    }

    st.log(f"Fetching IXIA sessions from VM IP: {ixia_vm_ip}")
    # Execute GET request to retrieve all active sessions
    # Disable SSL verification and proxy for direct chassis communication
    try:
        response = requests.request(
            "GET", session_url, headers=headers, verify=False, proxies={}
        )

        # Validate API response and handle errors
        if response.status_code != 200:
            st.log(f"Failed to fetch IXIA sessions: {response.text}")
            return None

        # Parse JSON response and validate session availability
        sessions = response.json()
        if not sessions:
            st.log("No active IXIA sessions found, will create new session")
            return None

        # Return the first available session ID for use in testing
        session_id = sessions[0]["id"]
        st.log(f"Found existing IXIA session: {session_id}")
        return session_id
    except Exception as e:
        st.log(f"Error fetching sessions: {e}, will create new session")
        return None


def session_assistant(ixia_vm_ip, api_key):
    """
    Create and configure an Ixia SessionAssistant for traffic generator operations.
    
    Automatically discovers existing session or creates new one. This prevents
    "port in use" errors by reusing existing sessions when available.
    
    Args:
        ixia_vm_ip (str): IP address of the Ixia Virtual Machine/Chassis
        api_key (str): API key for authentication with Ixia Web API
        
    Returns:
        SessionAssistant: Configured session object for Ixia operations
        
    Note:
        Uses default admin credentials and INFO log level for debugging.
        Automatically discovers and connects to existing session if available.
    """
    # Try to get existing session first
    session_id = get_session_id(ixia_vm_ip, api_key)
    
    st.log(f"Creating IXIA SessionAssistant for VM IP: {ixia_vm_ip}, Session ID: {session_id}")
    params = {
        "IpAddress": ixia_vm_ip,
        "UserName": "admin",
        "Password": "admin",
        "ApiKey": api_key,
        "LogLevel": SessionAssistant.LOGLEVEL_INFO,
        "ClearConfig": True
    }
    if session_id is not None:
        params["SessionId"] = int(session_id)
    sess = SessionAssistant(**params)
    st.log(f"Successfully created IXIA SessionAssistant")
    return sess
