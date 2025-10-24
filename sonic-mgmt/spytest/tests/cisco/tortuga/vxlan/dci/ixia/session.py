from ixnetwork_restpy import Files, SessionAssistant
from spytest import st
import requests
import socket


def test_ixia_connectivity(ixia_vm_ip, api_key):
    """
    Test basic network connectivity to Ixia server before attempting full connection.
    
    Args:
        ixia_vm_ip (str): IP address of the Ixia server
        api_key (str): API key for authentication
        
    Returns:
        bool: True if connectivity tests pass, False otherwise
    """
    st.log(f"Testing connectivity to Ixia server {ixia_vm_ip}")
    
    # Test 1: Basic TCP connectivity on port 443
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout
        result = sock.connect_ex((ixia_vm_ip, 443))
        sock.close()
        
        if result == 0:
            st.log(f"✓ TCP connection to {ixia_vm_ip}:443 successful")
        else:
            st.log(f"✗ TCP connection to {ixia_vm_ip}:443 failed (error {result})")
            return False
    except Exception as e:
        st.log(f"✗ TCP connection test failed: {str(e)}")
        return False
    
    # Test 2: HTTPS connectivity
    try:
        test_url = f"https://{ixia_vm_ip}:443"
        response = requests.get(test_url, timeout=30, verify=False)
        st.log(f"✓ HTTPS connectivity to {ixia_vm_ip} successful (status: {response.status_code})")
    except requests.exceptions.ConnectTimeout:
        st.log(f"✗ HTTPS connection timeout to {ixia_vm_ip}")
        return False
    except requests.exceptions.ConnectionError as e:
        st.log(f"✗ HTTPS connection error to {ixia_vm_ip}: {str(e)}")
        return False
    except Exception as e:
        st.log(f"⚠ HTTPS test completed with warning: {str(e)}")
    
    return True


def get_session_id(api_key):
    """
    Dynamically retrieve active Ixia session ID from the traffic generator.
    
    Queries the Ixia Web API to discover existing sessions and returns the first
    active session ID. This enables automatic session discovery without requiring
    manual session ID specification.
    
    Args:
        api_key (str): API key for authentication with Ixia Web API
        
    Returns:
        str: Session ID of the first active Ixia session
        
    Raises:
        Exception: If no active sessions are found or API call fails
        
    Note:
        Uses testbed configuration to determine Ixia VM IP address from "T1" device
    """
    # Retrieve testbed information and extract Ixia VM IP from T1 device configuration
    wa = st.getwa()
    ixia_vm_ip = wa.net.tb.devices["T1"]["properties"]["ix_server"]

    # Construct REST API URL for session discovery on Ixia chassis
    session_url = f"https://{ixia_vm_ip}:443/api/v1/sessions"
    # Configure HTTP headers for authenticated API request
    headers = {
        "content-type": "application/json",
        "x-api-key": f"{api_key}",
    }

    # Execute GET request to retrieve all active sessions
    # Disable SSL verification and proxy for direct chassis communication
    response = requests.request(
        "GET", session_url, headers=headers, verify=False, proxies={}
    )

    # Validate API response and handle errors
    if response.status_code != 200:
        raise Exception(f"Failed to fetch IXIA sessions: {response.text}")

    # Parse JSON response and validate session availability
    sessions = response.json()
    if not sessions:
        raise Exception("No active IXIA sessions found.")

    # Return the first available session ID for use in testing
    return sessions[0]["id"]

def session_assistant(ixia_vm_ip, api_key, session_id):
    """
    Create and configure an Ixia SessionAssistant for traffic generator operations.
    
    Initializes a SessionAssistant object with authentication credentials and
    session parameters for communicating with the Ixia traffic generator.
    
    Args:
        ixia_vm_ip (str): IP address of the Ixia Virtual Machine/Chassis
        api_key (str): API key for authentication with Ixia Web API
        session_id (str): Unique session identifier to connect to
        
    Returns:
        SessionAssistant: Configured session object for Ixia operations
        
    Note:
        Uses default admin credentials and INFO log level for debugging
    """
    return SessionAssistant(
        IpAddress=ixia_vm_ip,
        UserName="admin",  # Default Ixia username
        Password="admin",  # Default Ixia password
        ApiKey=api_key,
        LogLevel=SessionAssistant.LOGLEVEL_INFO,  # Enable detailed logging
        SessionId=int(session_id),  # Convert string session ID to integer
    )
