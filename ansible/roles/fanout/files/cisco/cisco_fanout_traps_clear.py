#!/usr/bin/python3
import subprocess
import sys
import time

# NOTE: This payload is formatted to avoid "IndentationError" and "EOFError" in dshell.
# 1. No empty lines inside the code block (prevents premature execution).
# 2. We dynamically check for SDK constants to support different image versions.
DSHELL_PAYLOAD = """
import sdk
import sys
try:
    d0 = sdk.la_get_device(0)
    # SDK Version Compatibility Note:
    # - SDK < 1.66 uses uppercase constants (e.g., LA_EVENT_ETHERNET_LACP)
    # - SDK >= 1.66 uses lowercase constants (e.g., la_event_e_ETHERNET_LACP)
    # We map the old name to the new name to support both environments.
    traps = [
        ("LA_EVENT_ETHERNET_L2CP0", "la_event_e_ETHERNET_L2CP0"),
        ("LA_EVENT_ETHERNET_LACP", "la_event_e_ETHERNET_LACP"),
        ("LA_EVENT_ETHERNET_ARP", "la_event_e_ETHERNET_ARP"),
        ("LA_EVENT_ETHERNET_L2CP2", "la_event_e_ETHERNET_L2CP2"),
        ("LA_EVENT_ETHERNET_DHCPV4_SERVER", "la_event_e_ETHERNET_DHCPV4_SERVER"),
        ("LA_EVENT_ETHERNET_DHCPV4_CLIENT", "la_event_e_ETHERNET_DHCPV4_CLIENT"),
        ("LA_EVENT_ETHERNET_DHCPV6_SERVER", "la_event_e_ETHERNET_DHCPV6_SERVER"),
        ("LA_EVENT_ETHERNET_DHCPV6_CLIENT", "la_event_e_ETHERNET_DHCPV6_CLIENT"),
        ("LA_EVENT_ETHERNET_CISCO_PROTOCOLS", "la_event_e_ETHERNET_CISCO_PROTOCOLS"),
        ("LA_EVENT_L3_ISIS_OVER_L3", "la_event_e_L3_ISIS_OVER_L3")
    ]
    print("--- STARTING TRAP CLEAR ---")
    for old, new in traps:
        # Try to get the constant using the new name (SDK 1.66+).
        # If not found, fall back to the old name (SDK < 1.66).
        event_id = getattr(sdk, new, getattr(sdk, old, None))
        if event_id is not None:
            try:
                d0.clear_trap_configuration(event_id)
                print("Cleared: " + new)
            except Exception as e:
                print("Error clearing " + new + ": " + str(e))
        else:
            print("Skipping: " + new + " (Constant not found)")
    print("--- TRAP CLEAR COMPLETE ---")
except Exception as e:
    print("FATAL SDK ERROR: " + str(e))
    sys.exit(1)
"""


def start_dshell_client():
    """
    Starts the dshell_client service inside the syncd container.
    Exits the script if this fails.
    """
    print("Attempting to start dshell_client service...")
    cmd = ["docker", "exec", "syncd", "supervisorctl", "start", "dshell_client"]

    try:
        # Run command with a timeout to prevent hanging
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Check return code
        if result.returncode != 0:
            # Check if it failed because it is already running (supervisor specific)
            if "already started" in result.stdout or "already started" in result.stderr:
                print("dshell_client is already running.")
                return

            print(f"CRITICAL: Failed to start dshell_client. Return Code: {result.returncode}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            sys.exit(1)
        else:
            print("dshell_client started successfully.")

    except Exception as e:
        print(f"CRITICAL: Execution error while starting dshell_client: {e}")
        sys.exit(1)


def attempt_trap_clear():
    # Strip empty lines and append quit()
    lines = [line for line in DSHELL_PAYLOAD.splitlines() if line.strip()]
    clean_payload = "\n".join(lines) + "\n\nquit()\n\n"

    docker_cmd = ["docker", "exec", "-i", "syncd", "sh", "-c", "/usr/bin/dshell_client.py -i"]

    try:
        process = subprocess.run(
            docker_cmd,
            input=clean_payload,
            capture_output=True,
            text=True,
            timeout=45
        )

        if "--- TRAP CLEAR COMPLETE ---" in process.stdout:
            print("Success: Traps cleared.")
            return True
        else:
            # Log failure but don't exit yet
            print(f"Attempt failed. Stderr: {process.stderr}")
            return False
    except Exception as e:
        print(f"Execution error: {e}")
        return False


def main():
    print("Starting Cisco 8102 Trap Clear Sequence...")

    # 1. Start the service ONCE. Fail if it doesn't start.
    start_dshell_client()

    # 2. Retry loop for SDK initialization (trap clearing)
    timeout = 600
    start_time = time.time()

    while (time.time() - start_time) < timeout:
        if attempt_trap_clear():
            sys.exit(0)

        print("SDK not ready. Retrying in 30 seconds...")
        time.sleep(30)

    print("Timeout: Failed to clear traps after 10 minutes.")
    sys.exit(1)


if __name__ == "__main__":
    main()
