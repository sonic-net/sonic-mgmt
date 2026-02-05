#!/bin/bash

# Management interface flap script (unified) using Cisco Pacific CLI
# Supports multiple modes: mgmt_flap_single, mgmt_flap_stress, check_prerequisites, check_status

# Make script immune to SSH disconnections and SIGHUP
trap '' HUP
nohup true 2>/dev/null || true

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration constants
readonly DEFAULT_INTERFACE_ID="0/25"               # Default management interface for Cisco devices
readonly DEFAULT_ETH_SWITCH_RETRY="10"             # Default retry count for eth switch CLI
readonly DEFAULT_STRESS_CYCLES="10"                # Default number of cycles for stress test
readonly SCRIPT_NAME="$(basename "$0")"

# Set defaults if not provided via environment
ETH_SWITCH_RETRY=${ETH_SWITCH_RETRY:-$DEFAULT_ETH_SWITCH_RETRY}
INTERFACE_ID=${INTERFACE_ID:-$DEFAULT_INTERFACE_ID}
DEBUG=${DEBUG:-0}  # Disable debug logging by default for performance

# Optimized logging function with minimal overhead
log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%H:%M:%S')"
    
    case "$level" in
        ERROR)
            echo "[$timestamp] ERROR: $message" | tee -a "${LOG_FILE:-/dev/stderr}"
            ;;
        INFO)
            echo "[$timestamp] INFO: $message" | tee -a "${LOG_FILE:-/dev/stdout}"
            ;;
        DEBUG)
            if [[ "${DEBUG:-0}" == "1" ]]; then
                echo "[$timestamp] DEBUG: $message" >> "${LOG_FILE:-/dev/stdout}"
            fi
            ;;
    esac
}

# Function to check if Cisco Pacific CLI module is available
check_cisco_module() {
    if python3 -c "import cisco.pacific.eth_switch_cli" >/dev/null 2>&1; then
        log_message DEBUG "Cisco Pacific CLI module is available"
        return 0
    else
        log_message ERROR "Cisco Pacific CLI module not available"
        return 1
    fi
}

# Optimized function to check interface status - return 0 if UP, 1 if DOWN  
# Uses grep for more reliable pattern matching
check_interface_status() {
    local output
    local cmd_result
    
    # Try the command and capture both output and error status
    output=$(python3 -m cisco.pacific.eth_switch_cli "$ETH_SWITCH_RETRY" interfaces status all 2>&1)
    cmd_result=$?
    
    # Log the command result for debugging if needed
    if [[ $cmd_result -ne 0 ]]; then
        log_message DEBUG "Interface status command failed: exit=$cmd_result, output='$output'"
        return 1
    fi
    
    # Check if we got any output at all
    if [[ -z "$output" ]]; then
        log_message DEBUG "Interface status command returned empty output"
        return 1
    fi
    
    # Use grep to find the interface line and check if it contains "Up"
    # Looking for pattern: "0/25" followed by any text, then "Up"
    if echo "$output" | grep -E "^[[:space:]]*${INTERFACE_ID}[[:space:]]+[^[:space:]]+[[:space:]]+Up[[:space:]]" >/dev/null 2>&1; then
        log_message DEBUG "Interface $INTERFACE_ID found as UP"
        return 0
    else
        log_message DEBUG "Interface $INTERFACE_ID not found as UP in output"
        # For debugging purposes, log the actual output when interface is not UP
        if [[ "${DEBUG:-0}" == "1" ]]; then
            log_message DEBUG "Full output was: $output"
        fi
        return 1
    fi
}

# Function to perform prerequisite checks
check_prerequisites() {
    [[ -f "$0" ]] && check_cisco_module
}

# Validate required environment variables for flap tests
validate_flap_environment() {
    local errors=0
    
    if [[ -z "${TEST_ID:-}" ]]; then
        log_message ERROR "TEST_ID environment variable is required"
        ((errors++))
    fi
    
    if [[ -z "${LOG_FILE:-}" ]]; then
        log_message ERROR "LOG_FILE environment variable is required"
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_message ERROR "Missing $errors required environment variable(s)"
        log_message INFO "ETH_SWITCH_RETRY will default to $DEFAULT_ETH_SWITCH_RETRY"
        log_message INFO "INTERFACE_ID will default to $DEFAULT_INTERFACE_ID"
        return 1
    fi
    
    return 0
}

# Parse command line arguments
MODE="${1:-}"

# Handle different modes
case "$MODE" in
    "check_prerequisites")
        check_prerequisites
        exit $?
        ;;
    "check_status")
        check_interface_status
        exit $?
        ;;
    "mgmt_flap_single"|"mgmt_flap_stress")
        # Validate environment and continue with flap test execution
        if ! validate_flap_environment; then
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {check_prerequisites|check_status|mgmt_flap_single|mgmt_flap_stress}"
        echo "Environment variables for flap tests:"
        echo "  ETH_SWITCH_RETRY (default: $DEFAULT_ETH_SWITCH_RETRY)"
        echo "  INTERFACE_ID (default: $DEFAULT_INTERFACE_ID)" 
        echo "  TEST_ID (required for flap tests)"
        echo "  LOG_FILE (required for flap tests)"
        echo "  NUM_CYCLES (default: 1 for single, $DEFAULT_STRESS_CYCLES for stress)"
        echo "  DEBUG (optional: set to 1 for debug logging)"
        exit 1
        ;;
esac

# Set TEST_MODE based on command argument
readonly TEST_MODE="$MODE"

# Initialize log file immediately with script start marker
if [[ -n "${LOG_FILE:-}" ]]; then
    {
        echo "[$(date '+%H:%M:%S')] INFO: === SCRIPT START: $TEST_MODE ==="
        echo "[$(date '+%H:%M:%S')] INFO: Script: $0"
        echo "[$(date '+%H:%M:%S')] INFO: PID: $$"
    } > "$LOG_FILE"
fi

# File-based locking to prevent concurrent execution
acquire_lock() {
    local lock_file="/tmp/.mgmt_flap_test.lock"
    local max_attempts=5
    local wait_time=3
    
    for ((i=1; i<=max_attempts; i++)); do
        if (set -C; echo $$ > "$lock_file") 2>/dev/null; then
            log_message INFO "Acquired test lock (PID: $$)"
            # Set trap to cleanup lock on exit
            trap "rm -f '$lock_file' 2>/dev/null" EXIT
            return 0
        fi
        
        # Check if lock file exists and if the process is still running
        if [[ -f "$lock_file" ]]; then
            local lock_pid=$(cat "$lock_file" 2>/dev/null || echo "")
            if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
                log_message INFO "Another test is running (PID: $lock_pid), waiting ${wait_time}s (attempt $i/$max_attempts)"
                sleep $wait_time
            else
                log_message INFO "Removing stale lock file (PID: $lock_pid no longer running)"
                rm -f "$lock_file" 2>/dev/null
            fi
        else
            log_message INFO "Lock acquisition failed, retrying (attempt $i/$max_attempts)"
            sleep 1
        fi
    done
    
    log_message ERROR "Failed to acquire test lock after $max_attempts attempts"
    return 1
}

if ! acquire_lock; then
    exit 1
fi

# Set default NUM_CYCLES based on TEST_MODE if not provided
if [[ -z "${NUM_CYCLES:-}" ]]; then
    if [[ "$TEST_MODE" == "mgmt_flap_single" ]]; then
        NUM_CYCLES=1
    else
        NUM_CYCLES="$DEFAULT_STRESS_CYCLES"
    fi
fi
readonly NUM_CYCLES

# Set logger tag and test type based on test mode
if [[ "$TEST_MODE" == "mgmt_flap_single" ]]; then
    readonly LOGGER_TAG="mgmt_restart_test"
    readonly TEST_TYPE="restart"
else
    readonly LOGGER_TAG="mgmt_stress_test"
    readonly TEST_TYPE="stress"
fi

# Log test configuration
log_message INFO "Starting management interface $TEST_TYPE test"
log_message INFO "Configuration: RETRY=$ETH_SWITCH_RETRY, INTERFACE=$INTERFACE_ID, CYCLES=$NUM_CYCLES"

# Prerequisites and initial status check
log_message INFO "=== Prerequisites Check ==="
if ! check_cisco_module; then
    log_message ERROR "Cisco Pacific CLI module not available"
    exit 1
fi

log_message INFO "=== Initial Status Check ==="
if ! check_interface_status; then
    log_message ERROR "Interface $INTERFACE_ID is not UP initially"
    exit 1
fi

# Optimized interface flap function
flap_interface() {
    local cycle="${1:-1}"
    local prefix="${2:-}"
    
    log_message INFO "${prefix}Starting interface flap (cycle $cycle)"
    
    # Disable interface
    if ! timeout 30 python3 -m cisco.pacific.eth_switch_cli "$ETH_SWITCH_RETRY" config-interface-no-speed "$INTERFACE_ID" &>> "$LOG_FILE"; then
        log_message ERROR "${prefix}Failed to disable interface"
        return 1
    fi
    
    # Interface down window for SSH disconnect detection
    sleep 10
    
    # Re-enable interface 
    if ! timeout 30 python3 -m cisco.pacific.eth_switch_cli "$ETH_SWITCH_RETRY" config-interface-speed "$INTERFACE_ID" 1000 SGMII &>> "$LOG_FILE"; then
        log_message ERROR "${prefix}Failed to re-enable interface"
        return 1
    fi
    
    log_message INFO "${prefix}Flap completed successfully"
    return 0
}

# Execute based on test mode
if [[ "$TEST_MODE" == "mgmt_flap_single" ]]; then
    # Single interface restart
    log_message INFO "=== Single Interface Flap Test ==="
    log_message INFO "=== Cycle 1/1 ==="
    
    if flap_interface 1 ""; then
        log_message INFO "Single flap test: SUCCESS"
    else
        log_message ERROR "Single flap test: FAILED"
        exit 1
    fi
else
    # Stress test: multiple cycles with optimized loop
    log_message INFO "=== Stress Test: $NUM_CYCLES Cycles ==="
    
    # Validate NUM_CYCLES
    if [[ ! "$NUM_CYCLES" =~ ^[0-9]+$ ]] || [[ "$NUM_CYCLES" -le 0 ]]; then
        log_message ERROR "Invalid NUM_CYCLES: $NUM_CYCLES"
        exit 1
    fi
    
    SUCCESS_COUNT=0
    stress_start_time=$(date +%s)
    stress_timeout=210  # 3.5 minutes maximum - reduced for efficiency
    
    # Optimized stress test loop
    for ((i=1; i<=NUM_CYCLES; i++)); do
        # Check timeout every 5 cycles
        if [[ $((i % 5)) -eq 1 ]] && [[ $(( $(date +%s) - stress_start_time )) -gt $stress_timeout ]]; then
            log_message ERROR "Stress test timed out after ${stress_timeout}s at cycle $i"
            break
        fi
        
        log_message INFO "=== Cycle $i/$NUM_CYCLES ==="
        
        if flap_interface "$i" "Cycle $i: "; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            log_message ERROR "Cycle $i: FAILED"
        fi
    done
    
    local success_rate=$((SUCCESS_COUNT * 100 / NUM_CYCLES))
    log_message INFO "Summary: $SUCCESS_COUNT/$NUM_CYCLES cycles successful ($success_rate%)"
    
    # All cycles must succeed for stress test to pass
    if [[ $SUCCESS_COUNT -ne $NUM_CYCLES ]]; then
        log_message ERROR "Stress test failed: $SUCCESS_COUNT/$NUM_CYCLES cycles successful"
        exit 1
    fi
    
    log_message INFO "Stress test: SUCCESS"
fi

# Test completed - Python test script handles SSH connectivity verification
sleep 5  # Brief stabilization before exit
log_message INFO "Overall test result: PASSED (interface flaps completed successfully)"
sync
sleep 2
exit 0
