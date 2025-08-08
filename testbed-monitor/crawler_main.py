#!/usr/bin/env python3
"""
MAIN FUNCTIONS OVERVIEW:
=======================

Configuration & Database:
- load_duts_and_commands(): Parse YAML config file for devices and commands
- dump_to_db(): Store command results in SQLite database

Core Parsing Functions:
- parse_show_output(): Main parser for tabular CLI outputs (interfaces, drops, etc.)
- parse_column_positions(): Extract column boundaries from separator lines
- parse_npu_counters_output(): Parse NPU/ASIC hardware drop counters
- parse_npu_platform_output(): Parse NPU hardware configuration info
- parse_npu_rx_interface_cgm_output(): Parse RX congestion management details
- parse_npu_tx_cgm_output(): Parse TX congestion management details

Command Execution:
- run_command_on_dut(): Execute CLI commands via SSH with error handling
- handle_npu_counters_command(): Adaptive NPU command execution
- execute_single_command(): Generic command execution wrapper

Setup & Utility:
- setup_drop_counters_on_dut(): Configure drop counter collection
- needs_drop_counter_setup(): Check if drop counter setup is required
- get_npu_command_preference(): Retrieve saved NPU command preferences
- save_npu_command_preference(): Store NPU command preferences per device

Error Handling:
- All functions include comprehensive error handling
- Graceful degradation when parsing fails
- Raw data preservation for debugging
- Configurable abort-on-error behavior

Supported CLI Commands:
- show int counter -d all                    # Interface statistics
- show dropcounter count                     # Drop reason analysis  
- show queue counters                        # Queue-level drops
- show priority-group drop counters          # Priority group drops
- sudo show platform npu counters           # NPU/ASIC hardware counters
- sudo show platform npu global             # NPU configuration info
- sudo show platform npu rx interface_cgm   # RX congestion details
- sudo show platform npu tx cgm_state       # TX congestion details

Dependencies:
- pexpect: SSH session management and command execution
- yaml: Configuration file parsing
- sqlite3: Database operations for result storage
- re: Regular expression parsing for CLI outputs

Compatible with: Python 3.5+ (uses .format() instead of f-strings)
"""

import pexpect
import yaml
import re
import json
import sqlite3
import logging
from datetime import datetime

# Configure logging for debugging and monitoring
# INFO level shows normal operation flow
# WARNING level shows recoverable issues
# ERROR level shows critical failures
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def dump_to_db(dut_name, command, parsed_data, db_path=None, raw_data=None):
    """
    Store command execution results in SQLite database.
    
    This function creates a permanent record of all CLI commands executed,
    their parsed results, and optionally the raw output for debugging.
    
    Args:
        dut_name (str): Device name from testbed configuration
                       Example: "T2-1-LC0", "SPINE-01", "sfd-lc0"
        command (str): The exact CLI command that was executed
                      Example: "show int counter -d all"
        parsed_data (list): Structured data extracted from CLI output
                          Example: [{'iface': 'Ethernet0', 'rx_drp': '0', 'tx_drp': '0'}, ...]
        db_path (str): Full path to SQLite database file
                      Example: "/nobackup/user/packet_monitor_data/crawler-2025-07-14.db"
        raw_data (str, optional): Original CLI output text for debugging
                                 Used when parsing fails or for verification
    
    Raises:
        ValueError: If db_path is None (prevents data loss)
        sqlite3.Error: If database operations fail
    
    Database Schema:
        crawler_logs table:
        - id: Auto-increment primary key
        - dut_name: Device identifier
        - command: CLI command executed
        - json_data: Parsed results as JSON string
        - raw_data: Original CLI output (nullable)
    """
    # Ensure db_path is provided - prevents accidental data loss
    if db_path is None:
        raise ValueError("db_path must be provided - no default database file")
    
    # Convert parsed_data to JSON string for database storage
    # This preserves the structured data while allowing flexible querying
    json_blob = json.dumps(parsed_data)

    # Connect to specified SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table if it doesn't exist - idempotent operation
    # This allows the function to be called without prior database setup
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crawler_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dut_name TEXT,
            command TEXT,
            json_data TEXT,
            raw_data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Add timestamp column to existing tables if it doesn't exist
    try:
        cursor.execute("ALTER TABLE crawler_logs ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Insert new row with command results
    cursor.execute("""
        INSERT INTO crawler_logs (dut_name, command, json_data, raw_data, timestamp)
        VALUES (?, ?, ?, ?, datetime('now'))
    """, (dut_name, command, json_blob, raw_data))

    conn.commit()
    conn.close()

def load_duts_and_commands(file_path):
    """
    Load device configuration and command list from YAML file.
    
    This function parses the testbed configuration file that defines:
    - Device connectivity information (IP, credentials)
    - List of CLI commands to execute on each device
    
    Args:
        file_path (str): Path to YAML configuration file
                        Example: "/path/to/testbed_info.yml"
    
    Returns:
        tuple: (duts_list, commands_list)
            duts_list (list): List of device dictionaries
                Example: [
                    {
                        'name': 'sfd-lc0',
                        'host': '10.81.124.127', 
                        'user': 'cisco',
                        'password': 'cisco123'
                    },
                    ...
                ]
            commands_list (list): List of CLI commands to execute
                Example: [
                    'show int counter -d all',
                    'show dropcounter count',
                    'show queue counters',
                    'show priority-group drop counters'
                ]
    
    Expected YAML Structure:
        all:
          children:
            dut_group:
              hosts:
                device-name-1:
                  ansible_host: "IP_ADDRESS"
                  ansible_user: "USERNAME" 
                  ansible_password: "PASSWORD"
                device-name-2: ...
          commands:
            - "command1"
            - "command2"
    
    Raises:
        yaml.YAMLError: If YAML file is malformed
        KeyError: If required configuration sections are missing
        SystemExit(2): If no commands are defined (configuration error)
    """
    # Load and parse YAML configuration file
    with open(file_path, "r") as f:
        data = yaml.safe_load(f)

    # Extract global command timeout (default to 60 if not specified)
    global_command_timeout = data["all"].get("command_timeout", 60)

    # Extract device information from YAML structure
    # Navigate: all -> children -> dut_group -> hosts
    duts = []
    hosts = data["all"]["children"]["dut_group"]["hosts"]
    for dut_name, dut_info in hosts.items():
        # Create standardized device dictionary for SSH connections
        duts.append({
            "name": dut_name,                           # Device identifier for logs/database
            "host": dut_info["ansible_host"],           # IP address or hostname
            "user": dut_info["ansible_user"],           # SSH username
            "password": dut_info["ansible_password"]    # SSH password (consider using keys)
        })

    # Extract command list with robust error handling
    # Ensure commands is always a list, never None
    commands = data["all"].get("commands", [])
    if commands is None:
        commands = []
    
    # Filter out any None entries that might come from commented YAML lines
    # This prevents issues when YAML comments create null entries
    commands = [cmd for cmd in commands if cmd is not None]
    
    # Validate that at least one command is defined
    # Without commands, the crawler has nothing to do
    if not commands or len(commands) == 0:
        logger.error("ALERT: No commands found in configuration file")
        logger.error("Please add commands to the 'commands:' section in {}".format(file_path))
        exit(2)  # Use exit code 2 for configuration errors
    
    logger.info("Loaded {} devices and {} commands from configuration".format(
        len(duts), len(commands)))
    logger.info("Using command timeout: {} seconds".format(global_command_timeout))
    
    return duts, commands, global_command_timeout

def parse_column_positions(sep_line, sep_char='-'):
    """
    Parse column boundaries from separator line in CLI table output.
    
    SONiC CLI commands often produce tabular output with separator lines
    made of dashes that define column boundaries. This function identifies
    where each column starts and ends.
    
    Args:
        sep_line (str): Line containing column separators
                       Example: "----------  -------  --------  --------"
        sep_char (str): Character used for separation (default: '-')
    
    Returns:
        list: List of (left, right) tuples defining column boundaries
              Example: [(0, 10), (12, 19), (21, 29), (31, 39)]
              
    Example Input:
        "----------  -------  --------  --------"
        
    Example Output:
        [(0, 10), (12, 19), (21, 29), (31, 39)]
        
    This allows extracting column data by position:
        interface_name = data_line[0:10].strip()
        rx_drops = data_line[21:29].strip()
    """
    positions = []
    in_column = False
    
    # Iterate through each character to find column boundaries
    for i, char in enumerate(sep_line + ' '):  # Add space to close final column
        if char == sep_char:
            # Start of a new column boundary
            if not in_column:
                left = i
                in_column = True
        else:
            # End of current column boundary
            if in_column:
                right = i
                positions.append((left, right))
                in_column = False
    
    return positions

def parse_show_output(output_lines, header_len=1):
    """
    Parse structured tabular output from SONiC CLI commands.
    
    This is the main parser for most SONiC commands that produce
    table-formatted output with headers and separator lines.
    
    Supported Output Format:
        HEADER1    HEADER2    HEADER3
        -------    -------    -------
        value1     value2     value3
        value4     value5     value6
        
    OR with multi-line headers:
        HEADER   COMPLEX     ANOTHER
        LINE1    HEADER      HEADER
        -------  -------     -------
        data1    data2       data3
        
    Args:
        output_lines (list): Raw CLI output split into lines
                           Example: ["IFACE  STATE  RX_DRP", 
                                   "-----  -----  ------",
                                   "Eth0   U      0"]
        header_len (int): Number of header lines before separator (default: 1)
                         Set to 2 for multi-line headers
    
    Returns:
        tuple: (parsed_data, failed_raw_data)
            parsed_data (list): List of dictionaries, one per data row
                Example: [
                    {'iface': 'Ethernet0', 'state': 'U', 'rx_drp': '0'},
                    {'iface': 'Ethernet4', 'state': 'X', 'rx_drp': '0'}
                ]
            failed_raw_data (str or None): Raw text of sections that failed parsing
                Used for debugging when CLI format changes
    
    Error Handling:
        - Logs parsing failures but continues processing
        - Returns partial results + failed sections for investigation
        - Gracefully handles malformed or unexpected output formats
        
    Field Name Processing:
        - Converts headers to lowercase
        - Joins multi-line headers with spaces
        - Example: "RX_OK" becomes "rx_ok", "RX ERR" becomes "rx err"
    """
    result = []
    # Regex to identify separator lines (multiple dashes with optional spaces)
    sep_line_pattern = re.compile(r"^\s*-{2,}\s*(-{2,}\s*)*$")
    parse_failed_sections = []

    idx = 0
    while idx < len(output_lines):
        line = output_lines[idx]

        # Look for separator lines that mark table boundaries
        if not sep_line_pattern.match(line):
            idx += 1
            continue

        sep_idx = idx
        sep_line = output_lines[sep_idx]
        
        # Extract section header if present (line before header lines)
        section_line_idx = sep_idx - header_len - 1
        current_section = output_lines[section_line_idx].strip() if section_line_idx >= 0 else None
        
        # Validate we have enough lines for headers
        if sep_idx < header_len:
            logger.warning("Not enough lines above separator to extract headers.")
            idx += 1
            continue

        # Extract header lines (immediately above separator)
        header_lines = output_lines[sep_idx - header_len:sep_idx]
        
        # Extract data lines (immediately below separator until next separator or end)
        content_lines = []
        idx = sep_idx + 1
        while idx < len(output_lines):
            next_line = output_lines[idx]
            # Skip empty lines
            if next_line.strip() == "":
                idx += 1
                continue
            # Stop at next separator (indicates new table section)
            if sep_line_pattern.match(next_line):
                break
            content_lines.append(next_line)
            idx += 1

        # Parse column boundaries from separator line
        try:
            positions = parse_column_positions(sep_line)
        except Exception as e:
            logger.error("Failed to compute column positions: {}".format(e))
            logger.warning("ALERT: Section parsing failed - raw data preserved in database")
            # Save failed section for debugging
            parse_failed_sections.append('\n'.join(header_lines + [sep_line] + content_lines))
            continue

        # Build column headers from header lines
        # Multi-line headers are joined with spaces and converted to lowercase
        headers = []
        for (left, right) in positions:
            # Extract header text from each header line and join
            header = " ".join(header_line[left:right].strip().lower() for header_line in header_lines).strip()
            headers.append(header)

        # Parse each data line into a dictionary
        for line in content_lines:
            row = {}
            # Extract data for each column using position boundaries
            for col_idx, (left, right) in enumerate(positions):
                if col_idx >= len(headers):
                    continue
                key = headers[col_idx]
                val = line[left:right].strip()
                row[key] = val
            
            # Add section information if available
            if current_section:
                row["section"] = current_section
            result.append(row)

    # Return results with any failed sections for debugging
    if parse_failed_sections:
        return result, '\n\n--- FAILED SECTIONS ---\n\n'.join(parse_failed_sections)
    else:
        return result, None

def parse_npu_platform_output(output_lines, asic_id):
    """
    Parse NPU platform information from 'sudo show platform npu global' command.
    
    This command provides hardware-level information about NPU/ASIC configuration,
    including interface mappings, port configurations, and device properties.
    
    Args:
        output_lines (list): Raw command output split into lines
        asic_id (str): ASIC identifier (e.g., "0", "1") for multi-ASIC systems
    
    Returns:
        dict: Structured NPU platform data
            {
                'asic': '0',
                'summary_info': {...},         # Basic ASIC info
                'interface_mapping': [...],    # Interface to port mappings
                'port_mapping': [...],         # Port configuration details  
                'device_properties': {...}     # Hardware capabilities
            }
    
    Example CLI Output Format:
        NPU Global Summary
        ==================
        Number of ports: 128
        Number of queues: 1024
        
        Interface Mapping
        =================
        Interface     Port    Lane
        ---------     ----    ----
        Ethernet0     1       0
        Ethernet4     2       0
        
    Note: Output format varies by NPU vendor and SONiC version
    """
    result = {
        "asic": asic_id,
        "summary_info": {},
        "interface_mapping": [],
        "port_mapping": [],
        "device_properties": {}
    }

    idx = 0
    state = "summary"
    headers = []
    current_table = []

    def flush_table(headers, rows):
        parsed = []
        for row in rows:
            cols = re.findall(r"\S+", row)
            if len(cols) >= len(headers):
                parsed.append({headers[i]: cols[i] for i in range(len(headers))})
        return parsed

    while idx < len(output_lines):
        line = output_lines[idx].strip()

        if not line:
            idx += 1
            continue

        # Detect transition to first table
        if re.match(r"^interface\s+slice\s+ifg\s+serdes", line.lower()):
            state = "interface_table"
            headers = re.findall(r"\S+", line.lower())
            current_table = []
            idx += 1
            continue

        # Detect port mapping table
        if re.match(r"^port\s+sai_lane\s+slice\s+ifg\s+serdes\s+sysport", line.lower()):
            if state == "interface_table":
                result["interface_mapping"] = flush_table(headers, current_table)
            state = "port_table"
            headers = re.findall(r"\S+", line.lower())
            current_table = []
            idx += 1
            continue

        # Detect device properties
        if line.lower().startswith("device properties"):
            if state == "port_table":
                result["port_mapping"] = flush_table(headers, current_table)
            state = "device_properties"
            idx += 1
            continue

        # Handle summary section
        if state == "summary":
            m = re.match(r"([^:]+)\s*:\s*(.*)", line)
            if m:
                k, v = m.groups()
                result["summary_info"][k.strip()] = v.strip()
            elif re.match(r"^[A-Z ]+$", line.strip()):
                result["summary_info"][line.strip()] = True
            idx += 1
            continue

        # Handle tables
        if state in ["interface_table", "port_table"]:
            current_table.append(line)

        # Handle device properties
        elif state == "device_properties":
            match = re.match(r"([^:]+)\s*:\s*(.*)", line)
            if match:
                key, val = match.groups()
                result["device_properties"][key.strip()] = val.strip()

        idx += 1

    # Final flush
    if state == "interface_table":
        result["interface_mapping"] = flush_table(headers, current_table)
    elif state == "port_table":
        result["port_mapping"] = flush_table(headers, current_table)

    return result
def parse_npu_counters_output(output_lines, asic_id):
    """
    Parse NPU drop counters from 'sudo show platform npu counters' command.
    
    This is a critical parser for packet drop monitoring. It extracts detailed
    drop statistics from the NPU/ASIC hardware counters, which provide the
    most accurate view of packet drops at the hardware level.
    
    Args:
        output_lines (list): Raw command output split into lines
        asic_id (str): ASIC identifier (e.g., "0", "1") for multi-ASIC systems
    
    Returns:
        dict: Comprehensive NPU counter statistics
            {
                'asic': '0',
                'npu_host_stats': {...},           # CPU-bound traffic stats
                'forwarding_drop_stats': {...},    # L2/L3 forwarding drops
                'rxcgm_drop_stats': {...},         # RX congestion management drops
                'pdvoq_drop_stats': {...},         # Packet descriptor/VOQ drops  
                'txcgm_drop_stats': {...},         # TX congestion management drops
                'sms_drop_stats': {...},           # SMS fabric drops
                'other_summary_stats': {...},      # Miscellaneous counters
                'slice_counters': {                # Per-slice detailed counters
                    'Slice0': {...},
                    'Slice1': {...}, ...
                },
                'port_error_counters': [...],      # Per-port error statistics
                'crossbar_detected': True/False,   # Crossbar fabric detected
                'counter_overflow_note': True/False # Counter overflow warning
            }
    
    Example CLI Output Sections:
        NPU Host Stats:
        ===============
        Host Pkt Rcvd: 12345
        Host Pkt Drop: 0
        
        Forwarding Drop Stats:
        ======================
        L2_Drops: 0
        L3_Drops: 5
        
        RX CGM Drop Stats:
        ==================
        VOQ_CGM_drops: 100
        ...
        
        ------ crossbar ------  (indicates RX/TX classification boundary)
        
        TX CGM Drop Stats:
        ==================
        Egress_drops: 50
        ...
    
    Key Features:
        - Detects crossbar separator for RX/TX classification
        - Handles counter overflow notifications
        - Parses per-slice detailed statistics
        - Extracts port-specific error counters
        - Robust error handling for format variations
    
    Note: Counter values reset after each command execution on some platforms
    """
    result = {
        "asic": asic_id,
        "npu_host_stats": {},           # Host interface statistics
        "forwarding_drop_stats": {},    # Forwarding engine drops
        "rxcgm_drop_stats": {},         # RX congestion management
        "pdvoq_drop_stats": {},         # Packet descriptor/VOQ drops
        "txcgm_drop_stats": {},         # TX congestion management  
        "sms_drop_stats": {},           # SMS fabric drops
        "other_summary_stats": {},      # Other miscellaneous counters
        "slice_counters": {},           # Per-slice detailed counters
        "port_error_counters": [],      # Per-port error statistics
        "crossbar_detected": False,     # Flag: crossbar boundary found
        "counter_overflow_note": False  # Flag: counter overflow warning
    }

    # Initialize all 6 slices (standard NPU configuration)
    slice_names = ["Slice0", "Slice1", "Slice2", "Slice3", "Slice4", "Slice5"]
    for slice_name in slice_names:
        result["slice_counters"][slice_name] = {}

    idx = 0
    while idx < len(output_lines):
        line = output_lines[idx].strip()

        # Skip empty lines
        if not line:
            idx += 1
            continue

        # Remove ANSI color codes for easier parsing
        # Some CLI outputs contain escape sequences that interfere with regex
        clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)

        # Parse NPU_HOST line
        if "NPU_HOST" in clean_line and "PktsOut=" in clean_line:
            npu_match = re.search(r"NPU_HOST\s+PktsOut=\s*(\d+)\s*,\s*PktsIn \(from TXPP\)=\s*(\d+)", clean_line)
            if npu_match:
                result["npu_host_stats"]["packets_out"] = int(npu_match.group(1))
                result["npu_host_stats"]["packets_in_from_txpp"] = int(npu_match.group(2))
            idx += 1
            continue

        # Parse Total Forwarding drop counter line
        if "Total Forwarding drop counter" in clean_line and "DSP==1" in clean_line:
            drop_match = re.search(r"Total Forwarding drop counter \(DSP==1\):\s*packets\s*=\s*(\d+)\s*,\s*bytes\s*=\s*(\d+)", clean_line)
            if drop_match:
                result["forwarding_drop_stats"]["packets"] = int(drop_match.group(1))
                result["forwarding_drop_stats"]["bytes"] = int(drop_match.group(2))
            idx += 1
            continue

        # Parse RXCGM drop lines with detailed slice/SSP/TC info
        # Pattern: RXCGM Slice=0, SSP = 24, TC = 7  | drops = 5
        if "RXCGM" in clean_line and "drops =" in clean_line:
            rxcgm_match = re.search(r"RXCGM Slice=(\d+),\s*SSP\s*=\s*(\d+),\s*TC\s*=\s*(\d+)\s*\|\s*drops\s*=\s*(\d+)", clean_line)
            if rxcgm_match:
                slice_id = int(rxcgm_match.group(1))
                ssp = int(rxcgm_match.group(2))
                tc = int(rxcgm_match.group(3))
                drops = int(rxcgm_match.group(4))
                key = "slice_{}_ssp_{}_tc_{}_drops".format(slice_id, ssp, tc)
                result["rxcgm_drop_stats"][key] = drops
            idx += 1
            continue

        # Parse RX_METER drop lines (alternative pattern)
        if "RX_METER" in clean_line and "drop_pkts" in clean_line:
            rxcgm_match = re.search(r"RX_METER\s+Slice\s+(\d+):\s*drop_pkts\s*=\s*(\d+)", clean_line)
            if rxcgm_match:
                slice_id = int(rxcgm_match.group(1))
                drop_count = int(rxcgm_match.group(2))
                result["rxcgm_drop_stats"]["slice_{}_drop_pkts".format(slice_id)] = drop_count
            idx += 1
            continue

        # Parse RXCGM slice_drop_pkts lines
        # Pattern: RXCGM Slice0 (counter index = 0), slice_drop_pkts = 168
        if "RXCGM" in clean_line and "slice_drop_pkts" in clean_line:
            rxcgm_match = re.search(r"RXCGM Slice(\d+).*slice_drop_pkts\s*=\s*(\d+)", clean_line)
            if rxcgm_match:
                slice_id = int(rxcgm_match.group(1))
                drop_count = int(rxcgm_match.group(2))
                result["rxcgm_drop_stats"]["slice_{}_slice_drop_pkts".format(slice_id)] = drop_count
            idx += 1
            continue

        # Parse RXCGM total drop counter SQ/SQG lines
        # Pattern: RXCGM Slice 0, total drop counter SQ , SQG = 168
        if "RXCGM" in clean_line and "total drop counter" in clean_line and "SQ" in clean_line:
            rxcgm_match = re.search(r"RXCGM Slice\s+(\d+),\s*total drop counter.*=\s*(\d+)", clean_line)
            if rxcgm_match:
                slice_id = int(rxcgm_match.group(1))
                drop_count = int(rxcgm_match.group(2))
                result["rxcgm_drop_stats"]["slice_{}_total_drop_counter_sq".format(slice_id)] = drop_count
            idx += 1
            continue

        # Parse PDVOQ drop packets (slice-specific)
        if "PDVOQ" in clean_line and "drop packets" in clean_line and "|" in clean_line:
            # Pattern: PDVOQ Slc0 drop packets  =             480    |PDVOQ1  =           26827    |...
            parts = clean_line.split("|")
            for part in parts:
                part_clean = part.strip()
                if not part_clean:
                    continue
                # Match patterns like "PDVOQ Slc0 drop packets  =             480" or "PDVOQ1  =           26827"
                pdvoq_match = re.search(r"PDVOQ(\d*)(?:\s+Slc\d+)?\s+[^=]*=\s*(\d+)", part_clean)
                if pdvoq_match:
                    slice_num = pdvoq_match.group(1) if pdvoq_match.group(1) else "0"
                    drop_count = int(pdvoq_match.group(2))
                    result["pdvoq_drop_stats"]["slice_{}_drop_packets".format(slice_num)] = drop_count
            idx += 1
            continue

        # Parse PDVOQ DROP COUNTERS summary lines
        if "PDVOQ DROP COUNTERS:" in clean_line:
            if "sms_buffers_drop_green" in clean_line:
                drop_match = re.search(r"sms_buffers_drop_green\s*=\s*(\d+)", clean_line)
                if drop_match:
                    result["pdvoq_drop_stats"]["sms_buffers_drop_green"] = int(drop_match.group(1))
            elif "sms_pkts_drop_green" in clean_line:
                drop_match = re.search(r"sms_pkts_drop_green\s*=\s*(\d+)", clean_line)
                if drop_match:
                    result["pdvoq_drop_stats"]["sms_pkts_drop_green"] = int(drop_match.group(1))
            idx += 1
            continue

        # Parse TXCGM non-txcgm drop lines
        if "TXCGM" in clean_line and "non-txcgm drop" in clean_line and "|" in clean_line:
            # Pattern: TXCGM0 non-txcgm drop    =          547579    |TXCGM1  =          529583    |...
            parts = clean_line.split("|")
            for part in parts:
                part_clean = part.strip()
                if not part_clean:
                    continue
                # Match patterns like "TXCGM0 non-txcgm drop    =          547579" or "TXCGM1  =          529583"
                txcgm_match = re.search(r"TXCGM(\d+)\s+[^=]*=\s*(\d+)", part_clean)
                if txcgm_match:
                    slice_num = txcgm_match.group(1)
                    drop_count = int(txcgm_match.group(2))
                    result["txcgm_drop_stats"]["slice_{}_non_txcgm_drop".format(slice_num)] = drop_count
            idx += 1
            continue

        # Parse SMS Read drop fragments
        if "SMS Read:" in clean_line and "drop fragments" in clean_line:
            # Pattern: SMS Read: drop fragments = 5679785
            sms_match = re.search(r"SMS Read:\s*drop fragments\s*=\s*(\d+)", clean_line)
            if sms_match:
                result["sms_drop_stats"]["read_drop_fragments"] = int(sms_match.group(1))
            idx += 1
            continue

        # Parse port-specific error counters
        if "Port" in clean_line and "=" in clean_line and "|" not in clean_line:
            # Pattern: IFG_RX  3 Port  0 rx_errored_blocks_cnt      = 98
            # Pattern: IFG RX  3 Port  0 rx_uncor_cw_cnt            = 4
            port_match = re.search(r"IFG[_ ]RX\s+(\d+)\s+Port\s+(\d+)\s+([^=]+?)\s*=\s*(\d+)", clean_line)
            if port_match:
                ifg_id = int(port_match.group(1))
                port_num = int(port_match.group(2))
                counter_name = port_match.group(3).strip()
                counter_value = int(port_match.group(4))
                
                result["port_error_counters"].append({
                    "ifg_id": ifg_id,
                    "port": port_num,
                    "counter_name": counter_name,
                    "value": counter_value
                })
            idx += 1
            continue

        # Parse general summary lines (for other misc counters) - exclude drop lines since we handle those specifically
        if ("=" in clean_line or ":" in clean_line) and "|" not in clean_line and "Slice" not in clean_line and "CROSS" not in clean_line and "drop" not in clean_line.lower():
            if "=" in clean_line and "," in clean_line:
                pairs = re.findall(r"([^=,]+)=\s*(\d+)", clean_line)
                for key, value in pairs:
                    clean_key = key.strip().replace("(", "").replace(")", "")
                    result["other_summary_stats"][clean_key] = int(value)
            elif ":" in clean_line:
                colon_match = re.match(r"(.+?):\s*(.+)", clean_line)
                if colon_match:
                    key = colon_match.group(1).strip()
                    value_part = colon_match.group(2).strip()
                    numbers = re.findall(r"\d+", value_part)
                    if numbers:
                        if len(numbers) == 1:
                            result["other_summary_stats"][key] = int(numbers[0])
                        else:
                            result["other_summary_stats"][key] = [int(n) for n in numbers]
                    else:
                        result["other_summary_stats"][key] = value_part
            idx += 1
            continue

        # Skip slice header
        if "Slice0" in line and "Slice1" in line:
            idx += 1
            continue

        # Crossbar separator
        if "CROSS" in line and "BAR" in line and "X" in line:
            result["crossbar_detected"] = True
            idx += 1
            continue

        # Counter overflow
        if "(*) = counter overflow" in line:
            result["counter_overflow_note"] = True
            idx += 1
            continue

        # Slice counter lines (general pattern for non-drop counters)
        if "=" in line and "|" in line and "drop" not in line.lower():
            parts = line.split("|")
            if len(parts) >= 6:
                for slice_idx in range(6):
                    if slice_idx < len(parts):
                        part = parts[slice_idx].strip()
                        # Remove ANSI codes from part
                        part_clean = re.sub(r'\x1b\[[0-9;]*m', '', part)
                        match = re.search(r"(.+?)\s*=\s*(\d+)", part_clean)
                        if match:
                            metric = match.group(1).strip()
                            value_str = match.group(2)
                            # Handle overflow markers
                            if "(*)" in part:
                                result["counter_overflow_note"] = True
                            value = int(value_str)
                            slice_name = "Slice{}".format(slice_idx)
                            existing = result["slice_counters"][slice_name].get(metric)
                            if existing is not None:
                                if isinstance(existing, list):
                                    existing.append(value)
                                else:
                                    result["slice_counters"][slice_name][metric] = [existing, value]
                            else:
                                result["slice_counters"][slice_name][metric] = value

        idx += 1

    return result

def parse_npu_rx_interface_cgm_output(output_lines, interface, traffic_class):
    """
    Parse output from 'sudo show platform npu rx interface_cgm -t X -i EthernetY'
    Focus on drop counters only
    """
    result = {
        "interface": interface,
        "traffic_class": traffic_class,
        "tc_drops": {},
        "drop_reasons": {}
    }
    
    idx = 0
    while idx < len(output_lines):
        line = output_lines[idx].strip()
        
        if not line:
            idx += 1
            continue
        
        # Parse TC drop counters: "TC 0: 123"
        if line.startswith("TC ") and ":" in line:
            tc_match = re.match(r"TC (\d+):\s*(\d+)", line)
            if tc_match:
                tc_num = int(tc_match.group(1))
                drop_count = int(tc_match.group(2))
                result["tc_drops"]["tc_{}".format(tc_num)] = drop_count
        
        # Parse drop reasons
        elif "CTC/CTCG drops:" in line:
            drops_match = re.search(r"CTC/CTCG drops:\s*(\d+)", line)
            if drops_match:
                result["drop_reasons"]["ctc_ctcg_drops"] = int(drops_match.group(1))
        
        elif "SQ/SQG drops:" in line:
            drops_match = re.search(r"SQ/SQG drops:\s*(\d+)", line)
            if drops_match:
                result["drop_reasons"]["sq_sqg_drops"] = int(drops_match.group(1))
        
        elif "Headroom drops:" in line:
            drops_match = re.search(r"Headroom drops:\s*(\d+)", line)
            if drops_match:
                result["drop_reasons"]["headroom_drops"] = int(drops_match.group(1))
        
        idx += 1
    
    return result

def parse_npu_tx_cgm_output(output_lines, interface):
    """
    Parse output from 'sudo show platform npu tx cgm_state -i EthernetX'
    Focus on drop packets only
    """
    result = {
        "interface": interface,
        "oq_drops": {}
    }
    
    idx = 0
    while idx < len(output_lines):
        line = output_lines[idx].strip()
        
        if not line:
            idx += 1
            continue
        
        # Parse OQ drop packets: "Interface Ethernet0, OQ 6:"
        # Next lines contain: "drop packets 0 enqueue_packets 0"
        if "Interface" in line and ", OQ " in line:
            oq_match = re.search(r"Interface\s+(\S+),\s+OQ\s+(\d+):", line)
            if oq_match:
                iface = oq_match.group(1)
                oq_num = int(oq_match.group(2))
                
                # Look ahead for drop packets line
                next_idx = idx + 1
                while next_idx < len(output_lines):
                    next_line = output_lines[next_idx].strip()
                    if not next_line:
                        next_idx += 1
                        continue
                    
                    # Parse drop packets from line like: "drop packets 0 enqueue_packets 0"
                    drop_match = re.search(r"drop packets\s+(\d+)", next_line)
                    if drop_match:
                        drop_count = int(drop_match.group(1))
                        result["oq_drops"]["oq_{}".format(oq_num)] = drop_count
                        break
                    
                    # Stop looking if we hit another Interface line
                    if "Interface" in next_line and ", OQ " in next_line:
                        break
                    
                    next_idx += 1
        
        idx += 1
    
    return result

def run_command_on_dut(dut, command, db_path=None, abort_on_error=False, command_timeout=60):
    """
    Execute CLI command on SONiC device via SSH with comprehensive error handling.
    
    This function manages the complete lifecycle of command execution:
    1. SSH connection establishment with authentication
    2. Command execution with timeout protection  
    3. Output capture and parsing
    4. Error detection and recovery
    5. Database storage of results
    
    Args:
        dut (dict): Device configuration dictionary
            {
                'name': 'device-id',      # Device identifier for logs
                'host': '10.1.1.100',     # IP address or hostname  
                'user': 'admin',          # SSH username
                'password': 'secret'      # SSH password
            }
        command (str): CLI command to execute
                      Example: "show int counter -d all"
        db_path (str): Path to SQLite database for result storage
        abort_on_error (bool): If True, raise exception on any error
                              If False, log error and continue (default)
    
    Returns:
        None (results stored in database)
    
    Error Handling:
        - Connection timeouts (30 seconds)
        - Authentication failures  
        - Command execution errors
        - Parsing failures (graceful degradation)
        - SSH session management (proper cleanup)
    
    Special Command Handling:
        - NPU commands: Adaptive ASIC option detection
        - Drop counter setup: Automatic configuration if needed
        - Deep-dive commands: RX/TX interface analysis
        
    Timeout Configuration:
        - SSH connection: 30 seconds
        - Command execution: 120 seconds  
        - Prompt detection: Based on command type
        
    Database Storage:
        All results stored in crawler_logs table:
        - Successful parsing: structured JSON data
        - Failed parsing: raw output for debugging
        - Errors: error details for investigation
    """
    logger.info("Connecting to {} ({})".format(dut['name'], dut['host']))
    child = None

    try:
        # Establish SSH connection with timeout protection
        # Use -tt for proper terminal allocation and TERM=dumb to avoid formatting issues
        # Use -o PubkeyAuthentication=no to force password auth and avoid SSH key issues
        child = pexpect.spawn("ssh -tt -o PubkeyAuthentication=no {}@{}".format(dut['user'], dut['host']), 
                            env={"TERM": "dumb"}, timeout=30)

        # Handle SSH connection prompts
        i = child.expect([
            "Are you sure you want to continue connecting",  # First-time connection
            "password:",                                     # Password prompt
            "Host key verification failed",                  # Host key mismatch
            "REMOTE HOST IDENTIFICATION HAS CHANGED",       # Host key changed warning
            pexpect.EOF,                                     # Connection failed
            pexpect.TIMEOUT                                  # Connection timeout
        ])

        if i == 0:
            # Accept SSH host key for first-time connections
            child.sendline("yes")
            child.expect("password:")
            child.sendline(dut["password"])
        elif i == 1:
            # Standard password authentication
            child.sendline(dut["password"])
        elif i == 2 or i == 3:
            # Host key verification failed - automatically fix it
            logger.warning("SSH host key verification failed for {} - fixing automatically".format(dut['host']))
            child.close()
            
            # Extract the ssh-keygen command to fix the issue
            fix_cmd = "ssh-keygen -f \"{}/.ssh/known_hosts\" -R {}".format(
                os.path.expanduser("~"), dut['host'])
            logger.info("Running: {}".format(fix_cmd))
            
            # Execute the fix command
            import subprocess
            try:
                result = subprocess.run(fix_cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info("Successfully removed old host key for {}".format(dut['host']))
                else:
                    logger.warning("ssh-keygen command completed with return code {}: {}".format(
                        result.returncode, result.stderr.strip()))
            except Exception as e:
                logger.error("Failed to run ssh-keygen: {}".format(e))
                if abort_on_error:
                    raise Exception("Failed to fix SSH host key for {}".format(dut['host']))
                return
            
            # Retry SSH connection after fixing host key
            logger.info("Retrying SSH connection to {} after host key fix".format(dut['host']))
            child = pexpect.spawn("ssh -tt -o PubkeyAuthentication=no {}@{}".format(dut['user'], dut['host']), 
                                env={"TERM": "dumb"}, timeout=30)
            
            # Handle retry connection prompts
            retry_i = child.expect([
                "Are you sure you want to continue connecting",  # First-time connection after fix
                "password:",                                     # Password prompt
                "Host key verification failed",                  # Still failing
                pexpect.EOF,                                     # Connection failed
                pexpect.TIMEOUT                                  # Connection timeout
            ])
            
            if retry_i == 0:
                # Accept new SSH host key
                child.sendline("yes")
                child.expect("password:")
                child.sendline(dut["password"])
            elif retry_i == 1:
                # Standard password authentication
                child.sendline(dut["password"])
            else:
                # Still failing after fix
                logger.error("SSH connection still failing for {} after host key fix".format(dut['host']))
                if abort_on_error:
                    raise Exception("SSH connection failed after host key fix for {}".format(dut['host']))
                return
        else:
            # Connection failure - log error and handle gracefully
            logger.error("Could not connect to {}".format(dut['host']))
            if abort_on_error:
                raise Exception("Failed to connect to {}".format(dut['host']))
            return

        # Wait for shell prompt - indicates successful login
        prompt_regex = r"\$ ?$"  # Matches "$ " or "$" at end of line
        child.expect(prompt_regex)

        # MANDATORY: Check for core files on every device login
        # This detects system crashes/failures indicated by new .core.gz files
        check_core_files_on_login(child, dut, db_path, prompt_regex)

        logger.info("Executing command on {}: {}".format(dut['name'], command))
        
        # Special handling for NPU counter commands (requires adaptive ASIC options)
        if command.strip() == "sudo show platform npu counters":
            success = handle_npu_counters_command(child, dut, command, db_path, prompt_regex, abort_on_error, command_timeout)
            if not success and abort_on_error:
                raise Exception("NPU counters command failed on {}".format(dut['name']))
            return
        
        # Regular command execution
        child.sendline(command)
        
        # Wait for command to complete with timeout
        try:
            child.expect(prompt_regex, timeout=command_timeout)
        except pexpect.TIMEOUT:
            logger.warning("Command timed out on {} after {}s: {}".format(dut['name'], command_timeout, command))
            logger.warning("Attempting to recover and skip this command...")
            
            # Try to recover by sending Ctrl+C and getting back to prompt
            child.sendcontrol('c')
            try:
                child.expect(prompt_regex, timeout=10)
                logger.info("Successfully recovered from timeout")
            except pexpect.TIMEOUT:
                logger.error("Could not recover from timeout, closing connection")
                if abort_on_error:
                    raise Exception("Command timed out and could not recover: {} on {}".format(command, dut['name']))
                return
            
            # Store empty result for failed command
            dump_to_db(dut["name"], command, [], db_path)
            child.sendline("exit")
            return

        output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
        lines = output.splitlines()
        if lines and lines[0].strip() == command:
            lines = lines[1:]

        # Choose the correct parser
        try:
            if command.startswith("sudo show platform npu global -n"):
                match = re.search(r"-n (\S+)", command)
                asic_id = match.group(1) if match else "unknown"
                parsed = parse_npu_platform_output(lines, asic_id)
            elif command.startswith("sudo show platform npu counters"):
                # NPU counters commands are handled separately in handle_npu_counters_command
                # This should not be reached, but just in case
                logger.warning("NPU counters command reached main parser - this should not happen")
                parsed = []
            elif command.startswith("sudo show platform npu rx interface_cgm"):
                match = re.search(r"-t (\S+) -i (\S+)", command)
                if match:
                    traffic_class = match.group(1)
                    interface = match.group(2)
                    parsed = parse_npu_rx_interface_cgm_output(lines, interface, traffic_class)
                else:
                    parsed = []  # Unable to determine interface and traffic class
            elif command.startswith("sudo show platform npu tx cgm_state"):
                match = re.search(r"-i (\S+)", command)
                interface = match.group(1) if match else "unknown"
                parsed = parse_npu_tx_cgm_output(lines, interface)
            else:
                parsed, failed_raw = parse_show_output(lines)
                if failed_raw:
                    logger.warning("ALERT: Some sections failed parsing - raw data stored")
                    dump_to_db(dut["name"], command, parsed, db_path, failed_raw)
                    child.sendline("exit")
                    return
        except Exception as e:
            logger.error("Failed to parse command output: {}".format(e))
            logger.warning("ALERT: Parsing failed - storing raw output for investigation")
            parsed = []  # Store empty result for parsing failures
            # Store raw data when parsing fails
            raw_output = '\n'.join(lines) if lines else None
            dump_to_db(dut["name"], command, parsed, db_path, raw_output)
            child.sendline("exit")
            return

        if isinstance(parsed, list):
            if len(parsed) == 0:
                logger.warning("Command returned no parseable data (empty result)")
                logger.warning("Raw output may have been: error message, empty, or unsupported format")

        dump_to_db(dut["name"], command, parsed, db_path)

        child.sendline("exit")
        
    except Exception as e:
        logger.error("Unexpected error with {} / {}: {}".format(dut['name'], command, e))
        if abort_on_error:
            logger.error("Aborting due to error (-E specified)")
            raise
        else:
            logger.info("Continuing with next command/DUT...")
    finally:
        # Ensure SSH connection is always closed
        if child is not None:
            try:
                child.close()
            except:
                pass  # Ignore errors when closing

def needs_drop_counter_setup(command_list):
    """Check if any command in the list requires drop counter setup"""
    drop_counter_commands = [
        "show dropcounters count",
        "show dropcounter count",
        "sudo show dropcounters count", 
        "sudo show dropcounter count"
    ]
    return any(any(drop_cmd in cmd.lower() for drop_cmd in drop_counter_commands) for cmd in command_list)


def setup_drop_counters_on_dut(dut, db_path=None, abort_on_error=False, force_setup=False):
    """Set up drop counters on DUT with automatic single/multi-ASIC detection"""
    logger.info("Setting up drop counters on {} using unified implementation".format(dut['name']))
    
    child = None
    try:
        # Connect to DUT
        child = pexpect.spawn("ssh -tt -o PubkeyAuthentication=no {}@{}".format(dut['user'], dut['host']), 
                            env={"TERM": "dumb"}, timeout=30)

        # Handle SSH authentication
        i = child.expect([
            "Are you sure you want to continue connecting",
            "password:",
            pexpect.EOF,
            pexpect.TIMEOUT
        ])

        if i == 0:
            child.sendline("yes")
            child.expect("password:")
            child.sendline(dut["password"])
        elif i == 1:
            child.sendline(dut["password"])
        else:
            logger.error("Could not connect to {} for drop counter setup".format(dut['host']))
            if abort_on_error:
                raise Exception("Could not connect to {}".format(dut['host']))
            return False

        prompt_regex = r"\$ ?$"
        child.expect(prompt_regex)

        # STEP 1: DETECT DEVICE TYPE (Single-ASIC vs Multi-ASIC)
        logger.info("Detecting device type (single-ASIC vs multi-ASIC)...")
        child.sendline("ip netns | grep asic")
        child.expect(prompt_regex, timeout=10)
        
        netns_output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
        logger.info("ASIC detection output: '{}'".format(netns_output.strip()))
        
        # Parse ASIC names from ip netns output
        asic_lines = []
        for line in netns_output.splitlines():
            line = line.strip()
            if line and line.startswith('asic') and not line.startswith('ip netns'):
                # Extract just the ASIC name (before any spaces or extra info)
                asic_name = line.split()[0] if ' ' in line else line
                asic_lines.append(asic_name)
        
        # Determine device type and setup approach
        if not asic_lines:
            logger.info("SINGLE-ASIC device detected - using direct commands")
            return setup_single_asic_drop_counters(child, dut, prompt_regex, force_setup)
        else:
            logger.info("MULTI-ASIC device detected - found ASICs: {}".format(', '.join(asic_lines)))
            return setup_multi_asic_drop_counters(child, dut, asic_lines, prompt_regex, force_setup)
        
    except Exception as e:
        logger.error("Failed to set up drop counters on {}: {}".format(dut['name'], e))
        if abort_on_error:
            raise
        return False
    finally:
        if child is not None:
            try:
                child.close()
            except:
                pass


def setup_single_asic_drop_counters(child, dut, prompt_regex, force_setup):
    """Setup drop counters for single-ASIC devices (no ip netns exec needed)"""
    logger.info("Configuring drop counters for single-ASIC device: {}".format(dut['name']))
    
    try:
        # Check if drop counters are already configured (if not forcing setup)
        if not force_setup:
            child.sendline("show dropcounters configuration")
            child.expect(prompt_regex, timeout=30)
            config_output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
            
            # Count configured entries
            config_lines = [line.strip() for line in config_output.splitlines() 
                           if line.strip() and 'PORT_INGRESS_DROPS' in line]
            
            if config_lines:
                logger.info("Drop counters already configured on {} ({} entries), skipping...".format(
                    dut['name'], len(config_lines)))
                return True
        
        # Get drop counter capabilities using the working single-ASIC approach
        logger.info("Getting drop counter capabilities...")
        child.sendline("show dropcounters capabilities")
        child.expect(prompt_regex, timeout=30)
        
        capabilities_output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
        logger.info("Raw capabilities output:\n{}".format(capabilities_output))
        
        # Parse capabilities - look for lines that start with 8 spaces (your working pattern)
        capabilities = []
        for line in capabilities_output.splitlines():
            if line.startswith('        ') and line.strip():  # 8 spaces + content
                capability = line.strip()
                capabilities.append(capability)
                logger.info("Found capability: {}".format(capability))
        
        if not capabilities:
            logger.warning("No drop counter capabilities found for {}".format(dut['name']))
            return True
        
        logger.info("Found {} drop counter capabilities: {}".format(
            len(capabilities), ', '.join(capabilities)))
        
        # Install each drop counter using direct commands (no ip netns exec)
        count = 1
        for capability in capabilities:
            install_cmd = "sudo config dropcounters install {} PORT_INGRESS_DROPS [{}] -d \"{}\" -g {} -a {}".format(
                capability, capability, capability, capability, capability)
            logger.info("Installing counter {}/{}: {}".format(count, len(capabilities), install_cmd))
            child.sendline(install_cmd)
            child.expect(prompt_regex, timeout=30)
            count += 1
        
        logger.info("Successfully configured {} drop counters for single-ASIC device {}".format(
            len(capabilities), dut['name']))
        return True
        
    except Exception as e:
        logger.error("Failed to configure single-ASIC drop counters on {}: {}".format(dut['name'], e))
        return False


def setup_multi_asic_drop_counters(child, dut, asic_lines, prompt_regex, force_setup):
    """Setup drop counters for multi-ASIC devices (requires ip netns exec)"""
    logger.info("Configuring drop counters for multi-ASIC device: {} (ASICs: {})".format(
        dut['name'], ', '.join(asic_lines)))
    
    try:
        # Switch to root for multi-ASIC configuration
        logger.info("Switching to root for multi-ASIC drop counter configuration...")
        child.sendline("sudo su")
        
        # Handle potential password prompt for sudo
        i = child.expect([
            r"#.*$",  # Root prompt
            r"\[sudo\] password.*:",  # Sudo password prompt
            prompt_regex,  # Regular prompt (passwordless sudo)
            pexpect.TIMEOUT
        ], timeout=10)
        
        if i == 0:
            logger.info("Successfully switched to root")
            prompt_regex = r"#.*$"
        elif i == 1:
            child.sendline(dut["password"])
            child.expect(r"#.*$", timeout=10)
            logger.info("Successfully switched to root with password")
            prompt_regex = r"#.*$"
        elif i == 2:
            child.expect(r"#.*$", timeout=10)
            logger.info("Successfully switched to root")
            prompt_regex = r"#.*$"
        else:
            logger.error("Failed to switch to root on {}".format(dut['name']))
            return False
        
        # Configure drop counters for each ASIC
        for asic in asic_lines:
            logger.info("Processing drop counters for {}...".format(asic))
            
            # Check if this ASIC already has drop counters configured
            if not force_setup and check_drop_counters_configured_on_asic(child, asic, prompt_regex):
                logger.info("Drop counters already configured for {}, skipping...".format(asic))
                continue
            elif force_setup:
                logger.info("Force setup enabled - reconfiguring drop counters for {}".format(asic))
            
            # Get capabilities for this ASIC using ip netns exec
            capabilities_cmd = "ip netns exec {} show dropcounters capabilities".format(asic)
            logger.info("Getting capabilities: {}".format(capabilities_cmd))
            child.sendline(capabilities_cmd)
            child.expect(prompt_regex, timeout=30)
            
            capabilities_output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
            logger.info("Raw capabilities output for {}:\n{}".format(asic, capabilities_output))
            
            # Parse capabilities - look for lines that start with 8 spaces
            capabilities = []
            for line in capabilities_output.splitlines():
                if line.startswith('        ') and line.strip():  # 8 spaces + content
                    capability = line.strip()
                    capabilities.append(capability)
                    logger.info("Found capability for {}: {}".format(asic, capability))
            
            if not capabilities:
                logger.warning("No drop counter capabilities found for {}".format(asic))
                continue
            
            logger.info("Found {} drop counter capabilities for {}: {}".format(
                len(capabilities), asic, ', '.join(capabilities)))
            
            # Install each drop counter using ip netns exec
            count = 1
            for capability in capabilities:
                install_cmd = "ip netns exec {} config dropcounters install {} PORT_INGRESS_DROPS [{}] -d \"{}\" -g {} -a {}".format(
                    asic, capability, capability, capability, capability, capability)
                logger.info("Installing counter {}/{} for {}: {}".format(count, len(capabilities), asic, install_cmd))
                child.sendline(install_cmd)
                child.expect(prompt_regex, timeout=30)
                count += 1
            
            logger.info("Completed drop counter configuration for {}".format(asic))
        
        # Exit root
        child.sendline("exit")
        child.expect(r"\$ ?$", timeout=10)
        
        logger.info("Successfully configured drop counters for multi-ASIC device {} ({} ASICs)".format(
            dut['name'], len(asic_lines)))
        return True
        
    except Exception as e:
        logger.error("Failed to configure multi-ASIC drop counters on {}: {}".format(dut['name'], e))
        return False


def check_drop_counters_configured_on_asic(child, asic, prompt_regex):
    """Check if drop counters are already configured on a specific ASIC"""
    logger.info("Checking if drop counters are already configured on {}".format(asic))
    
    child.sendline("ip netns exec {} show dropcounters configuration".format(asic))
    child.expect(prompt_regex, timeout=30)
    
    config_output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
    logger.info("Drop counter configuration for {}:\n{}".format(asic, config_output))
    
    # Count lines in configuration output, if more than just header, counters are configured
    config_lines = [line.strip() for line in config_output.splitlines() 
                   if line.strip() and not line.strip().startswith('ip netns exec')]
    
    counter_entries = 0
    for line in config_lines:
        # Look for lines that contain counter configurations
        if 'PORT_INGRESS_DROPS' in line or any(keyword in line for keyword in ['EXCEEDS_L2_MTU', 'MC_DMAC_MISMATCH', 'TTL']):
            counter_entries += 1
    
    is_configured = counter_entries > 0
    logger.info("ASIC {} drop counter status: {} ({} counter entries found)".format(
        asic, "CONFIGURED" if is_configured else "NOT CONFIGURED", counter_entries))
    
    return is_configured

def get_npu_command_preference(dut_name, db_path):
    """Get the preferred NPU command format for a DUT from database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create preference table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS npu_command_preferences (
            dut_name TEXT PRIMARY KEY,
            requires_asic_option BOOLEAN DEFAULT FALSE,
            available_asics TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Check if we have a preference for this DUT
    cursor.execute("""
        SELECT requires_asic_option, available_asics 
        FROM npu_command_preferences 
        WHERE dut_name = ?
    """, (dut_name,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        requires_asic, asics_str = result
        asics = asics_str.split(',') if asics_str else []
        return bool(requires_asic), asics
    else:
        return None, []  # No preference stored yet

def save_npu_command_preference(dut_name, requires_asic_option, available_asics, db_path):
    """Save the NPU command preference for a DUT"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create preference table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS npu_command_preferences (
            dut_name TEXT PRIMARY KEY,
            requires_asic_option BOOLEAN DEFAULT FALSE,
            available_asics TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    asics_str = ','.join(available_asics) if available_asics else ''
    
    cursor.execute("""
        INSERT OR REPLACE INTO npu_command_preferences 
        (dut_name, requires_asic_option, available_asics, last_updated)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    """, (dut_name, requires_asic_option, asics_str))
    
    conn.commit()
    conn.close()

def detect_available_asics(error_output):
    """Extract available ASIC options from error message"""
    asics = []
    found_choose_from = False
    
    for line in error_output:
        line = line.strip()
        
        # Look for the "Choose from:" line
        if "Choose from:" in line:
            found_choose_from = True
            # Check if ASICs are on the same line
            after_colon = line.split("Choose from:")[-1]
            parts = after_colon.split(',')
            for part in parts:
                cleaned = part.strip().rstrip('.,')
                if cleaned and cleaned.startswith('asic'):
                    asics.append(cleaned)
        elif found_choose_from and line and (line.startswith('asic') or line.startswith('\tasic')):
            # ASICs are on separate lines after "Choose from:"
            cleaned = line.strip().rstrip('.,')
            if cleaned.startswith('asic'):
                asics.append(cleaned)
        elif found_choose_from and line and not line.startswith('asic') and not line.startswith('\tasic'):
            # We've moved past the ASIC list
            break
    
    return asics

def handle_npu_counters_command(child, dut, command, db_path, prompt_regex, abort_on_error, command_timeout=60):
    """Handle NPU counters command with adaptive -n asic option"""
    dut_name = dut['name']
    
    # Check if we already know the preference for this DUT
    requires_asic, known_asics = get_npu_command_preference(dut_name, db_path)
    
    if requires_asic is True and known_asics:
        # We know this DUT requires -n asic options, run them directly
        logger.info("DUT {} requires ASIC options, running commands for ASICs: {}".format(dut_name, ', '.join(known_asics)))
        
        for asic in known_asics:
            asic_command = "sudo show platform npu counters -n {}".format(asic)
            success = execute_single_command(child, dut, asic_command, db_path, prompt_regex, abort_on_error, command_timeout)
            if not success:
                return False
        return True
        
    elif requires_asic is False:
        # We know this DUT works with the base command
        logger.info("DUT {} uses base NPU counters command".format(dut_name))
        return execute_single_command(child, dut, command, db_path, prompt_regex, abort_on_error, command_timeout)
    
    else:
        # First time or unknown preference - try base command first
        logger.info("Testing NPU counters command format for DUT {}".format(dut_name))
        child.sendline(command)
        
        try:
            child.expect(prompt_regex, timeout=command_timeout)
        except pexpect.TIMEOUT:
            logger.warning("NPU counters command timed out on {} after {}s".format(dut_name, command_timeout))
            return False
        
        output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
        lines = output.splitlines()
        if lines and lines[0].strip() == command:
            lines = lines[1:]
        
        # Check for error indicating missing -n option
        output_text = '\n'.join(lines)
        if 'Missing option "-n"' in output_text and 'Choose from:' in output_text:
            logger.info("DUT {} requires ASIC options, detecting available ASICs...".format(dut_name))
            
            # Extract available ASICs from error message
            available_asics = detect_available_asics(lines)
            if available_asics:
                logger.info("Found ASICs for {}: {}".format(dut_name, ', '.join(available_asics)))
                
                # Save preference
                save_npu_command_preference(dut_name, True, available_asics, db_path)
                
                # Run commands for each ASIC
                for asic in available_asics:
                    asic_command = "sudo show platform npu counters -n {}".format(asic)
                    success = execute_single_command(child, dut, asic_command, db_path, prompt_regex, abort_on_error, command_timeout)
                    if not success:
                        return False
                return True
            else:
                logger.error("Could not detect available ASICs from error message on {}".format(dut_name))
                return False
        else:
            # Base command worked, save preference and process output
            logger.info("DUT {} works with base NPU counters command".format(dut_name))
            save_npu_command_preference(dut_name, False, [], db_path)
            
            # Process the output we already got
            try:
                parsed = parse_npu_counters_output(lines, "0")  # Use "0" as default ASIC ID
                
                dump_to_db(dut_name, command, parsed, db_path)
                return True
                
            except Exception as e:
                logger.error("Failed to parse NPU counters output on {}: {}".format(dut_name, e))
                # Store raw output for investigation
                raw_output = '\n'.join(lines) if lines else None
                dump_to_db(dut_name, command, [], db_path, raw_output)
                return False

def execute_single_command(child, dut, command, db_path, prompt_regex, abort_on_error, command_timeout=60):
    """Execute a single command and parse/store the output"""
    dut_name = dut['name']
    logger.info("Executing: {}".format(command))
    
    child.sendline(command)
    
    try:
        child.expect(prompt_regex, timeout=command_timeout)
    except pexpect.TIMEOUT:
        logger.warning("Command timed out after {}s: {}".format(command_timeout, command))
        return False
    
    if isinstance(child.before, bytes):
        output = child.before.decode(errors='ignore')
    else:
        output = child.before
    lines = output.splitlines()
    if lines and lines[0].strip() == command:
        lines = lines[1:]
    
    # Parse the command output
    try:
        if command.startswith("sudo show platform npu counters -n"):
            match = re.search(r"-n (\S+)", command)
            asic_id = match.group(1) if match else "unknown"
            parsed = parse_npu_counters_output(lines, asic_id)
        elif command.startswith("sudo show platform npu counters"):
            parsed = parse_npu_counters_output(lines, "0")  # Default ASIC ID
        else:
            # For other commands, use the original parsing logic
            parsed, failed_raw = parse_show_output(lines)
            if failed_raw:
                logger.warning("Some sections failed parsing - raw data stored")
                dump_to_db(dut_name, command, parsed, db_path, failed_raw)
                return True
        
        dump_to_db(dut_name, command, parsed, db_path)
        return True
        
    except Exception as e:
        logger.error("Failed to parse command output: {}".format(e))
        raw_output = '\n'.join(lines) if lines else None
        dump_to_db(dut_name, command, [], db_path, raw_output)
        return False

def check_core_files_on_login(child, dut, db_path, prompt_regex):
    """
    Mandatory core file check when logging into each DUT.
    
    This function automatically runs 'ls -la /var/core' when logging into any device
    to detect core dump files that indicate system crashes or failures.
    
    Args:
        child: Active pexpect SSH session
        dut (dict): Device configuration
        db_path (str): Database path for storing results
        prompt_regex (str): Shell prompt pattern for command completion
    
    Returns:
        bool: True if check completed successfully, False on error
    """
    try:
        logger.info("Checking for core files on {}".format(dut['name']))
        
        # Execute core file check command
        core_command = "ls -la /var/core"
        child.sendline(core_command)
        
        # Wait for command completion
        try:
            child.expect(prompt_regex, timeout=10)
        except pexpect.TIMEOUT:
            logger.warning("Core file check timed out on {}".format(dut['name']))
            return False
        
        output = child.before.decode(errors='ignore') if isinstance(child.before, bytes) else child.before
        lines = output.splitlines()
        if lines and lines[0].strip() == core_command:
            lines = lines[1:]
        
        # Parse ls -la output to extract core files
        core_files = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('total '):
                continue
            
            # Parse ls -la format: permissions user group size date time filename
            # Example: -rw-r--r-- 1 root root 1234567 Jul 17 13:30 orchagent.1752699007.44.1.core.gz
            parts = line.split()
            if len(parts) >= 9 and parts[0].startswith('-'):  # Regular file
                filename = parts[8]  # Last part is filename
                file_size = parts[4]  # File size
                file_date = " ".join(parts[5:8])  # Date and time
                
                # Only interested in .core.gz files
                if filename.endswith('.core.gz'):
                    core_files.append({
                        'filename': filename,
                        'size': file_size,
                        'date': file_date,
                        'permissions': parts[0],
                        'owner': parts[2],
                        'group': parts[3]
                    })
        
        # Store results in database
        dump_to_db(dut["name"], core_command, core_files, db_path)
        
        # Log core file findings
        if core_files:
            logger.warning("Found {} core files on {}: {}".format(
                len(core_files), dut['name'], 
                [f['filename'] for f in core_files]
            ))
        else:
            logger.info("No core files found on {}".format(dut['name']))
        
        return True
        
    except Exception as e:
        logger.error("Failed to check core files on {}: {}".format(dut['name'], e))
        return False

def main():
    import sys
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description='Network Device Command Crawler')
    parser.add_argument('--db', '--database', dest='db_path', 
                        help='Database file path or directory (default: ~/packet_monitor_data/crawler-TIMESTAMP.db)')
    parser.add_argument('--config', '--testbed', dest='config_file', default='testbed_info.yml',
                        help='YAML configuration file with device info and commands (default: testbed_info.yml)')
    parser.add_argument('-E', action='store_true',
                        help='exit for any error (default: False)')
    parser.add_argument('--force-drop-counter-setup', action='store_true',
                        help='force drop counter reconfiguration even if already configured (default: False)')
    
    args = parser.parse_args()
    
    # Determine error handling behavior (default is continue)    
    # Set abort_on_error based on -E flag
    abort_on_error = args.E
    force_drop_counter_setup = getattr(args, 'force_drop_counter_setup', False)
    
    # Handle database path logic
    if args.db_path is None:
        # Default: Use ~/packet_monitor_data/crawler-TIMESTAMP.db  
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        db_filename = "crawler-{}.db".format(timestamp)
        home_dir = os.path.expanduser("~")
        db_dir = os.path.join(home_dir, "packet_monitor_data")
        
        # Create the directory if it doesn't exist
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
                logger.info("Created default database directory: {}".format(db_dir))
            except OSError as e:
                logger.error("Cannot create directory {}: {}".format(db_dir, e))
                logger.error("Please check permissions or use a different path")
                exit(1)
        else:
            logger.info("Using default database directory: {}".format(db_dir))
        
        db_path = os.path.join(db_dir, db_filename)
        logger.info("Using default database: {}".format(db_path))
        
    elif args.db_path.endswith('/'):
        # User explicitly provided a directory (ending with /) - use crawler-TIMESTAMP.db in that directory
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        db_filename = "crawler-{}.db".format(timestamp)
        db_dir = os.path.abspath(args.db_path.rstrip('/'))
        
        # Create the directory if it doesn't exist
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
                logger.info("Created database directory: {}".format(db_dir))
            except OSError as e:
                logger.error("Cannot create directory {}: {}".format(db_dir, e))
                logger.error("Please check permissions or use a different path")
                exit(1)
        
        db_path = os.path.join(db_dir, db_filename)
        logger.info("Using database in custom directory: {}".format(db_path))
        
    elif os.path.isdir(args.db_path):
        # Path exists and is actually a directory - use crawler-TIMESTAMP.db in that directory
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        db_filename = "crawler-{}.db".format(timestamp)
        db_dir = os.path.abspath(args.db_path)
        db_path = os.path.join(db_dir, db_filename)
        logger.info("Using database in existing directory: {}".format(db_path))
        
    else:
        # User provided a specific database file path
        db_path = os.path.abspath(args.db_path)
        
        # Create parent directory if it doesn't exist
        parent_dir = os.path.dirname(db_path)
        if parent_dir and not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
                logger.info("Created directory: {}".format(parent_dir))
            except OSError as e:
                logger.error("Cannot create directory {}: {}".format(parent_dir, e))
                logger.error("Please check permissions or use a different path")
                exit(1)
        
        if os.path.exists(db_path):
            logger.info("Using existing database file: {}".format(db_path))
        else:
            logger.info("Creating new database file: {}".format(db_path))
    
    # Validate config file exists
    if not os.path.exists(args.config_file):
        logger.error("Config file '{}' not found".format(args.config_file))
        exit(1)
    
    dut_list, command_list, command_timeout = load_duts_and_commands(args.config_file)
    
    logger.info("Starting crawler with {} DUTs and {} commands".format(len(dut_list), len(command_list)))
    if abort_on_error:
        logger.info("Error handling: Will exit for any error (-E flag enabled)")
    else:
        logger.info("Error handling: Will continue on errors (default behavior)")
    
    for dut in dut_list:
        print("\n" + "="*60)
        logger.info("Processing DUT: {}".format(dut['name']))
        
        # Check and setup drop counters if needed
        if needs_drop_counter_setup(command_list):
            logger.info("Drop counter setup required for {}".format(dut['name']))
            try:
                setup_drop_counters_on_dut(dut, db_path, abort_on_error, force_drop_counter_setup)
            except Exception as e:
                logger.error("Error setting up drop counters on {}: {}".format(dut['name'], e))
                if abort_on_error:
                    logger.error("Aborting due to error during drop counter setup")
                    exit(1)
                else:
                    logger.info("Continuing with command execution...")
        
        for command in command_list:
            try:
                run_command_on_dut(dut, command, db_path, abort_on_error, command_timeout)
            except Exception as e:
                logger.error("Failed to execute {} on {}: {}".format(command, dut['name'], e))
                if abort_on_error:
                    logger.error("Aborting crawler execution due to error")
                    exit(1)
                else:
                    logger.info("Continuing with next command...")
                    continue
    
    print("\n" + "="*60)
    logger.info("Crawler completed successfully")

if __name__ == "__main__":
    main()