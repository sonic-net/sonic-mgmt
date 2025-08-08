#!/usr/bin/env python3
"""
PFCWD (Priority Flow Control Watchdog) Analyzer

Analyzes 'show pfcwd stat' output to detect increments in:
- Storm detected counts (first value before slash)
- TX drop counts (second value after slash in TX OK/DROP)  
- RX drop counts (second value after slash in RX OK/DROP)

Handles cases where no PFCWD data exists (empty output).
"""

import sqlite3
import json
import os
import re
from datetime import datetime

class PFCWDAnalyzer:
    """
    Analyzes PFCWD (Priority Flow Control Watchdog) statistics from 'show pfcwd stat' command.
    
    Expected CLI Output Format:
    QUEUE        STATUS         STORM DETECTED/RESTORED    TX OK/DROP      RX OK/DROP
    ---------------------------------------------------------------------------
    Ethernet256:3  operational        9/9            159873/41785903558    0/5823727078
    
    Field Validation:
    - Monitors for CLI format changes and alerts when parsing fails
    - Validates presence of interface:queue, status, and count fields
    - Reports parsing success rates to detect format changes
    
    Alerts:
    - CRITICAL: When queues are in 'stormed' status
    - WARNING: When parsing success rate drops below 50%
    - INFO: When CLI format changes are detected
    """
    
    def __init__(self, db_path="crawler.db", output_handler=None, splunk_output=None):
        self.db_path = db_path
        self.output_handler = output_handler  # Legacy - kept for compatibility
        self.splunk_output = splunk_output    # Direct Splunk access for Pure Analyzer approach
        self.setup_database()
        
        # Expected PFCWD field structure from 'show pfcwd stat' command
        self.expected_pfcwd_fields = {
            'interface_queue': 'Interface:Queue identifier (e.g., Ethernet256:3)',
            'status': 'Queue status (operational, stormed, etc.)',
            'storm_counts': 'Storm detected/restored counts (e.g., 9/9)',
            'tx_counts': 'TX OK/DROP counts (e.g., 159873/41785903558)',
            'rx_counts': 'RX OK/DROP counts (e.g., 0/5823727078)'
        }
    
    def setup_database(self):
        """Create table for tracking PFCWD statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pfcwd_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                interface TEXT NOT NULL,
                queue_number TEXT NOT NULL,
                status TEXT,
                storm_detected INTEGER DEFAULT 0,
                storm_restored INTEGER DEFAULT 0,
                tx_ok INTEGER DEFAULT 0,
                tx_drops INTEGER DEFAULT 0,
                rx_ok INTEGER DEFAULT 0,
                rx_drops INTEGER DEFAULT 0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, interface, queue_number, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pfcwd_dut_interface_queue_time 
            ON pfcwd_history(dut_name, interface, queue_number, timestamp DESC)
        """)
        
        conn.commit()
        conn.close()
    
    def parse_pfcwd_line(self, line):
        """
        Parse a single PFCWD data line.
        
        Example input:
        'Ethernet256:3  operational                        9/9  159873/41785903558           0/0       0/5823727078                0/0'
        
        Returns:
        {
            'interface': 'Ethernet256',
            'queue_number': '3', 
            'status': 'operational',
            'storm_detected': 9,
            'storm_restored': 9,
            'tx_ok': 159873,
            'tx_drops': 41785903558,
            'rx_ok': 0,
            'rx_drops': 0
        }
        """
        try:
            # Skip obviously invalid lines
            line = line.strip()
            if not line:
                return None
            
            # Skip command prompts (contain @ and end with ~, #, or $)
            if '@' in line and (line.endswith('~') or line.endswith('#') or line.endswith('$')):
                return None
                
            # Skip lines that don't look like interface names (should start with letter or Ethernet)
            if not (line[0].isalpha() or line.startswith('Ethernet')):
                return None
            
            # Split the line into fields, handling multiple spaces
            fields = line.split()
            if len(fields) < 6:
                return None
                
            # Parse interface and queue (e.g., "Ethernet256:3")
            queue_field = fields[0]
            
            # Additional validation: interface should contain letters and numbers
            if not any(c.isalpha() for c in queue_field) or not any(c.isdigit() for c in queue_field):
                return None
                
            if ':' in queue_field:
                interface, queue_number = queue_field.split(':', 1)
            else:
                interface = queue_field
                queue_number = "0"  # Default queue if no colon found
            
            status = fields[1]
            
            # Parse storm detected/restored (e.g., "9/9")
            storm_field = fields[2]
            if '/' in storm_field:
                storm_detected, storm_restored = storm_field.split('/', 1)
                storm_detected = int(storm_detected)
                storm_restored = int(storm_restored)
            else:
                storm_detected = int(storm_field) if storm_field.isdigit() else 0
                storm_restored = 0
            
            # Parse TX OK/DROP (e.g., "159873/41785903558")
            tx_field = fields[3]
            if '/' in tx_field:
                tx_ok, tx_drops = tx_field.split('/', 1)
                tx_ok = int(tx_ok)
                tx_drops = int(tx_drops)
            else:
                tx_ok = int(tx_field) if tx_field.isdigit() else 0
                tx_drops = 0
            
            # Parse RX OK/DROP (e.g., "0/0")
            rx_field = fields[4]
            if '/' in rx_field:
                rx_ok, rx_drops = rx_field.split('/', 1)
                rx_ok = int(rx_ok)
                rx_drops = int(rx_drops)
            else:
                rx_ok = int(rx_field) if rx_field.isdigit() else 0
                rx_drops = 0
            
            return {
                'interface': interface,
                'queue_number': queue_number,
                'status': status,
                'storm_detected': storm_detected,
                'storm_restored': storm_restored,
                'tx_ok': tx_ok,
                'tx_drops': tx_drops,
                'rx_ok': rx_ok,
                'rx_drops': rx_drops
            }
            
        except (ValueError, IndexError) as e:
            print("WARNING: Failed to parse PFCWD line: '{}' - {}".format(line.strip(), e))
            print("WARNING: Expected format: 'interface:queue status storm_detected/restored tx_ok/drops rx_ok/drops'")
            print("WARNING: This could indicate CLI format change - check PFCWD command output manually")
            return None
    
    def process_pfcwd_stats(self, run_id):
        """Extract and store PFCWD statistics from crawler logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get latest PFCWD data from crawler database (not log file)
            # First, let's debug what PFCWD-related commands exist
            cursor.execute("""
                SELECT DISTINCT command
                FROM crawler_logs
                WHERE command LIKE '%pfcwd%'
                ORDER BY command
            """)
            pfcwd_commands = cursor.fetchall()
            
            # Let's also check what columns are available in crawler_logs
            cursor.execute("PRAGMA table_info(crawler_logs)")
            columns = cursor.fetchall()
            
            cursor.execute("""
                SELECT dut_name, json_data, command, raw_data
                FROM crawler_logs
                WHERE command LIKE '%show pfcwd stat%'
                ORDER BY id DESC
                LIMIT 5
            """)
            
            pfcwd_entries_processed = 0
            
            print("Starting PFCWD processing for run {}".format(run_id))
            
            for row in cursor.fetchall():
                dut_name = row[0]
                try:
                    pfcwd_data = json.loads(row[1])
                    command = row[2]
                    raw_data = row[3] if len(row) > 3 else None
                    timestamp = datetime.now().isoformat()  # Use current time since DB doesn't have timestamp
                    
                    
                    # Try to use raw_data first, fall back to parsed data
                    if raw_data:
                        pfcwd_output = raw_data
                    elif isinstance(pfcwd_data, dict):
                        pfcwd_output = pfcwd_data.get('output', '')
                    elif isinstance(pfcwd_data, list) and len(pfcwd_data) > 0:
                        # If parsed data contains command prompt, treat as headers-only case
                        if any('cisco@' in str(item) for item in pfcwd_data):
                            pfcwd_output = "HEADERS_ONLY"  # Special marker for headers-only case
                        else:
                            pfcwd_output = str(pfcwd_data)
                    else:
                        pfcwd_output = str(pfcwd_data)                    
                    print("Processing PFCWD data from DUT: {}".format(dut_name))
                    # Handle special case where we detected command prompt in parsed data
                    if pfcwd_output == "HEADERS_ONLY":
                        print("INFO: PFCWD headers found but no queue data for device {} (command prompt detected)".format(dut_name))
                        # Send status to Splunk for headers-only case
                        if self.splunk_output:
                            status_data = {
                                'run_id': run_id,
                                'status': 'no_queue_data',
                                'message': 'PFCWD headers found but no queue data (command prompt detected)',
                                'timestamp': timestamp
                            }
                            try:
                                self.splunk_output.store_drop_data(dut_name, "pfcwd", status_data)
                                print("✓ PFCWD status (no queue data) sent to Splunk: {}".format(dut_name))
                            except Exception as e:
                                print("ERROR: Failed to send PFCWD status to Splunk: {}".format(e))
                        pfcwd_entries_processed += 1  # Count this as processed to avoid duplicate status
                        continue
                    
                    # Handle case where no PFCWD data exists (empty or no data rows)
                    if not pfcwd_output or pfcwd_output.strip() == "":
                        print("INFO: No PFCWD data for device {}".format(dut_name))
                        continue
                    
                    # FIELD VALIDATION - Alert if CLI format changed
                    if not self.validate_pfcwd_format(pfcwd_data, dut_name):
                        print("ERROR: PFCWD format validation failed for device {} - skipping processing".format(dut_name))
                        continue
                    
                    print("Processing PFCWD data from DUT: {}".format(dut_name))
                    
                    # Process each line of PFCWD output
                    lines = pfcwd_output.split('\n')
                    data_found = False
                    lines_attempted = 0
                    lines_parsed_successfully = 0
                    
                    for pfcwd_line in lines:
                        # Skip header lines and empty lines
                        if ('QUEUE' in pfcwd_line and 'STATUS' in pfcwd_line) or \
                           '-------' in pfcwd_line or \
                           pfcwd_line.strip() == '':
                            continue
                        
                        # Skip command prompt lines (improved filtering)
                        line_stripped = pfcwd_line.strip()
                        if (line_stripped.endswith('#') or 
                            line_stripped.endswith('~') or 
                            line_stripped.endswith('$') or
                            'show pfcwd stat' in line_stripped or
                            '@' in line_stripped):
                            continue
                        
                        # Count lines that look like data (contain interface pattern)
                        if ':' in line_stripped and any(c.isalpha() for c in line_stripped):
                            lines_attempted += 1
                        
                        parsed_data = self.parse_pfcwd_line(pfcwd_line)
                        if parsed_data:
                            data_found = True
                            lines_parsed_successfully += 1
                            
                            # CRITICAL ALERT: Check for "stormed" status
                            if parsed_data['status'].lower() == 'stormed':
                                storm_alert_msg = "CRITICAL PFCWD ALERT: Queue {}/{}:{} is in STORMED state!".format(
                                    dut_name, parsed_data['interface'], parsed_data['queue_number'])
                                print(storm_alert_msg)
                                
                                # Send storm alert to Splunk if configured
                                if self.splunk_output:
                                    try:
                                        self.splunk_output.store_alert(
                                            dut_name, "pfcwd", "CRITICAL", 
                                            storm_alert_msg,
                                            {
                                                'interface': parsed_data['interface'],
                                                'queue_number': parsed_data['queue_number'],
                                                'status': parsed_data['status'],
                                                'storm_detected': parsed_data['storm_detected'],
                                                'storm_restored': parsed_data['storm_restored'],
                                                'alert_type': 'stormed_status'
                                            }
                                        )
                                        print("✓ PFCWD storm status alert sent to Splunk")
                                    except Exception as e:
                                        print("ERROR: Failed to send PFCWD storm alert to Splunk: {}".format(e))
                                
                                # Store in database
                                cursor.execute("""
                                    INSERT OR REPLACE INTO pfcwd_history 
                                    (dut_name, interface, queue_number, status, storm_detected, storm_restored,
                                     tx_ok, tx_drops, rx_ok, rx_drops, timestamp, run_id)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    dut_name, parsed_data['interface'], parsed_data['queue_number'],
                                    parsed_data['status'], parsed_data['storm_detected'], parsed_data['storm_restored'],
                                    parsed_data['tx_ok'], parsed_data['tx_drops'], 
                                    parsed_data['rx_ok'], parsed_data['rx_drops'],
                                    timestamp, run_id
                                ))
                                
                                # Send to Splunk if configured
                                if self.splunk_output:
                                    pfcwd_data_for_splunk = {
                                        'run_id': run_id,
                                        'interface': parsed_data['interface'],
                                        'queue_number': parsed_data['queue_number'],
                                        'status': parsed_data['status'],
                                        'storm_detected': parsed_data['storm_detected'],
                                        'storm_restored': parsed_data['storm_restored'],
                                        'tx_ok': parsed_data['tx_ok'],
                                        'tx_drops': parsed_data['tx_drops'],
                                        'rx_ok': parsed_data['rx_ok'],
                                        'rx_drops': parsed_data['rx_drops'],
                                        'timestamp': timestamp
                                    }
                                    
                                    try:
                                        success = self.splunk_output.store_drop_data(dut_name, "pfcwd", pfcwd_data_for_splunk)
                                        if success:
                                            print("✓ PFCWD data sent to Splunk: {}/{}:{}".format(
                                                dut_name, parsed_data['interface'], parsed_data['queue_number']))
                                    except Exception as e:
                                        print("ERROR: Failed to send PFCWD data to Splunk: {}".format(e))
                                
                                pfcwd_entries_processed += 1
                    
                    # Check if no data was found after processing all lines
                    if not data_found:
                        print("INFO: No PFCWD queue data found for device {} (headers only)".format(dut_name))
                        # Send status to Splunk even when no queue data
                        if self.splunk_output:
                            status_data = {
                                'run_id': run_id,
                                'status': 'no_queue_data',
                                'message': 'PFCWD headers found but no queue data',
                                'timestamp': timestamp
                            }
                            try:
                                self.splunk_output.store_drop_data(dut_name, "pfcwd", status_data)
                                print("✓ PFCWD status (no queue data) sent to Splunk: {}".format(dut_name))
                            except Exception as e:
                                print("ERROR: Failed to send PFCWD status to Splunk: {}".format(e))
                    
                    # PARSING STATISTICS - Alert if low success rate indicates CLI format change
                    if lines_attempted > 0:
                        success_rate = (lines_parsed_successfully / lines_attempted) * 100
                        print("PFCWD parsing stats for {}: {}/{} lines parsed successfully ({:.1f}%)".format(
                            dut_name, lines_parsed_successfully, lines_attempted, success_rate))
                        
                        if success_rate < 50 and lines_attempted >= 3:  # Alert if less than 50% success with multiple lines
                            print("CRITICAL ALERT: Low PFCWD parsing success rate for device {}: {:.1f}%".format(
                                dut_name, success_rate))
                            print("ALERT: This may indicate CLI format change - check 'show pfcwd stat' output manually")
                            print("ALERT: Expected format: interface:queue status storm_counts tx_counts rx_counts")
                    elif data_found:
                        print("PFCWD parsing completed for {} (some data processed)".format(dut_name))
                                
                except Exception as e:
                    print("ERROR: Failed to process PFCWD data for DUT {}: {}".format(dut_name, e))
                    continue
            
            conn.commit()
            print("Processed {} PFCWD entries for run {}".format(pfcwd_entries_processed, run_id))
            
            # Always send status to Splunk, even if no entries processed
            if pfcwd_entries_processed == 0 and self.splunk_output:
                status_data = {
                    'run_id': run_id,
                    'status': 'no_pfcwd_data',
                    'message': 'No PFCWD data found in crawler logs',
                    'timestamp': datetime.now().isoformat()
                }
                try:
                    self.splunk_output.store_drop_data('monitoring_system', "pfcwd", status_data)
                    print("✓ PFCWD monitoring status sent to Splunk")
                except Exception as e:
                    print("ERROR: Failed to send PFCWD monitoring status to Splunk: {}".format(e))
            
            return pfcwd_entries_processed > 0
            
        except Exception as e:
            print("ERROR processing PFCWD stats: {}".format(e))
            return False
        finally:
            conn.close()
    
    def analyze_pfcwd_increments(self, run_id):
        """Find PFCWD increments compared to previous run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get previous run ID
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM pfcwd_history 
                WHERE run_id < ?
            """, (run_id,))
            
            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                print("INFO: No previous PFCWD data for comparison (first run)")
                return []
            
            previous_run_id = previous_run_result[0]
            
            # Find increments in storm detected, TX drops, and RX drops
            cursor.execute("""
                SELECT 
                    curr.dut_name,
                    curr.interface,
                    curr.queue_number,
                    prev.storm_detected as prev_storm_detected,
                    curr.storm_detected as curr_storm_detected,
                    (curr.storm_detected - prev.storm_detected) as storm_increment,
                    prev.tx_drops as prev_tx_drops,
                    curr.tx_drops as curr_tx_drops,
                    (curr.tx_drops - prev.tx_drops) as tx_drop_increment,
                    prev.rx_drops as prev_rx_drops,
                    curr.rx_drops as curr_rx_drops,
                    (curr.rx_drops - prev.rx_drops) as rx_drop_increment
                FROM pfcwd_history curr
                JOIN pfcwd_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.interface = prev.interface
                    AND curr.queue_number = prev.queue_number
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND (
                        curr.storm_detected > prev.storm_detected OR
                        curr.tx_drops > prev.tx_drops OR
                        curr.rx_drops > prev.rx_drops
                    )
                ORDER BY storm_increment DESC, tx_drop_increment DESC, rx_drop_increment DESC
            """, (run_id, previous_run_id))
            
            increments = cursor.fetchall()
            
            increment_report = []
            for row in increments:
                (dut_name, interface, queue_number, prev_storm, curr_storm, storm_inc,
                 prev_tx_drops, curr_tx_drops, tx_drop_inc, 
                 prev_rx_drops, curr_rx_drops, rx_drop_inc) = row
                
                increment_data = {
                    'dut_name': dut_name,
                    'interface': interface,
                    'queue_number': queue_number,
                    'storm_increment': storm_inc,
                    'tx_drop_increment': tx_drop_inc,
                    'rx_drop_increment': rx_drop_inc,
                    'previous_storm_detected': prev_storm,
                    'current_storm_detected': curr_storm,
                    'previous_tx_drops': prev_tx_drops,
                    'current_tx_drops': curr_tx_drops,
                    'previous_rx_drops': prev_rx_drops,
                    'current_rx_drops': curr_rx_drops
                }
                
                increment_report.append(increment_data)
                
                # Generate alerts for significant increments
                alert_messages = []
                
                if storm_inc > 0:
                    alert_messages.append("Storm detected count increased by {} (from {} to {})".format(
                        storm_inc, prev_storm, curr_storm))
                
                if tx_drop_inc > 0:
                    alert_messages.append("TX drops increased by {} (from {} to {})".format(
                        tx_drop_inc, prev_tx_drops, curr_tx_drops))
                
                if rx_drop_inc > 0:
                    alert_messages.append("RX drops increased by {} (from {} to {})".format(
                        rx_drop_inc, prev_rx_drops, curr_rx_drops))
                
                for message in alert_messages:
                    print("PFCWD ALERT: {}/{}:{} - {}".format(dut_name, interface, queue_number, message))
                    
                    # Send alert to Splunk if configured
                    if self.splunk_output:
                        try:
                            self.splunk_output.store_alert(
                                dut_name, "pfcwd", "WARNING", 
                                "PFCWD increment detected: {}".format(message),
                                increment_data
                            )
                        except Exception as e:
                            print("ERROR: Failed to send PFCWD alert to Splunk: {}".format(e))
            
            return increment_report
            
        except Exception as e:
            print("ERROR analyzing PFCWD increments: {}".format(e))
            return []
        finally:
            conn.close()
    
    def analyze_storm_status(self, run_id):
        """Check for queues currently in 'stormed' status and generate alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Find all queues with 'stormed' status in the current run
            cursor.execute("""
                SELECT dut_name, interface, queue_number, status, storm_detected, storm_restored, timestamp
                FROM pfcwd_history
                WHERE run_id = ? AND LOWER(status) = 'stormed'
                ORDER BY dut_name, interface, queue_number
            """, (run_id,))
            
            stormed_queues = cursor.fetchall()
            
            if stormed_queues:
                print("\n🚨 CRITICAL PFCWD STORM ALERTS ({} queues in stormed state):".format(len(stormed_queues)))
                print("=" * 70)
                
                for row in stormed_queues:
                    dut_name, interface, queue_number, status, storm_detected, storm_restored, timestamp = row
                    queue_info = "{}/{}:{}".format(dut_name, interface, queue_number)
                    storm_balance = storm_detected - storm_restored
                    
                    print("🚨 STORM ACTIVE: {} - Status: {} | Storms: {} | Restored: {} | Balance: {}".format(
                        queue_info, status, storm_detected, storm_restored, storm_balance))
                    
                    # Send detailed storm alert to Splunk
                    if self.splunk_output:
                        storm_alert_data = {
                            'interface': interface,
                            'queue_number': queue_number,
                            'status': status,
                            'storm_detected': storm_detected,
                            'storm_restored': storm_restored,
                            'storm_balance': storm_balance,
                            'alert_type': 'stormed_status',
                            'severity': 'CRITICAL',
                            'run_id': run_id,
                            'timestamp': timestamp
                        }
                        
                        try:
                            self.splunk_output.store_alert(
                                dut_name, "pfcwd", "CRITICAL",
                                "PFCWD Queue in STORMED state: {}/{}:{} (Storm Balance: {})".format(
                                    dut_name, interface, queue_number, storm_balance),
                                storm_alert_data
                            )
                        except Exception as e:
                            print("ERROR: Failed to send detailed storm alert to Splunk: {}".format(e))
                
                print("=" * 70)
                return stormed_queues
            else:
                print("INFO: No queues currently in 'stormed' status")
                return []
                
        except Exception as e:
            print("ERROR analyzing storm status: {}".format(e))
            return []
        finally:
            conn.close()
    
    def validate_pfcwd_format(self, pfcwd_data, dut_name):
        """
        Validate PFCWD CLI output format and alert if unexpected changes detected.
        Expected format for 'show pfcwd stat' should contain interface:queue entries with specific fields.
        """
        expected_fields_in_line = ['interface:queue', 'status', 'storm_detected/restored', 'tx_ok/drops', 'rx_ok/drops']
        
        try:
            # Handle different data formats
            if isinstance(pfcwd_data, dict):
                pfcwd_output = pfcwd_data.get('output', str(pfcwd_data))
            elif isinstance(pfcwd_data, list):
                pfcwd_output = '\n'.join(str(item) for item in pfcwd_data)
            else:
                pfcwd_output = str(pfcwd_data)
            
            if not pfcwd_output or pfcwd_output.strip() == "":
                return True  # Empty output is valid (no PFCWD data)
            
            lines = pfcwd_output.split('\n')
            data_lines = []
            header_found = False
            
            # Look for header and data lines
            for line in lines:
                line_stripped = line.strip()
                
                # Skip empty lines and command prompts
                if not line_stripped or '@' in line_stripped:
                    continue
                
                # Detect header line
                if 'QUEUE' in line_stripped and 'STATUS' in line_stripped:
                    header_found = True
                    continue
                
                # Skip separator lines
                if '-------' in line_stripped:
                    continue
                
                # Potential data line (should contain interface and colon)
                if ':' in line_stripped and any(c.isalpha() for c in line_stripped):
                    data_lines.append(line_stripped)
            
            # Field validation - alert if CLI format changed
            if header_found:
                if not data_lines:
                    print("INFO: PFCWD headers found but no queue data for device {} (normal when no queues configured)".format(dut_name))
                    return True
                
                # Validate format of first few data lines
                validation_sample = data_lines[:3]  # Check first 3 lines
                format_issues = []
                
                for i, line in enumerate(validation_sample):
                    fields = line.split()
                    
                    # Expected minimum fields: interface:queue, status, storm_counts, tx_counts, rx_counts
                    if len(fields) < 5:
                        format_issues.append("Line {} has insufficient fields ({} < 5): '{}'".format(i+1, len(fields), line))
                        continue
                    
                    # Validate interface:queue format
                    if ':' not in fields[0]:
                        format_issues.append("Line {} missing interface:queue format in field 0: '{}'".format(i+1, fields[0]))
                    
                    # Validate count fields have slash format (storm_detected/restored, tx_ok/drops, rx_ok/drops)
                    count_fields = fields[2:]  # Skip interface:queue and status
                    slash_fields = [field for field in count_fields if '/' in field]
                    
                    if len(slash_fields) < 3:  # Expect at least 3 slash-separated count fields
                        format_issues.append("Line {} missing expected count fields with '/' format. Found: {}".format(i+1, slash_fields))
                
                # Alert user if format issues detected
                if format_issues:
                    print("CRITICAL ALERT: PFCWD CLI format issues detected on DUT {}: {}".format(dut_name, len(format_issues)))
                    print("ALERT: PFCWD parsing may fail - CLI output format may have changed!")
                    print("ALERT: Expected format: 'interface:queue status storm_detected/restored tx_ok/drops rx_ok/drops ...'")
                    for issue in format_issues[:3]:  # Show first 3 issues
                        print("ALERT: {}".format(issue))
                    if len(format_issues) > 3:
                        print("ALERT: ... and {} more format issues".format(len(format_issues) - 3))
                    print("ALERT: Sample data lines found: {}".format(len(data_lines)))
                    return False
                
                print("INFO: PFCWD format validation passed for device {} ({} data lines)".format(dut_name, len(data_lines)))
                return True
            
            else:
                # No header found - could be empty output or format change
                if any('ethernet' in line.lower() or 'interface' in line.lower() for line in lines):
                    print("CRITICAL ALERT: PFCWD data detected on DUT {} but no standard header found!".format(dut_name))
                    print("ALERT: PFCWD CLI format may have changed - missing expected 'QUEUE' and 'STATUS' headers")
                    print("ALERT: Raw output preview: {}".format(pfcwd_output[:200]))
                    return False
                else:
                    # Likely empty/no data case
                    return True
                
        except Exception as e:
            print("ERROR: PFCWD format validation failed for DUT {}: {}".format(dut_name, e))
            return False

if __name__ == "__main__":
    # Test the PFCWD analyzer
    analyzer = PFCWDAnalyzer()
    
    # Test parsing a sample line
    test_line = "Ethernet256:3  operational                        9/9  159873/41785903558           0/0       0/5823727078                0/0"
    parsed = analyzer.parse_pfcwd_line(test_line)
    print("Parsed PFCWD line:")
    print(json.dumps(parsed, indent=2))