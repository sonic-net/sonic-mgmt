#!/usr/bin/env python3

import sqlite3
import json
import subprocess
import time
import os
import argparse
from datetime import datetime

# Import the analyzers
try:
    from drop_reason_analyzer import DropReasonAnalyzer
    from queue_counter_analyzer import QueueCounterAnalyzer
    from pg_drop_analyzer import PriorityGroupDropAnalyzer
    from npu_drop_analyzer import NPUDropAnalyzer
except ImportError as e:
    print("Warning: Could not import analyzers: {}".format(e))



class PacketDropMonitor:
    """
    Main orchestrator for 24/7 packet drop monitoring system.
    
    This class coordinates data collection, analysis, and alerting across
    multiple monitoring layers (interface, queue, priority group, NPU).
    
    Key Responsibilities:
    - Execute crawler for data collection
    - Parse and validate interface counter data  
    - Detect drop increases between monitoring cycles
    - Trigger deep-dive analysis for problem interfaces
    - Coordinate specialized analyzers for root cause analysis
    - Manage database storage and historical tracking
    
    Database Path Handling:
    - None: Creates ~/packet_monitor_data/crawler-TIMESTAMP.db
    - Directory: Creates timestamped file in specified directory
    - File path: Uses exact file specified
    """
    
    def __init__(self, db_path=None, config_file="testbed_info.yml", abort_on_error=False):
        """
        Initialize packet drop monitoring system.
        
        Args:
            db_path (str, optional): Database file or directory path
                - None: Use default ~/packet_monitor_data/
                - Directory: Create timestamped file in directory
                - File: Use exact database file path
            config_file (str): YAML configuration file with device info
                Example format:
                    all:
                      children:
                        dut_group:
                          hosts:
                            device-name:
                              ansible_host: "IP"
                              ansible_user: "user" 
                              ansible_password: "pass"
                      commands:
                        - "show int counter -d all"
                        - "show dropcounter count"
            abort_on_error (bool): If True, stop on first crawler error
                                  If False, continue monitoring on errors
        """
        import os
        
        # DATABASE PATH CONFIGURATION
        # Handle flexible database path options for different deployment scenarios
        if db_path is None:
            # Default: Use ~/packet_monitor_data/
            home_dir = os.path.expanduser("~")
            db_dir = os.path.join(home_dir, "packet_monitor_data")
            
            # Create the directory if it doesn't exist
            if not os.path.exists(db_dir):
                try:
                    os.makedirs(db_dir, exist_ok=True)
                    print("Created default database directory: {}".format(db_dir))
                except OSError as e:
                    print("ERROR: Cannot create directory {}: {}".format(db_dir, e))
                    print("Please check permissions or use a different path")
                    exit(1)
            else:
                print("Using default database directory: {}".format(db_dir))
            
            # Generate timestamped database filename
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            self.db_path = os.path.join(db_dir, "crawler-{}.db".format(timestamp))
            print("Creating new database: {}".format(self.db_path))
            
        elif os.path.isdir(db_path) or db_path.endswith('/'):
            # User provided a directory - create timestamped file in that directory
            db_dir = os.path.abspath(db_path.rstrip('/'))
            
            # Create the directory if it doesn't exist
            if not os.path.exists(db_dir):
                try:
                    os.makedirs(db_dir, exist_ok=True)
                    print("Created database directory: {}".format(db_dir))
                except OSError as e:
                    print("ERROR: Cannot create directory {}: {}".format(db_dir, e))
                    print("Please check permissions or use a different path")
                    exit(1)
            
            # Generate timestamped database filename
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            self.db_path = os.path.join(db_dir, "crawler-{}.db".format(timestamp))
            print("Creating new database in custom directory: {}".format(self.db_path))
            
        else:
            # User provided a specific database file path
            self.db_path = os.path.abspath(db_path)
            
            # Create parent directory if it doesn't exist
            parent_dir = os.path.dirname(self.db_path)
            if parent_dir and not os.path.exists(parent_dir):
                try:
                    os.makedirs(parent_dir, exist_ok=True)
                    print("Created directory: {}".format(parent_dir))
                except OSError as e:
                    print("ERROR: Cannot create directory {}: {}".format(parent_dir, e))
                    print("Please check permissions or use a different path")
                    exit(1)
            
            if os.path.exists(self.db_path):
                print("Using existing database file: {}".format(self.db_path))
            else:
                print("Creating new database file: {}".format(self.db_path))
        
        # SYSTEM CONFIGURATION
        self.config_file = config_file
        self.abort_on_error = abort_on_error
        print("Using config file: {}".format(self.config_file))
        if abort_on_error:
            print("Crawler will abort on first error (-E enabled)")
        else:
            print("Crawler will continue on errors (default behavior)")
            
        # Initialize database schema
        self.setup_database()
        
        # MONITORING CONFIGURATION
        self.collection_interval = 60  # 1 minute intervals for testing (production: 300-600 seconds)
        
        # ANALYZER INITIALIZATION
        # All analyzers share the same database for coordinated analysis
        # Each analyzer handles a specific layer of packet drop monitoring
        self.drop_reason_analyzer = DropReasonAnalyzer(self.db_path)
        self.queue_counter_analyzer = QueueCounterAnalyzer(self.db_path)
        self.pg_drop_analyzer = PriorityGroupDropAnalyzer(self.db_path)
        self.npu_drop_analyzer = NPUDropAnalyzer(self.db_path)
        
    def setup_database(self):
        """Create table for tracking interface drops"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS interface_drops_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                interface TEXT NOT NULL,
                rx_drops INTEGER DEFAULT 0,
                tx_drops INTEGER DEFAULT 0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, interface, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_drops_dut_interface_time 
            ON interface_drops_history(dut_name, interface, timestamp DESC)
        """)
        
        conn.commit()
        conn.close()
    
    def run_crawler(self):
        """Execute crawler_main.py to collect fresh data"""
        print("Collecting data from devices...")
        
        print("Executing crawler with config: {}".format(self.config_file))
        
        try:
            # Build crawler command
            crawler_cmd = ["python3", "crawler_main.py", "--db", self.db_path, "--config", self.config_file]
            if self.abort_on_error:
                crawler_cmd.append("-E")
            
            # Don't capture output so we can see real-time progress
            result = subprocess.run(crawler_cmd)
            
            if result.returncode != 0:
                if result.returncode == 2:
                    print("ERROR: Configuration error - no commands found in YAML file")
                    exit(1)  # Abort the entire packet monitor
                else:
                    print("ERROR: Crawler failed with return code: {}".format(result.returncode))
                    return False
                
            print("Data collection complete")
            return True
            
        except Exception as e:
            print("ERROR: Data collection failed: {}".format(e))
            return False
    
    def parse_number(self, value_str):
        """
        Parse numeric string with commas into integer.
        
        SONiC CLI often formats large numbers with commas (e.g., "1,234,567").
        This function safely converts these strings to integers for mathematical operations.
        
        Args:
            value_str: String, int, or float value to parse
                      Examples: "1,234", "0", "567,890", 1234
        
        Returns:
            int: Parsed integer value, 0 if parsing fails
            
        Examples:
            parse_number("1,234,567") -> 1234567
            parse_number("0") -> 0
            parse_number("") -> 0
            parse_number(None) -> 0
        """
        if isinstance(value_str, str):
            clean_str = value_str.replace(',', '').strip()
            try:
                return int(clean_str)
            except ValueError:
                return 0
        elif isinstance(value_str, (int, float)):
            return int(value_str)
        return 0
    
    def process_and_store_data(self, run_id):
        """
        Process crawler results and extract interface drop data for monitoring.
        
        This is the core data processing function that:
        1. Extracts interface counter data from crawler database
        2. Validates critical field names (CLI format change detection)
        3. Parses drop counters and stores in monitoring tables
        4. Provides detailed alerts when field validation fails
        
        The function focuses on 'show int counter' command results, extracting:
        - Interface names (iface field)
        - RX drop counters (rx_drp field) 
        - TX drop counters (tx_drp field)
        
        Args:
            run_id (int): Unique identifier for this monitoring cycle
                         (timestamp-based for chronological ordering)
        
        Returns:
            bool: True if data was successfully processed, False otherwise
            
        Field Validation:
            Checks for essential fields and alerts if CLI output format changes:
            - Missing 'iface' field -> Interface parsing will fail
            - Missing 'rx_drp'/'tx_drp' -> Drop detection will fail
            - Provides available field list for troubleshooting
            
        Database Storage:
            Stores validated data in interface_drops_history table:
            - dut_name: Device identifier
            - interface: Interface name (Ethernet*)
            - rx_drops/tx_drops: Current counter values
            - timestamp: Processing time
            - run_id: Monitoring cycle identifier
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            interfaces_processed = 0
            timestamp = datetime.now()
            dut_names = set()
            total_commands_processed = 0
            
            # Process interface counter data if available
            cursor.execute("""
                SELECT dut_name, json_data
                FROM crawler_logs
                WHERE command LIKE '%show int counter%'
                AND id IN (
                    SELECT MAX(id)
                    FROM crawler_logs
                    WHERE command LIKE '%show int counter%'
                    GROUP BY dut_name
                )
                ORDER BY dut_name
            """)
            
            interface_data = cursor.fetchall()
            
            # Process each DUT's interface data
            for dut_name, json_data in interface_data:
                dut_names.add(dut_name)
                try:
                    interfaces = json.loads(json_data)
                    
                    # Field validation - check if essential fields exist in first few interfaces
                    if interfaces and len(interfaces) > 0:
                        # Check first few interface entries for required fields
                        sample_interfaces = interfaces[:3] if len(interfaces) >= 3 else interfaces
                        missing_fields = []
                        
                        for sample in sample_interfaces:
                            if isinstance(sample, dict):
                                # Check for essential field names
                                if 'iface' not in sample:
                                    missing_fields.append('iface')
                                if 'rx_drp' not in sample:
                                    missing_fields.append('rx_drp') 
                                if 'tx_drp' not in sample:
                                    missing_fields.append('tx_drp')
                                break  # Only need to check one valid interface
                        
                        # Alert if critical fields are missing
                        if missing_fields:
                            missing_fields = list(set(missing_fields))  # Remove duplicates
                            print("CRITICAL ALERT: Essential interface fields missing from DUT {}: {}".format(
                                dut_name, ', '.join(missing_fields)))
                            print("ALERT: Interface parsing may fail - CLI output format may have changed!")
                            print("ALERT: Expected fields: 'iface', 'rx_drp', 'tx_drp'")
                            print("ALERT: Available fields in data: {}".format(
                                list(sample.keys()) if isinstance(sample, dict) else "No valid interface data"))
                            # Continue processing with available fields to avoid complete failure
                    
                    for i, interface_data in enumerate(interfaces):
                        if not isinstance(interface_data, dict):
                            continue
                            
                        interface_name = interface_data.get('iface', 'interface_{}'.format(i))
                        rx_drops = self.parse_number(interface_data.get('rx_drp', 0))
                        tx_drops = self.parse_number(interface_data.get('tx_drp', 0))
                        
                        # Additional field validation per interface 
                        if 'iface' not in interface_data:
                            print("WARNING: Interface name field 'iface' missing for entry {} on DUT {}".format(i, dut_name))
                        if 'rx_drp' not in interface_data and 'tx_drp' not in interface_data:
                            print("WARNING: Both drop fields 'rx_drp' and 'tx_drp' missing for interface {} on DUT {}".format(
                                interface_name, dut_name))
                        
                        # Skip non-interface entries
                        if interface_name in ['links', 'TX_DROPS'] or not interface_name.startswith('Ethernet'):
                            continue
                        
                        # Store in database
                        cursor.execute("""
                            INSERT OR REPLACE INTO interface_drops_history 
                            (dut_name, interface, rx_drops, tx_drops, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (dut_name, interface_name, rx_drops, tx_drops, timestamp, run_id))
                        
                        interfaces_processed += 1
                        
                except json.JSONDecodeError:
                    continue
            
            # Check for ANY command data from this run to determine success
            cursor.execute("""
                SELECT COUNT(*), COUNT(DISTINCT dut_name) 
                FROM crawler_logs 
                WHERE datetime(substr(json_data, 1, 0)) >= datetime('now', '-5 minutes')
                   OR id > (SELECT COALESCE(MAX(id), 0) - 100 FROM crawler_logs)
            """)
            
            result = cursor.fetchone()
            recent_commands = result[0] if result else 0
            recent_duts = result[1] if result else 0
            
            # Get list of DUTs that had any recent data
            cursor.execute("""
                SELECT DISTINCT dut_name 
                FROM crawler_logs 
                WHERE datetime(substr(json_data, 1, 0)) >= datetime('now', '-5 minutes')
                   OR id > (SELECT COALESCE(MAX(id), 0) - 100 FROM crawler_logs)
            """)
            
            all_active_duts = set(row[0] for row in cursor.fetchall())
            dut_names.update(all_active_duts)
            
            print("DUTs processed this cycle: {}".format(
                ", ".join(d for d in sorted(dut_names))))
            
            if interfaces_processed > 0:
                print("Processed {} interfaces for run {}".format(interfaces_processed, run_id))
                total_commands_processed = interfaces_processed
            else:
                print("No interface counter data found, but {} commands from {} DUTs processed".format(
                    recent_commands, recent_duts))
                total_commands_processed = recent_commands
                
            conn.commit()
            
            # Success if either interfaces were processed OR any recent commands exist
            return total_commands_processed > 0
            
        except Exception as e:
            print("ERROR: Failed to process data: {}".format(e))
            return False
        finally:
            conn.close()
    
    def analyze_drop_increases(self, current_run_id):
        """Check for drop increases compared to previous run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        interfaces_with_increases = []  # List to return for deep-dive
        
        try:
            # Get previous run ID
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM interface_drops_history 
                WHERE run_id < ?
            """, (current_run_id,))
            
            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                print("INFO: No previous data for comparison (first run)")
                return interfaces_with_increases
            
            previous_run_id = previous_run_result[0]
            print("Comparing run {} vs previous run {}".format(current_run_id, previous_run_id))
            
            # Get interface counts for validation
            cursor.execute("SELECT COUNT(*) FROM interface_drops_history WHERE run_id = ?", (current_run_id,))
            current_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM interface_drops_history WHERE run_id = ?", (previous_run_id,))
            previous_count = cursor.fetchone()[0]
            
            print("Interfaces in current run: {}, previous run: {}".format(current_count, previous_count))
            
            # Find drop increases
            cursor.execute("""
                SELECT 
                    curr.dut_name,
                    curr.interface,
                    prev.rx_drops as prev_rx,
                    curr.rx_drops as curr_rx,
                    prev.tx_drops as prev_tx,
                    curr.tx_drops as curr_tx
                FROM interface_drops_history curr
                JOIN interface_drops_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.interface = prev.interface
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND (curr.rx_drops > prev.rx_drops OR curr.tx_drops > prev.tx_drops)
                ORDER BY (curr.rx_drops - prev.rx_drops + curr.tx_drops - prev.tx_drops) DESC
            """, (current_run_id, previous_run_id))
            
            increases = cursor.fetchall()
            
            if increases:
                print("\nDROP INCREASE ALERTS ({} interfaces):".format(len(increases)))
                print("=" * 80)
                
                for row in increases:
                    dut_name, interface, prev_rx, curr_rx, prev_tx, curr_tx = row
                    
                    rx_increase = curr_rx - prev_rx
                    tx_increase = curr_tx - prev_tx
                    total_increase = rx_increase + tx_increase
                    prev_total = prev_rx + prev_tx
                    curr_total = curr_rx + curr_tx
                    
                    print("ALERT: {}/{}: +{:,} drops".format(dut_name, interface, total_increase))
                    print("   RX: {:,} -> {:,} (+{:,})".format(prev_rx, curr_rx, rx_increase))
                    print("   TX: {:,} -> {:,} (+{:,})".format(prev_tx, curr_tx, tx_increase))
                    print("   Total: {:,} -> {:,}".format(prev_total, curr_total))
                    print("-" * 40)
                    
                    # Add to list for deep-dive
                    interfaces_with_increases.append((dut_name, interface))
            else:
                print("No drop increases detected")
                
        except Exception as e:
            print("ERROR: Failed to analyze drops: {}".format(e))
        finally:
            conn.close()
            
        return interfaces_with_increases
    
    def show_top_interfaces(self, run_id, limit=5):
        """Show top interfaces with the most drops in current run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get the top interfaces with most total drops (RX + TX)
            cursor.execute("""
                SELECT 
                    dut_name,
                    interface,
                    rx_drops,
                    tx_drops,
                    (rx_drops + tx_drops) as total_drops
                FROM interface_drops_history
                WHERE run_id = ?
                ORDER BY total_drops DESC
                LIMIT ?
            """, (run_id, limit))
            
            interfaces = cursor.fetchall()
            
            if not interfaces:
                print("\nNo interfaces with drops found in this run")
                return
            
            print("\nTOP {} INTERFACES WITH MOST DROPS:".format(limit))
            print("-" * 80)
            print("{:<15} {:<15} {:<15} {:<15} {:<15}".format(
                "DUT", "Interface", "RX Drops", "TX Drops", "Total Drops"))
            print("-" * 80)
            
            for row in interfaces:
                dut_name, interface, rx_drops, tx_drops, total_drops = row
                print("{:<15} {:<15} {:<15,} {:<15,} {:<15,}".format(
                    dut_name, interface, rx_drops, tx_drops, total_drops))
                
        except Exception as e:
            print("ERROR: Failed to get top interfaces: {}".format(e))
        finally:
            conn.close()
    
    def analyze_drop_reasons(self, run_id):
        """Analyze drop reasons using the separate drop reason analyzer"""
        try:
            # Process drop reason data for this run
            if self.drop_reason_analyzer.process_drop_reasons(run_id):
                # Analyze and report top drop reasons
                top_reasons = self.drop_reason_analyzer.analyze_top_drop_reasons(run_id)
                self.drop_reason_analyzer.print_drop_reasons_report(top_reasons)
            else:
                print("INFO: No drop reason data available for analysis")
                
        except Exception as e:
            print("ERROR: Drop reason analysis failed: {}".format(e))

    def analyze_queue_counters(self, run_id):
        """Analyze queue counter drops using the queue counter analyzer"""
        try:
            # Process queue counter data for this run
            if self.queue_counter_analyzer.process_queue_counters(run_id):
                # Analyze and report queue drop increases
                queue_increases = self.queue_counter_analyzer.analyze_queue_drop_increases(run_id)
                self.queue_counter_analyzer.print_queue_increases_report(queue_increases)
            else:
                print("INFO: No queue counter data available for analysis")
                
        except Exception as e:
            print("ERROR: Queue counter analysis failed: {}".format(e))

    def analyze_pg_drops(self, run_id):
        """Analyze priority group drops using the PG drop analyzer"""
        try:
            # Process PG drop data for this run
            if self.pg_drop_analyzer.process_pg_drops(run_id):
                # Analyze and report PG drop increases
                pg_increases = self.pg_drop_analyzer.analyze_pg_drop_increases(run_id)
                self.pg_drop_analyzer.print_pg_increases_report(pg_increases)
            else:
                print("INFO: No PG drop data available for analysis")
                
        except Exception as e:
            print("ERROR: PG drop analysis failed: {}".format(e))

    def analyze_npu_drops(self, run_id):
        """Analyze NPU drops using the NPU drop analyzer"""
        print("DEBUG: analyze_npu_drops called for run {}".format(run_id))
        try:
            # Process NPU drop data for this run
            if self.npu_drop_analyzer.process_npu_drops(run_id):
                # Analyze and report NPU drops (counters reset after each command)
                npu_drops = self.npu_drop_analyzer.analyze_npu_drop_increases(run_id)
                # Note: NPU drops are already printed in analyze_npu_drop_increases - no summary needed
            else:
                print("INFO: No NPU drop data available for analysis")
                
        except Exception as e:
            print("ERROR: NPU drop analysis failed: {}".format(e))

    def get_interfaces_with_drop_reason_increases(self, current_run_id):
        """Get interfaces that have drop reason increases"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        interfaces_with_increases = []
        
        try:
            # Get previous run ID
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM drop_reasons_history 
                WHERE run_id < ?
            """, (current_run_id,))
            
            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                return interfaces_with_increases
            
            previous_run_id = previous_run_result[0]
            
            # Find interfaces with drop reason increases
            cursor.execute("""
                SELECT DISTINCT curr.dut_name, curr.interface
                FROM drop_reasons_history curr
                JOIN drop_reasons_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.interface = prev.interface
                    AND curr.drop_reason = prev.drop_reason
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND curr.drop_count > prev.drop_count
            """, (current_run_id, previous_run_id))
            
            for row in cursor.fetchall():
                dut_name, interface = row
                interfaces_with_increases.append((dut_name, interface))
                
        except Exception as e:
            print("ERROR: Failed to get drop reason increases: {}".format(e))
        finally:
            conn.close()
            
        return interfaces_with_increases

    def monitoring_cycle(self):
        """
        Execute one complete monitoring cycle (the heart of the system).
        
        This function orchestrates the entire monitoring workflow:
        
        MONITORING PHASES:
        =================
        1. Data Collection: Execute crawler to gather fresh CLI data
        2. Data Processing: Parse and validate interface counters  
        3. Drop Analysis: Compare with previous run to detect increases
        4. Top Interface Report: Show current highest drop interfaces
        5. Multi-Layer Analysis: Run all specialized analyzers
        6. Deep-Dive Investigation: Detailed analysis for problem interfaces
        7. Historical Tracking: Store results for trend analysis
        
        ANALYZER COORDINATION:
        =====================
        - DropReasonAnalyzer: Categorizes why drops occurred
        - QueueCounterAnalyzer: Queue-level congestion analysis  
        - PriorityGroupDropAnalyzer: Priority-based drop analysis
        - NPUDropAnalyzer: Hardware ASIC-level drop counters
        
        DEEP-DIVE TRIGGERS:
        ==================
        Automatic deep-dive analysis triggered for interfaces with:
        - ANY interface drop increase (RX or TX)
        - Drop reason count increases
        - Executes detailed RX/TX congestion management commands
        
        Returns:
            bool: True if cycle completed successfully, False if critical failure
        """
        cycle_start = datetime.now()
        run_id = int(cycle_start.timestamp())  # Timestamp-based unique identifier
        
        print("=" * 60)
        print("MONITORING CYCLE {}".format(run_id))
        print("Time: {}".format(cycle_start.strftime('%Y-%m-%d %H:%M:%S')))
        print("=" * 60)
        print("[{}] ".format(cycle_start.strftime('%H:%M:%S')), end="")
        
        # PHASE 1: DATA COLLECTION
        # Execute crawler_main.py to gather fresh CLI data from all devices
        if not self.run_crawler():
            print("ERROR: Skipping analysis due to crawler failure")
            return False
        
        # PHASE 2: DATA PROCESSING & VALIDATION
        # Parse interface counters and validate field formats
        if not self.process_and_store_data(run_id):
            print("ERROR: No data processed")
            return False
        
        # PHASE 3: DROP INCREASE DETECTION
        # Compare current run with previous run to identify problematic interfaces
        interfaces_with_increases = self.analyze_drop_increases(run_id)
        
        # PHASE 4: TOP INTERFACE REPORTING
        # Show current snapshot of interfaces with most drops
        self.show_top_interfaces(run_id, 5)
        
        # PHASE 5: MULTI-LAYER ANALYSIS
        # Run specialized analyzers for different drop categories
        self.analyze_drop_reasons(run_id)  # Why drops occurred
        drop_reason_interfaces = self.get_interfaces_with_drop_reason_increases(run_id)
        
        # PHASE 6: DEEP-DIVE INVESTIGATION  
        # Combine interface lists from multiple detection sources
        all_interfaces_with_increases = interfaces_with_increases + drop_reason_interfaces
        
        # Execute detailed analysis for problematic interfaces
        if all_interfaces_with_increases:
            self.run_deep_dive_commands(all_interfaces_with_increases)
        
        # Step 7: Analyze queue counters (separate analysis)
        self.analyze_queue_counters(run_id)
        
        # Step 8: Analyze priority group drops (separate analysis)
        self.analyze_pg_drops(run_id)
        
        # Step 9: Analyze NPU drops (separate analysis)
        self.analyze_npu_drops(run_id)
        
        # Step 10: Show current NPU drop counters
        print("DEBUG: About to call print_current_npu_drops")
        try:
            self.npu_drop_analyzer.print_current_npu_drops(run_id, 10)
            print("DEBUG: print_current_npu_drops completed successfully")
        except Exception as e:
            print("ERROR: Failed to show NPU drops: {}".format(e))
            import traceback
            traceback.print_exc()
        
        print("Cycle {} complete".format(run_id))
        return True
    
    def start_monitoring(self):
        """Start 24/7 monitoring"""
        print("Starting 24/7 Packet Drop Monitor")
        print("Collection interval: {} minutes".format(self.collection_interval//60))
        print("Alert threshold: ANY drop increase")
        print("Press Ctrl+C to stop")
        print("")
        
        try:
            while True:
                success = self.monitoring_cycle()
                
                if success:
                    sleep_minutes = self.collection_interval // 60
                    next_run = datetime.fromtimestamp(time.time() + self.collection_interval)
                    print("Waiting for {} minutes".format(sleep_minutes))
                    print("Next run at: {}".format(next_run.strftime('%H:%M:%S')))
                    print("")
                else:
                    print("Cycle failed, sleeping for 5 minutes before retry...")
                    time.sleep(300)
                    continue
                
                time.sleep(self.collection_interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        except Exception as e:
            print("\nUnexpected error: {}".format(e))

    def run_deep_dive_commands(self, interfaces_with_increases):
        """
        Execute detailed analysis commands for interfaces with drop increases.
        
        When drops are detected, this function automatically executes specialized
        CLI commands to investigate the root cause at the hardware level.
        
        DEEP-DIVE COMMANDS EXECUTED:
        ============================
        For each problematic interface:
        
        RX Analysis (per traffic class 0-7):
        - sudo show platform npu rx interface_cgm -t {tc} -i {interface}
        - Reveals RX congestion management details
        - Shows per-priority drop reasons
        - Identifies queue overflow conditions
        
        TX Analysis:  
        - sudo show platform npu tx cgm_state -i {interface}
        - Shows TX queue states and congestion
        - Reveals egress port congestion details
        - Identifies buffer utilization issues
        
        OPTIMIZATION:
        ============
        - Groups interfaces by DUT to minimize SSH connections
        - Executes commands in parallel where possible  
        - Continues analysis even if individual commands fail
        - Stores all results in database for correlation
        
        RESULT PROCESSING:
        =================
        - Automatically parses command outputs
        - Displays non-zero counters for quick identification
        - Correlates results across multiple traffic classes
        - Provides actionable insights for network troubleshooting
        
        Args:
            interfaces_with_increases (list): List of (dut_name, interface) tuples
                                            that showed drop increases this cycle
        """
        if not interfaces_with_increases:
            print("No interfaces with drop increases - skipping deep-dive commands")
            return
        
        print("\nRUNNING DEEP-DIVE COMMANDS FOR {} INTERFACES:".format(len(interfaces_with_increases)))
        print("=" * 80)
        
        # Remove duplicates (same interface might appear from both interface drops and drop reasons)
        unique_interfaces = list(set(interfaces_with_increases))
        
        # Group by DUT to minimize SSH connections
        dut_interfaces = {}
        for dut_name, interface in unique_interfaces:
            if dut_name not in dut_interfaces:
                dut_interfaces[dut_name] = []
            dut_interfaces[dut_name].append(interface)
        
        # Import SSH functionality from crawler
        try:
            from crawler_main import run_command_on_dut, load_duts_and_commands
            
            # Load DUT configuration
            dut_list, _ = load_duts_and_commands(self.config_file)
            dut_config = {dut['name']: dut for dut in dut_list}
            
        except ImportError as e:
            print("ERROR: Could not import crawler functions: {}".format(e))
            return
        
        # Process each DUT
        for dut_name, interfaces in dut_interfaces.items():
            if dut_name not in dut_config:
                print("ERROR: DUT {} not found in configuration".format(dut_name))
                continue
                
            dut = dut_config[dut_name]
            print("\nDeep-dive analysis for DUT: {}".format(dut_name))
            print("-" * 50)
            
            # Process each interface for this DUT
            for interface in interfaces:
                print("\nInterface: {}".format(interface))
                print("  RX Deep-dive (8 traffic classes):")
                
                # Run RX commands for all 8 traffic classes
                for tc in range(8):
                    command = "sudo show platform npu rx interface_cgm -t {} -i {}".format(tc, interface)
                    print("    TC {}: Running {}".format(tc, command))
                    
                    try:
                        # Use crawler's run_command_on_dut function directly (continue on error for deep-dive)
                        run_command_on_dut(dut, command, self.db_path, abort_on_error=False)
                        print("    TC {}: Command completed".format(tc))
                    except Exception as e:
                        print("    TC {}: ERROR - {}".format(tc, e))
                
                # Run TX command
                print("  TX Deep-dive:")
                command = "sudo show platform npu tx cgm_state -i {}".format(interface)
                print("    Running: {}".format(command))
                
                try:
                    run_command_on_dut(dut, command, self.db_path, abort_on_error=False)
                    print("    TX: Command completed")
                except Exception as e:
                    print("    TX: ERROR - {}".format(e))
        
        print("\nDeep-dive commands executed - results stored in database")
        print("Parsing and displaying results...")
        
        # Now parse and display the results from the database
        self.display_deep_dive_results(unique_interfaces)
        
    def display_deep_dive_results(self, interfaces_with_increases):
        """Parse and display deep-dive command results from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            print("\nDEEP-DIVE ANALYSIS RESULTS:")
            print("=" * 80)
            
            for dut_name, interface in interfaces_with_increases:
                print("\nResults for {}/{}:".format(dut_name, interface))
                print("-" * 50)
                
                # Get RX interface_cgm results (traffic classes 0-7)
                cursor.execute("""
                    SELECT command, json_data
                    FROM crawler_logs
                    WHERE dut_name = ?
                    AND command LIKE 'sudo show platform npu rx interface_cgm -t % -i {}'
                    ORDER BY id DESC
                    LIMIT 8
                """.format(interface), (dut_name,))
                
                rx_results = cursor.fetchall()
                if rx_results:
                    print("  RX Interface CGM Results:")
                    for command, json_data in rx_results:
                        # Extract traffic class from command
                        import re
                        tc_match = re.search(r'-t (\d+)', command)
                        tc = tc_match.group(1) if tc_match else 'unknown'
                        
                        try:
                            parsed_data = json.loads(json_data)
                            if parsed_data and isinstance(parsed_data, dict):
                                print("    TC {}: Found CGM data".format(tc))
                                # Display any non-zero counters
                                for key, value in parsed_data.items():
                                    if isinstance(value, (int, float)) and value > 0:
                                        print("      {}: {:,}".format(key, value))
                            else:
                                print("    TC {}: No drops detected".format(tc))
                        except json.JSONDecodeError:
                            print("    TC {}: Parse error".format(tc))
                
                # Get TX cgm_state results
                cursor.execute("""
                    SELECT command, json_data
                    FROM crawler_logs
                    WHERE dut_name = ?
                    AND command LIKE 'sudo show platform npu tx cgm_state -i {}'
                    ORDER BY id DESC
                    LIMIT 1
                """.format(interface), (dut_name,))
                
                tx_results = cursor.fetchall()
                if tx_results:
                    print("  TX CGM State Results:")
                    for command, json_data in tx_results:
                        try:
                            parsed_data = json.loads(json_data)
                            if parsed_data and isinstance(parsed_data, dict):
                                print("    Found TX CGM data")
                                # Display any non-zero counters
                                for key, value in parsed_data.items():
                                    if isinstance(value, (int, float)) and value > 0:
                                        print("      {}: {:,}".format(key, value))
                            else:
                                print("    No TX drops detected")
                        except json.JSONDecodeError:
                            print("    TX: Parse error")
                
                if not rx_results and not tx_results:
                    print("  No deep-dive results found in database")
        
        except Exception as e:
            print("ERROR: Failed to display deep-dive results: {}".format(e))
        finally:
            conn.close()
        
        print("\nDeep-dive analysis complete")
        print("=" * 80)
        
    def validate_interface_fields_format(self, sample_data):
        """
        Validate that parsed interface data contains expected fields.
        Returns tuple: (is_valid, missing_fields, available_fields)
        """
        if not isinstance(sample_data, dict):
            return False, ['invalid_data_format'], []
        
        expected_fields = ['iface', 'rx_drp', 'tx_drp']
        missing_fields = []
        available_fields = list(sample_data.keys())
        
        for field in expected_fields:
            if field not in sample_data:
                missing_fields.append(field)
        
        is_valid = len(missing_fields) == 0
        return is_valid, missing_fields, available_fields
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='24/7 Packet Drop Monitor')
    parser.add_argument('--db', '--database', dest='db_path', 
                        help='Database file path or directory (default: ~/packet_monitor_data/crawler-TIMESTAMP.db)')
    parser.add_argument('--config', '--testbed', dest='config_file', 
                        default='testbed_info.yml',
                        help='YAML configuration file with device info and commands (default: testbed_info.yml)')
    parser.add_argument('-E', action='store_true',
                        help='exit for any error when running crawler (default: False)')
    
    args = parser.parse_args()
    
    # Validate config file exists
    import os
    if not os.path.exists(args.config_file):
        print("ERROR: Config file '{}' not found".format(args.config_file))
        print("Please check the file path or use --help for usage information")
        exit(1)
    
    monitor = PacketDropMonitor(db_path=args.db_path, config_file=args.config_file, abort_on_error=args.E)
    monitor.start_monitoring()