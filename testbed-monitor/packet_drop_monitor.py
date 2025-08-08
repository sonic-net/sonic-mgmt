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
    from interface_drop_analyzer import InterfaceDropAnalyzer
    from drop_reason_analyzer import DropReasonAnalyzer
    from queue_counter_analyzer import QueueCounterAnalyzer
    from pg_drop_analyzer import PriorityGroupDropAnalyzer
    from npu_drop_analyzer import NPUDropAnalyzer
    from core_file_analyzer import CoreFileAnalyzer
    from pfcwd_analyzer import PFCWDAnalyzer
except ImportError as e:
    print("Warning: Could not import analyzers: {}".format(e))

# Import output modules
try:
    from splunk_output import SplunkOutput, load_splunk_config_from_yaml
except ImportError as e:
    print("Warning: Could not import output modules: {}".format(e))



class PacketDropMonitor:
    """
    Main orchestrator for 24/7 packet drop monitoring system.
    
    This class coordinates data collection, analysis, and alerting across
    multiple monitoring layers (interface, queue, priority group, NPU, core files).
    
    Key Responsibilities:
    - Execute crawler for data collection
    - Coordinate specialized analyzers for root cause analysis
    - Trigger deep-dive analysis for problem interfaces
    - Monitor core files for system crash detection
    - Manage database storage and historical tracking
    - Send alerts to local DB and/or Splunk
    
    Database Path Handling:
    - None: Creates ~/packet_monitor_data/crawler-TIMESTAMP.db
    - Directory: Creates timestamped file in specified directory
    - File path: Uses exact file specified
    """
    
    def __init__(self, db_path=None, config_file="testbed_info.yml", abort_on_error=False, output_mode='db'):
        """
        Initialize packet drop monitoring system.
        
        Args:
            db_path (str, optional): Database file or directory path
                - None: Use default ~/packet_monitor_data/
                - Directory: Create timestamped file in directory
                - File: Use exact database file path
            config_file (str): YAML configuration file with device info
            abort_on_error (bool): If True, stop on first crawler error
            output_mode (str): Output destination - 'db' or 'splunk'
        """
        import os
        import yaml
        
        self.output_mode = output_mode
        print("Output mode: {}".format(output_mode))
        
        # DATABASE PATH CONFIGURATION - Always create database (needed for internal operations)
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
            db_file_path = os.path.join(db_dir, "crawler-{}.db".format(timestamp))
            print("Creating new database in custom directory: {}".format(db_file_path))
            self.db_path = db_file_path
            
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
            
        # Load YAML configuration
        try:
            with open(self.config_file, 'r') as f:
                self.config_data = yaml.safe_load(f)
        except Exception as e:
            print("ERROR: Failed to load config file {}: {}".format(self.config_file, e))
            exit(1)
        
        # OUTPUT INITIALIZATION - Pure Analyzer Tables Approach
        # No centralized db_output - each analyzer manages its own database tables
        # This eliminates database locking conflicts entirely
        
        # Set up Splunk output if requested
        self.splunk_output = None
        if self.output_mode == 'splunk':
            splunk_config = load_splunk_config_from_yaml(self.config_data)
            if splunk_config:
                try:
                    self.splunk_output = SplunkOutput(**splunk_config)
                    # Test connection
                    if self.splunk_output.test_connection():
                        print("✓ Splunk HEC connection verified")
                    else:
                        print("WARNING: Splunk HEC connection test failed")
                        if self.output_mode == 'splunk':
                            print("ERROR: Splunk-only mode requires working connection")
                            exit(1)
                except Exception as e:
                    print("ERROR: Failed to initialize Splunk output: {}".format(e))
                    if self.output_mode == 'splunk':
                        exit(1)
                    else:
                        print("WARNING: Continuing with database output only")
                        self.splunk_output = None
            else:
                print("ERROR: Splunk output requested but no configuration found in {}".format(self.config_file))
                print("Please add 'splunk:' section with hec_url and hec_token")
                if self.output_mode == 'splunk':
                    exit(1)
                else:
                    print("WARNING: Continuing with database output only")
        
        # Monitoring Configuration of data collection time interval
        self.collection_interval = 60  #60 seconds
        
        # Analyzer Initiation - Pure Analyzer Tables Approach
        # Each analyzer manages its own database tables and handles Splunk output directly
        # This eliminates centralized db_output and prevents database locking conflicts
        
        # Pass splunk_output directly to analyzers for Splunk mode
        analyzer_splunk_output = self.splunk_output if self.output_mode == 'splunk' else None
        
        self.interface_drop_analyzer = InterfaceDropAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
        self.drop_reason_analyzer = DropReasonAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
        self.queue_counter_analyzer = QueueCounterAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
        self.pg_drop_analyzer = PriorityGroupDropAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
        self.npu_drop_analyzer = NPUDropAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
        self.core_file_analyzer = CoreFileAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
        self.pfcwd_analyzer = PFCWDAnalyzer(self.db_path, splunk_output=analyzer_splunk_output)
    
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
    
    def analyze_interface_drops(self, run_id):
        """Analyze interface drops using the interface drop analyzer"""
        try:
            # Process interface counter data for this run
            if self.interface_drop_analyzer.process_interface_data(run_id):
                # Analyze and report interface drop increases
                interface_increases = self.interface_drop_analyzer.analyze_drop_increases(run_id)
                self.interface_drop_analyzer.print_interface_increases_report(interface_increases)
                return interface_increases
            else:
                print("INFO: No interface counter data available for analysis")
                return []
                
        except Exception as e:
            print("ERROR: Interface drop analysis failed: {}".format(e))
            return []

    def show_top_interfaces(self, run_id, limit=5):
        """Show interfaces with highest drop counts for current run using the analyzer"""
        try:
            self.interface_drop_analyzer.show_top_interfaces(run_id, limit)
        except Exception as e:
            print("ERROR: Top interfaces report failed: {}".format(e))
    
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
        try:
            # Process NPU drop data for this run
            if self.npu_drop_analyzer.process_npu_drops(run_id):
                # Analyze and report NPU drops (counters reset after each command)
                npu_drops = self.npu_drop_analyzer.analyze_npu_drop_increases(run_id)
                self.npu_drop_analyzer.print_npu_increases_report(npu_drops)
            else:
                print("INFO: No NPU drop data available for analysis")
                
        except Exception as e:
            print("ERROR: NPU drop analysis failed: {}".format(e))

    def analyze_core_files(self, run_id):
        """Analyze core files using the core file analyzer"""
        try:
            # Process core file data for this run
            if self.core_file_analyzer.process_core_files(run_id):
                # Analyze and report new core files
                new_cores = self.core_file_analyzer.analyze_new_core_files(run_id)
                self.core_file_analyzer.print_core_file_report(new_cores)
                self.core_file_analyzer.get_core_file_summary(run_id)
            else:
                print("INFO: No core file data available for analysis")
                
        except Exception as e:
            print("ERROR: Core file analysis failed: {}".format(e))

    def analyze_pfcwd_stats(self, run_id):
        """Analyze PFCWD statistics using the PFCWD analyzer"""
        try:
            # Always process PFCWD statistics (sends status to Splunk even if no data)
            has_data = self.pfcwd_analyzer.process_pfcwd_stats(run_id)
            
            if has_data:
                # Analyze and report PFCWD increments
                pfcwd_increments = self.pfcwd_analyzer.analyze_pfcwd_increments(run_id)
                if pfcwd_increments:
                    print("\nPFCWD INCREMENT ALERTS ({} queues with changes):".format(len(pfcwd_increments)))
                    print("-" * 60)
                    for increment in pfcwd_increments:
                        queue_info = "{}/{}:{}".format(increment['dut_name'], increment['interface'], increment['queue_number'])
                        if increment['storm_increment'] > 0:
                            print("PFCWD STORM: {} - Storm detected +{} (total: {})".format(
                                queue_info, increment['storm_increment'], increment['current_storm_detected']))
                        if increment['tx_drop_increment'] > 0:
                            print("PFCWD TX DROP: {} - TX drops +{:,} (total: {:,})".format(
                                queue_info, increment['tx_drop_increment'], increment['current_tx_drops']))
                        if increment['rx_drop_increment'] > 0:
                            print("PFCWD RX DROP: {} - RX drops +{:,} (total: {:,})".format(
                                queue_info, increment['rx_drop_increment'], increment['current_rx_drops']))
                else:
                    print("INFO: No PFCWD increments detected")
                
                # Analyze storm status for all queues (regardless of increments)
                stormed_queues = self.pfcwd_analyzer.analyze_storm_status(run_id)
                if stormed_queues:
                    print("WARNING: {} queue(s) currently in STORMED state - immediate attention required!".format(len(stormed_queues)))
            else:
                print("INFO: No PFCWD data available for analysis")
                
        except Exception as e:
            print("ERROR: PFCWD analysis failed: {}".format(e))

    def get_interfaces_with_drop_reason_increases(self, current_run_id):
        """Get interfaces that have drop reason increases"""
        interfaces_with_increases = []
        
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        cursor = conn.cursor()
        
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
        - CoreFileAnalyzer: System crash detection via core files
        - PFCWDAnalyzer: Priority Flow Control Watchdog statistics
        
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
        
        # PHASE 2: INTERFACE DROP ANALYSIS  
        # Process interface counters and detect drop increases
        interfaces_with_increases = self.analyze_interface_drops(run_id)
        
        # PHASE 3: TOP INTERFACE REPORTING
        # Show current snapshot of interfaces with most drops
        self.show_top_interfaces(run_id, 5)
        
        # PHASE 4: MULTI-LAYER ANALYSIS
        # Run specialized analyzers for different drop categories
        self.analyze_drop_reasons(run_id)  # Why drops occurred
        drop_reason_interfaces = self.get_interfaces_with_drop_reason_increases(run_id)
        
        # PHASE 5: DEEP-DIVE INVESTIGATION  
        # Combine interface lists from multiple detection sources
        all_interfaces_with_increases = interfaces_with_increases + drop_reason_interfaces
        
        # Execute detailed analysis for problematic interfaces
        # COMMENTED OUT: Deep dive commands (rxcgm/txcgm analysis)
        if all_interfaces_with_increases:
            self.run_deep_dive_commands(all_interfaces_with_increases)
        
        # Step 6: Analyze queue counters (separate analysis)
        self.analyze_queue_counters(run_id)
        
        # Step 7: Analyze priority group drops (separate analysis)
        self.analyze_pg_drops(run_id)
        
        # Step 8: Analyze NPU drops (separate analysis)
        self.analyze_npu_drops(run_id)
        
        # Step 9: Analyze core files (critical system health check)
        self.analyze_core_files(run_id)
        
        # Step 10: Analyze PFCWD statistics
        self.analyze_pfcwd_stats(run_id)
        
        # Step 11: Show current NPU drop counters
        try:
            self.npu_drop_analyzer.print_current_npu_drops(run_id, 10)
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
        finally:
            print("Closing output connections...")
            self.close_outputs()

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
            dut_list, _, _ = load_duts_and_commands(self.config_file)
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        cursor = conn.cursor()
        
        try:
            print("\nDEEP-DIVE ANALYSIS RESULTS:")
            print("=" * 80)
            
            for dut_name, interface in interfaces_with_increases:
                print("\nResults for {}/{}:".format(dut_name, interface))
                print("-" * 50)
                
                # Get RX interface_cgm results (traffic classes 0-7)
                cursor.execute("""
                    SELECT command, raw_data, json_data
                    FROM crawler_logs
                    WHERE dut_name = ?
                    AND command LIKE 'sudo show platform npu rx interface_cgm -t % -i {}'
                    ORDER BY id DESC
                    LIMIT 8
                """.format(interface), (dut_name,))
                
                rx_results = cursor.fetchall()
                if rx_results:
                    print("  RX Interface CGM Results:")
                    for command, raw_data, json_data in rx_results:
                        # Extract traffic class from command
                        import re
                        tc_match = re.search(r'-t (\d+)', command)
                        tc = tc_match.group(1) if tc_match else 'unknown'
                        
                        print("    TC {}: {}".format(tc, command))
                        print("    " + "-" * 70)
                        
                        # Show raw output if available
                        if raw_data:
                            print("    RAW OUTPUT:")
                            for line in raw_data.split('\n'):
                                print("    {}".format(line))
                        else:
                            # Fallback to parsed data if no raw data
                            try:
                                parsed_data = json.loads(json_data)
                                if parsed_data and isinstance(parsed_data, dict):
                                    print("    PARSED DATA:")
                                    for key, value in parsed_data.items():
                                        print("      {}: {}".format(key, value))
                                else:
                                    print("    No data available")
                            except json.JSONDecodeError:
                                print("    Parse error - no data available")
                        print("")
                
                # Get TX cgm_state results
                cursor.execute("""
                    SELECT command, raw_data, json_data
                    FROM crawler_logs
                    WHERE dut_name = ?
                    AND command LIKE 'sudo show platform npu tx cgm_state -i {}'
                    ORDER BY id DESC
                    LIMIT 1
                """.format(interface), (dut_name,))
                
                tx_results = cursor.fetchall()
                if tx_results:
                    print("  TX CGM State Results:")
                    for command, raw_data, json_data in tx_results:
                        print("    Command: {}".format(command))
                        print("    " + "-" * 70)
                        
                        # Show raw output if available
                        if raw_data:
                            print("    RAW OUTPUT:")
                            for line in raw_data.split('\n'):
                                print("    {}".format(line))
                        else:
                            # Fallback to parsed data if no raw data
                            try:
                                parsed_data = json.loads(json_data)
                                if parsed_data and isinstance(parsed_data, dict):
                                    print("    PARSED DATA:")
                                    for key, value in parsed_data.items():
                                        print("      {}: {}".format(key, value))
                                else:
                                    print("    No data available")
                            except json.JSONDecodeError:
                                print("    Parse error - no data available")
                        print("")
                
                if not rx_results and not tx_results:
                    print("  No deep-dive results found in database")
        
        except Exception as e:
            print("ERROR: Failed to display deep-dive results: {}".format(e))
        finally:
            conn.close()
        print("\nDeep-dive analysis complete")
        print("=" * 80)
    
    def store_drop_data(self, device_name, analyzer_type, data):
        """
        Store drop counter data using Splunk only (Pure Analyzer Tables approach).
        
        This method is now only used for interface analyzer data.
        Specialized analyzers handle their own database tables and Splunk output directly.
        
        Args:
            device_name (str): Name of the monitored device
            analyzer_type (str): Type of analyzer (interface, drop_reason, queue, etc.)
            data (dict): Drop counter data to store
        """
        # Only Splunk output - no centralized database
        if self.splunk_output:
            try:
                success = self.splunk_output.store_drop_data(device_name, analyzer_type, data)
                if not success:
                    print("WARNING: Failed to send data to Splunk")
                else:
                    print("✓ Data sent to Splunk successfully")
            except Exception as e:
                print("ERROR: Failed to send data to Splunk: {}".format(e))
        else:
            print("INFO: No Splunk output configured for {} data from {}".format(analyzer_type, device_name))
    
    def store_alert(self, device_name, analyzer_type, alert_level, message, details=None):
        """
        Store alert using Splunk only (Pure Analyzer Tables approach).
        
        Args:
            device_name (str): Name of the monitored device
            analyzer_type (str): Type of analyzer that generated the alert
            alert_level (str): Alert severity level (INFO, WARNING, ERROR)
            message (str): Alert message
            details (dict, optional): Additional alert details
        """
        if self.splunk_output:
            try:
                success = self.splunk_output.store_alert(device_name, analyzer_type, alert_level, message, details)
                if not success:
                    print("WARNING: Failed to send alert to Splunk")
            except Exception as e:
                print("ERROR: Failed to send alert to Splunk: {}".format(e))
        else:
            print("INFO: Alert logged locally - {} - {}: {}".format(alert_level, device_name, message))
    
    def close_outputs(self):
        """Close all output connections and clean up temporary files."""
        if self.splunk_output:
            self.splunk_output.close()
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='24/7 Packet Drop Monitor')
    parser.add_argument('--db', '--database', dest='db_path', 
                        help='Database file path or directory (default: ~/packet_monitor_data/crawler-TIMESTAMP.db)')
    parser.add_argument('--config', '--testbed', dest='config_file', 
                        help='YAML configuration file with device info and commands')
    parser.add_argument('-E', action='store_true',
                        help='exit for any error when running crawler (default: False)')
    parser.add_argument('--output', choices=['db', 'splunk'], default='db',
                        help='Output destination: db (SQLite database) or splunk (HEC) (default: db)')
    
    args = parser.parse_args()
    
    # Validate config file is provided and exists
    import os
    if not args.config_file:
        print("ERROR: Config file is required. Use --config <filename>")
        print("Please specify a YAML configuration file with device info and commands")
        exit(1)
    
    if not os.path.exists(args.config_file):
        print("ERROR: Config file '{}' not found".format(args.config_file))
        print("Please check the file path or use --help for usage information")
        exit(1)
    
    monitor = PacketDropMonitor(db_path=args.db_path, config_file=args.config_file, 
                                abort_on_error=args.E, output_mode=args.output)
    monitor.start_monitoring()