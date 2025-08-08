#!/usr/bin/env python3
"""
Interface Drop Analyzer - Analyzes interface counter data from 'show int counter'
Tracks RX/TX drop counters and utilization per interface across all devices
"""

import sqlite3
import json
from datetime import datetime


class InterfaceDropAnalyzer:
    """Analyzes and tracks interface drop counters from SONiC 'show int counter' command"""
    
    def __init__(self, db_path="crawler.db", output_handler=None, splunk_output=None):
        self.db_path = db_path
        self.output_handler = output_handler  # Legacy - kept for compatibility
        self.splunk_output = splunk_output    # Direct Splunk access for Pure Analyzer approach
        self.setup_database()
    
    def setup_database(self):
        """Create interface_drops_history table with indexing for performance"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS interface_drops_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                interface TEXT NOT NULL,
                rx_drops INTEGER DEFAULT 0,
                tx_drops INTEGER DEFAULT 0,
                rx_util REAL DEFAULT 0.0,
                tx_util REAL DEFAULT 0.0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, interface, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_interface_drops_dut_interface_time 
            ON interface_drops_history(dut_name, interface, timestamp DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_interface_drops_run_id 
            ON interface_drops_history(run_id)
        """)
        
        conn.commit()
        conn.close()
    
    def parse_number(self, value_str):
        """Parse numeric string with commas (e.g., '1,234' -> 1234)"""
        if isinstance(value_str, str):
            clean_str = value_str.replace(',', '').strip()
            try:
                return int(clean_str)
            except ValueError:
                return 0
        elif isinstance(value_str, (int, float)):
            return int(value_str)
        return 0
    
    def store_drop_data(self, dut_name, data_type, data):
        """Store data using either database or Splunk output, matching pattern from other analyzers"""
        if self.splunk_output:
            # Send to Splunk in the same format as other analyzers
            self.splunk_output.store_drop_data(dut_name, data_type, data)
    
    def process_interface_data(self, run_id):
        """
        Extract interface counter data from crawler logs and store with field validation.
        
        This is the core data processing function that:
        1. Extracts interface counter data from crawler database
        2. Validates critical field names (CLI format change detection)
        3. Parses drop counters and stores in monitoring tables
        4. Provides detailed alerts when field validation fails
        
        The function focuses on 'show int counter' command results, extracting:
        - Interface names (iface field)
        - RX drop counters (rx_drp field) 
        - TX drop counters (tx_drp field)
        - RX/TX utilization percentages
        
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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
                        rx_util = interface_data.get('rx_util', '0.00%')
                        tx_util = interface_data.get('tx_util', '0.00%')
                        
                        # Parse utilization percentages (remove % and convert to float)
                        def parse_util(util_str):
                            if isinstance(util_str, str) and util_str.endswith('%'):
                                try:
                                    return float(util_str.rstrip('%'))
                                except ValueError:
                                    return 0.0
                            return 0.0
                        
                        rx_util_pct = parse_util(rx_util)
                        tx_util_pct = parse_util(tx_util)
                        
                        # Additional field validation per interface 
                        if 'iface' not in interface_data:
                            print("WARNING: Interface name field 'iface' missing for entry {} on DUT {}".format(i, dut_name))
                        if 'rx_drp' not in interface_data and 'tx_drp' not in interface_data:
                            print("WARNING: Both drop fields 'rx_drp' and 'tx_drp' missing for interface {} on DUT {}".format(
                                interface_name, dut_name))
                        
                        # Skip non-interface entries
                        if interface_name in ['links', 'TX_DROPS'] or not interface_name.startswith('Ethernet'):
                            continue
                        
                        # Store in local interface_drops_history table (Pure Analyzer approach)
                        # Each data type manages its own table to prevent database conflicts
                        cursor.execute("""
                            INSERT OR REPLACE INTO interface_drops_history 
                            (dut_name, interface, rx_drops, tx_drops, rx_util, tx_util, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (dut_name, interface_name, rx_drops, tx_drops, rx_util_pct, tx_util_pct, timestamp, run_id))
                        
                        # Send combined interface data to outputs (single event with all values including utilization)
                        interface_data_output = {
                            'interface_name': interface_name,
                            'current_value': rx_drops + tx_drops,  # Total drops
                            'rx_drops': rx_drops,
                            'tx_drops': tx_drops,
                            'rx_util': rx_util_pct,
                            'tx_util': tx_util_pct,
                            'metadata': {
                                'run_id': run_id,
                                'timestamp': timestamp,
                                'rx_util_str': rx_util,
                                'tx_util_str': tx_util
                            }
                        }
                        self.store_drop_data(dut_name, 'interface', interface_data_output)
                        
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
            return interfaces_processed > 0 or recent_commands > 0
            
        except Exception as e:
            print("ERROR: Interface data processing failed: {}".format(e))
            import traceback
            traceback.print_exc()
            return False
        finally:
            conn.close()
    
    def analyze_drop_increases(self, current_run_id):
        """
        Analyze interface drop increases between monitoring cycles.
        
        Compares current run with the most recent previous run to identify
        interfaces that have experienced drop count increases.
        
        Args:
            current_run_id (int): Current monitoring cycle identifier
            
        Returns:
            list: List of (dut_name, interface) tuples with drop increases
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Find the most recent previous run
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM interface_drops_history 
                WHERE run_id < ?
            """, (current_run_id,))
            
            result = cursor.fetchone()
            previous_run_id = result[0] if result and result[0] else None
            
            if not previous_run_id:
                print("INFO: No previous interface data for comparison")
                return []
            
            print("Comparing interface drops: Run {} vs Run {}".format(current_run_id, previous_run_id))
            
            # Find interfaces with drop increases
            cursor.execute("""
                SELECT curr.dut_name, curr.interface,
                       prev.rx_drops as prev_rx, prev.tx_drops as prev_tx,
                       curr.rx_drops as curr_rx, curr.tx_drops as curr_tx,
                       (curr.rx_drops - prev.rx_drops) as rx_increase,
                       (curr.tx_drops - prev.tx_drops) as tx_increase
                FROM interface_drops_history curr
                JOIN interface_drops_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.interface = prev.interface
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND ((curr.rx_drops - prev.rx_drops) > 0 
                         OR (curr.tx_drops - prev.tx_drops) > 0)
                ORDER BY (curr.rx_drops + curr.tx_drops - prev.rx_drops - prev.tx_drops) DESC
            """, (current_run_id, previous_run_id))
            
            increases = cursor.fetchall()
            interfaces_with_increases = []
            
            if increases:
                print("\nINTERFACE DROP INCREASES DETECTED ({} interfaces):".format(len(increases)))
                print("-" * 80)
                
                for row in increases:
                    dut_name, interface, prev_rx, prev_tx, curr_rx, curr_tx, rx_inc, tx_inc = row
                    interfaces_with_increases.append((dut_name, interface))
                    
                    total_increase = rx_inc + tx_inc
                    print("  {}/{}: RX: {} -> {} (+{}), TX: {} -> {} (+{}) [Total: +{}]".format(
                        dut_name, interface, prev_rx, curr_rx, rx_inc, 
                        prev_tx, curr_tx, tx_inc, total_increase))
            else:
                print("INFO: No interface drop increases detected")
            
            return interfaces_with_increases
            
        except Exception as e:
            print("ERROR: Interface drop increase analysis failed: {}".format(e))
            import traceback
            traceback.print_exc()
            return []
        finally:
            conn.close()
    
    def show_top_interfaces(self, run_id, limit=5):
        """Show interfaces with highest drop counts for current run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT dut_name, interface, rx_drops, tx_drops, 
                       (rx_drops + tx_drops) as total_drops,
                       rx_util, tx_util
                FROM interface_drops_history
                WHERE run_id = ?
                ORDER BY total_drops DESC
                LIMIT ?
            """, (run_id, limit))
            
            results = cursor.fetchall()
            
            if results:
                print("\nTOP {} INTERFACES BY DROP COUNT (Run {}):".format(limit, run_id))
                print("-" * 80)
                print("  {:20} {:15} {:>10} {:>10} {:>12} {:>8} {:>8}".format(
                    'DUT', 'Interface', 'RX Drops', 'TX Drops', 'Total', 'RX%', 'TX%'))
                print("-" * 80)
                
                for row in results:
                    dut_name, interface, rx_drops, tx_drops, total_drops, rx_util, tx_util = row
                    print("  {:20} {:15} {:>10,} {:>10,} {:>12,} {:>7.2f} {:>7.2f}".format(
                        dut_name, interface, rx_drops, tx_drops, total_drops, rx_util, tx_util))
            else:
                print("INFO: No interface data available for top interfaces report")
                
        except Exception as e:
            print("ERROR: Top interfaces report failed: {}".format(e))
        finally:
            conn.close()
    
    def print_interface_increases_report(self, interfaces_with_increases):
        """Print detailed report of interface drop increases (for compatibility with other analyzers)"""
        if not interfaces_with_increases:
            print("INFO: No interface drop increases to report")
            return
        
        print("\nINTERFACE DROP INCREASES SUMMARY:")
        print("=" * 50)
        print("Interfaces with drop increases: {}".format(len(interfaces_with_increases)))
        for dut_name, interface in interfaces_with_increases:
            print("  - {}/{}".format(dut_name, interface))
        print("")
