#!/usr/bin/env python3

import sqlite3
import json
from datetime import datetime

class NPUDropAnalyzer:
    def __init__(self, db_path="crawler.db", output_handler=None, splunk_output=None):
        self.db_path = db_path
        self.output_handler = output_handler  # Legacy - kept for compatibility
        self.splunk_output = splunk_output    # Direct Splunk access for Pure Analyzer approach
        self.setup_database()
    
    def setup_database(self):
        """Create table for tracking NPU drop counters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS npu_drops_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                asic_id TEXT NOT NULL,
                counter_name TEXT NOT NULL,
                counter_type TEXT NOT NULL,
                slice_info TEXT,
                drop_count INTEGER DEFAULT 0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, asic_id, counter_name, counter_type, slice_info, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_npu_drops_dut_asic_counter_time 
            ON npu_drops_history(dut_name, asic_id, counter_name, timestamp DESC)
        """)
        
        conn.commit()
        conn.close()
    
    def parse_number(self, value_str):
        """Parse numeric string with commas"""
        if isinstance(value_str, str):
            clean_str = value_str.replace(',', '').strip()
            try:
                return int(clean_str)
            except ValueError:
                return 0
        elif isinstance(value_str, (int, float)):
            return int(value_str)
        return 0
    
    def process_npu_drops(self, run_id):
        """Extract and store NPU drop data from crawler logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # First, clear old NPU data to prevent confusion with previous runs
            self.clear_old_npu_data(keep_runs=3)
            
            # Get NPU counter data from the CURRENT monitoring cycle only
            # First try with timestamp filtering (for newer databases)
            try:
                cursor.execute("""
                    SELECT dut_name, json_data, id, timestamp
                    FROM crawler_logs
                    WHERE command LIKE '%sudo show platform npu counters%'
                        AND datetime(timestamp) > datetime('now', '-2 minutes')
                    ORDER BY id DESC
                    LIMIT 10
                """)
                recent_entries = cursor.fetchall()
                has_timestamp = True
            except sqlite3.OperationalError:
                # Fallback for older databases without timestamp column
                print("INFO: Using ID-based filtering (timestamp column not available)")
                cursor.execute("""
                    SELECT dut_name, json_data, id
                    FROM crawler_logs
                    WHERE command LIKE '%sudo show platform npu counters%'
                    ORDER BY id DESC
                    LIMIT 5
                """)
                entries = cursor.fetchall()
                recent_entries = [(row[0], row[1], row[2], 'N/A') for row in entries]
                has_timestamp = False
            
            if not recent_entries:
                print("No recent NPU counter data found in crawler_logs for run {}".format(run_id))
                return False
            
            print("Starting NPU processing for run {} (processing {} recent entries)".format(run_id, len(recent_entries)))
            
            npu_entries_processed = 0
            processed_entries = set()
            
            for row in recent_entries:
                if has_timestamp:
                    print("Processing NPU data from DUT: {} (entry ID: {}, timestamp: {})".format(row[0], row[2], row[3]))
                else:
                    print("Processing NPU data from DUT: {} (entry ID: {})".format(row[0], row[2]))
                dut_name = row[0]
                try:
                    npu_data = json.loads(row[1])
                    
                    # Extract ASIC ID from the parsed data
                    asic_id = npu_data.get('asic', 'unknown')
                    
                    # Process RXCGM drop stats
                    rxcgm_drops = npu_data.get('rxcgm_drop_stats', {})
                    for counter_name, drop_count in rxcgm_drops.items():
                        entry_key = (dut_name, asic_id, 'RXCGM', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        # Extract slice info if present
                        slice_info = self._extract_slice_info(counter_name)
                        parsed_drop_count = self.parse_number(drop_count)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'RXCGM', slice_info, 
                            parsed_drop_count, run_id
                        ))
                        npu_entries_processed += 1
                        
                        # Send NPU data to Splunk - Pure Analyzer approach
                        if self.splunk_output:
                            npu_data_for_splunk = {
                                'counter_name': counter_name,
                                'counter_type': 'RXCGM',
                                'asic_id': asic_id,
                                'slice_info': slice_info,
                                'current_value': parsed_drop_count,
                                'metadata': {
                                    'run_id': run_id,
                                    'timestamp': datetime.now().isoformat()
                                }
                            }
                            try:
                                success = self.splunk_output.store_drop_data(dut_name, "npu", npu_data_for_splunk)
                                if success:
                                    print("✓ NPU RXCGM data sent to Splunk: {}/{}".format(dut_name, counter_name))
                            except Exception as e:
                                print("ERROR: Failed to send NPU RXCGM data to Splunk: {}".format(e))
                    
                    # Process PDVOQ drop stats
                    pdvoq_drops = npu_data.get('pdvoq_drop_stats', {})
                    for counter_name, drop_count in pdvoq_drops.items():
                        entry_key = (dut_name, asic_id, 'PDVOQ', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        slice_info = self._extract_slice_info(counter_name)
                        parsed_drop_count = self.parse_number(drop_count)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'PDVOQ', slice_info,
                            parsed_drop_count, run_id
                        ))
                        npu_entries_processed += 1
                        
                        # Send NPU data to Splunk - Pure Analyzer approach
                        if self.splunk_output:
                            npu_data_for_splunk = {
                                'counter_name': counter_name,
                                'counter_type': 'PDVOQ',
                                'asic_id': asic_id,
                                'slice_info': slice_info,
                                'current_value': parsed_drop_count,
                                'metadata': {
                                    'run_id': run_id,
                                    'timestamp': datetime.now().isoformat()
                                }
                            }
                            try:
                                success = self.splunk_output.store_drop_data(dut_name, "npu", npu_data_for_splunk)
                                if success:
                                    print("✓ NPU PDVOQ data sent to Splunk: {}/{}".format(dut_name, counter_name))
                            except Exception as e:
                                print("ERROR: Failed to send NPU PDVOQ data to Splunk: {}".format(e))
                    
                    # Process TXCGM drop stats
                    txcgm_drops = npu_data.get('txcgm_drop_stats', {})
                    for counter_name, drop_count in txcgm_drops.items():
                        entry_key = (dut_name, asic_id, 'TXCGM', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        slice_info = self._extract_slice_info(counter_name)
                        parsed_drop_count = self.parse_number(drop_count)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'TXCGM', slice_info,
                            parsed_drop_count, run_id
                        ))
                        npu_entries_processed += 1
                        
                        # Send NPU data to Splunk - Pure Analyzer approach
                        if self.splunk_output:
                            npu_data_for_splunk = {
                                'counter_name': counter_name,
                                'counter_type': 'TXCGM',
                                'asic_id': asic_id,
                                'slice_info': slice_info,
                                'current_value': parsed_drop_count,
                                'metadata': {
                                    'run_id': run_id,
                                    'timestamp': datetime.now().isoformat()
                                }
                            }
                            try:
                                success = self.splunk_output.store_drop_data(dut_name, "npu", npu_data_for_splunk)
                                if success:
                                    print("✓ NPU TXCGM data sent to Splunk: {}/{}".format(dut_name, counter_name))
                            except Exception as e:
                                print("ERROR: Failed to send NPU TXCGM data to Splunk: {}".format(e))
                    
                    # Process SMS drop stats
                    sms_drops = npu_data.get('sms_drop_stats', {})
                    for counter_name, drop_count in sms_drops.items():
                        entry_key = (dut_name, asic_id, 'SMS', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        slice_info = self._extract_slice_info(counter_name)
                        parsed_drop_count = self.parse_number(drop_count)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'SMS', slice_info,
                            parsed_drop_count, run_id
                        ))
                        npu_entries_processed += 1
                        
                        # Send NPU data to Splunk - Pure Analyzer approach
                        if self.splunk_output:
                            npu_data_for_splunk = {
                                'counter_name': counter_name,
                                'counter_type': 'SMS',
                                'asic_id': asic_id,
                                'slice_info': slice_info,
                                'current_value': parsed_drop_count,
                                'metadata': {
                                    'run_id': run_id,
                                    'timestamp': datetime.now().isoformat()
                                }
                            }
                            try:
                                success = self.splunk_output.store_drop_data(dut_name, "npu", npu_data_for_splunk)
                                if success:
                                    print("✓ NPU SMS data sent to Splunk: {}/{}".format(dut_name, counter_name))
                            except Exception as e:
                                print("ERROR: Failed to send NPU SMS data to Splunk: {}".format(e))
                    
                    # Process forwarding drop stats
                    fwd_drops = npu_data.get('forwarding_drop_stats', {})
                    for counter_name, drop_count in fwd_drops.items():
                        entry_key = (dut_name, asic_id, 'FORWARDING', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        parsed_drop_count = self.parse_number(drop_count)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'FORWARDING', None,
                            parsed_drop_count, run_id
                        ))
                        npu_entries_processed += 1
                        
                        # Send NPU data to Splunk - Pure Analyzer approach
                        if self.splunk_output:
                            npu_data_for_splunk = {
                                'counter_name': counter_name,
                                'counter_type': 'FORWARDING',
                                'asic_id': asic_id,
                                'slice_info': None,
                                'current_value': parsed_drop_count,
                                'metadata': {
                                    'run_id': run_id,
                                    'timestamp': datetime.now().isoformat()
                                }
                            }
                            try:
                                success = self.splunk_output.store_drop_data(dut_name, "npu", npu_data_for_splunk)
                                if success:
                                    print("✓ NPU FORWARDING data sent to Splunk: {}/{}".format(dut_name, counter_name))
                            except Exception as e:
                                print("ERROR: Failed to send NPU FORWARDING data to Splunk: {}".format(e))
                            
                except json.JSONDecodeError:
                    continue
            
            conn.commit()
            print("Processed {} NPU drop entries for run {}".format(npu_entries_processed, run_id))
            return npu_entries_processed > 0
            
        except Exception as e:
            print("ERROR processing NPU drops: {}".format(e))
            return False
        finally:
            conn.close()
    
    def clear_old_npu_data(self, keep_runs=5):
        """Clear old NPU data to prevent confusion between monitoring cycles"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Keep only the most recent N runs
            cursor.execute("""
                DELETE FROM npu_drops_history 
                WHERE run_id NOT IN (
                    SELECT DISTINCT run_id 
                    FROM npu_drops_history 
                    ORDER BY run_id DESC 
                    LIMIT ?
                )
            """, (keep_runs,))
            
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                print("Cleaned up {} old NPU entries (keeping {} most recent runs)".format(deleted_count, keep_runs))
            
            conn.commit()
            
        except Exception as e:
            print("ERROR: Failed to clear old NPU data: {}".format(e))
        finally:
            conn.close()
    
    def _extract_slice_info(self, counter_name):
        """Extract slice information from counter name"""
        if 'slice' in counter_name.lower():
            # Extract slice number from patterns like "slice_0_drop_pkts" or "slice_0"
            import re
            match = re.search(r'slice[_\s]*(\d+)', counter_name.lower())
            if match:
                return "slice_{}".format(match.group(1))
        return None
    
    def analyze_npu_drop_increases(self, run_id):
        """Find NPU drops in current run (counters reset to 0 after each command)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Since NPU counters are cleared after each command execution,
            # ANY non-zero value indicates actual drops that occurred
            cursor.execute("""
                SELECT 
                    dut_name,
                    asic_id,
                    counter_name,
                    counter_type,
                    slice_info,
                    drop_count
                FROM npu_drops_history
                WHERE run_id = ? 
                    AND drop_count > 0
                ORDER BY drop_count DESC
            """, (run_id,))
            
            drops = cursor.fetchall()
            
            if drops:
                print("\nNPU DROP ALERTS ({} counters with drops in run {}):".format(len(drops), run_id))
                print("=" * 80)
                
                for row in drops:
                    dut_name, asic_id, counter_name, counter_type, slice_info, drop_count = row
                    
                    slice_str = " [{}]".format(slice_info) if slice_info else ""
                    print("NPU DROP: {}/{} - {} {}{}: {:,} drops".format(
                        dut_name, asic_id, counter_type, counter_name, slice_str, drop_count))
            else:
                print("INFO: No NPU drops detected in run {}".format(run_id))
            
            return drops
            
        except Exception as e:
            print("ERROR: Failed to analyze NPU drops: {}".format(e))
            return []
        finally:
            conn.close()
    
    def print_npu_increases_report(self, npu_drops):
        """Print formatted NPU drop analysis (counters reset after each command)"""
        if not npu_drops:
            print("No NPU drops detected from show platform npu counters")
            return
        
        print("\nNPU DROP SUMMARY ({} counters with drops):".format(len(npu_drops)))
        print("=" * 80)
        
        for dut_name, asic_id, counter_name, counter_type, slice_info, drop_count in npu_drops:
            # Build detailed counter description
            counter_desc = "{}/{}".format(counter_type, counter_name)
            if slice_info:
                counter_desc = "{}/{}".format(counter_desc, slice_info)
            
            print("NPU Drop: {}/ASIC{}: {} = {:,} drops".format(
                dut_name, asic_id, counter_desc, drop_count))
            
            # Send NPU drop data to Splunk - Pure Analyzer approach
            if self.splunk_output:
                npu_data = {
                    'counter_name': counter_name,
                    'counter_type': counter_type,
                    'asic_id': asic_id,
                    'slice_info': slice_info,
                    'current_value': drop_count,
                    'metadata': {
                        'counter_description': counter_desc,
                        'timestamp': datetime.now().isoformat()
                    }
                }
                try:
                    success = self.splunk_output.store_drop_data(dut_name, "npu", npu_data)
                    if success:
                        print("✓ NPU drop analysis sent to Splunk: {}/{}".format(dut_name, counter_desc))
                except Exception as e:
                    print("ERROR: Failed to send NPU drop analysis to Splunk: {}".format(e))
                
                # Send alert for significant NPU drops
                if drop_count >= 10:  # Alert threshold for NPU drops
                    alert_message = "NPU {} counter {} on ASIC{} has {:,} drops on {}".format(
                        counter_type, counter_name, asic_id, drop_count, dut_name)
                    try:
                        self.splunk_output.store_alert(dut_name, "npu", "WARNING", 
                                                       alert_message, npu_data)
                    except Exception as e:
                        print("ERROR: Failed to send NPU alert to Splunk: {}".format(e))
        
        print("-" * 40)
    
    def print_current_npu_drops(self, run_id, limit=10):
        """Print current NPU drop counters for this run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # First check if we have any NPU data at all for this run
            cursor.execute("""
                SELECT COUNT(*) FROM npu_drops_history WHERE run_id = ?
            """, (run_id,))
            
            total_count = cursor.fetchone()[0]
            print("Found {} total NPU entries for run {}".format(total_count, run_id))
            
            # Get current NPU drop data for this run
            cursor.execute("""
                SELECT 
                    dut_name,
                    asic_id,
                    counter_type,
                    counter_name,
                    drop_count
                FROM npu_drops_history
                WHERE run_id = ?
                ORDER BY drop_count DESC
                LIMIT ?
            """, (run_id, limit))
            
            npu_drops = cursor.fetchall()
            
            if not npu_drops:
                print("No NPU drops found in current run")
                return
            
            print("\nTOP {} NPU DROP COUNTERS:".format(min(len(npu_drops), limit)))
            print("-" * 100)
            print("{:<15} {:<8} {:<15} {:<35} {:<15}".format(
                "DUT", "ASIC", "Category", "Counter", "Drop Count"))
            print("-" * 100)
            
            for dut_name, asic_id, counter_type, counter_name, drop_count in npu_drops:
                print("{:<15} {:<8} {:<15} {:<35} {:<15,}".format(
                    dut_name, asic_id, counter_type, counter_name, drop_count))
                    
        except Exception as e:
            print("ERROR: Failed to get current NPU drops: {}".format(e))
            import traceback
            traceback.print_exc()
        finally:
            conn.close()

if __name__ == "__main__":
    analyzer = NPUDropAnalyzer()
    
    # For testing - use a timestamp as run_id
    import time
    test_run_id = int(time.time())
    
    print("NPU Drop Analyzer - Test Run")
    print("Run ID: {}".format(test_run_id))
    print("=" * 60)
    
    # Clear old NPU data (except for the most recent 5 runs)
    analyzer.clear_old_npu_data(keep_runs=5)
    
    if analyzer.process_npu_drops(test_run_id):
        npu_increases = analyzer.analyze_npu_drop_increases(test_run_id)
        analyzer.print_npu_increases_report(npu_increases)
        analyzer.print_current_npu_drops(test_run_id)
    else:
        print("No NPU drop data processed")