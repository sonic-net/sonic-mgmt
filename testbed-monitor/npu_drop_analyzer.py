#!/usr/bin/env python3
"""
NPU Drop Analyzer - Analyzes NPU drop increases from 'sudo show platform npu counters -n asicX'
Identifies specific ASIC/slice/counter combinations with drop increases
Focuses on red (drop) counters only
"""

import sqlite3
import json
from datetime import datetime



class NPUDropAnalyzer:
    def __init__(self, db_path="crawler.db"):
        self.db_path = db_path
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
            # Get latest NPU counter data
            cursor.execute("""
                SELECT dut_name, json_data
                FROM crawler_logs
                WHERE command LIKE '%sudo show platform npu counters%'
                ORDER BY id DESC
                LIMIT 20
            """)
            
            npu_entries_processed = 0
            processed_entries = set()
            
            print("Starting NPU processing for run {}".format(run_id))
            
            for row in cursor.fetchall():
                print("Processing NPU data from DUT: {}".format(row[0]))
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
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'RXCGM', slice_info, 
                            self.parse_number(drop_count), run_id
                        ))
                        npu_entries_processed += 1
                    
                    # Process PDVOQ drop stats
                    pdvoq_drops = npu_data.get('pdvoq_drop_stats', {})
                    for counter_name, drop_count in pdvoq_drops.items():
                        entry_key = (dut_name, asic_id, 'PDVOQ', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        slice_info = self._extract_slice_info(counter_name)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'PDVOQ', slice_info,
                            self.parse_number(drop_count), run_id
                        ))
                        npu_entries_processed += 1
                    
                    # Process TXCGM drop stats
                    txcgm_drops = npu_data.get('txcgm_drop_stats', {})
                    for counter_name, drop_count in txcgm_drops.items():
                        entry_key = (dut_name, asic_id, 'TXCGM', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        slice_info = self._extract_slice_info(counter_name)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'TXCGM', slice_info,
                            self.parse_number(drop_count), run_id
                        ))
                        npu_entries_processed += 1
                    
                    # Process SMS drop stats
                    sms_drops = npu_data.get('sms_drop_stats', {})
                    for counter_name, drop_count in sms_drops.items():
                        entry_key = (dut_name, asic_id, 'SMS', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        slice_info = self._extract_slice_info(counter_name)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'SMS', slice_info,
                            self.parse_number(drop_count), run_id
                        ))
                        npu_entries_processed += 1
                    
                    # Process forwarding drop stats
                    fwd_drops = npu_data.get('forwarding_drop_stats', {})
                    for counter_name, drop_count in fwd_drops.items():
                        entry_key = (dut_name, asic_id, 'FORWARDING', counter_name)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO npu_drops_history 
                            (dut_name, asic_id, counter_name, counter_type, slice_info, drop_count, timestamp, run_id)
                            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                        """, (
                            dut_name, asic_id, counter_name, 'FORWARDING', None,
                            self.parse_number(drop_count), run_id
                        ))
                        npu_entries_processed += 1
                            
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
            # Since NPU counters reset to 0 after each command run,
            # any non-zero values represent drops since the last command execution
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
                print("\nNPU DROP ALERTS ({} counters with drops):".format(len(drops)))
                print("=" * 80)
                
                for row in drops:
                    dut_name, asic_id, counter_name, counter_type, slice_info, drop_count = row
                    
                    slice_str = " [{}]".format(slice_info) if slice_info else ""
                    print("NPU DROP: {}/{} - {} {}{}: {:,} drops".format(
                        dut_name, asic_id, counter_type, counter_name, slice_str, drop_count))
            
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
                    drop_category,
                    drop_counter,
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
            
            for dut_name, asic_id, drop_category, drop_counter, drop_count in npu_drops:
                print("{:<15} {:<8} {:<15} {:<35} {:<15,}".format(
                    dut_name, asic_id, drop_category, drop_counter, drop_count))
                    
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
    
    if analyzer.process_npu_drops(test_run_id):
        npu_increases = analyzer.analyze_npu_drop_increases(test_run_id)
        analyzer.print_npu_increases_report(npu_increases)
        analyzer.print_current_npu_drops(test_run_id)
    else:
        print("No NPU drop data processed")