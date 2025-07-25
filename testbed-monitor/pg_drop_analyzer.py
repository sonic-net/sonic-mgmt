#!/usr/bin/env python3
"""
Priority Group Drop Analyzer - Analyzes PG drop increases from 'pg-drop -c show'
Identifies specific Port/PG combinations with drop increases
"""

import sqlite3
import json
from datetime import datetime



class PriorityGroupDropAnalyzer:
    def __init__(self, db_path="crawler.db"):
        self.db_path = db_path
        self.setup_database()
        
        # Priority group columns
        self.pg_columns = ['pg0', 'pg1', 'pg2', 'pg3', 'pg4', 'pg5', 'pg6', 'pg7']
    
    def setup_database(self):
        """Create table for tracking priority group drops"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pg_drops_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                port TEXT NOT NULL,
                pg TEXT NOT NULL,
                drop_count INTEGER DEFAULT 0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, port, pg, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pg_drops_dut_port_pg_time 
            ON pg_drops_history(dut_name, port, pg, timestamp DESC)
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
    
    def process_pg_drops(self, run_id):
        """Extract and store priority group drop data from crawler logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get latest pg-drop data
            cursor.execute("""
                SELECT dut_name, json_data
                FROM crawler_logs
                WHERE command LIKE '%pg-drop -c show%'
                ORDER BY id DESC
                LIMIT 10
            """)
            
            pg_entries_processed = 0
            processed_entries = set()
            
            for row in cursor.fetchall():
                dut_name = row[0]
                try:
                    json_data = json.loads(row[1])
                    
                    # Field validation - alert if CLI format changed
                    if json_data and len(json_data) > 0:
                        # Check first PG entry for required fields
                        sample_pg = None
                        for sample in json_data[:3]:  # Check first few entries
                            if isinstance(sample, dict):
                                sample_pg = sample
                                break
                        
                        if sample_pg:
                            missing_fields = []
                            
                            # Validate port field exists
                            if 'port' not in sample_pg:
                                missing_fields.append('port')
                            
                            # Validate PG fields exist
                            available_pg_fields = [field for field in self.pg_columns 
                                                 if field in sample_pg]
                            
                            if len(available_pg_fields) == 0:
                                missing_fields.append('pg_fields')
                            
                            # Alert user if CLI format may have changed
                            if missing_fields:
                                print("CRITICAL ALERT: Essential PG drop fields missing from DUT {}: {}".format(
                                    dut_name, ', '.join(missing_fields)))
                                print("ALERT: PG drop parsing may fail - CLI output format may have changed!")
                                print("ALERT: Expected fields: 'port' and PG columns")
                                print("ALERT: Available fields in data: {}".format(list(sample_pg.keys())))
                                if len(available_pg_fields) > 0:
                                    print("ALERT: Found {} PG fields: {}".format(
                                        len(available_pg_fields), available_pg_fields))
                    
                    for pg_data in json_data:
                        if isinstance(pg_data, dict) and 'port' in pg_data:
                            port = pg_data['port']
                            
                            # Process each priority group column
                            for pg_column in self.pg_columns:
                                if pg_column in pg_data:
                                    entry_key = (dut_name, port, pg_column)
                                    
                                    # Skip if we already processed this entry in this run
                                    if entry_key in processed_entries:
                                        continue
                                    processed_entries.add(entry_key)
                                    
                                    # Parse drop count
                                    drop_count = self.parse_number(pg_data[pg_column])
                                    
                                    # Store in history
                                    cursor.execute("""
                                        INSERT OR REPLACE INTO pg_drops_history 
                                        (dut_name, port, pg, drop_count, timestamp, run_id)
                                        VALUES (?, ?, ?, ?, datetime('now'), ?)
                                    """, (
                                        dut_name,
                                        port,
                                        pg_column.upper(),
                                        drop_count,
                                        run_id
                                    ))
                                    pg_entries_processed += 1
                            
                except json.JSONDecodeError:
                    continue
            
            conn.commit()
            print("Processed {} PG drop entries for run {}".format(pg_entries_processed, run_id))
            return pg_entries_processed > 0
            
        except Exception as e:
            print("ERROR processing PG drops: {}".format(e))
            return False
        finally:
            conn.close()
    
    def analyze_pg_drop_increases(self, run_id):
        """Find priority group drop increases compared to previous run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get previous run ID
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM pg_drops_history 
                WHERE run_id < ?
            """, (run_id,))
            
            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                print("INFO: No previous PG drop data for comparison (first run)")
                return []
            
            previous_run_id = previous_run_result[0]
            
            # Find PG drop increases between current and previous run
            cursor.execute("""
                SELECT 
                    curr.dut_name,
                    curr.port,
                    curr.pg,
                    prev.drop_count as prev_drops,
                    curr.drop_count as curr_drops,
                    (curr.drop_count - prev.drop_count) as increase
                FROM pg_drops_history curr
                JOIN pg_drops_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.port = prev.port
                    AND curr.pg = prev.pg
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND curr.drop_count > prev.drop_count
                ORDER BY increase DESC
            """, (run_id, previous_run_id))
            
            increases = cursor.fetchall()
            return increases
            
        except Exception as e:
            print("ERROR analyzing PG drop increases: {}".format(e))
            return []
        finally:
            conn.close()
    
    def print_pg_increases_report(self, pg_increases):
        """Print formatted priority group drop increases analysis"""
        if not pg_increases:
            print("No priority group drop increases detected from pg-drop -c show")
            return
        
        print("\nPRIORITY GROUP DROP INCREASES ({} PG entries):".format(len(pg_increases)))
        print("=" * 80)
        
        for dut_name, port, pg, prev_drops, curr_drops, increase in pg_increases:
            print("PG DROP ALERT: {}/{}/{}: +{:,} drops".format(
                dut_name, port, pg, increase))
            print("   Drops: {:,} -> {:,}".format(prev_drops, curr_drops))
            print("-" * 40)

if __name__ == "__main__":
    analyzer = PriorityGroupDropAnalyzer()
    
    # For testing - use a timestamp as run_id
    import time
    test_run_id = int(time.time())
    
    print("Priority Group Drop Analyzer - Test Run")
    print("Run ID: {}".format(test_run_id))
    print("=" * 60)
    
    if analyzer.process_pg_drops(test_run_id):
        pg_increases = analyzer.analyze_pg_drop_increases(test_run_id)
        analyzer.print_pg_increases_report(pg_increases)
    else:
        print("No PG drop data processed")