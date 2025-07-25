#!/usr/bin/env python3
"""
Queue Counter Analyzer - Analyzes queue drop increases from 'show queue counters'
Identifies specific Port/TxQ combinations with drop increases
"""

import sqlite3
import json
from datetime import datetime

class QueueCounterAnalyzer:
    def __init__(self, db_path="crawler.db"):
        self.db_path = db_path
        self.setup_database()
    
    def setup_database(self):
        """Create table for tracking queue drop counters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS queue_drops_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                port TEXT NOT NULL,
                txq TEXT NOT NULL,
                drop_pkts INTEGER DEFAULT 0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, port, txq, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_queue_drops_dut_port_txq_time 
            ON queue_drops_history(dut_name, port, txq, timestamp DESC)
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
    
    def process_queue_counters(self, run_id):
        """Extract and store queue counter data from crawler logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get latest queue counter data
            cursor.execute("""
                SELECT dut_name, json_data
                FROM crawler_logs
                WHERE command LIKE '%show queue counters%'
                ORDER BY id DESC
                LIMIT 10
            """)
            
            queues_processed = 0
            processed_queues = set()
            
            for row in cursor.fetchall():
                dut_name = row[0]
                try:
                    json_data = json.loads(row[1])
                    
                    # Field validation - alert if CLI format changed
                    if json_data and len(json_data) > 0:
                        # Check first queue entry for required fields
                        sample_queue = None
                        for sample in json_data[:3]:  # Check first few entries
                            if isinstance(sample, dict):
                                sample_queue = sample
                                break
                        
                        if sample_queue:
                            missing_fields = []
                            required_fields = ['port', 'txq', 'drop/pkts']
                            
                            for field in required_fields:
                                if field not in sample_queue:
                                    missing_fields.append(field)
                            
                            # Alert user if CLI format may have changed
                            if missing_fields:
                                print("CRITICAL ALERT: Essential queue counter fields missing from DUT {}: {}".format(
                                    dut_name, ', '.join(missing_fields)))
                                print("ALERT: Queue counter parsing may fail - CLI output format may have changed!")
                                print("ALERT: Expected fields: {}".format(required_fields))
                                print("ALERT: Available fields in data: {}".format(list(sample_queue.keys())))
                    
                    for queue_data in json_data:
                        if isinstance(queue_data, dict) and 'port' in queue_data and 'txq' in queue_data:
                            port = queue_data['port']
                            txq = queue_data['txq']
                            queue_key = (dut_name, port, txq)
                            
                            # Skip if we already processed this queue in this run
                            if queue_key in processed_queues:
                                continue
                            processed_queues.add(queue_key)
                            
                            # Parse drop packet count
                            drop_pkts = self.parse_number(queue_data.get('drop/pkts', '0'))
                            
                            # Store in history
                            cursor.execute("""
                                INSERT OR REPLACE INTO queue_drops_history 
                                (dut_name, port, txq, drop_pkts, timestamp, run_id)
                                VALUES (?, ?, ?, ?, datetime('now'), ?)
                            """, (
                                dut_name,
                                port,
                                txq,
                                drop_pkts,
                                run_id
                            ))
                            queues_processed += 1
                            
                except json.JSONDecodeError:
                    continue
            
            conn.commit()
            print("Processed {} queue entries for run {}".format(queues_processed, run_id))
            return queues_processed > 0
            
        except Exception as e:
            print("ERROR processing queue counters: {}".format(e))
            return False
        finally:
            conn.close()
    
    def analyze_queue_drop_increases(self, run_id):
        """Find queue drop increases compared to previous run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get previous run ID
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM queue_drops_history 
                WHERE run_id < ?
            """, (run_id,))
            
            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                print("INFO: No previous queue data for comparison (first run)")
                return []
            
            previous_run_id = previous_run_result[0]
            
            # Find queue drop increases between current and previous run
            cursor.execute("""
                SELECT 
                    curr.dut_name,
                    curr.port,
                    curr.txq,
                    prev.drop_pkts as prev_drops,
                    curr.drop_pkts as curr_drops,
                    (curr.drop_pkts - prev.drop_pkts) as increase
                FROM queue_drops_history curr
                JOIN queue_drops_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.port = prev.port
                    AND curr.txq = prev.txq
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND curr.drop_pkts > prev.drop_pkts
                ORDER BY increase DESC
            """, (run_id, previous_run_id))
            
            increases = cursor.fetchall()
            return increases
            
        except Exception as e:
            print("ERROR analyzing queue drop increases: {}".format(e))
            return []
        finally:
            conn.close()
    
    def print_queue_increases_report(self, queue_increases):
        """Print formatted queue drop increases analysis"""
        if not queue_increases:
            print("No queue drop increases detected")
            return
        
        print("\nQUEUE DROP INCREASES ({} queues):".format(len(queue_increases)))
        print("=" * 80)
        
        for dut_name, port, txq, prev_drops, curr_drops, increase in queue_increases:
            print("QUEUE ALERT: {}/{}/{}: +{:,} drops".format(
                dut_name, port, txq, increase))
            print("   Drop/pkts: {:,} -> {:,}".format(prev_drops, curr_drops))
            print("-" * 40)

if __name__ == "__main__":
    analyzer = QueueCounterAnalyzer()
    
    # For testing - use a timestamp as run_id
    import time
    test_run_id = int(time.time())
    
    print("Queue Counter Analyzer - Test Run")
    print("Run ID: {}".format(test_run_id))
    print("=" * 60)
    
    if analyzer.process_queue_counters(test_run_id):
        queue_increases = analyzer.analyze_queue_drop_increases(test_run_id)
        analyzer.print_queue_increases_report(queue_increases)
    else:
        print("No queue counter data processed")