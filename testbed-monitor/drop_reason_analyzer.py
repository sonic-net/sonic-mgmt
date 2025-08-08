#!/usr/bin/env python3
"""
Drop Reason Analyzer - Analyzes packet drop reasons from 'show dropcounter count'
Identifies top drop reasons per DUT per interface and tracks incremental changes
"""

import sqlite3
import json
from datetime import datetime


class DropReasonAnalyzer:
    """Analyzes and tracks drop reason counters from SONiC 'show dropcounter count' command"""
    
    def __init__(self, db_path="crawler.db", output_handler=None, splunk_output=None):
        self.db_path = db_path
        self.output_handler = output_handler  # Legacy - kept for compatibility
        self.splunk_output = splunk_output    # Direct Splunk access for Pure Analyzer approach
        self.setup_database()
        
        # Standard drop reason columns from SONiC dropcounter output
        self.drop_reason_columns = [
            'acl_any', 'blackhole_route', 'dip_link_local', 'dip_loopback', 
            'dmac_reserved', 'exceeds_l2_mtu', 'exceeds_l3_mtu', 'fdb_mc_discard',
            'fdb_uc_discard', 'ingress_stp_filter', 'ingress_vlan_filter', 
            'ip_header_error', 'l2_any', 'l2_loopback_filter', 'l3_any', 
            'lpm4_miss', 'mc_dmac_mismatch', 'non_routable', 'no_l3_header',
            'sip_class_e', 'sip_link_local', 'sip_loopback', 'sip_mc', 
            'sip_unspecified', 'smac_equals_dmac', 'smac_multicast', 'ttl',
            'uc_dip_mc_dmac', 'unresolved_next_hop'
        ]
    
    def setup_database(self):
        """Create drop_reasons_history table with indexing for performance"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS drop_reasons_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                interface TEXT NOT NULL,
                drop_reason TEXT NOT NULL,
                drop_count INTEGER DEFAULT 0,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, interface, drop_reason, run_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_drop_reasons_dut_interface_time 
            ON drop_reasons_history(dut_name, interface, timestamp DESC)
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
    
    def process_drop_reasons(self, run_id):
        """Extract drop reason data from crawler logs and store with field validation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get latest dropcounter data from crawler logs
            cursor.execute("""
                SELECT dut_name, json_data
                FROM crawler_logs
                WHERE command LIKE '%show dropcounter count%'
                ORDER BY id DESC
                LIMIT 10
            """)
            
            reasons_processed = 0
            processed_interfaces = set()
            
            for row in cursor.fetchall():
                dut_name = row[0]
                try:
                    json_data = json.loads(row[1])
                    
                    # Field validation - alert if CLI format changed
                    if json_data and len(json_data) > 0:
                        # Check first interface entry for required fields
                        sample_interface = None
                        for sample in json_data[:3]:  # Check first few entries
                            if isinstance(sample, dict):
                                sample_interface = sample
                                break
                        
                        if sample_interface:
                            missing_fields = []
                            
                            # Validate interface field exists
                            if 'iface' not in sample_interface:
                                missing_fields.append('iface')
                            
                            # Validate drop reason fields exist
                            available_drop_fields = [field for field in self.drop_reason_columns 
                                                   if field in sample_interface]
                            
                            if len(available_drop_fields) == 0:
                                missing_fields.append('drop_reason_fields')
                            
                            # Alert user if CLI format may have changed
                            if missing_fields:
                                print("CRITICAL ALERT: Essential drop reason fields missing from DUT {}: {}".format(
                                    dut_name, ', '.join(missing_fields)))
                                print("ALERT: Drop reason parsing may fail - CLI output format may have changed!")
                                print("ALERT: Expected fields: 'iface' and drop reason columns")
                                print("ALERT: Available fields in data: {}".format(list(sample_interface.keys())))
                                if len(available_drop_fields) > 0:
                                    print("ALERT: Found {} drop reason fields: {}".format(
                                        len(available_drop_fields), available_drop_fields[:5]))
                    
                    # Process each interface's drop reason data
                    for interface_data in json_data:
                        if isinstance(interface_data, dict) and 'iface' in interface_data:
                            interface_name = interface_data['iface']
                            interface_key = (dut_name, interface_name)
                            
                            # Skip duplicates within same run
                            if interface_key in processed_interfaces:
                                continue
                            processed_interfaces.add(interface_key)
                            
                            # Check if interface has any drop reason data
                            available_reasons = [col for col in self.drop_reason_columns if col in interface_data]
                            if not available_reasons:
                                print("WARNING: No drop reason fields found for interface {} on DUT {}".format(
                                    interface_name, dut_name))
                                continue
                            
                            # Store drop counts for each reason
                            for reason_column in self.drop_reason_columns:
                                if reason_column in interface_data:
                                    drop_count = self.parse_number(interface_data[reason_column])
                                    
                                    # Store in history (including zero counts for complete tracking)
                                    cursor.execute("""
                                        INSERT OR REPLACE INTO drop_reasons_history 
                                        (dut_name, interface, drop_reason, drop_count, timestamp, run_id)
                                        VALUES (?, ?, ?, ?, datetime('now'), ?)
                                    """, (
                                        dut_name,
                                        interface_name,
                                        reason_column.upper(),
                                        drop_count,
                                        run_id
                                    ))
                                    
                                    # Send ALL drop reason data to Splunk (including zeros) - Pure Analyzer approach
                                    if self.splunk_output:
                                        drop_data = {
                                            'interface_name': interface_name,
                                            'drop_reason': reason_column.upper(),
                                            'current_value': drop_count,
                                            'metadata': {
                                                'run_id': run_id,
                                                'timestamp': datetime.now().isoformat()
                                            }
                                        }
                                        try:
                                            success = self.splunk_output.store_drop_data(dut_name, "drop_reason", drop_data)
                                            if success:
                                                print("✓ Drop reason data sent to Splunk: {}/{}".format(dut_name, reason_column.upper()))
                                        except Exception as e:
                                            print("ERROR: Failed to send drop reason data to Splunk: {}".format(e))
                                    
                                    reasons_processed += 1
                                    
                except json.JSONDecodeError:
                    continue
            
            conn.commit()
            print("Processed {} drop reason entries for run {}".format(reasons_processed, run_id))
            return reasons_processed > 0
            
        except Exception as e:
            print("ERROR processing drop reasons: {}".format(e))
            return False
        finally:
            conn.close()
    
    def analyze_top_drop_reasons(self, run_id):
        """Analyze drop reason INCREASES between current and previous run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Find previous run for comparison
            cursor.execute("""
                SELECT MAX(run_id) 
                FROM drop_reasons_history 
                WHERE run_id < ?
            """, (run_id,))
            
            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                print("INFO: No previous drop reason data for comparison (first run)")
                return []
            
            previous_run_id = previous_run_result[0]
            
            # Calculate increases between runs (only positive changes)
            cursor.execute("""
                SELECT 
                    curr.dut_name,
                    curr.interface,
                    curr.drop_reason,
                    prev.drop_count as prev_count,
                    curr.drop_count as curr_count,
                    (curr.drop_count - prev.drop_count) as increase
                FROM drop_reasons_history curr
                JOIN drop_reasons_history prev 
                    ON curr.dut_name = prev.dut_name 
                    AND curr.interface = prev.interface
                    AND curr.drop_reason = prev.drop_reason
                WHERE curr.run_id = ? 
                    AND prev.run_id = ?
                    AND curr.drop_count > prev.drop_count
                ORDER BY increase DESC
            """, (run_id, previous_run_id))
            
            increases = cursor.fetchall()
            
            # Group increases by DUT/interface for top reason analysis
            interface_increases = {}
            
            for dut_name, interface, reason, prev_count, curr_count, increase in increases:
                key = (dut_name, interface)
                if key not in interface_increases:
                    interface_increases[key] = []
                interface_increases[key].append((reason, prev_count, curr_count, increase))
            
            # Find top increased reasons for each interface
            top_increases_report = []
            
            for (dut_name, interface), reason_increases in interface_increases.items():
                if not reason_increases:
                    continue
                
                # Sort by increase amount (highest first)
                reason_increases.sort(key=lambda x: x[3], reverse=True)
                
                # Find maximum increase and handle ties
                max_increase = reason_increases[0][3]
                top_increased_reasons = [
                    (reason, prev_count, curr_count, increase) 
                    for reason, prev_count, curr_count, increase in reason_increases 
                    if increase == max_increase
                ]
                
                # Calculate total increase across all reasons for this interface
                total_increase = sum(increase for reason, prev_count, curr_count, increase in reason_increases)
                
                top_increases_report.append({
                    'dut_name': dut_name,
                    'interface': interface,
                    'top_increased_reasons': top_increased_reasons,
                    'max_increase': max_increase,
                    'total_increase': total_increase,
                    'all_increases': reason_increases
                })
            
            return top_increases_report
            
        except Exception as e:
            print("ERROR analyzing drop reason increases: {}".format(e))
            return []
        finally:
            conn.close()
    
    def print_drop_reasons_report(self, top_increases_report):
        """Print formatted report of drop reason increases with alerts"""
        if not top_increases_report:
            print("No drop reason increases detected from show dropcounter count")
            return
        
        print("\nDROP REASON INCREASES ({} interfaces):".format(len(top_increases_report)))
        print("=" * 80)
        
        # Sort by max increase (highest impact first)
        top_increases_report.sort(key=lambda x: x['max_increase'], reverse=True)
        
        for entry in top_increases_report:
            dut_name = entry['dut_name']
            interface = entry['interface']
            top_increased_reasons = entry['top_increased_reasons']
            max_increase = entry['max_increase']
            all_increases = entry['all_increases']
            
            print("DROP REASON ALERT: {}/{}".format(dut_name, interface))
            
            # Send each significant drop reason increase to Splunk - Pure Analyzer approach
            for reason, prev_count, curr_count, increase in top_increased_reasons:
                if self.splunk_output:
                    drop_data = {
                        'interface_name': interface,
                        'drop_reason': reason,
                        'current_value': curr_count,
                        'previous_value': prev_count,
                        'increment': increase,
                        'metadata': {
                            'max_increase': max_increase,
                            'total_interface_increase': entry['total_increase'],
                            'timestamp': datetime.now().isoformat()
                        }
                    }
                    try:
                        success = self.splunk_output.store_drop_data(dut_name, "drop_reason", drop_data)
                        if success:
                            print("✓ Drop reason increase sent to Splunk: {}/{} +{}".format(dut_name, reason, increase))
                    except Exception as e:
                        print("ERROR: Failed to send drop reason increase to Splunk: {}".format(e))
                    
                    # Send alert for significant increases
                    if increase >= 100:  # Alert threshold
                        alert_message = "Drop reason {} increased by {:,} drops on {}/{}".format(
                            reason, increase, dut_name, interface)
                        try:
                            self.splunk_output.store_alert(dut_name, "drop_reason", "WARNING", 
                                                           alert_message, drop_data)
                        except Exception as e:
                            print("ERROR: Failed to send drop reason alert to Splunk: {}".format(e))
            
            # Handle single vs multiple top reasons
            if len(top_increased_reasons) == 1:
                reason, prev_count, curr_count, increase = top_increased_reasons[0]
                print("   Top increased reason: {} (+{:,} drops)".format(reason, increase))
                print("   {} drops: {:,} -> {:,}".format(reason, prev_count, curr_count))
            else:
                # Handle tied top reasons
                reason_names = [reason for reason, prev_count, curr_count, increase in top_increased_reasons]
                print("   Top increased reasons (tied): {} (+{:,} drops each)".format(
                    ", ".join(reason_names), max_increase))
                
                # Show details for tied reasons
                for reason, prev_count, curr_count, increase in top_increased_reasons:
                    print("   {} drops: {:,} -> {:,} (+{:,})".format(reason, prev_count, curr_count, increase))
            
            # Show summary of other increased reasons
            other_increases = [
                (reason, prev_count, curr_count, increase) 
                for reason, prev_count, curr_count, increase in all_increases 
                if increase < max_increase
            ]
            
            if other_increases:
                other_increases_summary = ", ".join(
                    "{}: +{:,}".format(reason, increase) 
                    for reason, prev_count, curr_count, increase in other_increases[:3]
                )
                print("   Other increases: {}".format(other_increases_summary))
                if len(other_increases) > 3:
                    print("   ... and {} more reasons".format(len(other_increases) - 3))
            
            print("-" * 40)


if __name__ == "__main__":
    # Standalone testing mode
    analyzer = DropReasonAnalyzer()
    
    # Use timestamp as test run_id
    import time
    test_run_id = int(time.time())
    
    print("Drop Reason Analyzer - Test Run (Increment Analysis)")
    print("Run ID: {}".format(test_run_id))
    print("=" * 60)
    
    # Process and analyze drop reasons
    if analyzer.process_drop_reasons(test_run_id):
        top_increases = analyzer.analyze_top_drop_reasons(test_run_id)
        analyzer.print_drop_reasons_report(top_increases)
    else:
        print("No drop reason data processed")