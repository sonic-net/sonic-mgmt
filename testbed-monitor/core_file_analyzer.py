#!/usr/bin/env python3
"""
Core File Analyzer - Monitors /var/core for new core dump files
Detects device crashes by tracking new *.core.gz files
(typically orchagent.*.core.gz)
Sends alerts for system stability issues
"""

import sqlite3
import json
import re
from datetime import datetime


class CoreFileAnalyzer:
    """Analyzes and tracks core dump files from SONiC devices"""

    def __init__(self, db_path="crawler.db", output_handler=None,
                 splunk_output=None):
        self.db_path = db_path
        # Legacy - kept for compatibility
        self.output_handler = output_handler
        # Direct Splunk access for Pure Analyzer approach
        self.splunk_output = splunk_output
        self.setup_database()

    def setup_database(self):
        """Create core_files_history table for tracking core dumps"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS core_files_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dut_name TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size TEXT,
                file_date TEXT,
                timestamp DATETIME NOT NULL,
                run_id INTEGER NOT NULL,
                UNIQUE(dut_name, filename, run_id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_core_files_dut_time
            ON core_files_history(dut_name, timestamp DESC)
        """)

        conn.commit()
        conn.close()

    def process_core_files(self, run_id):
        """Extract and store core file data from crawler logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Get latest core file data from crawler logs
            cursor.execute("""
                SELECT dut_name, json_data
                FROM crawler_logs
                WHERE command LIKE '%ls -la /var/core%'
                ORDER BY id DESC
                LIMIT 20
            """)

            core_entries_processed = 0
            processed_entries = set()

            print("Starting core file processing for run {}".format(run_id))

            for row in cursor.fetchall():
                dut_name = row[0]
                try:
                    core_data = json.loads(row[1])

                    # Process each core file entry
                    for file_entry in core_data:
                        if not isinstance(file_entry, dict):
                            continue

                        filename = file_entry.get('filename', '')

                        # Only process .core.gz files
                        # (skip directories and other files)
                        if not filename.endswith('.core.gz'):
                            continue

                        # Skip if already processed this run
                        entry_key = (dut_name, filename)
                        if entry_key in processed_entries:
                            continue
                        processed_entries.add(entry_key)

                        file_size = file_entry.get('size', 'unknown')
                        file_date = file_entry.get('date', 'unknown')

                        # Store in database
                        cursor.execute("""
                            INSERT OR REPLACE INTO core_files_history
                            (dut_name, filename, file_size, file_date,
                             timestamp, run_id)
                            VALUES (?, ?, ?, ?, datetime('now'), ?)
                        """, (dut_name, filename, file_size, file_date,
                              run_id))

                        core_entries_processed += 1

                        # NOTE: We don't send core file data to Splunk here
                        # Only NEW core files (detected in
                        # analyze_new_core_files) generate alerts

                except json.JSONDecodeError:
                    continue

            conn.commit()
            print("Processed {} core file entries for run {}".format(
                core_entries_processed, run_id))

            # Send a monitoring status event to Splunk
            # (not an alert, just status) - Pure Analyzer approach
            if self.splunk_output:
                # Get list of devices that were monitored
                cursor.execute("""
                    SELECT DISTINCT dut_name
                    FROM crawler_logs
                    WHERE command LIKE '%ls -la /var/core%'
                    ORDER BY id DESC
                    LIMIT 20
                """)
                monitored_devices = [row[0] for row in cursor.fetchall()]

                for dut_name in monitored_devices:
                    # Send monitoring status (not an alert)
                    core_status_data = {
                        'filename': 'monitoring_status',
                        'current_value': core_entries_processed,
                        'run_id': run_id,
                        'alert_type': 'monitoring_status',
                        'metadata': {
                            'timestamp': datetime.now().isoformat(),
                            'total_core_files': core_entries_processed,
                            'monitoring_status': 'active'
                        }
                    }
                    try:
                        success = self.splunk_output.store_drop_data(
                            dut_name, "core_file", core_status_data)
                        if success:
                            print("✓ Core monitoring status sent to "
                                  "Splunk: {}".format(dut_name))
                    except Exception as e:
                        print("ERROR: Failed to send core monitoring "
                              "status to Splunk: {}".format(e))

            return core_entries_processed > 0

        except Exception as e:
            print("ERROR processing core files: {}".format(e))
            return False
        finally:
            conn.close()

    def analyze_new_core_files(self, run_id):
        """Find new core files compared to previous run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Get previous run ID
            cursor.execute("""
                SELECT MAX(run_id)
                FROM core_files_history
                WHERE run_id < ?
            """, (run_id,))

            previous_run_result = cursor.fetchone()
            if not previous_run_result or not previous_run_result[0]:
                print("INFO: No previous core file data for comparison "
                      "(first run)")
                print("INFO: Core file monitoring established - alerts will "
                      "start from next cycle")

                # Count existing core files but don't alert on them
                # (they're pre-existing)
                cursor.execute("""
                    SELECT COUNT(*), COUNT(DISTINCT dut_name)
                    FROM core_files_history
                    WHERE run_id = ?
                """, (run_id,))

                count_result = cursor.fetchone()
                total_cores = count_result[0] if count_result else 0
                total_devices = count_result[1] if count_result else 0

                if total_cores > 0:
                    print("INFO: Found {} existing core files across {} "
                          "devices (baseline established)".format(
                              total_cores, total_devices))
                else:
                    print("INFO: No existing core files found "
                          "(clean baseline)")

                # Send monitoring status to Splunk (not an alert)
                # Pure Analyzer approach
                if self.splunk_output:
                    status_data = {
                        'filename': 'monitoring_status',
                        'current_value': total_cores,
                        'file_size': 0,
                        'file_date': 'baseline',
                        'alert_type': 'monitoring_established',
                        'metadata': {
                            'total_cores': total_cores,
                            'total_devices': total_devices,
                            'baseline_run': True,
                            'timestamp': datetime.now().isoformat()
                        }
                    }
                    try:
                        success = self.splunk_output.store_drop_data(
                            'all_devices', "core_file", status_data)
                        if success:
                            print("✓ Core file monitoring status sent to "
                                  "Splunk")
                    except Exception as e:
                        print("ERROR: Failed to send core file monitoring "
                              "status to Splunk: {}".format(e))

                return []  # No alerts for first run

            previous_run_id = previous_run_result[0]
            print("Comparing core files run {} vs previous run {}".format(
                run_id, previous_run_id))

            # Find new core files not present in previous run
            cursor.execute("""
                SELECT curr.dut_name, curr.filename, curr.file_size,
                       curr.file_date
                FROM core_files_history curr
                WHERE curr.run_id = ?
                AND NOT EXISTS (
                    SELECT 1 FROM core_files_history prev
                    WHERE prev.run_id = ?
                    AND prev.dut_name = curr.dut_name
                    AND prev.filename = curr.filename
                )
                ORDER BY curr.dut_name, curr.filename
            """, (run_id, previous_run_id))

            new_cores = cursor.fetchall()

            if new_cores:
                print("\\nCORE FILE ALERTS ({} new core files):".format(
                    len(new_cores)))
                print("=" * 80)

                for dut_name, filename, file_size, file_date in new_cores:
                    print("NEW CORE ALERT: {}: {} ({}, {})".format(
                        dut_name, filename, file_size, file_date))

                    # Send CRITICAL alert to Splunk for NEW core files
                    if self.output_handler:
                        self.output_handler.store_alert(
                            dut_name, "core_file", "CRITICAL",
                            "NEW core file detected - potential system "
                            "crash: {}".format(filename),
                            {
                                'filename': filename,
                                'file_size': file_size,
                                'file_date': file_date,
                                'alert_reason': 'new_core_file_detected',
                                'severity': 'critical'
                            }
                        )
            else:
                print("No new core files detected")

            return new_cores

        except Exception as e:
            print("ERROR: Failed to analyze core files: {}".format(e))
            return []
        finally:
            conn.close()

    def print_core_file_report(self, new_cores):
        """Print formatted core file analysis report"""
        if not new_cores:
            print("No new core files detected")
            return

        print("\\nCORE FILE SUMMARY ({} new core files):".format(
            len(new_cores)))
        print("=" * 80)

        # Group by device for cleaner output
        device_cores = {}
        for dut_name, filename, file_size, file_date in new_cores:
            if dut_name not in device_cores:
                device_cores[dut_name] = []
            device_cores[dut_name].append((filename, file_size, file_date))

        for dut_name, cores in device_cores.items():
            print("Device: {}".format(dut_name))
            for filename, file_size, file_date in cores:
                # Extract process name from filename
                # (typically orchagent.timestamp.pid.tid.core.gz)
                process_match = re.match(r'([^.]+)\..*\.core\.gz', filename)
                process_name = (process_match.group(1)
                                if process_match else 'unknown')

                print("  CRITICAL: {} crashed - {} ({}, {})".format(
                    process_name, filename, file_size, file_date))
            print("-" * 40)

    def get_core_file_summary(self, run_id):
        """Get summary of all core files for current run"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT dut_name, COUNT(*) as core_count
                FROM core_files_history
                WHERE run_id = ?
                GROUP BY dut_name
                ORDER BY core_count DESC, dut_name
            """, (run_id,))

            summary = cursor.fetchall()

            if summary:
                print("\\nCORE FILE SUMMARY BY DEVICE:")
                print("-" * 40)
                total_cores = 0
                for dut_name, core_count in summary:
                    print("{}: {} core files".format(dut_name, core_count))
                    total_cores += core_count
                print("Total: {} core files across {} devices".format(
                    total_cores, len(summary)))

            return summary

        except Exception as e:
            print("ERROR: Failed to get core file summary: {}".format(e))
            return []
        finally:
            conn.close()


if __name__ == "__main__":
    analyzer = CoreFileAnalyzer()

    # For testing - use a timestamp as run_id
    import time
    test_run_id = int(time.time())

    print("Core File Analyzer - Test Run")
    print("Run ID: {}".format(test_run_id))
    print("=" * 60)

    if analyzer.process_core_files(test_run_id):
        new_cores = analyzer.analyze_new_core_files(test_run_id)
        analyzer.print_core_file_report(new_cores)
        analyzer.get_core_file_summary(test_run_id)
    else:
        print("No core file data processed")
