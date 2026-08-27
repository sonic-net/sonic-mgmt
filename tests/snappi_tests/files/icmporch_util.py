#!/usr/bin/env python3

import argparse
import time

from sonic_py_common import logger as log
from swsscommon.swsscommon import DBConnector, FieldValuePairs, ProducerStateTable, Table
from swsscommon.swsscommon import APPL_DB, STATE_DB
from tabulate import tabulate

logger = log.Logger('write_standby')

REDIS_SOCK_PATH = '/var/run/redis/redis.sock'


class ICMPOrchUtil:
    def __init__(self, verbose):
        self.adb = DBConnector(APPL_DB, REDIS_SOCK_PATH, True)
        self.ptbl = ProducerStateTable(self.adb, "ICMP_ECHO_SESSION_TABLE")
        self.sdb = DBConnector(STATE_DB, REDIS_SOCK_PATH, True)
        self.stbl = Table(self.sdb, "ICMP_ECHO_SESSION_TABLE")
        self.verbose = verbose

    def verify_key(self, key=""):
        kparts = key.split(":")
        if len(kparts) != 4:
            print("Invalid key format, expected vrf:port:guid:type but got: {}".format(key))
            exit(1)

    def create_icmp_session(self, key, pairs):
        """ Writes icmp session to APP DB """
        self.verify_key(key)
        if self.verbose:
            print("Creating session with key: {}".format(key))
            for f, v in pairs:
                print("Field: {}, Value: {}".format(f, v))
        fvs = FieldValuePairs(list(pairs))
        self.ptbl.set(key, fvs)
        if self.verbose:
            print("Session created in APP_DB")
            # Verify the entry was written
            time.sleep(0.1)  # Give a moment for write
            self.verify_app_db_entry(key)

    def verify_app_db_entry(self, key):
        """Verify that the entry exists in APP_DB"""
        try:
            app_tbl = Table(self.adb, "ICMP_ECHO_SESSION_TABLE")
            (status, fvs) = app_tbl.get(key)
            if status:
                print("✓ Entry found in APP_DB for key: {}".format(key))
                for f, v in fvs:
                    print("  {}: {}".format(f, v))
                return True
            else:
                print("✗ No entry found in APP_DB for key: {}".format(key))
                return False
        except Exception as e:
            print("Error checking APP_DB: {}".format(e))
            return False

    def remove_icmp_echo_session(self, key):
        """Remove icmp echo session entry from producer tbl."""
        self.verify_key(key)
        self.ptbl._del(key)

    def show_icmp_echo_entry(self, key):
        """Show icmp echo session entry from state db."""
        (status, fvs) = self.stbl.get(key)
        if status:
            # Prepare data for tabulate
            fields = {"key": key, "state": None, "dst_ip": None, "tx_interval": None,
                      "rx_interval": None, "hw_lookup": None, "session_cookie": None}
            for f, v in fvs:
                if f in fields:
                    fields[f] = v
            return [fields["key"], fields["dst_ip"], fields["tx_interval"],
                    fields["rx_interval"], fields["hw_lookup"],
                    fields["session_cookie"], fields["state"]]
        else:
            return None

    def show_icmp_echo_session(self, key):
        """Show icmp echo sessions from state db."""
        table_data = []
        if self.verbose:
            print("Show key {}".format(key))
        if key == '':
            keys = sorted(self.stbl.getKeys())
        else:
            self.verify_key(key)
            key = key.replace(":", "|")
            keys = [key]

        for k in keys:
            entry = self.show_icmp_echo_entry(k)
            if entry:
                table_data.append(entry)

        if table_data:
            headers = ["Key", "Dst IP", "Tx Interval", "Rx Interval", "HW lookup", "Cookie", "State"]
            print(tabulate(table_data, headers=headers))
        else:
            print("No keys found or no entries available")

    def check_orchestrator_status(self):
        """Check if ICMP orchestrator is running"""
        import subprocess
        try:
            # Check if orchagent is running
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            if 'orchagent' in result.stdout:
                print("✓ orchagent is running")
                # Check for ICMP orchestrator specifically
                if 'icmp' in result.stdout.lower():
                    print("✓ ICMP-related process found")
                else:
                    print("? No ICMP-specific process found, but orchagent is running")
                return True
            else:
                print("✗ orchagent is NOT running")
                return False
        except Exception as e:
            print(f"Error checking orchestrator status: {e}")
            return False

    def flush(self):
        """Remove ALL ICMP-related entries from both APP_DB and STATE_DB"""
        if self.verbose:
            print("=== Flushing ALL ICMP-related entries ===")

        # Flush ALL ICMP-related entries from APP_DB using direct Redis commands
        app_count = 0
        try:
            import subprocess
            # Get all ICMP-related keys from APP_DB
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     '-n', '0', 'KEYS', '*ICMP*'],
                                    capture_output=True, text=True)
            if result.stdout.strip():
                icmp_keys = result.stdout.strip().split('\n')
                for key in icmp_keys:
                    if key:  # Skip empty lines
                        if self.verbose:
                            print("Removing from APP_DB: {}".format(key))
                        # Delete the key directly
                        subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                        '-n', '0', 'DEL', key],
                                       capture_output=True, text=True)
                        app_count += 1
        except Exception as e:
            print("Error flushing APP_DB: {}".format(e))

        print("Removed {} ICMP-related entries from APP_DB".format(app_count))

        # Flush ALL ICMP-related entries from STATE_DB using direct Redis commands
        state_count = 0
        try:
            import subprocess
            # Get all ICMP-related keys from STATE_DB
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     '-n', '6', 'KEYS', '*ICMP*'],
                                    capture_output=True, text=True)
            if result.stdout.strip():
                icmp_keys = result.stdout.strip().split('\n')
                for key in icmp_keys:
                    if key:  # Skip empty lines
                        if self.verbose:
                            print("Removing from STATE_DB: {}".format(key))
                        # Delete the key directly
                        subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                        '-n', '6', 'DEL', key],
                                       capture_output=True, text=True)
                        state_count += 1
        except Exception as e:
            print("Error flushing STATE_DB: {}".format(e))

        print("Removed {} ICMP-related entries from STATE_DB".format(state_count))

        if self.verbose:
            print("=== Flush completed ===")


def parse_string_pairs(arg):
    """Parses a string of comma-separated pairs into a list of tuples."""
    pairs = arg.split(',')
    result = []
    for pair in pairs:
        try:
            # Split on first colon only to handle MAC addresses properly
            field, value = pair.split(':', 1)
            if field == 'dst_mac' or field == 'src_mac':
                # MAC addresses already in correct format, no replacement needed
                if '-' in value:
                    value = value.replace('-', ':')
                print("Processed MAC {}:{}".format(field, value))
            if field == 'trap_id':
                value = value.replace('-', ',')
                print("Replaced {}:{}".format(field, value))
            result.append((field.strip(), value.strip()))
        except ValueError:
            raise argparse.ArgumentTypeError(
                "Invalid string pair format: '{}'. Use 'field:value'".format(pair))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write icmp session entry')
    parser.add_argument('-v', '--verbose',
                        help='Verbose output',
                        action='store_true', required=False, default=False)
    parser.add_argument('-c', '--command',
                        help='create icmp session',
                        type=str, required=True,
                        choices=['create', 'remove', 'flush', 'show', 'debug', 'test'],
                        default=None)
    parser.add_argument('-k', '--key',
                        help='key',
                        type=str, required=True, default=None)
    parser.add_argument('-f', '--fvpairs',
                        help="Comma-separated field value pairs (e.g., field1:value1,field2:value2)",
                        type=parse_string_pairs, required=False, default=None)

    args = parser.parse_args()
    command = args.command
    key = args.key
    if args.verbose:
        print("Command: {}".format(command))
        print("Session Key: {}".format(key))

    icmp = ICMPOrchUtil(args.verbose)
    if command == 'create':
        create_fvs = args.fvpairs
        icmp.create_icmp_session(key, create_fvs)

    if command == 'remove':
        icmp.remove_icmp_echo_session(key)

    if command == 'flush':
        icmp.flush()

    if command == 'show':
        icmp.show_icmp_echo_session(key)

    if command == 'debug':
        print("=== ICMP Orchestrator Debug Information ===")
        icmp.check_orchestrator_status()
        print("\n--- APP_DB Connection ---")
        try:
            print("APP_DB connection established: {}".format(icmp.adb is not None))
            print("Producer table name: ICMP_ECHO_SESSION_TABLE")
        except Exception as e:
            print("Error with APP_DB: {}".format(e))

        print("\n--- STATE_DB Connection ---")
        try:
            print("STATE_DB connection established: {}".format(icmp.sdb is not None))
            state_keys = icmp.stbl.getKeys()
            print("Keys in STATE_DB ICMP_ECHO_SESSION_TABLE: {}".format(list(state_keys)))
        except Exception as e:
            print("Error getting STATE_DB keys: {}".format(e))

        print("\n--- Redis Database Check ---")
        try:
            import subprocess
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     'info', 'keyspace'],
                                    capture_output=True, text=True)
            print("Redis keyspace info:")
            print(result.stdout)
        except Exception as e:
            print("Error checking Redis: {}".format(e))

        print("\n--- Manual APP_DB Check ---")
        try:
            import subprocess
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     '-n', '0', 'KEYS', '*ICMP*'],
                                    capture_output=True, text=True)
            print("ICMP-related keys in APP_DB:")
            print(result.stdout)
        except Exception as e:
            print("Error checking APP_DB manually: {}".format(e))

        print("\n--- Manual STATE_DB Check ---")
        try:
            import subprocess
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     '-n', '6', 'KEYS', '*ICMP*'],
                                    capture_output=True, text=True)
            print("ICMP-related keys in STATE_DB:")
            print(result.stdout)
        except Exception as e:
            print("Error checking STATE_DB manually: {}".format(e))

        print("\n--- All APP_DB Keys Check ---")
        try:
            import subprocess
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     '-n', '0', 'KEYS', '*'],
                                    capture_output=True, text=True)
            all_keys = result.stdout.strip().split('\n')
            session_keys = [key for key in all_keys
                            if 'SESSION' in key or 'ECHO' in key or 'default:' in key]
            print("Session-related keys in APP_DB: {}".format(session_keys))
        except Exception as e:
            print("Error checking all APP_DB keys: {}".format(e))

        print("\n--- All STATE_DB Keys Check ---")
        try:
            import subprocess
            result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                     '-n', '6', 'KEYS', '*'],
                                    capture_output=True, text=True)
            all_keys = result.stdout.strip().split('\n')
            session_keys = [key for key in all_keys
                            if 'SESSION' in key or 'ECHO' in key or 'default:' in key]
            print("Session-related keys in STATE_DB: {}".format(session_keys))
        except Exception as e:
            print("Error checking all STATE_DB keys: {}".format(e))

    if command == 'test':
        print("=== Testing APP_DB Write ===")
        test_key = "default:Ethernet8:test-guid-12345:NORMAL"
        test_pairs = [
            ("dst_ip", "192.168.0.5"),
            ("tx_interval", "100"),
            ("rx_interval", "1500")
        ]

        print("Writing test entry with key: {}".format(test_key))
        icmp.create_icmp_session(test_key, test_pairs)

        # Immediate check
        print("\n--- Immediate Check ---")
        import subprocess
        result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                 '-n', '0', 'KEYS', '*default*'],
                                capture_output=True, text=True)
        print("Keys with 'default' in APP_DB:")
        print(result.stdout)

        # Check for the exact key
        result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                 '-n', '0', 'HGETALL',
                                 'ICMP_ECHO_SESSION_TABLE:{}'.format(test_key)],
                                capture_output=True, text=True)
        print("\nDirect key lookup for ICMP_ECHO_SESSION_TABLE:{}:".format(test_key))
        print(result.stdout)

        # Wait and check again
        print("\n--- Waiting 2 seconds ---")
        time.sleep(2)

        result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                 '-n', '0', 'HGETALL',
                                 'ICMP_ECHO_SESSION_TABLE:{}'.format(test_key)],
                                capture_output=True, text=True)
        print("After 2 seconds - ICMP_ECHO_SESSION_TABLE:{}:".format(test_key))
        print(result.stdout)

        # Check STATE_DB for any updates
        result = subprocess.run(['redis-cli', '-s', '/var/run/redis/redis.sock',
                                 '-n', '6', 'KEYS', '*default*'],
                                capture_output=True, text=True)
        print("\nKeys with 'default' in STATE_DB:")
        print(result.stdout)
