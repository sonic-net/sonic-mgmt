#!/usr/bin/env python3

"""
    Script for adding lock timing information
"""

import argparse
import json
import os
import sys


def add_lock_timing_info(input_file, min_worker, max_worker, platform, topology):
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        return False
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        data['min_worker'] = min_worker
        data['max_worker'] = max_worker
        data['platform'] = platform
        data['topology'] = topology

        with open(input_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Successfully uploaded {input_file} with testbed configuration.")
        return True
    except json.JSONDecodeError as e:
        print(f"WARNING: Failed to parse JSON from '{input_file}': {e}")
        return False
    except IOError as e:
        print(f"WARNING: Failed to read '{input_file}': {e}")
        return False
    except Exception as e:
        print(f"WARNING: Unexpected error reading '{input_file}': {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--input-file",
        type=str,
        default="lock_timing.json",
        help="Path to the lock timing JSON file (default: lock_timing.json)"
    )
    parser.add_argument(
        "--min-worker",
        type=int,
        help="Minimum worker count"
    )
    parser.add_argument(
        "--max-worker",
        type=int,
        help="Maximum worker count"
    )
    parser.add_argument(
        "--platform",
        type=str,
        default="",
        help="Platform type (e.g., 'kvm')"
    )
    parser.add_argument(
        "--topology",
        type=str,
        default="",
        help="Topology type (e.g., 't0', 't1')"
    )
    
    args = parser.parse_args()
    
    success = add_lock_timing_info(
        args.input_file,
        args.min_worker,
        args.max_worker,
        args.platform,
        args.topology
    )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
