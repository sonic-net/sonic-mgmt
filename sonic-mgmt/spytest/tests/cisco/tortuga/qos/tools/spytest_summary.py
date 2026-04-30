#!/usr/bin/env python3
"""
Quick summary of spytest results - no upload, no XML, just the facts.

Usage:
    python3 spytest_summary.py <results_dir>
    python3 spytest_summary.py .                    # Current directory
    python3 spytest_summary.py /path/to/results -f  # Show only failures
"""
import os
import sys

# Add script directory to path for importing spytest_lib (allows running from anywhere)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spytest_lib import (
    time_to_seconds, find_results_files, parse_summary, parse_functions,
    count_results, format_duration, STATUS_SYMBOLS
)


def print_test_list(tests, failures_only=False):
    """Print test execution list."""
    print(f"\n{'='*70}")
    if failures_only:
        print("FAILED TESTS")
    else:
        print("TEST EXECUTION SUMMARY")
    print(f"{'='*70}")
    
    shown = 0
    for i, t in enumerate(tests, 1):
        result = t['result']
        
        # Skip passes if failures_only
        if failures_only and result not in ['Fail', 'ConfigFail', 'TGenFail']:
            continue
        
        shown += 1
        symbol = STATUS_SYMBOLS.get(result, '?')
        func_name = t['function']
        time_str = t['time']
        
        print(f"{i:3}. [{symbol}] {func_name} ({time_str}) - {result}")
        
        # Show error for failures
        if result in ['Fail', 'ConfigFail', 'TGenFail']:
            desc = t['description'][:100]
            if desc and desc != 'No description':
                print(f"         └─ {desc}")
    
    if failures_only and shown == 0:
        print("  No failures! 🎉")
    
    print(f"{'='*70}")


def print_summary(tests, subtests_pass, subtests_fail):
    """Print test counts and pass rate."""
    counts = count_results(tests)
    total_tests = len(tests)
    
    print(f"\nTotal: {total_tests}  |  Pass: {counts['Pass']}  |  Fail: {counts['Fail']}  |  ConfigFail: {counts['ConfigFail']}  |  TGenFail: {counts['TGenFail']}  |  Unsupported: {counts['Unsupported']}")
    
    if subtests_pass + subtests_fail > 0:
        print(f"Subtests: {subtests_pass + subtests_fail}  |  Pass: {subtests_pass}  |  Fail: {subtests_fail}")
    
    # Pass rate
    total = total_tests + subtests_pass + subtests_fail
    passed = counts['Pass'] + subtests_pass
    if total > 0:
        rate = 100 * passed / total
        print(f"\nPass Rate: {rate:.1f}% ({passed}/{total})")
    
    # Total time
    total_secs = sum(time_to_seconds(t['time']) for t in tests)
    print(f"Duration: {format_duration(total_secs)}")


def main():
    if len(sys.argv) < 2:
        print("Usage: spytest_summary.py <results_dir> [-f|--failures]")
        print("")
        print("Options:")
        print("  -f, --failures    Show only failed tests")
        print("")
        print("Examples:")
        print("  spytest_summary.py /path/to/gamut_full_run_4_29_image_40442")
        print("  spytest_summary.py . -f")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    failures_only = '-f' in sys.argv or '--failures' in sys.argv
    
    if not os.path.isdir(results_dir):
        print(f"Error: {results_dir} is not a directory")
        sys.exit(1)
    
    try:
        summary_file, functions_file = find_results_files(results_dir)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Parse
    summary = parse_summary(summary_file)
    tests, subtests_pass, subtests_fail = parse_functions(functions_file)
    
    # Header
    print(f"\nResults: {os.path.basename(results_dir)}")
    if 'Execution Started' in summary:
        print(f"Started: {summary['Execution Started']}")
    
    # Print test list and summary
    print_test_list(tests, failures_only)
    print_summary(tests, subtests_pass, subtests_fail)


if __name__ == '__main__':
    main()
