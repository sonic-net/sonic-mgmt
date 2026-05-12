#!/usr/bin/env python3
"""
Shared library for spytest result parsing utilities.

Used by:
  - spytest_publish.py (full workflow: parse → XML → upload → dashboard)
  - spytest_summary.py (quick local summary)
"""
import os
import re
import csv
import glob


def time_to_seconds(time_str):
    """Convert time string (H:MM:SS or HH:MM:SS) to seconds."""
    if not time_str or time_str == 'None':
        return 0
    try:
        parts = time_str.split(':')
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        elif len(parts) == 2:
            return int(parts[0]) * 60 + int(parts[1])
        else:
            return int(float(time_str))
    except (ValueError, AttributeError):
        return 0


def extract_build_id(results_dir):
    """Extract build ID from results directory name or version_info/build.txt file.
    
    Checks in order:
    1. version_info.txt (written by spytest_run.py)
    2. Directory name pattern: *_image_<build_id>
    3. Directory name pattern: *_<build_id> at end (4+ digits, but NOT
       for run_logs_* dirs where trailing digits are timestamps HHMMSS)
    4. build.txt file: SONiC.<branch>.<ver>-<NI>-<build_id>-<date>
    5. *_summary.txt: Software Version = SONiC.<branch>...
    """
    # Try version_info.txt first (written by spytest_run.py)
    info_file = os.path.join(results_dir, 'version_info.txt')
    if os.path.exists(info_file):
        try:
            with open(info_file) as f:
                for line in f:
                    if line.startswith('build='):
                        val = line.strip().split('=', 1)[1]
                        if val and val != 'unknown':
                            return val
        except Exception:
            pass

    dirname = os.path.basename(results_dir.rstrip('/'))
    
    # Try pattern: *_image_<build_id>
    match = re.search(r'image_(\d+)', dirname)
    if match:
        return match.group(1)
    
    # Try pattern: *_<build_id> at end (4+ digits)
    # Skip run_logs_* dirs — trailing digits are timestamps (YYYYMMDD_HHMMSS)
    if not dirname.startswith('run_logs_'):
        match = re.search(r'_(\d{4,})$', dirname)
        if match:
            return match.group(1)
    
    # Try reading build.txt file (written by spytest framework)
    build_txt = os.path.join(results_dir, 'build.txt')
    build_id = _extract_build_from_version_file(build_txt)
    if build_id:
        return build_id
    
    # Try reading *_summary.txt (has "Software Version = SONiC.xxx...")
    summary_files = glob.glob(os.path.join(results_dir, '*_summary.txt'))
    for sf in sorted(summary_files, reverse=True):
        try:
            with open(sf, encoding='utf-8', errors='replace') as f:
                for line in f:
                    if 'Software Version' in line and 'SONiC' in line:
                        build_id = _extract_build_from_version_string(line)
                        if build_id:
                            return build_id
        except Exception:
            pass
    
    return None


def _extract_build_from_version_file(filepath):
    """Extract build ID from a file containing a SONiC version string."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return _extract_build_from_version_string(content)
    except Exception:
        return None


def _extract_build_from_version_string(text):
    """Extract build ID from a SONiC version string.
    
    Matches: SONiC.202505c.1.0.0-3I-41146-20260511.014954
    Returns: '41146'
    """
    # Pattern: -<NI>-<build_id>-<date>  (build_id is 4+ digits)
    match = re.search(r'-\d+[A-Z]*-(\d{4,})-\d{8}', text)
    if match:
        return match.group(1)
    return None


def find_results_files(results_dir):
    """Find the summary.txt and functions.csv files in the results directory.
    
    Returns:
        tuple: (summary_file_path, functions_file_path)
        
    Raises:
        FileNotFoundError: If required files are not found
    """
    summary_files = glob.glob(os.path.join(results_dir, '*_summary.txt'))
    functions_files = glob.glob(os.path.join(results_dir, '*_functions.csv'))
    
    if not summary_files:
        raise FileNotFoundError(f"No *_summary.txt found in {results_dir}")
    if not functions_files:
        raise FileNotFoundError(f"No *_functions.csv found in {results_dir}")
    
    # Use most recent if multiple
    return sorted(summary_files)[-1], sorted(functions_files)[-1]


def parse_summary(summary_file):
    """Parse the summary.txt file into a dictionary."""
    summary = {}
    with open(summary_file, encoding='utf-8', errors='replace') as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split('=', 1)
                summary[key.strip()] = val.strip()
    return summary


def parse_functions(functions_file):
    """Parse functions.csv and extract test results with subtest counts.
    
    Returns:
        tuple: (tests_list, subtests_pass_count, subtests_fail_count)
        
    Each test in tests_list is a dict with:
        module, function, result, time, description, subtests_pass, subtests_fail
    """
    tests = []
    subtests_pass = 0
    subtests_fail = 0

    with open(functions_file, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Handle both column name variants
            func = row.get('TestFunction', '') or row.get('Function', '')
            result = row.get('Result', '')
            desc = row.get('Description', '')
            
            # Skip prolog/epilog entries and non-test rows
            if not func or 'Prolog' in desc or 'Epilog' in desc:
                continue
            if result in ['', 'Skipped']:
                continue
            
            # Extract subtests from description (e.g., "Passed=6 Failed=0")
            subtest_match = re.search(r'Passed=(\d+)\s+Failed=(\d+)', desc)
            sub_pass = sub_fail = 0
            if subtest_match:
                sub_pass = int(subtest_match.group(1))
                sub_fail = int(subtest_match.group(2))
                subtests_pass += sub_pass
                subtests_fail += sub_fail
            
            tests.append({
                'module': row.get('Module', ''),
                'function': func,
                'result': result,
                'time': row.get('TimeTaken', '0:00:00'),
                'description': desc or 'No description',
                'subtests_pass': sub_pass,
                'subtests_fail': sub_fail
            })

    return tests, subtests_pass, subtests_fail


def count_results(tests):
    """Count test results by type.
    
    Returns:
        dict: {Pass: N, Fail: N, ConfigFail: N, TGenFail: N, ScriptError: N, Unsupported: N}
    """
    counts = {'Pass': 0, 'Fail': 0, 'ConfigFail': 0, 'TGenFail': 0, 'ScriptError': 0, 'Unsupported': 0}
    for t in tests:
        r = t['result']
        if r in counts:
            counts[r] += 1
    return counts


def format_duration(total_secs):
    """Format seconds as Xh Ym string."""
    hours = total_secs // 3600
    mins = (total_secs % 3600) // 60
    return f"{hours}h {mins}m"


# Status symbols for display
STATUS_SYMBOLS = {
    'Pass': '✓',
    'Fail': '✗',
    'ConfigFail': '⚠',
    'TGenFail': '⚡',
    'ScriptError': '⚠',
    'Unsupported': '○'
}
