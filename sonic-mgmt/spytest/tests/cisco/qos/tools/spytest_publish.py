#!/usr/bin/env python3
"""
Unified spytest results processor: Generate XML, upload logs, and import to dashboard.

Usage:
    python spytest_publish.py <results_dir> --yaml <testbed.yaml> [options]

Examples:
    # Full workflow: generate XML, upload logs, import to dashboard
    python spytest_publish.py /path/to/results --yaml tortuga_2x2_G200_testbed.yaml

    # Override auto-detected branch
    python spytest_publish.py /path/to/results --yaml tortuga_2x2_G200_testbed.yaml --branch 202505c

    # Dry run (preview all steps)
    python spytest_publish.py /path/to/results --yaml tortuga_2x2_G200_testbed.yaml --dry-run

    # Just generate XML locally
    python spytest_publish.py /path/to/results --yaml tortuga_2x2_G200_testbed.yaml \\
        --xml-only -o results.xml

Workflow:
    1. Parse spytest results (*_summary.txt, *_functions.csv)
    2. Generate JUnit-compatible XML with profile/platform metadata
    3. Upload logs and XML to server via SCP
    4. Import results to dashboard via curl POST
"""

import csv
import re
import sys
import os
import glob
import subprocess
import argparse
import json
import shutil
import xml.etree.ElementTree as ET
from xml.dom import minidom
from getpass import getpass
from datetime import datetime

# Add script directory to path for importing spytest_lib (allows running from anywhere)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spytest_lib import (
    time_to_seconds, extract_build_id, find_results_files, 
    parse_summary, parse_functions, count_results, 
    format_duration, STATUS_SYMBOLS
)
from testbed_config import get_config as get_testbed_config, TESTBED_CONFIGS

# ============================================================================
# Configuration
# ============================================================================

# Server configuration
SERVER = 'sonic-ucs-m6-51'
SERVER_USER = 'sonic'
SERVER_PASSWORD = 'roZes@123'  # Default password (can be overridden via --password)
SERVER_BASE_PATH = '/home/sonic/test_logs_central/spytest_logs'

# Dashboard API configuration
DASHBOARD_URL = 'http://sonic-ucs-m6-51:5005'
IMPORT_XML_ENDPOINT = '/api/import-xml'  # For XML already on server
UPLOAD_XML_ENDPOINT = '/api/upload-xml'  # For uploading XML from local machine
RESULTS_ENDPOINT = '/api/results'  # Direct results posting

# Valid options (for validation and help) - from dashboard UI dropdowns
VALID_FABRICS = ['IPv4', 'VXLAN', 'IPv6']
VALID_TOPOS = ['2x2', 'B2B', '3-tier', 'standalone']

# Profiles that don't use platform subdirectory (e.g., gamut_bringup/<build>/ instead of gamut_bringup/g200/<build>/)
PROFILES_WITHOUT_PLATFORM_DIR = ['202505c-Gamut', 'gamut_bringup']

# Test name patterns for fabric classification
# Priority: VXLAN patterns checked first, then filename prefix (v4/v6), then keyword fallback
VXLAN_PATTERNS = ['vxlan', 'l2vni', 'l3vni']
IPV4_PATTERNS = ['congestion', 'dwrr', 'strict_priority', 'wred', 'ecn_marking', 'mmu_config', 'breakout', 'pfc_stream', 'compare_three', '4stream_tc3']


# ============================================================================
# XML Generation Functions
# ============================================================================

def generate_xml(summary, tests, subtests_pass, subtests_fail, profile, npu, build_id, logs_location):
    """Generate JUnit-compatible XML with profile/platform metadata.
    
    Args:
        npu: Canonical NPU name (already uppercase: G200, Q200, SPECTRUM4)
    
    Creates single testsuite structure expected by dashboard parser:
    <testsuites>
      <testsuite tests="N" failures="M" ...>
        <properties>...</properties>
        <testcase .../>
        <testcase .../>
      </testsuite>
    </testsuites>
    """
    # Count results by type
    counts = {'Pass': 0, 'Fail': 0, 'ConfigFail': 0, 'TGenFail': 0, 'ScriptError': 0, 'Unsupported': 0}
    for t in tests:
        r = t['result']
        if r in counts:
            counts[r] += 1

    total_failures = counts['Fail'] + counts['ConfigFail'] + counts['TGenFail'] + counts['ScriptError']
    total_time = time_to_seconds(summary.get('Execution Time', '0'))
    
    # Build XML root
    root = ET.Element('testsuites')
    root.set('name', 'spytest')
    
    # Create single testsuite with all tests (dashboard expects this structure)
    ts = ET.SubElement(root, 'testsuite')
    ts.set('name', 'spytest')
    ts.set('tests', str(len(tests)))
    ts.set('failures', str(total_failures))
    ts.set('errors', '0')
    ts.set('skipped', str(counts['Unsupported']))
    ts.set('time', str(total_time))
    ts.set('hostname', '')  # Can be filled if available
    
    # Add timestamp
    exec_started = summary.get('Execution Started', '')
    if exec_started:
        ts.set('timestamp', exec_started)
    
    # Add properties for dashboard metadata extraction
    props = ET.SubElement(ts, 'properties')
    
    # Profile property
    prop_profile = ET.SubElement(props, 'property')
    prop_profile.set('name', 'profile')
    prop_profile.set('value', profile)
    
    # Build ID (os_version format for auto-detection)
    prop_build = ET.SubElement(props, 'property')
    prop_build.set('name', 'os_version')
    prop_build.set('value', f'HEAD.{build_id}')
    
    # Platform/NPU (already uppercase)
    prop_npu = ET.SubElement(props, 'property')
    prop_npu.set('name', 'npu')
    prop_npu.set('value', npu)
    
    # Logs location
    if logs_location:
        prop_logs = ET.SubElement(props, 'property')
        prop_logs.set('name', 'logs_location')
        prop_logs.set('value', logs_location)
    
    # Add all testcases directly under the single testsuite
    for t in tests:
        tc = ET.SubElement(ts, 'testcase')
        tc.set('name', t['function'])
        # Include full module path in classname for category detection
        tc.set('classname', t['module'].replace('/', '.').replace('.py', ''))
        tc.set('file', t['module'])  # Add file attribute for category detection
        tc.set('time', str(time_to_seconds(t['time'])))
        
        if t['result'] in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']:
            fail = ET.SubElement(tc, 'failure')
            fail.set('message', t['description'][:200])
            fail.set('type', t['result'])
            fail.text = t['description']
        elif t['result'] == 'Unsupported':
            skip = ET.SubElement(tc, 'skipped')
            skip.set('message', t['description'][:200])

    return root, counts


def prettify_xml(root):
    """Convert ElementTree to pretty-printed XML string."""
    xml_str = minidom.parseString(ET.tostring(root, encoding='unicode')).toprettyxml(indent='  ')
    xml_str = '\n'.join(line for line in xml_str.split('\n') if line.strip())
    return xml_str


# ============================================================================
# Upload Functions
# ============================================================================

def run_command(cmd, capture=True, password=None):
    """Run a shell command, optionally with sshpass for password."""
    sshpass_available = subprocess.run(['which', 'sshpass'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
    
    if password and sshpass_available:
        cmd = ['sshpass', '-p', password] + cmd
    
    if capture:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return result.returncode == 0, result.stdout, result.stderr
    else:
        result = subprocess.run(cmd)
        return result.returncode == 0, '', ''


def ssh_mkdir(remote_path, password):
    """Create directory on remote server."""
    cmd = ['ssh', f'{SERVER_USER}@{SERVER}', f'mkdir -p {remote_path}']
    success, _, stderr = run_command(cmd, password=password)
    if not success:
        print(f"  Warning: mkdir failed: {stderr}")
    return success


def scp_upload(local_path, remote_path, password, recursive=False):
    """Upload file or directory via SCP."""
    cmd = ['scp']
    if recursive:
        cmd.append('-r')
    cmd.extend([local_path, f'{SERVER_USER}@{SERVER}:{remote_path}'])
    success, _, stderr = run_command(cmd, password=password)
    if not success:
        print(f"  Warning: scp failed: {stderr}")
    return success


def curl_import(xml_path, profile, npu, build_id, logs_location, dashboard_url, password=None):
    """Import results to dashboard via SSH + curl POST to /api/import-xml.
    
    Args:
        npu: Canonical NPU name (already uppercase: G200, Q200, SPECTRUM4)
    
    Runs the curl command via SSH on the server itself to bypass DNS/proxy issues.
    Uses localhost:PORT on the server side.
    """
    # Extract port from dashboard URL (e.g., http://sonic-ucs-m6-51:5005 -> 5005)
    import re
    port_match = re.search(r':(\d+)', dashboard_url)
    port = port_match.group(1) if port_match else '5005'
    
    # Use localhost on the server to avoid DNS/proxy issues
    local_url = f"http://localhost:{port}{IMPORT_XML_ENDPOINT}"
    
    # Build POST data - API expects xml_path on server, plus optional overrides
    data = {
        'xml_path': xml_path,
        'profile': profile,
        'build_id': build_id,
        'npu': npu,
        'test_suite': 'spytest',
        'test_logs_location': logs_location
    }
    
    # Build curl command to run on the server via SSH
    # Escape single quotes in JSON for shell
    json_data = json.dumps(data).replace("'", "'\\''")
    remote_curl = f"curl -s -X POST '{local_url}' -H 'Content-Type: application/json' -d '{json_data}'"
    
    # Use sshpass for password authentication
    if password:
        cmd = ['sshpass', '-p', password, 'ssh', '-o', 'StrictHostKeyChecking=no',
               f'{SERVER_USER}@{SERVER}', remote_curl]
    else:
        cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', f'{SERVER_USER}@{SERVER}', remote_curl]
    
    success, stdout, stderr = run_command(cmd)
    return success, stdout, stderr


def curl_upload_xml(local_xml_path, profile, npu, build_id, dashboard_url):
    """Upload XML file directly to dashboard via curl POST to /api/upload-xml.
    
    Args:
        npu: Canonical NPU name (already uppercase)
    """
    upload_url = f"{dashboard_url}{UPLOAD_XML_ENDPOINT}"
    
    # Build curl command with multipart form data
    cmd = [
        'curl', '-s', '-X', 'POST', upload_url,
        '-F', f'file=@{local_xml_path}',
        '-F', f'profile={profile}',
        '-F', f'build_id={build_id}',
        '-F', f'npu={npu}'
    ]
    
    success, stdout, stderr = run_command(cmd)
    return success, stdout, stderr


def post_result_direct(data, dashboard_url, password=None):
    """Post result directly to /api/results endpoint via SSH.
    
    This gives full control over all dashboard fields including:
    - fabric, topo, notes, jira_link, save_to_confluence
    
    Args:
        data: Dict with result fields (test_suite, npu, topo, profile, fabric, 
              build_id, status, total_tests, passed, failed, skipped, errors,
              notes, test_logs_location, jira_link, save_to_confluence)
        dashboard_url: Dashboard URL (used to extract port)
        password: Server password for SSH
    
    Returns:
        (success, stdout, stderr) tuple
    """
    # Extract port from dashboard URL
    port_match = re.search(r':(\d+)', dashboard_url)
    port = port_match.group(1) if port_match else '5005'
    
    local_url = f"http://localhost:{port}{RESULTS_ENDPOINT}"
    
    # Escape single quotes in JSON for shell
    json_data = json.dumps(data).replace("'", "'\\''")
    remote_curl = f"curl -s -X POST '{local_url}' -H 'Content-Type: application/json' -d '{json_data}'"
    
    if password:
        cmd = ['sshpass', '-p', password, 'ssh', '-o', 'StrictHostKeyChecking=no',
               f'{SERVER_USER}@{SERVER}', remote_curl]
    else:
        cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', f'{SERVER_USER}@{SERVER}', remote_curl]
    
    success, stdout, stderr = run_command(cmd)
    return success, stdout, stderr


def build_result_view_url(resp, dashboard_url):
    """Return a browser URL for reviewing a posted result.

    Prefers a URL field returned by the dashboard API (`url`, `view_url`,
    `result_url`). Falls back to common Flask-style patterns based on
    `result_id` so users at least get something clickable; if the path
    differs, the dashboard root is also printed by the caller.
    """
    if not isinstance(resp, dict):
        return None
    # 1) Honor any URL the API returns
    for key in ('url', 'view_url', 'result_url'):
        url = resp.get(key)
        if url:
            if url.startswith(('http://', 'https://')):
                return url
            # Relative path returned -- join with dashboard base
            return dashboard_url.rstrip('/') + '/' + url.lstrip('/')
    # 2) Construct from result_id -- common pattern is /result/<id>
    rid = resp.get('result_id')
    if rid is None:
        return None
    return f"{dashboard_url.rstrip('/')}/result/{rid}"


def classify_test_fabric(test_name):
    """Classify a test as VXLAN or IPv4 based on name patterns.

    VXLAN: contains vxlan/l2vni/l3vni keywords
    IPv4:  everything else (includes v4 and v6 underlay tests)
    """
    test_lower = test_name.lower()
    base = test_lower.rsplit('/', 1)[-1] if '/' in test_lower else test_lower

    for pattern in VXLAN_PATTERNS:
        if pattern in base:
            return 'VXLAN'

    return 'IPv4'


def filter_tests_by_fabric(tests, fabric):
    """Filter tests by fabric type (VXLAN or IPv4/IPv6 underlay)."""
    return [t for t in tests if classify_test_fabric(t['function']) == fabric]


def generate_failed_tests_notes(tests):
    """Generate notes string listing failed tests."""
    failed = [t['function'] for t in tests if t['result'] in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']]
    config_fail = [t['function'] for t in tests if t['result'] == 'ConfigFail']
    tgen_fail = [t['function'] for t in tests if t['result'] == 'TGenFail']
    script_error = [t['function'] for t in tests if t['result'] == 'ScriptError']
    regular_fail = [t['function'] for t in tests if t['result'] == 'Fail']
    
    notes_parts = []
    if regular_fail:
        notes_parts.append(f"Failed: {', '.join(regular_fail)}")
    if config_fail:
        notes_parts.append(f"ConfigFail: {', '.join(config_fail)}")
    if tgen_fail:
        notes_parts.append(f"TGenFail: {', '.join(tgen_fail)}")
    if script_error:
        notes_parts.append(f"ScriptError: {', '.join(script_error)}")
    
    return '. '.join(notes_parts) if notes_parts else ''


# ============================================================================
# Main Workflow
# ============================================================================

def print_test_execution_summary(tests):
    """Print test execution summary in chronological order with error details."""
    print(f"\n{'='*70}")
    print(f"TEST EXECUTION SUMMARY (Chronological Order)")
    print(f"{'='*70}")
    
    for i, t in enumerate(tests, 1):
        result = t['result']
        symbol = STATUS_SYMBOLS.get(result, '?')
        func_name = t['function']
        time_str = t['time']
        
        # Format: [symbol] test_name (time) - RESULT
        status_line = f"{i:3}. [{symbol}] {func_name} ({time_str}) - {result}"
        print(status_line)
        
        # For failures, show error description indented
        if result in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']:
            desc = t['description'][:100]  # Truncate long descriptions
            if desc and desc != 'No description':
                print(f"         └─ {desc}")
    
    print(f"{'='*70}")


def print_summary(tests, counts, subtests_pass, subtests_fail):
    """Print test results summary."""
    print(f"\n{'='*60}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"Test Functions: {len(tests)}")
    print(f"  Pass:        {counts['Pass']}")
    print(f"  Fail:        {counts['Fail']}")
    print(f"  ConfigFail:  {counts['ConfigFail']}")
    print(f"  TGenFail:    {counts['TGenFail']}")
    print(f"  ScriptError: {counts.get('ScriptError', 0)}")
    print(f"  Unsupported: {counts['Unsupported']}")
    
    if subtests_pass + subtests_fail > 0:
        print(f"\nSubtests: {subtests_pass + subtests_fail}")
        print(f"  Pass: {subtests_pass}")
        print(f"  Fail: {subtests_fail}")
    
    total = len(tests) + subtests_pass + subtests_fail
    passed = counts['Pass'] + subtests_pass
    if total > 0:
        print(f"\nCombined Pass Rate: {100*passed/total:.2f}% ({passed}/{total})")
    print(f"{'='*60}\n")


def print_brief_usage():
    """Print brief usage when required arguments are missing."""
    print("Usage: spytest_publish.py <results_dir> --yaml <testbed.yaml> [options]")
    print("")
    print("Required:")
    print("  results_dir           Path to spytest results directory")
    print("  --yaml YAML           Testbed YAML filename (derives profile, platform, fabric)")
    print("")
    print("Available testbed YAMLs:")
    for name, cfg in TESTBED_CONFIGS.items():
        print(f"  {name:45s}  npu={cfg['npu']:10s}  profile=*-{cfg['profile_suffix']}")
    print("")
    print("Options:   --branch X  --dry-run  --xml-only  --skip-upload  --skip-import")
    print("")
    print("Use --help for full documentation.")


def _read_version_info(results_dir):
    """Read version_info.txt written by spytest_run.py. Returns (branch, build) or (None, None)."""
    info_file = os.path.join(results_dir, 'version_info.txt')
    if not os.path.exists(info_file):
        return None, None
    try:
        vals = {}
        with open(info_file) as f:
            for line in f:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    vals[k] = v
        branch = vals.get('branch') or None
        build = vals.get('build') or None
        return branch, build
    except Exception:
        return None, None


def _extract_branch_from_dir(results_dir):
    """Try to extract branch name (e.g. '202405c') from results directory name.
    
    Checks in order:
    1. version_info.txt (written by spytest_run.py)
    2. Directory name patterns (e.g. '202405c_tortuga_results')
    3. build.txt or *_summary.txt (SONiC version string)
    """
    # Try version_info.txt first (written by spytest_run.py)
    results_dir_abs = os.path.abspath(results_dir)
    branch, _ = _read_version_info(results_dir_abs)
    if branch:
        return branch

    # Match 6-digit branch optionally + letter and/or dot-release, NOT followed by more digits (dates)
    # Order matters: try most specific first (with letter/dot), then plain 6-digit
    branch_re = r'(?<!\d)(20\d{4}(?:[a-z](?:\.\d+)?|\.\d+))(?!\d)'  # 202405c, 202405c.2, 202511.2
    branch_re_plain = r'(?<!\d)(20\d{4})(?![a-z\d])'                 # 202505 (not followed by letter or digit)
    
    for pattern in [branch_re, branch_re_plain]:
        basename = os.path.basename(results_dir.rstrip('/'))
        m = re.search(pattern, basename)
        if m:
            return m.group(1)
        # Also try parent directory
        parent = os.path.basename(os.path.dirname(results_dir.rstrip('/')))
        m = re.search(pattern, parent)
        if m:
            return m.group(1)
    
    # Fall back to build.txt or *_summary.txt
    # Version string may be: SONiC-OS-202505c.1.0.0-..., SONiC-OS-Enterprise_Base-202505c.1.0.0-..., etc.
    results_dir_abs = os.path.abspath(results_dir)
    version_str = _read_version_from_logs(results_dir_abs)
    if version_str:
        # Extract branch (20XXYY + optional letter) followed by dot-version
        m = re.search(r'(?:^|[.\-_])(20\d{4}[a-z]?)\.', version_str)
        if m:
            return m.group(1)
    
    return None


def _read_version_from_logs(results_dir):
    """Read SONiC version string from build.txt or *_summary.txt in results_dir."""
    # Try build.txt first
    build_txt = os.path.join(results_dir, 'build.txt')
    if os.path.exists(build_txt):
        try:
            with open(build_txt, encoding='utf-8', errors='replace') as f:
                content = f.read()
            if 'SONiC' in content:
                return content
        except Exception:
            pass
    
    # Try summary file
    summary_files = glob.glob(os.path.join(results_dir, '*_summary.txt'))
    for sf in sorted(summary_files, reverse=True):
        try:
            with open(sf, encoding='utf-8', errors='replace') as f:
                for line in f:
                    if 'Software Version' in line and 'SONiC' in line:
                        return line
        except Exception:
            pass
    
    return None


def main():
    # Quick check for missing required args before full parsing
    import sys
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] not in ['-h', '--help']):
        print_brief_usage()
        sys.exit(1)
    
    # Check for --yaml
    if '--help' not in sys.argv and '-h' not in sys.argv:
        if '--yaml' not in sys.argv:
            print("Error: --yaml <testbed.yaml> is required\n")
            print_brief_usage()
            sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description='Process spytest results, generate XML, upload to server, and import to dashboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Required arguments
    parser.add_argument('results_dir', help='Path to spytest results directory')
    
    yaml_names = ', '.join(TESTBED_CONFIGS.keys())
    parser.add_argument('--yaml', required=True, metavar='TESTBED_YAML',
                        help=f'Testbed YAML filename. Auto-derives profile, platform, fabric. '
                             f'Available: {yaml_names}')
    parser.add_argument('--branch', metavar='BRANCH',
                        help='Branch/release name for profile (e.g. 202405c). '
                             'Auto-detected from results dir name if not specified.')
    
    # Optional arguments
    parser.add_argument('--build', help='Build ID (auto-detected from dir name if not specified)')
    parser.add_argument('--password', default=SERVER_PASSWORD,
                        help=f'Server password (default: {SERVER_PASSWORD[:3]}...)')
    parser.add_argument('--dashboard-url', default=DASHBOARD_URL,
                        help=f'Dashboard URL (default: {DASHBOARD_URL})')
    
    # Dashboard metadata fields
    parser.add_argument('--fabric', choices=VALID_FABRICS, metavar='FABRIC',
                        help=f'Fabric type. Choices: {", ".join(VALID_FABRICS)}')
    parser.add_argument('--topo', choices=VALID_TOPOS, metavar='TOPO',
                        help=f'Topology. Choices: {", ".join(VALID_TOPOS)}')
    parser.add_argument('--notes', help='Notes / failed tests (auto-generated if not specified)')
    parser.add_argument('--jira', help='Jira link URL')
    parser.add_argument('--no-confluence', action='store_true', default=True,
                        help='Don\'t save to Confluence table (default: True)')
    parser.add_argument('--confluence', action='store_true',
                        help='Save to Confluence table')
    
    # API mode options (both True by default)
    parser.add_argument('--direct-api', action='store_true', default=True,
                        help='Use direct /api/results POST instead of XML import (default: True)')
    parser.add_argument('--no-direct-api', action='store_true',
                        help='Use XML import via /api/import-xml instead of direct API')
    parser.add_argument('--split-fabric', action='store_true', default=True,
                        help='Split results into separate VXLAN and IPv4 entries (default: True)')
    parser.add_argument('--no-split-fabric', action='store_true',
                        help='Create single entry for all tests')
    
    # Workflow control
    parser.add_argument('--dry-run', action='store_true', 
                        help='Preview all steps without executing')
    parser.add_argument('--xml-only', action='store_true',
                        help='Generate XML file locally, skip upload and import')
    parser.add_argument('--skip-upload', action='store_true',
                        help='Skip uploading logs to server')
    parser.add_argument('--skip-import', action='store_true',
                        help='Skip importing to dashboard')
    parser.add_argument('--no-cleanup', action='store_true',
                        help='Keep local logs directory after upload (default: remove after successful upload)')
    parser.add_argument('--logs-path', metavar='PATH',
                        help='Explicit remote logs path (overrides computed path). Used by spytest_run.py when Phase 3 already transferred logs.')
    parser.add_argument('-o', '--output', help='Output XML file path (for --xml-only)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # ========================================================================
    # Step 0: Validate inputs & resolve config
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"SPYTEST RESULTS PUBLISHER")
    print(f"{'='*60}")
    
    results_dir = os.path.abspath(args.results_dir)
    if not os.path.isdir(results_dir):
        print(f"Error: {results_dir} is not a directory")
        sys.exit(1)
    
    # NPU to directory name mapping
    NPU_TO_DIR = {
        'G200': 'g200',
        'Q200': 'q200', 
        'P200': 'p200',
        'SPECTRUM4': 'spectrum4',
    }
    
    # ── Resolve profile, platform, fabric from testbed YAML ──
    tb_config = get_testbed_config(args.yaml)
    if not tb_config:
        print(f"Error: Unknown testbed YAML '{args.yaml}'")
        print(f"Available:")
        for name in TESTBED_CONFIGS:
            print(f"  {name}")
        sys.exit(1)
    
    # Derive NPU
    npu = tb_config['npu']
    platform_dir = NPU_TO_DIR.get(npu, npu.lower())
    
    # Derive profile: <branch>-<suffix>
    profile_suffix = tb_config['profile_suffix']
    branch = args.branch or _extract_branch_from_dir(results_dir)
    if branch:
        profile = f"{branch}-{profile_suffix}"
    else:
        profile = profile_suffix
        print(f"  Warning: Could not detect branch from dir name, using profile '{profile}'")
        print(f"  Hint: use --branch 202405c to set explicitly")
    
    # Derive fabric split behavior from config
    tb_fabrics = tb_config.get('fabric', ['IPv4', 'VXLAN'])
    if len(tb_fabrics) == 1 and not args.fabric:
        # Single fabric (e.g. ["IPv6"]) -> set --fabric and disable split
        args.fabric = tb_fabrics[0]
        args.no_split_fabric = True
    # Multi-fabric (e.g. ["IPv4", "VXLAN"]) -> default split behavior is correct
    
    print(f"  Testbed YAML: {args.yaml}")
    print(f"  Derived: profile={profile}, npu={npu}, fabric={tb_fabrics}")
    
    # Extract or use provided build ID
    build_id = args.build or extract_build_id(results_dir)
    if not build_id:
        print("Error: Could not auto-detect build ID. Please specify --build")
        sys.exit(1)
    
    print(f"\nConfiguration:")
    print(f"  Profile:     {profile}")
    print(f"  NPU:         {npu}")
    print(f"  Build:       {build_id}")
    print(f"  Results Dir: {results_dir}")
    if args.fabric:
        print(f"  Fabric:      {args.fabric}")
    if args.topo:
        print(f"  Topology:    {args.topo}")
    # Show split mode status (default is ON)
    if args.no_split_fabric:
        print(f"  Split Mode:  OFF (single entry)")
    else:
        print(f"  Split Mode:  ON (separate VXLAN and IPv4 entries)")
    
    if args.dry_run:
        print(f"  Mode:        DRY RUN (no changes will be made)")
    
    # ========================================================================
    # Step 1: Parse results
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"STEP 1: Parsing spytest results")
    print(f"{'='*60}")
    
    try:
        summary_file, functions_file = find_results_files(results_dir)
        print(f"  Found: {os.path.basename(summary_file)}")
        print(f"  Found: {os.path.basename(functions_file)}")
        
        summary = parse_summary(summary_file)
        tests, subtests_pass, subtests_fail = parse_functions(functions_file)
        print(f"  Parsed {len(tests)} test functions")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # ========================================================================
    # Step 2: Generate XML
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"STEP 2: Generating JUnit XML")
    print(f"{'='*60}")
    
    # Build target paths - some profiles don't use platform subdirectory
    if args.logs_path:
        # Explicit path provided by spytest_run.py (Phase 3 already transferred)
        remote_logs_dir = args.logs_path
    elif profile in PROFILES_WITHOUT_PLATFORM_DIR:
        remote_base_dir = f"{SERVER_BASE_PATH}/{profile}/{build_id}"
        if args.skip_upload:
            remote_logs_dir = remote_base_dir
        else:
            remote_logs_dir = f"{remote_base_dir}/run_logs_{platform_dir}"
    else:
        remote_base_dir = f"{SERVER_BASE_PATH}/{profile}/{platform_dir}/{build_id}"
        # When --skip-upload is used, Phase 3 (spytest_run.py) already transferred logs
        # directly into remote_base_dir without a run_logs_* subdirectory.
        # Only add run_logs_* when this script handles the upload itself.
        if args.skip_upload:
            remote_logs_dir = remote_base_dir
        else:
            remote_logs_dir = f"{remote_base_dir}/run_logs_{platform_dir}"
    remote_xml_path = f"{remote_logs_dir}/tr.xml"
    
    root, counts = generate_xml(
        summary, tests, subtests_pass, subtests_fail,
        profile, npu, build_id, remote_logs_dir
    )
    xml_str = prettify_xml(root)
    
    print(f"  Generated XML with {len(tests)} test cases")
    print(f"  Target XML path: {remote_xml_path}")
    
    # Handle --xml-only mode
    if args.xml_only:
        output_file = args.output or f"results_{profile}_{platform_dir}_{build_id}.xml"
        if not args.dry_run:
            with open(output_file, 'w') as f:
                f.write(xml_str)
            print(f"  Written to: {output_file}")
        else:
            print(f"  Would write to: {output_file}")
        
        print_test_execution_summary(tests)
        print_summary(tests, counts, subtests_pass, subtests_fail)
        return
    
    # Save XML locally for upload
    local_xml = f"/tmp/tr_{os.environ.get('USER', 'user')}_{profile}_{platform_dir}_{build_id}.xml"
    if not args.dry_run:
        with open(local_xml, 'w') as f:
            f.write(xml_str)
        print(f"  Saved locally: {local_xml}")
    
    # ========================================================================
    # Step 3: Upload to server
    # ========================================================================
    if not args.skip_upload:
        print(f"\n{'='*60}")
        print(f"STEP 3: Uploading to server")
        print(f"{'='*60}")
        print(f"  Server: {SERVER_USER}@{SERVER}")
        print(f"  Target: {remote_logs_dir}/")
        
        if args.dry_run:
            print(f"  [DRY RUN] Would create directory: {remote_logs_dir}")
            print(f"  [DRY RUN] Would upload XML: {local_xml} -> {remote_xml_path}")
            print(f"  [DRY RUN] Would upload logs from: {results_dir}")
            
            # List files that would be uploaded
            items = os.listdir(results_dir)
            print(f"  [DRY RUN] Files to upload: {len(items)}")
            for item in items[:5]:
                print(f"    - {item}")
            if len(items) > 5:
                print(f"    ... and {len(items) - 5} more")
            if not args.no_cleanup:
                print(f"  [DRY RUN] Would remove local directory after upload: {results_dir}")
        else:
            password = args.password
            
            # Create remote directory
            print(f"  Creating remote directory...")
            if not ssh_mkdir(remote_logs_dir, password):
                print("  Warning: Failed to create remote directory")
            
            # Upload XML first
            print(f"  Uploading XML...")
            if not scp_upload(local_xml, remote_xml_path, password):
                print("  Error: Failed to upload XML")
                sys.exit(1)
            
            # Upload log files
            print(f"  Uploading log files...")
            items = os.listdir(results_dir)
            uploaded = 0
            failed = 0
            for item in items:
                item_path = os.path.join(results_dir, item)
                is_dir = os.path.isdir(item_path)
                if args.verbose:
                    print(f"    Uploading: {item}")
                if scp_upload(item_path, f"{remote_logs_dir}/", password, recursive=is_dir):
                    uploaded += 1
                else:
                    failed += 1
            
            print(f"  Uploaded: {uploaded} items, Failed: {failed} items")
            
            # Cleanup local logs directory after successful upload (default behavior)
            if not args.no_cleanup and failed == 0:
                print(f"\n  Cleaning up local directory: {results_dir}")
                try:
                    shutil.rmtree(results_dir)
                    print(f"  Removed: {results_dir}")
                except Exception as e:
                    print(f"  Warning: Failed to remove directory: {e}")
    else:
        print(f"\n[SKIPPED] Step 3: Upload to server (--skip-upload)")
        # Still upload the XML if import is not skipped (import needs it on the server)
        if not args.skip_import:
            password = args.password
            print(f"  Uploading XML only for import...")
            if not ssh_mkdir(remote_logs_dir, password):
                print("  Warning: Failed to create remote directory")
            if scp_upload(local_xml, remote_xml_path, password):
                print(f"  ✓ XML uploaded to {remote_xml_path}")
            else:
                print("  Error: Failed to upload XML")
    
    # ========================================================================
    # Step 4: Import to dashboard
    # ========================================================================
    # Determine save_to_confluence flag
    save_to_confluence = args.confluence and not args.no_confluence
    
    # Resolve --no-* flags (they override the defaults)
    split_fabric = args.split_fabric and not args.no_split_fabric
    direct_api = args.direct_api and not args.no_direct_api
    
    # Use direct API if enabled or if split-fabric/fabric/topo specified
    use_direct_api = direct_api or split_fabric or args.fabric or args.topo
    
    if not args.skip_import and not args.skip_upload:
        print(f"\n{'='*60}")
        if split_fabric:
            print(f"STEP 4: Importing to dashboard (Split by Fabric)")
        elif use_direct_api:
            print(f"STEP 4: Importing to dashboard (Direct API)")
        else:
            print(f"STEP 4: Importing to dashboard (via SSH)")
        print(f"{'='*60}")
    elif not args.skip_import and args.skip_upload:
        # Import still happens even without upload (XML was uploaded by Phase 3 or already exists)
        print(f"\n{'='*60}")
        print(f"STEP 4: Importing to dashboard (via SSH)")
        print(f"{'='*60}")

    if not args.skip_import:
        
        if split_fabric:
            # Split tests by fabric and create separate entries
            vxlan_tests = filter_tests_by_fabric(tests, 'VXLAN')
            ipv4_tests = filter_tests_by_fabric(tests, 'IPv4')
            
            for fabric_name, fabric_tests in [('VXLAN', vxlan_tests), ('IPv4', ipv4_tests)]:
                if not fabric_tests:
                    print(f"\n  No {fabric_name} tests found, skipping...")
                    continue
                
                # Count subtests for this fabric (use subtest counts, not function counts)
                sub_pass = sum(t.get('subtests_pass', 0) for t in fabric_tests)
                sub_fail = sum(t.get('subtests_fail', 0) for t in fabric_tests)
                # For tests without subtests, count the function result
                for t in fabric_tests:
                    if t.get('subtests_pass', 0) == 0 and t.get('subtests_fail', 0) == 0:
                        if t['result'] == 'Pass':
                            sub_pass += 1
                        elif t['result'] in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']:
                            sub_fail += 1
                
                total = sub_pass + sub_fail
                passed = sub_pass
                failed = sub_fail
                errors = 0  # Errors already counted in sub_fail
                skipped = sum(1 for t in fabric_tests if t['result'] == 'Unsupported')
                status = 'Passed' if failed == 0 else 'Failed'
                
                # Auto-generate notes if not provided
                notes = args.notes or generate_failed_tests_notes(fabric_tests)
                
                # Build failed_tests list for the dashboard detail view
                failed_tests_list = []
                for t in fabric_tests:
                    if t['result'] in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']:
                        failed_tests_list.append({
                            'name': t['function'],
                            'message': t.get('description', t['result'])
                        })
                
                # Build full test_details (all tests) for the view page
                test_details_list = []
                for t in fabric_tests:
                    test_details_list.append({
                        'name': t['function'],
                        'status': t['result'],
                        'duration': t.get('time', ''),
                        'description': t.get('description', '')
                    })
                
                print(f"\n  {fabric_name} Fabric: {total} tests ({passed} pass, {failed} fail)")
                
                data = {
                    'test_suite': 'spytest',
                    'npu': npu,
                    'topo': args.topo or '2x2',
                    'profile': profile,
                    'fabric': fabric_name,
                    'build_id': build_id,
                    'status': status,
                    'total_tests': total,
                    'passed': passed,
                    'failed': failed,
                    'skipped': skipped,
                    'errors': errors,
                    'notes': notes,
                    'failed_tests': failed_tests_list,
                    'test_details': test_details_list,
                    'test_logs_location': remote_logs_dir,
                    'jira_link': args.jira or '',
                    'save_to_confluence': save_to_confluence
                }
                
                if args.dry_run:
                    print(f"  [DRY RUN] Would POST to /api/results:")
                    print(f"    {json.dumps(data, indent=2)}")
                else:
                    success, stdout, stderr = post_result_direct(data, args.dashboard_url, password)
                    if success and stdout:
                        try:
                            resp = json.loads(stdout)
                            if resp.get('success'):
                                print(f"    Success! Result ID: {resp.get('result_id')}")
                                view_url = build_result_view_url(resp, args.dashboard_url)
                                if view_url:
                                    print(f"    View URL:  {view_url}")
                                print(f"    Dashboard: {args.dashboard_url}")
                            else:
                                print(f"    API Error: {resp.get('error', stdout)}")
                        except json.JSONDecodeError:
                            print(f"    Response: {stdout}")
                    else:
                        print(f"    Error: {stderr}")
        
        elif use_direct_api:
            # Single direct API post with specified fabric/topo
            # Use subtest counts (not function counts)
            sub_pass = sum(t.get('subtests_pass', 0) for t in tests)
            sub_fail = sum(t.get('subtests_fail', 0) for t in tests)
            # For tests without subtests, count the function result
            for t in tests:
                if t.get('subtests_pass', 0) == 0 and t.get('subtests_fail', 0) == 0:
                    if t['result'] == 'Pass':
                        sub_pass += 1
                    elif t['result'] in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']:
                        sub_fail += 1
            
            total = sub_pass + sub_fail
            passed = sub_pass
            failed = sub_fail
            errors = 0
            skipped = counts['Unsupported']
            status = 'Passed' if failed == 0 else 'Failed'
            
            # Auto-generate notes if not provided
            notes = args.notes or generate_failed_tests_notes(tests)
            
            # Build failed_tests and test_details for dashboard
            failed_tests_list = []
            test_details_list = []
            for t in tests:
                test_details_list.append({
                    'name': t['function'],
                    'status': t['result'],
                    'duration': t.get('time', ''),
                    'description': t.get('description', '')
                })
                if t['result'] in ['Fail', 'ConfigFail', 'TGenFail', 'ScriptError']:
                    failed_tests_list.append({
                        'name': t['function'],
                        'message': t.get('description', t['result'])
                    })
            
            data = {
                'test_suite': 'spytest',
                'npu': npu,
                'topo': args.topo or '2x2',
                'profile': profile,
                'fabric': args.fabric or 'IPv4',
                'build_id': build_id,
                'status': status,
                'total_tests': total,
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'errors': errors,
                'notes': notes,
                'failed_tests': failed_tests_list,
                'test_details': test_details_list,
                'test_logs_location': remote_logs_dir,
                'jira_link': args.jira or '',
                'save_to_confluence': save_to_confluence
            }
            
            print(f"  Server:     {SERVER_USER}@{SERVER}")
            print(f"  Dashboard:  localhost:5005 (on server)")
            print(f"  API:        POST {RESULTS_ENDPOINT}")
            print(f"  Profile:    {profile}")
            print(f"  Build ID:   {build_id}")
            print(f"  NPU:        {npu}")
            print(f"  Fabric:     {data['fabric']}")
            print(f"  Topology:   {data['topo']}")
            print(f"  Logs:       {remote_logs_dir}")
            print(f"  Confluence: {save_to_confluence}")
            
            if args.dry_run:
                print(f"\n  [DRY RUN] Would POST to /api/results:")
                print(f"    {json.dumps(data, indent=2)}")
            else:
                print(f"\n  Sending direct API request via SSH...")
                success, stdout, stderr = post_result_direct(data, args.dashboard_url, password)
                
                if success and stdout:
                    try:
                        resp = json.loads(stdout)
                        if resp.get('success'):
                            print(f"  Success! Result ID: {resp.get('result_id')}")
                            print(f"  Message: {resp.get('message')}")
                            view_url = build_result_view_url(resp, args.dashboard_url)
                            if view_url:
                                print(f"  View URL:  {view_url}")
                            print(f"  Dashboard: {args.dashboard_url}")
                        else:
                            print(f"  API Error: {resp.get('error', stdout)}")
                    except json.JSONDecodeError:
                        print(f"  Response: {stdout}")
                elif stderr:
                    print(f"  Error: {stderr}")
        
        else:
            # Original XML import logic
            print(f"  Server:     {SERVER_USER}@{SERVER}")
            print(f"  Dashboard:  localhost:5005 (on server)")
            print(f"  API:        POST {IMPORT_XML_ENDPOINT}")
            print(f"  XML Path:   {remote_xml_path}")
            print(f"  Profile:    {profile}")
            print(f"  Build ID:   {build_id}")
            print(f"  NPU:        {npu}")
            print(f"  Logs:       {remote_logs_dir}")
            
            if args.dry_run:
                print(f"\n  [DRY RUN] Would SSH to {SERVER} and POST to localhost:5005{IMPORT_XML_ENDPOINT}")
                print(f"  [DRY RUN] Payload:")
                print(f"    {{")
                print(f'      "xml_path": "{remote_xml_path}",')
                print(f'      "profile": "{profile}",')
                print(f'      "build_id": "{build_id}",')
                print(f'      "npu": "{npu}",')
                print(f'      "test_logs_location": "{remote_logs_dir}"')
                print(f"    }}")
            else:
                print(f"\n  Sending import request via SSH...")
                success, stdout, stderr = curl_import(
                    remote_xml_path, profile, npu, build_id, remote_logs_dir,
                    args.dashboard_url, password
                )
                
                if success and stdout:
                    try:
                        resp = json.loads(stdout)
                        if resp.get('success'):
                            print(f"  Success! Result ID: {resp.get('result_id')}")
                            print(f"  Message: {resp.get('message')}")
                            view_url = build_result_view_url(resp, args.dashboard_url)
                            if view_url:
                                print(f"  View URL:  {view_url}")
                            print(f"  Dashboard: {args.dashboard_url}")
                            if 'data' in resp:
                                data = resp['data']
                                print(f"  Imported: {data.get('total', 'N/A')} tests")
                                print(f"    Passed: {data.get('passed', 'N/A')}")
                                print(f"    Failed: {data.get('failed', 'N/A')}")
                                print(f"    Skipped: {data.get('skipped', 'N/A')}")
                        else:
                            print(f"  API Error: {resp.get('error', stdout)}")
                    except json.JSONDecodeError:
                        print(f"  Response: {stdout}")
                elif stderr:
                    print(f"  Error: {stderr}")
                
                if not success:
                    print(f"\n  Note: Dashboard import may require manual intervention")
                    print(f"  Manual import URL: {args.dashboard_url}")
                    print(f"  XML Path: {remote_xml_path}")
    elif args.skip_import:
        # Import explicitly skipped
        print(f"\n[SKIPPED] Step 4: Import to dashboard (--skip-import)")
        print(f"\n  To import later, use:")
        print(f"  curl -X POST {args.dashboard_url}{IMPORT_XML_ENDPOINT} \\")
        print(f'    -H "Content-Type: application/json" \\')
        print(f"    -d '{{\"xml_path\": \"{remote_xml_path}\", \"profile\": \"{profile}\", \"build_id\": \"{build_id}\", \"npu\": \"{npu}\"}}'")
    
    # ========================================================================
    # Summary
    # ========================================================================
    print_test_execution_summary(tests)
    print_summary(tests, counts, subtests_pass, subtests_fail)
    
    print(f"{'='*60}")
    print(f"COMPLETED")
    print(f"{'='*60}")
    print(f"Logs location:  {remote_logs_dir}")
    print(f"XML location:   {remote_xml_path}")
    print(f"\nFor manual dashboard import via API:")
    print(f"  curl -X POST {args.dashboard_url}{IMPORT_XML_ENDPOINT} \\")
    print(f'    -H "Content-Type: application/json" \\')
    print(f"    -d '{{\"xml_path\": \"{remote_xml_path}\", \"profile\": \"{profile}\", \"build_id\": \"{build_id}\", \"npu\": \"{npu}\"}}'")
    print(f"\nOr use the web UI:")
    print(f"  {args.dashboard_url}")


if __name__ == '__main__':
    main()
