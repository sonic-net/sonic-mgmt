#!/usr/bin/env python3
"""
Unified spytest results processor: Generate XML, upload logs, and import to dashboard.

Usage:
    python spytest_publish.py <results_dir> --profile <profile> --platform <platform> [options]

Examples:
    # Full workflow: generate XML, upload logs, import to dashboard
    python spytest_publish.py /path/to/gamut_full_run_4_29_image_40442 \\
        --profile 202405c_tortuga --platform g200

    # Just generate XML locally
    python spytest_publish.py /path/to/results --profile 202405c_tortuga --platform g200 \\
        --xml-only -o results.xml

    # Upload logs but skip dashboard import
    python spytest_publish.py /path/to/results --profile 202405c_tortuga --platform g200 \\
        --skip-import

    # Dry run (preview all steps)
    python spytest_publish.py /path/to/results --profile 202405c_tortuga --platform g200 \\
        --dry-run

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

# Valid options (for validation and help) - from dashboard UI dropdowns
VALID_PROFILES = [
    '202511-Community',
    '202505-OCI', 
    '202405c-Tortuga',
    '202405-T2',
    '202505-Community',
    '202505c-Gamut',
    '202511.2-Titan',
    'LinkedIn-202505',
    # Also accept underscore variants used in directory structure
    '202405c_tortuga',
    '202505c_tortuga', 
    '202505_oci',
    'gamut_bringup'
]
VALID_PLATFORMS = ['g200', 'q200', 'p200', 'spectrum4']

# Profiles that don't use platform subdirectory (e.g., gamut_bringup/<build>/ instead of gamut_bringup/g200/<build>/)
PROFILES_WITHOUT_PLATFORM_DIR = ['202505c-Gamut', 'gamut_bringup']


# ============================================================================
# XML Generation Functions
# ============================================================================

def generate_xml(summary, tests, subtests_pass, subtests_fail, profile, platform, build_id, logs_location):
    """Generate JUnit-compatible XML with profile/platform metadata.
    
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
    counts = {'Pass': 0, 'Fail': 0, 'ConfigFail': 0, 'TGenFail': 0, 'Unsupported': 0}
    for t in tests:
        r = t['result']
        if r in counts:
            counts[r] += 1

    total_failures = counts['Fail'] + counts['ConfigFail'] + counts['TGenFail']
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
    
    # Platform/NPU
    prop_npu = ET.SubElement(props, 'property')
    prop_npu.set('name', 'npu')
    prop_npu.set('value', platform.upper())
    
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
        
        if t['result'] in ['Fail', 'ConfigFail', 'TGenFail']:
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
    sshpass_available = subprocess.run(['which', 'sshpass'], capture_output=True).returncode == 0
    
    if password and sshpass_available:
        cmd = ['sshpass', '-p', password] + cmd
    
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True)
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


def curl_import(xml_path, profile, platform, build_id, logs_location, dashboard_url, password=None):
    """Import results to dashboard via SSH + curl POST to /api/import-xml.
    
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
        'npu': platform.upper(),
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


def curl_upload_xml(local_xml_path, profile, platform, build_id, dashboard_url):
    """Upload XML file directly to dashboard via curl POST to /api/upload-xml."""
    upload_url = f"{dashboard_url}{UPLOAD_XML_ENDPOINT}"
    
    # Build curl command with multipart form data
    cmd = [
        'curl', '-s', '-X', 'POST', upload_url,
        '-F', f'file=@{local_xml_path}',
        '-F', f'profile={profile}',
        '-F', f'build_id={build_id}',
        '-F', f'npu={platform.upper()}'
    ]
    
    success, stdout, stderr = run_command(cmd)
    return success, stdout, stderr


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
        if result in ['Fail', 'ConfigFail', 'TGenFail']:
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
    print("Usage: spytest_publish.py <results_dir> --profile PROFILE --platform PLATFORM [options]")
    print("")
    print("Required:")
    print("  results_dir           Path to spytest results directory")
    print("  --profile PROFILE     Profile name")
    print("  --platform PLATFORM   Platform/NPU")
    print("")
    print("Profiles:  202505c-Gamut | gamut_bringup | 202405c_tortuga | 202505c_tortuga")
    print("Platforms: g200 | q200 | p200 | spectrum4")
    print("")
    print("Options:   --dry-run  --xml-only  --skip-upload  --skip-import")
    print("")
    print("Use --help for full documentation.")


def main():
    # Quick check for missing required args before full parsing
    import sys
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] not in ['-h', '--help']):
        print_brief_usage()
        sys.exit(1)
    
    # Check for missing --profile or --platform
    if '--help' not in sys.argv and '-h' not in sys.argv:
        if '--profile' not in sys.argv or '--platform' not in sys.argv:
            print_brief_usage()
            sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description='Process spytest results, generate XML, upload to server, and import to dashboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Required arguments
    parser.add_argument('results_dir', help='Path to spytest results directory')
    
    profile_help = '''Profile name. Available profiles:
  Gamut:    202505c-Gamut, gamut_bringup
  Tortuga:  202405c_tortuga, 202505c_tortuga
  Other:    202511-Community, 202505-OCI, 202505-Community, 202511.2-Titan'''
    parser.add_argument('--profile', required=True, metavar='PROFILE', help=profile_help)
    
    platform_help = f'Platform/NPU. Choices: {", ".join(VALID_PLATFORMS)}'
    parser.add_argument('--platform', required=True, choices=VALID_PLATFORMS, 
                        metavar='PLATFORM', help=platform_help)
    
    # Optional arguments
    parser.add_argument('--build', help='Build ID (auto-detected from dir name if not specified)')
    parser.add_argument('--password', default=SERVER_PASSWORD,
                        help=f'Server password (default: {SERVER_PASSWORD[:3]}...)')
    parser.add_argument('--dashboard-url', default=DASHBOARD_URL,
                        help=f'Dashboard URL (default: {DASHBOARD_URL})')
    
    # Workflow control
    parser.add_argument('--dry-run', action='store_true', 
                        help='Preview all steps without executing')
    parser.add_argument('--xml-only', action='store_true',
                        help='Generate XML file locally, skip upload and import')
    parser.add_argument('--skip-upload', action='store_true',
                        help='Skip uploading logs to server')
    parser.add_argument('--skip-import', action='store_true',
                        help='Skip importing to dashboard')
    parser.add_argument('-o', '--output', help='Output XML file path (for --xml-only)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # ========================================================================
    # Step 0: Validate inputs
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"SPYTEST RESULTS PUBLISHER")
    print(f"{'='*60}")
    
    results_dir = os.path.abspath(args.results_dir)
    if not os.path.isdir(results_dir):
        print(f"Error: {results_dir} is not a directory")
        sys.exit(1)
    
    platform = args.platform.lower()
    if platform not in VALID_PLATFORMS:
        print(f"Warning: Platform '{platform}' not in known list: {VALID_PLATFORMS}")
    
    profile = args.profile
    
    # Extract or use provided build ID
    build_id = args.build or extract_build_id(results_dir)
    if not build_id:
        print("Error: Could not auto-detect build ID. Please specify --build")
        sys.exit(1)
    
    print(f"\nConfiguration:")
    print(f"  Profile:     {profile}")
    print(f"  Platform:    {platform}")
    print(f"  Build:       {build_id}")
    print(f"  Results Dir: {results_dir}")
    
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
    if profile in PROFILES_WITHOUT_PLATFORM_DIR:
        remote_logs_dir = f"{SERVER_BASE_PATH}/{profile}/{build_id}/run_logs_{platform}"
    else:
        remote_logs_dir = f"{SERVER_BASE_PATH}/{profile}/{platform}/{build_id}/run_logs_{platform}"
    remote_xml_path = f"{remote_logs_dir}/tr.xml"
    
    root, counts = generate_xml(
        summary, tests, subtests_pass, subtests_fail,
        profile, platform, build_id, remote_logs_dir
    )
    xml_str = prettify_xml(root)
    
    print(f"  Generated XML with {len(tests)} test cases")
    print(f"  Target XML path: {remote_xml_path}")
    
    # Handle --xml-only mode
    if args.xml_only:
        output_file = args.output or f"results_{profile}_{platform}_{build_id}.xml"
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
    local_xml = f"/tmp/tr_{profile}_{platform}_{build_id}.xml"
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
    else:
        print(f"\n[SKIPPED] Step 3: Upload to server (--skip-upload)")
    
    # ========================================================================
    # Step 4: Import to dashboard
    # ========================================================================
    if not args.skip_import and not args.skip_upload:
        print(f"\n{'='*60}")
        print(f"STEP 4: Importing to dashboard (via SSH)")
        print(f"{'='*60}")
        print(f"  Server:     {SERVER_USER}@{SERVER}")
        print(f"  Dashboard:  localhost:5005 (on server)")
        print(f"  API:        POST {IMPORT_XML_ENDPOINT}")
        print(f"  XML Path:   {remote_xml_path}")
        print(f"  Profile:    {profile}")
        print(f"  Build ID:   {build_id}")
        print(f"  NPU:        {platform.upper()}")
        print(f"  Logs:       {remote_logs_dir}")
        
        if args.dry_run:
            print(f"\n  [DRY RUN] Would SSH to {SERVER} and POST to localhost:5005{IMPORT_XML_ENDPOINT}")
            print(f"  [DRY RUN] Payload:")
            print(f"    {{")
            print(f'      "xml_path": "{remote_xml_path}",')
            print(f'      "profile": "{profile}",')
            print(f'      "build_id": "{build_id}",')
            print(f'      "npu": "{platform.upper()}",')
            print(f'      "test_logs_location": "{remote_logs_dir}"')
            print(f"    }}")
        else:
            print(f"\n  Sending import request via SSH...")
            success, stdout, stderr = curl_import(
                remote_xml_path, profile, platform, build_id, remote_logs_dir,
                args.dashboard_url, password
            )
            
            if success and stdout:
                try:
                    resp = json.loads(stdout)
                    if resp.get('success'):
                        print(f"  Success! Result ID: {resp.get('result_id')}")
                        print(f"  Message: {resp.get('message')}")
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
    elif args.skip_import and not args.skip_upload:
        # Logs uploaded but import skipped - offer direct upload option
        print(f"\n[SKIPPED] Step 4: Import to dashboard (--skip-import)")
        print(f"\n  To import later, use:")
        print(f"  curl -X POST {args.dashboard_url}{IMPORT_XML_ENDPOINT} \\")
        print(f'    -H "Content-Type: application/json" \\')
        print(f"    -d '{{\"xml_path\": \"{remote_xml_path}\", \"profile\": \"{profile}\", \"build_id\": \"{build_id}\", \"npu\": \"{platform.upper()}\"}}'")
    else:
        print(f"\n[SKIPPED] Step 4: Import to dashboard")
    
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
    print(f"    -d '{{\"xml_path\": \"{remote_xml_path}\", \"profile\": \"{profile}\", \"build_id\": \"{build_id}\", \"npu\": \"{platform.upper()}\"}}'")
    print(f"\nOr use the web UI:")
    print(f"  {args.dashboard_url}")


if __name__ == '__main__':
    main()
