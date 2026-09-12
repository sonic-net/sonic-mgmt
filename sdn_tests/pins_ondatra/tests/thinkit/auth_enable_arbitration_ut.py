#!/usr/bin/env python3

"""
===============================================================================
Script Name : auth_enable_arbitration_ut.py
Target      : //tests/thinkit:arbitration_test
Description : Automated test runner for Thinkit Arbitration test matrix with user_auth
              set to "password" in the SUT. This is the case when translib_write is
              enabled at the SUT.

              Validates auth_enable flags and authentication scenarios across both
              positive and negative test cases.

Sample gNMI config_db section in SUT :

    "GNMI": {
        "gnmi": {
            "port": "9339",
            "client_auth": "false",
            "user_auth": "password",
            "save_on_set": "true"
        },
        "certs": {
            "ca_crt": "",
            "server_crt": "",
            "server_key": ""
        }
    },


Test Matrix:
  Test 1: Default configuration (Expect: PASS)
  Test 2: Default + wrong password (Expect: FAIL)
  Test 3: auth_enable=false (Expect: FAIL)
  Test 4: auth_enable=true + wrong password (Expect: FAIL)
  Test 5: auth_enable=true + no password (Expect: PASS)
  Test 6: auth_enable=true + valid credentials (Expect: PASS)

Usage:
  python3 auth_enable_arbitration_ut.py.py
  OR
  chmod +x auth_enable_arbitration_ut.py.py
  ./auth_enable_arbitration_ut.py.py

Output:
  - Real-time Bazel test execution logs streamed to stdout.
  - Recap of all exact Bazel test commands executed.
  - Test execution summary comparing actual Bazel results against expectations.
===============================================================================
"""

import subprocess
import sys

TARGET = "//tests/thinkit:arbitration_test"

BASE_CMD = [
    "bazel", "test", TARGET,
    "--define=absl=1",
    "--test_strategy=standalone",
    "--test_output=streamed",
    "--test_arg=--stderrthreshold=0",
    "--test_arg=--logtostderr=true",
    "--test_arg=--v=2",
    "--test_arg=--gnmi_deviceid_support=false",
    "--test_arg=--gnmi_push_support=false",
    "--test_arg=--gnmi_boottime_support=false",
    "--test_arg=--gnmi_state_and_config_support=false",
    '--test_arg=--pins_p4info_file=/data/sonic-pins/sai_p4/instantiations/google/middleblock.p4info.pb.txt',
]

TEST_CASES = [
    {
        "id": 1,
        "name": "default",
        "env_flags": [],
        "expected": "PASSED"
    },
    {
        "id": 2,
        "name": "default + wrong password (negative test)",
        "env_flags": [
            "--test_env=gnmi_username=somename",
            "--test_env=gnmi_password=somepassword",
        ],
        "expected": "FAILED"
    },
    {
        "id": 3,
        "name": "auth_enable=false (negative test)",
        "env_flags": [
            "--test_env=auth_enable=false",
        ],
        "expected": "FAILED"
    },
    {
        "id": 4,
        "name": "auth_enable=true + wrong password (negative test)",
        "env_flags": [
            "--test_env=auth_enable=true",
            "--test_env=gnmi_username=somename",
            "--test_env=gnmi_password=somepassword",
        ],
        "expected": "FAILED"
    },
    {
        "id": 5,
        "name": "auth_enable=true + no password",
        "env_flags": [
            "--test_env=auth_enable=true",
        ],
        "expected": "PASSED"
    },
    {
        "id": 6,
        "name": "auth_enable=true + valid user and password",
        "env_flags": [
            "--test_env=auth_enable=true",
            "--test_env=gnmi_username=admin",
            "--test_env=gnmi_password=YourPaSsWoRd",
        ],
        "expected": "PASSED"
    },
]

def run_test(test_info):
    """Executes a single Bazel test command and determines actual Bazel outcome."""
    cmd = BASE_CMD + test_info["env_flags"]
    
    print("\n" + "=" * 80)
    print(f"RUNNING TEST {test_info['id']}: {test_info['name']}")
    print("Command:", " ".join(cmd))
    print("=" * 80 + "\n")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    full_log = []
    # Stream Bazel output live to terminal
    for line in process.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        full_log.append(line)

    process.wait()
    output_text = "".join(full_log)

    # Determine raw Bazel outcome
    if process.returncode != 0:
        actual_status = "FAILED"
    elif f"{TARGET} FAILED" in output_text or "test FAILED" in output_text or "FAILED in" in output_text:
        actual_status = "FAILED"
    else:
        actual_status = "PASSED"

    return actual_status

def main():
    results = []

    for test in TEST_CASES:
        actual = run_test(test)
        expected = test["expected"]
        
        # Test scenario passes if actual Bazel result matches expected result
        scenario_passed = (actual == expected)
        
        results.append({
            "id": test["id"],
            "name": test["name"],
            "actual": actual,
            "expected": expected,
            "scenario_passed": scenario_passed,
            "cmd_str": " ".join(BASE_CMD + test["env_flags"])
        })

    # Print List of Commands Executed
    print("\n" + "=" * 80)
    for r in results:
        print(f"TEST {r['id']}: {r['name']}")
        print(f"Command: {r['cmd_str']}\n")

    # Summary Output
    print("=" * 80)
    print("                      TEST EXECUTION SUMMARY                       ")
    print("=" * 80)

    total_passed = sum(1 for r in results if r["scenario_passed"])
    total_failed = sum(1 for r in results if not r["scenario_passed"])

    for r in results:
        status_str = "[PASS]" if r["scenario_passed"] else "[FAIL]"
        details = f"(Bazel returned: {r['actual']}, Expected: {r['expected']})"
        print(f"Test {r['id']}: {r['name']:<62} -> {status_str} {details}")

    print("-" * 80)
    print(f"Total Test Scenarios Executed : {len(results)}")
    print(f"Scenarios PASSED (Met Expectation)   : {total_passed}")
    print(f"Scenarios FAILED (Failed Expectation): {total_failed}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
