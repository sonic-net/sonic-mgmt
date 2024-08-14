from __future__ import print_function, division

import argparse
import ast
import json
import os
import sys
import subprocess
import copy
import time
from datetime import datetime, timedelta

import requests
import yaml
from enum import Enum

__metaclass__ = type
BUILDIMAGE_REPO_FLAG = "buildimage"
MGMT_REPO_FLAG = "sonic-mgmt"
INTERNAL_REPO_LIST = ["Networking-acs-buildimage", "sonic-mgmt-int"]
GITHUB_SONIC_MGMT_REPO = "https://github.com/sonic-net/sonic-mgmt"
INTERNAL_SONIC_MGMT_REPO = "https://dev.azure.com/mssonic/internal/_git/sonic-mgmt-int"
PR_TEST_SCRIPTS_FILE = "pr_test_scripts.yaml"
SPECIFIC_PARAM_KEYWORD = "specific_param"
TOLERATE_HTTP_EXCEPTION_TIMES = 20
TOKEN_EXPIRE_HOURS = 1
MAX_GET_TOKEN_RETRY_TIMES = 3


class PollTimeoutException(Exception):
    pass


class TestPlanStatus(Enum):
    INIT = 10
    LOCK_TESTBED = 20
    PREPARE_TESTBED = 30
    EXECUTING = 40
    KVMDUMP = 50
    FAILED = 60
    CANCELLED = 70
    FINISHED = 80


def get_test_scripts(test_set):
    _self_path = os.path.abspath(__file__)
    pr_test_scripts_file = os.path.join(os.path.dirname(_self_path), PR_TEST_SCRIPTS_FILE)
    with open(pr_test_scripts_file) as f:
        pr_test_scripts = yaml.safe_load(f)

        test_script_list = pr_test_scripts.get(test_set, [])
        specific_param_list = pr_test_scripts.get(SPECIFIC_PARAM_KEYWORD, {}).get(test_set, [])
        return test_script_list, specific_param_list


def test_plan_status_factory(status):
    if status == "INIT":
        return InitStatus()
    elif status == "LOCK_TESTBED":
        return LockStatus()
    elif status == "PREPARE_TESTBED":
        return PrePareStatus()
    elif status == "EXECUTING":
        return ExecutingStatus()
    elif status == "KVMDUMP":
        return KvmDumpStatus()
    elif status == "FAILED":
        return FailedStatus()
    elif status == "CANCELLED":
        return CancelledStatus()
    elif status == "FINISHED":
        return FinishStatus()

    raise Exception("The status is not correct.")


class AbstractStatus():
    def __init__(self, status):
        self.status = status

    def get_status(self):
        return self.status.value

    def print_logs(self, test_plan_id, resp_data, start_time):
        status = resp_data.get("status", None)
        current_status = test_plan_status_factory(status).get_status()

        if current_status == self.get_status():
            print("Test plan id: {}, status: {},  elapsed: {:.0f} seconds"
                  .format(test_plan_id, resp_data.get("status", None), time.time() - start_time))


class InitStatus(AbstractStatus):
    def __init__(self):
        super(InitStatus, self).__init__(TestPlanStatus.INIT)


class LockStatus(AbstractStatus):
    def __init__(self):
        super(LockStatus, self).__init__(TestPlanStatus.LOCK_TESTBED)


class PrePareStatus(AbstractStatus):
    def __init__(self):
        super(PrePareStatus, self).__init__(TestPlanStatus.PREPARE_TESTBED)


class ExecutingStatus(AbstractStatus):
    def __init__(self):
        super(ExecutingStatus, self).__init__(TestPlanStatus.EXECUTING)

    def print_logs(self, test_plan_id, resp_data, start_time):
        print("Test plan id: {}, status: {}, progress: {}%, elapsed: {:.0f} seconds"
              .format(test_plan_id, resp_data.get("status", None),
                      resp_data.get("progress", 0) * 100, time.time() - start_time))


class KvmDumpStatus(AbstractStatus):
    def __init__(self):
        super(KvmDumpStatus, self).__init__(TestPlanStatus.KVMDUMP)


class FailedStatus(AbstractStatus):
    def __init__(self):
        super(FailedStatus, self).__init__(TestPlanStatus.FAILED)


class CancelledStatus(AbstractStatus):
    def __init__(self):
        super(CancelledStatus, self).__init__(TestPlanStatus.CANCELLED)


class FinishStatus(AbstractStatus):
    def __init__(self):
        super(FinishStatus, self).__init__(TestPlanStatus.FINISHED)


def parse_list_from_str(s):
    # Since Azure Pipeline doesn't support to receive an empty parameter,
    # We use ' ' as a magic code for empty parameter.
    # So we should consider ' ' as en empty input.
    if isinstance(s, str):
        s = s.strip()
    if not s:
        return None
    return [single_str.strip()
            for single_str in s.split(',')
            if single_str.strip()]


class TestPlanManager(object):

    def __init__(self, url, frontend_url, client_id=None):
        self.url = url
        self.frontend_url = frontend_url
        self.client_id = client_id
        self.with_auth = False
        self._token = None
        self._token_expires_on = None
        if self.client_id:
            self.with_auth = True
            self.get_token()

    def cmd(self, cmds):
        process = subprocess.Popen(
            cmds,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        return_code = process.returncode

        return stdout, stderr, return_code

    def az_run(self, cmd):
        stdout, stderr, retcode = self.cmd(cmd.split())
        if retcode != 0:
            raise Exception(f'Command {cmd} execution failed, rc={retcode}, error={stderr}')
        return stdout, stderr, retcode

    def get_token(self):

        token_is_valid = \
            self._token_expires_on is not None and \
            (self._token_expires_on - datetime.now()) > timedelta(hours=TOKEN_EXPIRE_HOURS)

        if self._token is not None and token_is_valid:
            return self._token

        cmd = 'az account get-access-token --resource {}'.format(self.client_id)
        attempt = 0
        while (attempt < MAX_GET_TOKEN_RETRY_TIMES):
            try:
                stdout, _, _ = self.az_run(cmd)

                token = json.loads(stdout.decode("utf-8"))
                self._token = token.get("accessToken", None)
                if not self._token:
                    raise Exception("Parse token from stdout failed")

                # Parse token expires time from string
                token_expires_on = token.get("expiresOn", "")
                self._token_expires_on = datetime.strptime(token_expires_on, "%Y-%m-%d %H:%M:%S.%f")
                print("Get token successfully.")
                return self._token

            except Exception as exception:
                attempt += 1
                print("Failed to get token with exception: {}".format(repr(exception)))

        raise Exception("Failed to get token after {} attempts".format(MAX_GET_TOKEN_RETRY_TIMES))

    def create(self, topology, test_plan_name="my_test_plan", deploy_mg_extra_params="", kvm_build_id="",
               min_worker=None, max_worker=None, pr_id="unknown", output=None,
               common_extra_params="", **kwargs):
        tp_url = "{}/test_plan".format(self.url)
        testbed_name = parse_list_from_str(kwargs.get("testbed_name", None))
        image_url = kwargs.get("image_url", None)
        hwsku = kwargs.get("hwsku", None)
        test_plan_type = kwargs.get("test_plan_type", "PR")
        platform = kwargs.get("platform", "kvm")
        scripts = parse_list_from_str(kwargs.get("scripts", None))
        features = parse_list_from_str(kwargs.get("features", None))
        scripts_exclude = parse_list_from_str(kwargs.get("scripts_exclude", None))
        features_exclude = parse_list_from_str(kwargs.get("features_exclude", None))

        print("Creating test plan, topology: {}, name: {}, build info:{} {} {}".format(topology, test_plan_name,
                                                                                       repo_name, pr_id, build_id))
        print("Test scripts to be covered in this test plan:")
        print(json.dumps(scripts, indent=4))

        common_extra_params = common_extra_params + " --completeness_level=confident --allow_recover"

        # Add topo and device type args for PR test
        if test_plan_type == "PR":
            # Add topo arg
            if topology in ["t0", "t0-64-32"]:
                common_extra_params = common_extra_params + " --topology=t0,any"
            elif topology in ["t1-lag", "t1-8-lag"]:
                common_extra_params = common_extra_params + " --topology=t1,any"
            elif topology == "dualtor":
                common_extra_params = common_extra_params + " --topology=t0,dualtor,any"
            elif topology == "dpu":
                common_extra_params = common_extra_params + " --topology=dpu,any"

            # Add device type arg
            common_extra_params = common_extra_params + " --device_type=vs"

        # If triggered by the internal repos, use internal sonic-mgmt repo as the code base
        sonic_mgmt_repo_url = GITHUB_SONIC_MGMT_REPO
        if kwargs.get("source_repo") in INTERNAL_REPO_LIST:
            sonic_mgmt_repo_url = INTERNAL_SONIC_MGMT_REPO

        # If triggered by mgmt repo, use pull request id as the code base
        sonic_mgmt_pull_request_id = ""
        if MGMT_REPO_FLAG in kwargs.get("source_repo"):
            sonic_mgmt_pull_request_id = pr_id

        # If triggered by buildimage repo, use image built from the buildId
        kvm_image_build_id = kvm_build_id
        kvm_image_branch = kwargs.get("kvm_image_branch", "")
        if BUILDIMAGE_REPO_FLAG in kwargs.get("source_repo"):
            kvm_image_build_id = build_id
            kvm_image_branch = ""
        affinity = json.loads(kwargs.get("affinity", "[]"))
        payload = {
            "name": test_plan_name,
            "testbed": {
                "platform": platform,
                "name": testbed_name,
                "topology": topology,
                "hwsku": hwsku,
                "min": min_worker,
                "max": max_worker,
                "nbr_type": kwargs["vm_type"],
                "asic_num": kwargs["num_asic"],
                "lock_wait_timeout_seconds": kwargs.get("lock_wait_timeout_seconds", None),
            },
            "test_option": {
                "stop_on_failure": kwargs.get("stop_on_failure", True),
                "retry_times": kwargs.get("retry_times", 2),
                "test_cases": {
                    "features": features,
                    "scripts": scripts,
                    "features_exclude": features_exclude,
                    "scripts_exclude": scripts_exclude
                },
                "image": {
                    "url": image_url,
                    "upgrade_image_param": kwargs.get("upgrade_image_param", None),
                    "release": "",
                    "kvm_image_build_id": kvm_image_build_id,
                    "kvm_image_branch": kvm_image_branch
                },
                "sonic_mgmt": {
                    "repo_url": sonic_mgmt_repo_url,
                    "branch": kwargs["mgmt_branch"],
                    "pull_request_id": sonic_mgmt_pull_request_id
                },
                "common_param": common_extra_params,
                "specific_param": kwargs.get("specific_param", []),
                "affinity": affinity,
                "deploy_mg_param": deploy_mg_extra_params,
                "max_execute_seconds": kwargs.get("max_execute_seconds", None),
                "dump_kvm_if_fail": kwargs.get("dump_kvm_if_fail", False),
            },
            "type": test_plan_type,
            "trigger": {
                "requester": kwargs.get("requester", "Pull Request"),
                "source_repo": kwargs.get("source_repo"),
                "pull_request_id": pr_id,
                "build_id": build_id
            },
            "extra_params": {},
            "priority": 10
        }
        print('Creating test plan with payload:\n{}'.format(json.dumps(payload, indent=4)))
        headers = {
            "Authorization": "Bearer {}".format(self.get_token()),
            "scheduler-site": "PRTest",
            "Content-Type": "application/json"
        }
        raw_resp = {}
        try:
            raw_resp = requests.post(tp_url, headers=headers, data=json.dumps(payload), timeout=10)
            resp = raw_resp.json()
        except Exception as exception:
            raise Exception("HTTP execute failure, url: {}, raw_resp: {}, exception: {}"
                            .format(tp_url, str(raw_resp), str(exception)))
        if not resp["data"]:
            raise Exception("Pre deploy action failed with error: {}".format(resp["errmsg"]))
        if not resp["success"]:
            raise Exception("Create test plan failed with error: {}".format(resp["errmsg"]))

        print("Result of creating test plan: {}".format(str(resp["data"])))

        if output:
            print("Store new test plan id to file {}".format(output))
            with open(output, "a") as f:
                f.write(str(resp["data"]) + "\n")

        return resp["data"]

    def cancel(self, test_plan_id):

        tp_url = "{}/test_plan/{}".format(self.url, test_plan_id)
        cancel_url = "{}/cancel".format(tp_url)

        print("Cancelling test plan at {}".format(cancel_url))

        payload = json.dumps({})
        headers = {
            "Authorization": "Bearer {}".format(self.get_token()),
            "scheduler-site": "PRTest",
            "Content-Type": "application/json"
        }

        raw_resp = {}
        try:
            raw_resp = requests.post(cancel_url, headers=headers, data=payload, timeout=10)
            resp = raw_resp.json()
        except Exception as exception:
            raise Exception("HTTP execute failure, url: {}, raw_resp: {}, exception: {}"
                            .format(cancel_url, str(raw_resp), str(exception)))
        if not resp["success"]:
            raise Exception("Cancel test plan failed with error: {}".format(resp["errmsg"]))

        print("Result of cancelling test plan at {}:".format(tp_url))
        print(str(resp["data"]))

    def poll(self, test_plan_id, interval=60, timeout=-1, expected_state="", expected_result=None):
        print("Polling progress and status of test plan at {}/scheduler/testplan/{}"
              .format(self.frontend_url, test_plan_id))
        print("Polling interval: {} seconds".format(interval))

        poll_url = "{}/test_plan/{}".format(self.url, test_plan_id)
        headers = {
            "Content-Type": "application/json"
        }
        start_time = time.time()
        http_exception_times = 0
        while (timeout < 0 or (time.time() - start_time) < timeout):
            try:
                if self.with_auth:
                    headers["Authorization"] = "Bearer {}".format(self.get_token())
                resp = requests.get(poll_url, headers=headers, timeout=10).json()
            except Exception as exception:
                print("HTTP execute failure, url: {}, raw_resp: {}, exception: {}".format(poll_url, resp,
                                                                                          str(exception)))
                http_exception_times = http_exception_times + 1
                if http_exception_times >= TOLERATE_HTTP_EXCEPTION_TIMES:
                    raise Exception("HTTP execute failure, url: {}, raw_resp: {}, exception: {}"
                                    .format(poll_url, resp, str(exception)))
                else:
                    time.sleep(interval)
                    continue
            if not resp["success"]:
                raise Exception("Query test plan at {} failed with error: {}".format(poll_url, resp["errmsg"]))

            resp_data = resp.get("data", None)
            if not resp_data:
                raise Exception("No valid data in response: {}".format(str(resp)))

            status = resp_data.get("status", None)
            result = resp_data.get("result", None)

            if expected_state:
                current_status = test_plan_status_factory(status)
                expected_status = test_plan_status_factory(expected_state)

                if expected_status.get_status() == current_status.get_status():
                    current_status.print_logs(test_plan_id, resp_data, start_time)
                elif expected_status.get_status() < current_status.get_status():
                    steps = None
                    step_status = None
                    runtime = resp_data.get("runtime", None)
                    if runtime:
                        steps = runtime.get("steps", None)
                    if steps:
                        for step in steps:
                            if step.get("step") == expected_state:
                                step_status = step.get("status")
                                break
                    # We fail the step only if the step_status is "FAILED".
                    # Other status such as "SKIPPED", "CANCELED" are considered successful.
                    if step_status == "FAILED":
                        raise Exception("Test plan id: {}, status: {}, result: {}, Elapsed {:.0f} seconds. "
                                        "Check {}/scheduler/testplan/{} for test plan status"
                                        .format(test_plan_id, step_status, result, time.time() - start_time,
                                                self.frontend_url,
                                                test_plan_id))
                    if expected_result:
                        if result != expected_result:
                            raise Exception("Test plan id: {}, status: {}, result: {} not match expected result: {}, "
                                            "Elapsed {:.0f} seconds. "
                                            "Check {}/scheduler/testplan/{} for test plan status"
                                            .format(test_plan_id, step_status, result,
                                                    expected_result, time.time() - start_time,
                                                    self.frontend_url,
                                                    test_plan_id))

                    print("Current status is {}".format(step_status))
                    return
                else:
                    print("Current state is {}, waiting for the state {}".format(status, expected_state))

                time.sleep(interval)

        else:
            raise PollTimeoutException(
                "Max polling time reached, test plan at {} is not successfully finished or cancelled".format(poll_url)
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for managing test plan.")

    subparsers = parser.add_subparsers(
        title="action",
        help="Action to perform on test plan",
        dest="action"
    )

    parser_create = subparsers.add_parser("create", help="Create new test plan.")
    parser_create.add_argument(
        "-t", "--topology",
        type=str,
        dest="topology",
        nargs="?",
        const="",
        default="",
        required=False,
        help="The test topology to be used."
    )
    parser_create.add_argument(
        "-o", "--output",
        type=str,
        dest="output",
        required=False,
        help="Output id of created test plan to the specified file."
    )
    parser_create.add_argument(
        "--min-worker",
        type=int,
        dest="min_worker",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Min worker number for the test plan."
    )
    parser_create.add_argument(
        "--max-worker",
        type=int,
        dest="max_worker",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Max worker number for the test plan."
    )
    parser_create.add_argument(
        "--lock-wait-timeout-seconds",
        type=int,
        dest="lock_wait_timeout_seconds",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Max lock testbed wait seconds. None or the values <= 0 means endless."
    )
    parser_create.add_argument(
        "--test-set",
        type=str,
        dest="test_set",
        nargs='?',
        const='',
        default="",
        required=False,
        help="Test set."
    )
    parser_create.add_argument(
        "--deploy-mg-extra-params",
        type=str,
        nargs='?',
        const='',
        dest="deploy_mg_extra_params",
        default="",
        required=False,
        help="Deploy minigraph extra params"
    )
    parser_create.add_argument(
        "--kvm-image-branch",
        type=str,
        dest="kvm_image_branch",
        nargs='?',
        const="",
        default="",
        required=False,
        help="KVM build branch."
    )
    parser_create.add_argument(
        "--kvm-build-id",
        type=str,
        nargs='?',
        const='',
        dest="kvm_build_id",
        default="",
        required=False,
        help="KVM build id."
    )
    parser_create.add_argument(
        "--mgmt-branch",
        type=str,
        dest="mgmt_branch",
        nargs='?',
        const="master",
        default="master",
        required=False,
        help="Branch of sonic-mgmt repo to run the test"
    )
    parser_create.add_argument(
        "--vm-type",
        type=str,
        dest="vm_type",
        default="ceos",
        required=False,
        help="VM type of neighbors"
    )
    parser_create.add_argument(
        "--specified-params",
        type=str,
        dest="specified_params",
        default="{}",
        required=False,
        help="Test module specified params"
    )
    parser_create.add_argument(
        "--common-extra-params",
        type=str,
        dest="common_extra_params",
        nargs='?',
        const="",
        default="",
        required=False,
        help="Run test common extra params"
    )
    parser_create.add_argument(
        "--num-asic",
        type=int,
        dest="num_asic",
        default=1,
        required=False,
        help="The asic number of dut"
    )
    parser_create.add_argument(
        "--build-reason",
        type=str,
        dest="build_reason",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Build reason"
    )
    parser_create.add_argument(
        "--repo-name",
        type=str,
        dest="repo_name",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Repository name"
    )
    parser_create.add_argument(
        "--testbed-name",
        type=str,
        dest="testbed_name",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Testbed name, Split by ',', like: 'testbed1, testbed2'"
    )
    parser_create.add_argument(
        "--image_url",
        type=str,
        dest="image_url",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Image url"
    )
    parser_create.add_argument(
        "--upgrade-image-param",
        type=str,
        dest="upgrade_image_param",
        nargs="?",
        const="",
        default="",
        required=False,
        help="Parameter of upgrade image"
    )
    parser_create.add_argument(
        "--hwsku",
        type=str,
        dest="hwsku",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Hardware SKU."
    )
    parser_create.add_argument(
        "--test-plan-type",
        type=str,
        dest="test_plan_type",
        nargs='?',
        const='PR',
        default="PR",
        required=False,
        choices=['PR', 'NIGHTLY'],
        help="Test plan type. Optional: ['PR', 'NIGHTLY']"
    )
    parser_create.add_argument(
        "--platform",
        type=str,
        dest="platform",
        nargs='?',
        const='kvm',
        default="kvm",
        required=False,
        help="Testbed platform."
    )
    parser_create.add_argument(
        "--features",
        type=str,
        dest="features",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Test features, Split by ',', like: 'bgp, lldp'"
    )
    parser_create.add_argument(
        "--scripts",
        type=str,
        dest="scripts",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Test scripts, Split by ',', like: 'bgp/test_bgp_fact.py, test_feature.py'"
    )
    parser_create.add_argument(
        "--scripts-exclude",
        type=str,
        dest="scripts_exclude",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Exclude test scripts, Split by ',', like: 'bgp/test_bgp_fact.py, test_feature.py'"
    )
    parser_create.add_argument(
        "--features-exclude",
        type=str,
        dest="features_exclude",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Exclude test features, Split by ',', like: 'bgp, lldp'"
    )
    parser_create.add_argument(
        "--specific-param",
        type=str,
        dest="specific_param",
        nargs='?',
        const="[]",
        default="[]",
        required=False,
        help='Specific param, like: '
             '[{"name": "macsec", "param": "--enable_macsec --macsec_profile=128_SCI,256_XPN_SCI"}]'
    )
    parser_create.add_argument(
        "--affinity",
        type=str,
        dest="affinity",
        nargs='?',
        const="[]",
        default="[]",
        required=False,
        help='Test module affinity, like: '
             '[{"name": "bgp/test_bgp_fact.py", "op": "NOT_ON", "value": ["vms-kvm-t0"]}]'
    )
    parser_create.add_argument(
        "--stop-on-failure",
        type=ast.literal_eval,
        dest="stop_on_failure",
        nargs='?',
        const='True',
        default='True',
        required=False,
        choices=[True, False],
        help="Stop whole test plan if test failed."
    )
    parser_create.add_argument(
        "--retry-times",
        type=int,
        dest="retry_times",
        nargs='?',
        const=2,
        default=2,
        required=False,
        help="Retry times after tests failed."
    )
    parser_create.add_argument(
        "--dump-kvm-if-fail",
        type=ast.literal_eval,
        dest="dump_kvm_if_fail",
        nargs='?',
        const='True',
        default='True',
        required=False,
        choices=[True, False],
        help="Dump KVM DUT if test plan failed, only supports KVM test plan."
    )
    parser_create.add_argument(
        "--requester",
        type=str,
        dest="requester",
        nargs='?',
        const='Pull Request',
        default="Pull Request",
        required=False,
        help="Requester of the test plan."
    )
    parser_create.add_argument(
        "--max-execute-seconds",
        type=int,
        dest="max_execute_seconds",
        nargs='?',
        const=None,
        default=None,
        required=False,
        help="Max execute seconds of the test plan."
    )
    parser_create.add_argument(
        "--test-plan-num",
        type=int,
        dest="test_plan_num",
        nargs="?",
        const=1,
        default=1,
        required=False,
        help="Test plan num to be created."
    )

    parser_poll = subparsers.add_parser("poll", help="Poll test plan status.")
    parser_cancel = subparsers.add_parser("cancel", help="Cancel running test plan.")

    for p in [parser_cancel, parser_poll]:
        p.add_argument(
            "-i", "--test-plan-id",
            type=str,
            dest="test_plan_id",
            required=True,
            help="Test plan id."
        )

    parser_poll.add_argument(
        "--expected-state",
        type=str,
        dest="expected_state",
        required=False,
        help="Expected state.",
        default=""
    )
    parser_poll.add_argument(
        "--expected-result",
        type=str,
        dest="expected_result",
        nargs='?',
        const=None,
        default=None,
        required=False,
        choices=['PENDING', 'EXECUTING', 'SUCCESS', 'FAILED', 'CANCELLED'],
        help="If specify expected result, check test plan result after expected state matched."
    )
    parser_poll.add_argument(
        "--interval",
        type=int,
        required=False,
        default=60,
        dest="interval",
        help="Polling interval. Default 60 seconds."
    )
    parser_poll.add_argument(
        "--timeout",
        type=int,
        required=False,
        default=-1,
        dest="timeout",
        help="Max polling time in seconds. Default -1, no timeout."
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if "test_plan_id" in args:
        # vso may add unexpected "'" as trailing symbol
        # https://github.com/microsoft/azure-pipelines-tasks/issues/10331
        args.test_plan_id = args.test_plan_id.replace("'", "")

    print("Test plan utils parameters: {}".format(args))
    auth_env = ["CLIENT_ID"]
    required_env = ["ELASTICTEST_SCHEDULER_BACKEND_URL"]

    if args.action in ["create", "cancel"]:
        required_env.extend(auth_env)

    env = {
        "elastictest_scheduler_backend_url": os.environ.get("ELASTICTEST_SCHEDULER_BACKEND_URL"),
        "client_id": os.environ.get("ELASTICTEST_MSAL_CLIENT_ID"),
        "frontend_url": os.environ.get("ELASTICTEST_FRONTEND_URL", "https://elastictest.org"),
    }
    env_missing = [k.upper() for k, v in env.items() if k.upper() in required_env and not v]
    if env_missing:
        print("Missing required environment variables: {}".format(env_missing))
        sys.exit(1)

    try:
        tp = TestPlanManager(
            env["elastictest_scheduler_backend_url"],
            env["frontend_url"],
            env["client_id"])

        if args.action == "create":
            pr_id = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER") or os.environ.get(
                "SYSTEM_PULLREQUEST_PULLREQUESTID")
            repo = os.environ.get("BUILD_REPOSITORY_PROVIDER")
            reason = args.build_reason if args.build_reason else os.environ.get("BUILD_REASON")
            build_id = os.environ.get("BUILD_BUILDID")
            job_name = os.environ.get("SYSTEM_JOBDISPLAYNAME")
            repo_name = args.repo_name if args.repo_name else os.environ.get("BUILD_REPOSITORY_NAME")

            test_plan_prefix = "{repo}_{reason}_PR_{pr_id}_BUILD_{build_id}_JOB_{job_name}" \
                .format(
                    repo=repo,
                    reason=reason,
                    pr_id=pr_id,
                    build_id=build_id,
                    job_name=job_name
                ).replace(' ', '_')

            scripts = args.scripts
            specific_param = json.loads(args.specific_param)
            # For PR test, if specify test modules and specific_param explicitly, use them to run PR test.
            # Otherwise, get test modules from pr_test_scripts.yaml.
            explicitly_specify_test_module = args.features or args.scripts
            if args.test_plan_type == "PR":
                args.test_set = args.test_set if args.test_set else args.topology
                parsed_script, parsed_specific_param = get_test_scripts(args.test_set)
                if not explicitly_specify_test_module:
                    scripts = ",".join(parsed_script)
                if not specific_param:
                    specific_param = parsed_specific_param

            for num in range(args.test_plan_num):
                test_plan_name = copy.copy(test_plan_prefix)
                if args.test_plan_num > 1:
                    test_plan_name = "{}_{}".format(test_plan_name, num + 1)

                tp.create(
                    args.topology,
                    test_plan_name=test_plan_name,
                    deploy_mg_extra_params=args.deploy_mg_extra_params,
                    kvm_build_id=args.kvm_build_id,
                    kvm_image_branch=args.kvm_image_branch,
                    min_worker=args.min_worker,
                    max_worker=args.max_worker,
                    pr_id=pr_id,
                    scripts=scripts,
                    features=args.features,
                    scripts_exclude=args.scripts_exclude,
                    features_exclude=args.features_exclude,
                    output=args.output,
                    source_repo=repo_name,
                    mgmt_branch=args.mgmt_branch,
                    common_extra_params=args.common_extra_params,
                    num_asic=args.num_asic,
                    specified_params=args.specified_params,
                    specific_param=specific_param,
                    affinity=args.affinity,
                    vm_type=args.vm_type,
                    testbed_name=args.testbed_name,
                    image_url=args.image_url,
                    upgrade_image_param=args.upgrade_image_param,
                    hwsku=args.hwsku,
                    test_plan_type=args.test_plan_type,
                    platform=args.platform,
                    stop_on_failure=args.stop_on_failure,
                    retry_times=args.retry_times,
                    dump_kvm_if_fail=args.dump_kvm_if_fail,
                    requester=args.requester,
                    max_execute_seconds=args.max_execute_seconds,
                    lock_wait_timeout_seconds=args.lock_wait_timeout_seconds,
                )
        elif args.action == "poll":
            tp.poll(args.test_plan_id, args.interval, args.timeout, args.expected_state, args.expected_result)
        elif args.action == "cancel":
            tp.cancel(args.test_plan_id)
        sys.exit(0)
    except PollTimeoutException as e:
        print("Polling test plan failed with exception: {}".format(repr(e)))
        sys.exit(2)
    except Exception as e:
        print("Operation failed with exception: {}".format(repr(e)))
        sys.exit(3)
