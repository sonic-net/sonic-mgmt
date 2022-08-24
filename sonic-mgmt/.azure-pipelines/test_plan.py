from __future__ import print_function, division

import argparse
import json
import os
import sys
import time

import requests
import yaml

PR_TEST_SCRIPTS_FILE = "pr_test_scripts.yaml"
TOLERATE_HTTP_EXCEPTION_TIMES = 20


def get_test_scripts(topology):
    _self_path = os.path.abspath(__file__)
    pr_test_scripts_file = os.path.join(os.path.dirname(_self_path), PR_TEST_SCRIPTS_FILE)
    with open(pr_test_scripts_file) as f:
        pr_test_scripts = yaml.safe_load(f)
        return pr_test_scripts.get(topology, [])


class TestPlanManager(object):

    def __init__(self, url, tenant_id=None, client_id=None, client_secret=None):
        self.url = url
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        if self.tenant_id and self.client_id and self.client_secret:
            self._get_token()

    def _get_token(self):
        token_url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(self.tenant_id)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "api://sonic-testbed-tools-prod/.default"
        }
        try:
            resp = requests.post(token_url, headers=headers, data=payload, timeout=10).json()
            self.token = resp["access_token"]
        except Exception as e:
            raise Exception("Get token failed with exception: {}".format(repr(e)))

    def create(self, topology, name="my_test_plan", pr_id="unknown", scripts=[], output=None):
        tp_url = "{}/test_plan".format(self.url)
        print("Creating test plan, topology: {}, name: {}, pr_id: {}".format(topology, name, pr_id))
        print("Test scripts to be covered in this test plan:")
        print(json.dumps(scripts, indent=4))

        payload = json.dumps({
            "name": name,
            "testbed": {
                "platform": "kvm",
                "topology": topology,
                "min": 1,
                "max": 2
            },
            "test_option": {
                "stop_on_failure": True,
                "retry_times": 2,
                "test_cases": {
                    "features": [],
                    "scripts": scripts,
                    "features_exclude": [],
                    "scripts_exclude": []
                },
                "common_params": [
                    "--completeness_level=confident",
                    "--allow_recover"
                ],
                "specified_params": {
                }
            },
            "extra_params": {
                "pull_request_id": pr_id,
                "build_id": build_id,
                "source_repo": repo_name
            },
            "priority": 10,
            "requester": "pull request"
        })
        headers = {
            "Authorization": "Bearer {}".format(self.token),
            "scheduler-site": "PRTest",
            "Content-Type": "application/json"
        }
        raw_resp = {}
        try:
            raw_resp = requests.post(tp_url, headers=headers, data=payload, timeout=10)
            resp = raw_resp.json()
        except Exception as exception:
            raise Exception("HTTP execute failure, url: {}, raw_resp: {}, exception: {}"
                            .format(tp_url, str(raw_resp), str(exception)))
        if not resp["success"]:
            raise Exception("Create test plan failed with error: {}".format(resp["errmsg"]))

        print("Result of creating test plan: {}".format(str(resp["data"])))

        if output:
            print("Store new test plan id to file {}".format(output))
            with open(output, "w") as f:
                f.write(str(resp["data"]))

        return resp["data"]

    def cancel(self, test_plan_id):

        tp_url = "{}/test_plan/{}".format(self.url, test_plan_id)
        cancel_url = "{}/cancel".format(tp_url)

        print("Cancelling test plan at {}".format(cancel_url))

        payload = json.dumps({})
        headers = {
            "Authorization": "Bearer {}".format(self.token),
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

    def poll(self, test_plan_id, interval=60, timeout=36000):

        print("Polling progress and status of test plan at https://www.testbed-tools.org/scheduler/testplan/{}" \
              .format(test_plan_id))
        print("Polling interval: {} seconds".format(interval))
        print("Max polling time: {} seconds".format(timeout))

        poll_url = "{}/test_plan/{}".format(self.url, test_plan_id)
        headers = {
            "Content-Type": "application/json"
        }
        start_time = time.time()
        http_exception_times = 0
        while (time.time() - start_time) < timeout:
            raw_resp = {}
            try:
                raw_resp = requests.get(poll_url, headers=headers, timeout=10)
                resp = raw_resp.json()
            except Exception as exception:
                print("HTTP execute failure, url: {}, raw_resp: {}, exception: {}".format(poll_url, str(raw_resp),
                                                                                          str(exception)))
                http_exception_times = http_exception_times + 1
                if http_exception_times >= TOLERATE_HTTP_EXCEPTION_TIMES:
                    raise Exception("HTTP execute failure, url: {}, raw_resp: {}, exception: {}"
                                    .format(poll_url, str(raw_resp), str(exception)))
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

            if status in ["FINISHED", "CANCELLED", "FAILED"]:
                if result == "SUCCESS":
                    print("Test plan is successfully {}. Elapsed {:.0f} seconds" \
                          .format(status, time.time() - start_time))
                    return
                else:
                    raise Exception("Test plan id: {}, status: {}, result: {}, Elapsed {:.0f} seconds" \
                                    .format(test_plan_id, status, result, time.time() - start_time))
            print("Test plan id: {}, status: {}, progress: {}%, elapsed: {:.0f} seconds" \
                  .format(test_plan_id, status, resp_data.get("progress", 0) * 100, time.time() - start_time))
            time.sleep(interval)
        else:
            raise Exception("Max polling time reached, test plan at {} is not successfully finished or cancelled" \
                            .format(poll_url))


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
        required=True,
        help="The test topology to be used."
    )
    parser_create.add_argument(
        "-o", "--output",
        type=str,
        dest="output",
        required=False,
        help="Output id of created test plan to the specified file."
    )

    parser_poll = subparsers.add_parser("poll", help="Poll test plan status.")
    parser_cancel = subparsers.add_parser("cancel", help="Cancel running test plan.")

    for p in [parser_poll, parser_cancel]:
        p.add_argument(
            "-i", "--test-plan-id",
            type=int,
            dest="test_plan_id",
            required=True,
            help="Test plan id."
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
        default=36000,
        dest="timeout",
        help="Max polling time. Default 36000 seconds (10 hours)."
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    auth_env = ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"]
    required_env = ["TESTBED_TOOLS_URL"]

    if args.action in ["create", "cancel"]:
        required_env.extend(auth_env)

    env = {
        "testbed_tools_url": os.environ.get("TESTBED_TOOLS_URL"),
        "tenant_id": os.environ.get("TENANT_ID"),
        "client_id": os.environ.get("CLIENT_ID"),
        "client_secret": os.environ.get("CLIENT_SECRET"),
    }
    env_missing = [k.upper() for k, v in env.items() if k.upper() in required_env and not v]
    if env_missing:
        print("Missing required environment variables: {}".format(env_missing))
        sys.exit(1)

    try:
        tp = TestPlanManager(
            env["testbed_tools_url"],
            env["tenant_id"],
            env["client_id"],
            env["client_secret"])

        if args.action == "create":
            pr_id = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
            repo = os.environ.get("BUILD_REPOSITORY_PROVIDER")
            reason = os.environ.get("BUILD_REASON")
            build_id = os.environ.get("BUILD_BUILDID")
            job_name = os.environ.get("SYSTEM_JOBDISPLAYNAME")
            repo_name = os.environ.get("BUILD_REPOSITORY_NAME")

            name = "{repo}_{reason}_PR_{pr_id}_BUILD_{build_id}_JOB_{job_name}" \
                .format(
                repo=repo,
                reason=reason,
                pr_id=pr_id,
                build_id=build_id,
                job_name=job_name
            ).replace(' ', '_')
            tp.create(
                args.topology,
                name=name,
                pr_id=pr_id,
                scripts=get_test_scripts(args.topology),
                output=args.output
            )
        elif args.action == "poll":
            tp.poll(args.test_plan_id, args.interval, args.timeout)
        elif args.action == "cancel":
            tp.cancel(args.test_plan_id)
        sys.exit(0)
    except Exception as e:
        print("Operation failed with exception: {}".format(repr(e)))
        sys.exit(3)
