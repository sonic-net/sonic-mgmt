#!/usr/bin/env python3
"""Queue the Secure Boot image build and wait before submitting tests."""

import argparse
import json
import os
import re
import signal
import sys
import time
from urllib.request import Request, urlopen


BUILD_API = "https://dev.azure.com/mssonic/build/_apis"


def request(method, url, token, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    with urlopen(req, timeout=30) as response:
        return json.load(response)


def source_parameters(environ):
    repo = environ["BUILD_REPOSITORY_NAME"].lower()
    if "sonic-mgmt" in repo:
        return {}
    if not repo.endswith("/sonic-buildimage"):
        raise ValueError(f"Unsupported Secure Boot image source: {repo}")
    url = environ["BUILD_REPOSITORY_URI"]
    ref = environ["BUILD_SOURCEBRANCH"]
    commit = environ["BUILD_SOURCEVERSION"]
    if not re.fullmatch(r"https://github\.com/[\w.-]+/sonic-buildimage(?:\.git)?", url):
        raise ValueError("Secure Boot builds currently support public GitHub buildimage sources only")
    if not ref.startswith("refs/") or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ValueError("An exact source ref and commit are required for a buildimage PR")
    return {"SOURCE_REPOSITORY": url, "SOURCE_REF": ref, "SOURCE_COMMIT": commit}


def trigger_build(token, pipeline_id, branch, parameters, timeout=21600):
    if not token or token.startswith("$("):
        raise ValueError("System.AccessToken is required to queue the Secure Boot build")
    payload = {
        "resources": {"repositories": {"self": {"refName": branch}}},
        "templateParameters": parameters,
    }
    run = request("POST", f"{BUILD_API}/pipelines/{pipeline_id}/runs?api-version=7.1", token, payload)
    build_id = int(run["id"])
    url = f"{BUILD_API}/build/builds/{build_id}?api-version=7.1"
    print(f"Queued Secure Boot build {build_id} in pipeline {pipeline_id}", flush=True)
    complete = False
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            build = request("GET", url, token)
            if build["status"] == "completed":
                complete = True
                if build.get("result") != "succeeded":
                    raise RuntimeError(f"Secure Boot build {build_id} finished: {build.get('result')}")
                print(f"##vso[task.setvariable variable=BUILD_ID;isOutput=true]{build_id}", flush=True)
                return build_id
            time.sleep(30)
        raise TimeoutError(f"Timed out waiting for Secure Boot build {build_id}")
    finally:
        if not complete:
            try:
                request("PATCH", url, token, {"status": "cancelling"})
            except Exception as error:
                print(f"Could not cancel Secure Boot build {build_id}: {error}", file=sys.stderr)


def interrupt(signum, frame):
    raise KeyboardInterrupt(f"Received signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pipeline-id", type=int, default=3442)
    parser.add_argument("--branch", default="refs/heads/feature/secure-boot-vs-pipeline-clean")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    trigger_build(
        os.environ.get("SYSTEM_ACCESSTOKEN", ""),
        args.pipeline_id,
        args.branch,
        source_parameters(os.environ),
    )


if __name__ == "__main__":
    main()
