"""
Shared fixed structures and constants for PR binary search.
"""
import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class PipelineRunParameters:
    commit: str
    run_id: int
    run_url: str
    stage: str


@dataclass
class TestPipelineParameters:
    BUILD_REASON: str
    BUILD_BRANCH: str
    TEST_PLAN_NUM: str
    TEST_PLAN_STOP_ON_FAILURE: str
    RETRY_TIMES: str
    MGMT_COMMIT_HASH: str = None
    IMPACT_AREA_INFO: dict = None
    # KVM_BUILD_ID is passed as a templateParameter so the elastictest scheduler
    # can download the exact VS image built from a specific sonic-buildimage commit.
    KVM_BUILD_ID: str = None
    # OVERRIDE_PARAMS is forwarded to the pre_defined_pr_test pipeline's OVERRIDE_PARAMS
    # templateParameter (type: object).  Use it to pass extra elastictest arguments such
    # as KVM_IMAGE_BUILD_PIPELINE_ID without modifying the test-pipeline YAML.
    OVERRIDE_PARAMS: Optional[dict] = None
    # INCLUDE_JOBS limits which topology jobs run in pr_test_template.yml.
    # Comma-separated job names, e.g. "t1_job" or "t1_multi_asic_job".
    # Default "all" runs every job.  Derive from CHECKER_TO_INCLUDE_JOBS.
    INCLUDE_JOBS: str = None

    def to_payload(self) -> dict:
        payload = {}
        payload["BUILD_REASON"] = self.BUILD_REASON
        payload["BUILD_BRANCH"] = self.BUILD_BRANCH
        payload["TEST_PLAN_NUM"] = str(self.TEST_PLAN_NUM)
        payload["TEST_PLAN_STOP_ON_FAILURE"] = str(self.TEST_PLAN_STOP_ON_FAILURE)
        payload["RETRY_TIMES"] = str(self.RETRY_TIMES)
        if self.MGMT_COMMIT_HASH:
            payload["MGMT_COMMIT_HASH"] = self.MGMT_COMMIT_HASH
        if self.IMPACT_AREA_INFO:
            payload["IMPACT_AREA_INFO"] = json.dumps(self.IMPACT_AREA_INFO)
        if self.OVERRIDE_PARAMS:
            payload["OVERRIDE_PARAMS"] = json.dumps(self.OVERRIDE_PARAMS)
        if self.KVM_BUILD_ID:
            payload["KVM_BUILD_ID"] = self.KVM_BUILD_ID
        if self.INCLUDE_JOBS:
            payload["INCLUDE_JOBS"] = self.INCLUDE_JOBS
        return payload


@dataclass
class BuildPipelineParameters:
    SUBMODULE: str = None
    COMMIT_ID: str = None

    def to_payload(self) -> dict:
        return {
            k: v for k, v in self.__dict__.items()
            if v is not None
        }
