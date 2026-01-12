"""
Shared fixed structures and constants for PR binary search.
"""
import json
from dataclasses import dataclass


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
