import requests
import logging
import time
import json
from requests.auth import HTTPBasicAuth
from schemas import (
    PipelineRunParameters,
    TestPipelineParameters,
    BuildPipelineParameters
)

logging.basicConfig(level=logging.INFO, format='[%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


class AzureDevOpsClient:
    def __init__(self, base_url: str, organization: str, project: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.organization = organization
        self.project = project
        self.url_prefix = f"{self.base_url}/{self.organization}/{self.project}/_apis"
        self.token = token

    def queue_build(self, pipeline_id: int, payload: dict) -> dict:
        """Trigger a pipeline run"""
        url = f"{self.url_prefix}/pipelines/{pipeline_id}/runs?api-version=7.1-preview.1"
        logger.info(f"queue build url: {url}")
        logger.info(
            "Triggering pipeline %s with payload:\n%s",
            pipeline_id,
            json.dumps(payload, indent=2)
        )

        try:
            resp = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth("", self.token),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error occurred: {http_err}")
            return {"error": str(http_err)}
        except Exception as err:
            logger.error(f"An error occurred: {err}")
            return {"error": str(err)}

    def get_pipeline_status(self, run_id: int) -> dict:
        """Get pipeline run status for a given run_id"""
        url = f"{self.url_prefix}/build/builds/{run_id}?api-version=7.1"
        logger.info(f"Pipeline status URL: {url}")

        resp = requests.get(
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth("", self.token)
        )
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.error(f"Failed to get pipeline status: {resp.status_code}, {resp.text}")
            return None

    def poll_pipeline_results(
        self, pipeline_runs, timeout=21600, check_interval=60
    ) -> dict:
        """
        Poll multiple pipeline runs until completion.

        Returns a dict mapping commit -> is_bad (True = bad, False = good, None = error/timeout).
        """
        results = {}
        start_time = time.time()

        while time.time() - start_time < timeout and pipeline_runs:
            pending_runs = []
            for pipeline_run in pipeline_runs:
                logger.info(f"Polling pipeline for commit {pipeline_run.commit}, run ID {pipeline_run.run_id}")
                try:
                    status_data = self.get_pipeline_status(pipeline_run.run_id)
                    if status_data is None:
                        pending_runs.append(pipeline_run)
                        continue

                    status = status_data.get('status', 'unknown')
                    result = status_data.get('result', 'unknown')
                    logger.info(f"Pipeline status for commit {pipeline_run.commit}: status={status}, result={result}")

                    is_final = status.lower() in ['completed', 'canceled', 'cancelled'] or result.lower() in [
                        'succeeded', 'failed', 'canceled', 'partiallySucceeded']

                    if is_final:
                        is_bad = result.lower() not in ['succeeded', 'partiallySucceeded']
                        results[pipeline_run.commit] = is_bad
                        logger.info(f"Commit {pipeline_run.commit}: \
                                    {'BAD' if is_bad else 'GOOD'} (status={status}, result={result})")
                    else:
                        pending_runs.append(pipeline_run)

                except Exception as e:
                    logger.error(f"Error polling pipeline for {pipeline_run.commit}: {str(e)}")
                    results[pipeline_run.commit] = None

            pipeline_runs[:] = pending_runs
            if pipeline_runs:
                time.sleep(check_interval)

        # Timeout remaining runs
        for pipeline_run in pipeline_runs:
            results[pipeline_run.commit] = None
            logger.error(f"Pipeline timeout for {pipeline_run.commit}")

        pipeline_runs.clear()
        return results


def build_queue_payload(branch: str, commit: str, stage: str, parameters) -> dict:
    """Prepare payload for triggering a pipeline run"""
    if stage == "test":
        if not isinstance(parameters, TestPipelineParameters):
            raise ValueError("Expected TestPipelineParameters")
    elif stage == "build":
        if not isinstance(parameters, BuildPipelineParameters):
            raise ValueError("Expected BuildPipelineParameters")
    else:
        raise ValueError(f"Unknown stage: {stage}")

    return {
        "resources": {
            "repositories": {
                "self": {
                    "refName": f"refs/heads/{branch}",
                    "version": commit,
                }
            }
        },
        "templateParameters": parameters.to_payload()
    }


def trigger_pipeline(
    client: AzureDevOpsClient,
    branch: str,
    commit: str,
    stage: str,
    pipeline_id: int,
    parameters
) -> PipelineRunParameters:
    """
    Trigger a build/test pipeline using dataclass for parameters
    """
    payload = build_queue_payload(branch, commit, stage, parameters)
    response = client.queue_build(pipeline_id, payload)

    return PipelineRunParameters(
        commit=commit,
        run_id=response["id"],
        run_url=response.get("_links", {}).get("web", {}).get("href"),
        stage=stage
    )
