import requests
import logging
import time
import re
from requests.auth import HTTPBasicAuth
from schemas import (
    PipelineRunParameters,
    TestPipelineParameters,
    BuildPipelineParameters
)

logging.basicConfig(level=logging.INFO, format='[%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

ELASTICTEST_PLAN_PATTERNS = [
    re.compile(r"elastictest\.org/scheduler/testplan/([A-Za-z0-9-]+)"),
    re.compile(r"TestPlanId[\"'=:\s]+([A-Za-z0-9-]{6,})"),
]


class AzureDevOpsClient:
    def __init__(self, base_url: str, organization: str, project: str, token: str):
        if not token:
            raise ValueError("MSSONIC_TOKEN is empty. Azure DevOps PAT is required.")
        self.base_url = base_url.rstrip("/")
        self.organization = organization
        self.project = project
        self.url_prefix = f"{self.base_url}/{self.organization}/{self.project}/_apis"
        self.token = token

    def queue_build(self, pipeline_id: int, payload: dict, max_retries: int = 3) -> dict:
        if max_retries < 1:
            raise ValueError("max_retries must be at least 1")

        url = f"{self.url_prefix}/pipelines/{pipeline_id}/runs?api-version=7.1-preview.1"

        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    auth=HTTPBasicAuth("", self.token),
                    json=payload,
                    timeout=30
                )
                if resp.status_code >= 500:
                    raise requests.exceptions.HTTPError(
                        f"Server error {resp.status_code}: {resp.text}"
                    )
                resp.raise_for_status()
                return resp.json()

            except requests.exceptions.HTTPError as http_err:
                if resp.status_code < 500:
                    logger.error(f"Non-retriable HTTP error occurred: {http_err}")
                    raise
                logger.warning(f"Server error, retrying (attempt {attempt}/{max_retries}): {http_err}")

            except requests.exceptions.RequestException as e:
                logger.warning(f"Queue build failed (attempt {attempt}/{max_retries}): {e}")

            if attempt == max_retries:
                logger.error("Queue build failed after max retries")
                raise
            time.sleep(2 ** attempt)

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

    def get_pipeline_logs(self, run_id: int) -> list:
        url = f"{self.url_prefix}/build/builds/{run_id}/logs?api-version=7.1"
        resp = requests.get(
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth("", self.token)
        )
        if resp.status_code != 200:
            logger.error(f"Failed to get pipeline logs for {run_id}: {resp.status_code}, {resp.text}")
            return []
        return resp.json().get("value", [])

    def get_pipeline_log_content(self, run_id: int, log_id: int) -> str:
        url = f"{self.url_prefix}/build/builds/{run_id}/logs/{log_id}?api-version=7.1"
        resp = requests.get(
            url,
            headers={"Content-Type": "text/plain"},
            auth=HTTPBasicAuth("", self.token)
        )
        if resp.status_code != 200:
            logger.error(
                f"Failed to get pipeline log content for run={run_id}, log={log_id}: {resp.status_code}, {resp.text}")
            return ""
        return resp.text

    def extract_test_plan_ids(self, run_id: int) -> list:
        test_plan_ids = set()
        for log in self.get_pipeline_logs(run_id):
            log_id = log.get("id")
            if log_id is None:
                continue
            content = self.get_pipeline_log_content(run_id, log_id)
            if not content:
                continue
            for pattern in ELASTICTEST_PLAN_PATTERNS:
                test_plan_ids.update(pattern.findall(content))
        return sorted(test_plan_ids)

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

    def poll_pipeline_details(
        self, pipeline_runs, timeout=21600, check_interval=60
    ) -> dict:
        """
        Poll multiple pipeline runs until completion.

        Returns a dict mapping commit -> detail:
        {
            "is_bad": bool | None,
            "run_id": int,
            "run_url": str,
            "status": str,
            "result": str
        }
        """
        details = {}
        start_time = time.time()

        while time.time() - start_time < timeout and pipeline_runs:
            pending_runs = []
            for pipeline_run in pipeline_runs:
                logger.info(f"Polling pipeline detail for commit {pipeline_run.commit}, run ID {pipeline_run.run_id}")
                try:
                    status_data = self.get_pipeline_status(pipeline_run.run_id)
                    if status_data is None:
                        pending_runs.append(pipeline_run)
                        continue

                    status = status_data.get('status', 'unknown')
                    result = status_data.get('result', 'unknown')
                    is_final = status.lower() in ['completed', 'canceled', 'cancelled'] or result.lower() in [
                        'succeeded', 'failed', 'canceled', 'partiallySucceeded']

                    if is_final:
                        is_bad = result.lower() not in ['succeeded', 'partiallySucceeded']
                        details[pipeline_run.commit] = {
                            "is_bad": is_bad,
                            "run_id": pipeline_run.run_id,
                            "run_url": pipeline_run.run_url,
                            "status": status,
                            "result": result,
                        }
                    else:
                        pending_runs.append(pipeline_run)

                except Exception as e:
                    logger.error(f"Error polling pipeline detail for {pipeline_run.commit}: {str(e)}")
                    details[pipeline_run.commit] = {
                        "is_bad": None,
                        "run_id": pipeline_run.run_id,
                        "run_url": pipeline_run.run_url,
                        "status": "error",
                        "result": str(e),
                    }

            pipeline_runs[:] = pending_runs
            if pipeline_runs:
                time.sleep(check_interval)

        for pipeline_run in pipeline_runs:
            details[pipeline_run.commit] = {
                "is_bad": None,
                "run_id": pipeline_run.run_id,
                "run_url": pipeline_run.run_url,
                "status": "timeout",
                "result": "timeout",
            }
            logger.error(f"Pipeline timeout for {pipeline_run.commit}")

        pipeline_runs.clear()
        return details


def build_queue_payload(branch: str, commit: str, stage: str, parameters) -> dict:
    """Prepare payload for triggering a pipeline run via ADO Pipelines runs API."""
    if stage == "test":
        if not isinstance(parameters, TestPipelineParameters):
            raise ValueError("Expected TestPipelineParameters")
        # The test pipeline (pre_defined_pr_test) lives in sonic-net/sonic-mgmt.
        # Do NOT set "version" here: the incoming `commit` is a sonic-buildimage SHA
        # that does not exist in sonic-mgmt, which causes a 400 Bad Request.
        # Omitting "version" lets Azure DevOps use the branch HEAD of sonic-mgmt.
        payload = {
            "resources": {
                "repositories": {
                    "self": {
                        "refName": f"refs/heads/{branch}",
                    }
                }
            },
            "templateParameters": parameters.to_payload(),
        }
        return payload

    elif stage == "build":
        if not isinstance(parameters, BuildPipelineParameters):
            raise ValueError("Expected BuildPipelineParameters")
        # Build pipeline (build_vs_image) uses sonic-buildimage as its self-repo,
        # so setting "version" to a buildimage SHA is correct.
        return {
            "resources": {
                "repositories": {
                    "self": {
                        "refName": f"refs/heads/{branch}",
                        "version": commit,
                    }
                }
            },
            "templateParameters": parameters.to_payload(),
        }

    else:
        raise ValueError(f"Unknown stage: {stage}")

    def fetch_completed_ci_builds(
        self,
        definition_id: int,
        branch: str,
        min_time: str,
        max_time: str,
        result_filter: str = "succeeded",
    ) -> list:
        """Fetch completed CI builds from Azure DevOps within a time range.

        Args:
            definition_id: Pipeline definition ID (e.g. 1 for master CI).
            branch: Branch name (e.g. "master").
            min_time: ISO-8601 start time.
            max_time: ISO-8601 end time.
            result_filter: Comma-separated build results to include (default: "succeeded").

        Returns:
            List of build dicts sorted by finishTime ascending.  Each dict has at
            minimum: id, sourceVersion, result, finishTime, _links.
        """
        branch_ref = f"refs/heads/{branch}" if not branch.startswith("refs/") else branch
        url = (
            f"{self.url_prefix}/build/builds"
            f"?definitions={definition_id}"
            f"&branchName={branch_ref}"
            f"&statusFilter=completed"
            f"&resultFilter={result_filter}"
            f"&minTime={min_time}"
            f"&maxTime={max_time}"
            f"&api-version=7.1"
        )
        all_builds = []
        while url:
            try:
                resp = requests.get(
                    url,
                    headers={"Content-Type": "application/json"},
                    auth=HTTPBasicAuth("", self.token),
                    timeout=60,
                )
            except requests.exceptions.RequestException as e:
                logger.error(
                    f"Network error fetching CI builds (definition {definition_id}): {e}"
                )
                return all_builds
            if resp.status_code != 200:
                logger.error(
                    f"Failed to fetch CI builds (definition {definition_id}): "
                    f"{resp.status_code}, {resp.text}"
                )
                return all_builds
            data = resp.json()
            all_builds.extend(data.get("value", []))
            # Azure DevOps paginates via a continuation token header.
            continuation = resp.headers.get("x-ms-continuationtoken")
            if continuation:
                separator = "&" if "?" in url.split("&continuationToken=")[0] else "?"
                base_url = url.split("&continuationToken=")[0]
                url = f"{base_url}{separator}continuationToken={continuation}"
            else:
                url = None

        # Sort by finishTime ascending so earlier builds come first.
        all_builds.sort(key=lambda b: b.get("finishTime", ""))
        logger.info(
            f"Fetched {len(all_builds)} CI builds from definition {definition_id} "
            f"on {branch} between {min_time} and {max_time}"
        )
        return all_builds


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
    logger.info(f"Triggering {stage} pipeline for commit {commit} on branch {branch} with payload: {payload}")
    response = client.queue_build(pipeline_id, payload)
    logger.info(f"Pipeline response: {response}")

    if "id" not in response:
        raise RuntimeError(f"Pipeline trigger failed for commit {commit}, response: {response}")

    run_id = response.get("id")
    run_url = response.get("_links", {}).get("web", {}).get("href")

    return PipelineRunParameters(
        commit=commit,
        run_id=run_id,
        run_url=run_url,
        stage=stage
    )
