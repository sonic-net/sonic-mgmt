"""Orchestrator: query Kusto for pending failure episodes and trigger one pipeline
3305 run per episode.  Called from pr_binary_search_full_pipeline.yml instead of
running pr_binary_search.py inline so that each failure episode is processed in an
isolated, independently cancellable ADO pipeline run.

Environment variables required:
  ACCESS_TOKEN              - AAD token for Kusto (https://api.kusto.windows.net)
  KUSTO_CLUSTER_INGEST_URL  - ingest cluster URL (ingest-<cluster>)
  MSSONIC_TOKEN             - ADO PAT used to queue pipeline runs

CLI arguments:
  --kusto_lookback_hours    - lookback window for PRBinarySearchFailureInfo (default: 48)
  --analyzer_run_id         - if set, only dispatch failures from this specific batch
  --binary_search_pipeline  - ADO pipeline definition ID for pipeline 3305 (default: 3305)
  --max_parallel            - MAX_PARALLEL param forwarded to each triggered run (default: 5)
  --max_concurrent_runs     - max simultaneous 3305 runs to queue (default: 8)
  --upload_kusto            - UPLOAD_KUSTO param forwarded to each triggered run (default: true)
  --USE_AGENCY_FAILURE_INFO - use agency failure table (default: false)
  --enable_ci_prescreening  - CI prescreening param forwarded (default: false)
  --dry_run                 - print what would be triggered without actually triggering
"""

import argparse
import json
import logging
import os
import sys

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from pipeline_triggers import AzureDevOpsClient
from pr_binary_search import (
    fetch_failure_info_from_kusto,
    parse_failure_info_records,
    parse_bool_arg,
    ALLOWED_BRANCHES,
    BASE_URL,
    ORGANIZATION,
)
from config import get_failure_info_table, KUSTO_DATABASE  # noqa: F401 (KUSTO_DATABASE unused but kept for symmetry)

logging.basicConfig(level=logging.INFO, format='[%(threadName)s] %(message)s')
logger = logging.getLogger(__name__)

# Pipeline 3305 lives in the 'internal' project, not 'build'
BINARY_SEARCH_PIPELINE_PROJECT = "internal"
BINARY_SEARCH_PIPELINE_ID = 3305


def trigger_binary_search_pipeline(
    client: AzureDevOpsClient,
    pipeline_id: int,
    failure_join_key: str,
    kusto_lookback_hours: int,
    max_parallel: int,
    upload_kusto: bool,
    use_agency: bool,
    enable_ci_prescreening: bool,
    dry_run: bool = False,
) -> dict:
    """Queue one pipeline run for a single failure row."""
    payload = {
        "templateParameters": {
            "FAILURE_JOIN_KEY": failure_join_key,
            "KUSTO_LOOKBACK_HOURS": str(kusto_lookback_hours),
            "MAX_PARALLEL": str(max_parallel),
            "UPLOAD_KUSTO": str(upload_kusto).lower(),
            "USE_AGENCY_FAILURE_INFO": str(use_agency).lower(),
            "ENABLE_CI_PRESCREENING": str(enable_ci_prescreening).lower(),
        }
    }
    if dry_run:
        logger.info(f"[DRY RUN] Would trigger pipeline {pipeline_id} for {failure_join_key}: {json.dumps(payload)}")
        return {"id": None, "state": "dry_run", "failure_join_key": failure_join_key}
    run = client.queue_build(pipeline_id, payload)
    run_id = run.get("id")
    run_url = run.get("_links", {}).get("web", {}).get("href", "")
    logger.info(f"Triggered pipeline {pipeline_id} run {run_id} for {failure_join_key}: {run_url}")
    return run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kusto_lookback_hours", type=int, default=48)
    parser.add_argument("--analyzer_run_id", type=str, default="",
                        help="If set, only dispatch failures from this specific analyzer batch. "
                             "Bypasses the lookback time filter.")
    parser.add_argument("--binary_search_pipeline", type=int, default=BINARY_SEARCH_PIPELINE_ID)
    parser.add_argument("--max_parallel", type=int, default=5)
    parser.add_argument("--max_concurrent_runs", type=int, default=8,
                        help="Maximum number of parallel 3305 pipeline runs to queue. "
                             "Prevents flooding build/test pipelines.")
    parser.add_argument("--upload_kusto", type=parse_bool_arg, default=True)
    parser.add_argument("--USE_AGENCY_FAILURE_INFO", type=parse_bool_arg, default=False)
    parser.add_argument("--enable_ci_prescreening", type=parse_bool_arg, default=False)
    parser.add_argument("--dry_run", type=parse_bool_arg, default=False,
                        help="Log what would be triggered without calling ADO API")
    args = parser.parse_args()

    access_token = os.environ.get("ACCESS_TOKEN")
    kusto_ingest_url = os.environ.get("KUSTO_CLUSTER_INGEST_URL")
    mssonic_token = os.environ.get("MSSONIC_TOKEN")

    if not access_token or not kusto_ingest_url:
        logger.error("ACCESS_TOKEN and KUSTO_CLUSTER_INGEST_URL env vars are required")
        sys.exit(1)
    if not mssonic_token and not args.dry_run:
        logger.error("MSSONIC_TOKEN is required to trigger pipelines")
        sys.exit(1)

    kusto_query_url = kusto_ingest_url.replace("//ingest-", "//", 1)
    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(kusto_query_url, access_token)
    kusto_client = KustoClient(kcsb)

    table = get_failure_info_table(args.USE_AGENCY_FAILURE_INFO)
    records = fetch_failure_info_from_kusto(
        kusto_client,
        lookback_hours=args.kusto_lookback_hours,
        table=table,
        exact_analyzer_run_id=args.analyzer_run_id or None,
    )
    failure_info = parse_failure_info_records(records, allowed_branches=set(ALLOWED_BRANCHES))

    if not failure_info:
        logger.info("No pending failure episodes found — nothing to trigger")
        return

    # Deduplicate: same test failing in different checker types → keep one row per
    # (repo, branch, file_path, module_path, testcase).  We only need one binary
    # search per unique test failure regardless of which checker detected it.
    seen_test_keys = set()
    deduped = []
    for entry in failure_info:
        test_key = (
            entry.get("repo", ""),
            entry.get("branch", ""),
            entry.get("file_path", ""),
            entry.get("module_path", ""),
            entry.get("testcase", ""),
        )
        if test_key not in seen_test_keys:
            seen_test_keys.add(test_key)
            deduped.append(entry)
    logger.info(f"After dedup: {len(failure_info)} rows → {len(deduped)} unique test failures")
    failure_info = deduped

    # Cap total concurrent runs to avoid flooding build/test pipelines
    if len(failure_info) > args.max_concurrent_runs:
        logger.warning(
            f"Capping to {args.max_concurrent_runs} runs "
            f"(found {len(failure_info)} episodes, max_concurrent_runs={args.max_concurrent_runs})"
        )
        failure_info = failure_info[: args.max_concurrent_runs]

    logger.info(f"Triggering {len(failure_info)} binary search pipeline runs (one per episode)")

    ado_client = AzureDevOpsClient(
        BASE_URL, ORGANIZATION, BINARY_SEARCH_PIPELINE_PROJECT, token=mssonic_token or "dry_run")
    triggered = []
    errors = []
    for entry in failure_info:
        failure_join_key = entry.get("failure_join_key", "")
        if not failure_join_key:
            logger.warning(f"Skipping entry without failure_join_key: {entry.get('repo')}@{entry.get('branch')}")
            continue
        try:
            run = trigger_binary_search_pipeline(
                client=ado_client,
                pipeline_id=args.binary_search_pipeline,
                failure_join_key=failure_join_key,
                kusto_lookback_hours=args.kusto_lookback_hours,
                max_parallel=args.max_parallel,
                upload_kusto=args.upload_kusto,
                use_agency=args.USE_AGENCY_FAILURE_INFO,
                enable_ci_prescreening=args.enable_ci_prescreening,
                dry_run=args.dry_run,
            )
            triggered.append(run)
        except Exception as exc:
            logger.error(f"Failed to trigger pipeline for {failure_join_key}: {exc}")
            errors.append(failure_join_key)

    logger.info(f"Triggered {len(triggered)} runs, {len(errors)} errors")
    if errors:
        logger.warning(f"Failed to trigger: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
