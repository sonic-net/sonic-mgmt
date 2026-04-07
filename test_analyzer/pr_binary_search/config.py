"""
Shared configuration for PR failure analysis and binary search.
"""

DEFAULT_FAILURE_INFO_FILE = "failure_info.json"

KUSTO_DATABASE = "SonicTestData"
KUSTO_FAILURE_TABLE = "PRBinarySearchFailureInfo"
KUSTO_FAILURE_MAPPING = "PRBinarySearchFailureInfoMappingV1"
KUSTO_LOG_TABLE = "PRBinarySearchLog"
KUSTO_LOG_MAPPING = "PRBinarySearchLogMappingV1"
KUSTO_TESTPLAN_MAP_TABLE = "PRBinarySearchTestPlanMap"
KUSTO_TESTPLAN_MAP_MAPPING = "PRBinarySearchTestPlanMapMappingV1"
KUSTO_RESULT_TABLE = "PRBinarySearchResult"
KUSTO_RESULT_MAPPING = "PRBinarySearchResultMappingV1"
KUSTO_AGENCY_TABLE = "PRBinarySearchFailureInfoAgency"
KUSTO_AGENCY_MAPPING = "PRBinarySearchFailureInfoAgencyMappingV1"

MGMT_REPO = "sonic-net/sonic-mgmt"
SUPPORTED_PUBLIC_REPOS = [
    "sonic-net/sonic-mgmt",
    "sonic-net/sonic-buildimage",
]

ALLOWED_BRANCHES = ["master"]

# Azure DevOps pipeline definition ID for the master branch batched CI builds.
# These builds are used for CI pre-screening to narrow the commit range before
# building individual VS images.  See https://dev.azure.com/mssonic/build/_build?definitionId=1
MASTER_CI_PIPELINE_DEFINITION_ID = 1

# Mapping from failure-analyzer checker types to the INCLUDE_JOBS value(s)
# accepted by pr_test_template.yml.  Each checker maps to the comma-separated
# job names that should be enabled for that topology.
# See sonic-mgmt/.azure-pipelines/pr_test_template.yml for the full job list.
CHECKER_TO_INCLUDE_JOBS = {
    "t0_checker": "t0_job",
    "t0-2vlans_checker": "t0_2vlans_job",
    "t1_checker": "t1_job",
    "t1-multi-asic_checker": "t1_multi_asic_job",
    "dualtor_checker": "dualtor_job",
    "t0-sonic_checker": "t0_sonic_job",
    "dpu_checker": "dpu_job",
    "t2_checker": "t2_job",
}

# Checker types used in Kusto data that need to be remapped to the pipeline-
# compatible checker name for IMPACT_AREA_INFO.  For example the multi-asic-t1
# job's condition checks for 't1_checker', not 't1-multi-asic_checker'.
CHECKER_TO_PIPELINE_CHECKER = {
    "t1-multi-asic_checker": "t1_checker",
}


def get_failure_info_table(USE_AGENCY_FAILURE_INFO=False):
    return KUSTO_AGENCY_TABLE if USE_AGENCY_FAILURE_INFO else KUSTO_FAILURE_TABLE
