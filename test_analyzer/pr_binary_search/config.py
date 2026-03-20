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


def get_failure_info_table(USE_AGENCY_FAILURE_INFO=False):
    return KUSTO_AGENCY_TABLE if USE_AGENCY_FAILURE_INFO else KUSTO_FAILURE_TABLE
