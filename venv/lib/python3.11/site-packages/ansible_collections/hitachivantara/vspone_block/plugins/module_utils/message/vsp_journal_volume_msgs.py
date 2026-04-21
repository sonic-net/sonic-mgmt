from enum import Enum


class VSPSJournalVolumeValidateMsg(Enum):
    EMPTY_JOURNAL_VOLUME_ID = "JOURNAL_VOLUME_id is empty. Specify a value for JOURNAL_VOLUME_id or remove the parameter from the playbook."
    BOTH_JOURNAL_VOLUME_ID_AND_NAME = (
        "Both id and name are specified. Specify only one of them."
    )
    PG_ID_CAPACITY = "missing both capacity and parity_group_id in JOURNAL_VOLUME volumes. Specify both values or JOURNAL_VOLUME_volumes parameter"
    MISSING_CAPACITY = "capacity is missing in JOURNAL_VOLUME volumes. Specify the capacity value for {} parity_group_id."
    MISSING_PG_ID = "parity_group_id is missing in JOURNAL_VOLUME . Specify the parity_group_id where capacity is {}."
    JOURNAL_VOLUME_SIZE_MIN = "The capacity must be at least 8GB."
    JOURNAL_VOLUME_DOES_NOT_EXIST = "The specified JOURNAL_VOLUME does not exist."
    JOURNAL_VOLUME_REQUIRED = "Ldev volumes are required for new journal volume creation.specify the ldev ids."
    JOURNAL_VOLUME_ID_EXHAUSTED = (
        "The pool id is exhausted. No more pools can be created."
    )
    NO_JOURNAL_VOLUME_FOR_ID = (
        "Could not find the journal volume associated with journal_id {}."
    )
    BOTH__FREE_POOL_ID_AND_USED_PARAM = "Both is_free_journal_pool_id and is_mirror_not_used cannot be set select only one"
    NO_FREE_JOURNAL_POOL_ID = "No free journal pool id available"
    JOURNAL_POOL_DELETE = "Journal deleted successfully."
    JP_POOL_LDEV_LIMIT_MAX = (
        "The number of journal volume exceeds the maximum that can be registered"
    )
    JP_POOL_LDEV_LIMIT_MIN = "The pool has reached the minimum number of LDEVs."
    JP_ID = "The journal_id is required for the operation."
    JOURNAL_VOLUME_CREATE_FAILED = "Failed to create journal volume. or not able to fetch the journal volume from the UAIG."
