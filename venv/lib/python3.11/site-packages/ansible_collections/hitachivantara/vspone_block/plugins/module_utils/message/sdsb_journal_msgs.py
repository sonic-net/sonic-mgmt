from enum import Enum


class SDSBJournalValidationMsg(Enum):
    NO_SPEC = "Specifications for the journal are not provided."
    JOURNAL_NUMBER_PRESENT = "Journal already exists with this journalNumber {0}"
    JOURNAL_NUMBER_ABSENT = "Please provide Correct Journal Number"
    VOLUME_IDS_ABSENT = "Volume IDs must be provided and cannot be empty."
    NUMBER_OUT_OF_RANGE = "Journal Number must be an integer between 0 and 255."
    DATA_OVERFLOW_OUT_OF_RANGE = (
        "Data overflow watch time must be between 0 and 600 seconds."
    )
    VPS_ID_INVALID = "vps_id must match /^system$|^[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/"
    VOLUME_ID_INVALID = "Volume ID is not a valid UUID."
    STORAGE_CONTROL_ID_INVALID = "Storage Controller ID must be a string."
    CONTROL_ID_INVALID = "Storage Controller ID must be a valid UUID."
    CONFLICTING_JOURNAL_VOLUMES = "Conflicting journal {} already exists with different volume IDs Existing={}, Requested={})}"
    VOLUME_ALREADY_ATTACHED = "Volumes {} are already attached to this journal number{}"
    ID_NOT_AVAILABLE = "Provided id {} not available"
    JOURNAL_DELETE = "Journal has been deleted successfully."
    ID_INVALID = (
        "Id must match /^system$|^[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/"
    )
    VPS_NAME = "VPS with name {} not found"
    ID_AND_NUMBER_NOT_PROVIDE = "Either id or number must be provided."
    JOURNAL_ID_INVALID = "Provided Jounral id is not valid {}"
    ONLY_ONE_VOLUME_ID = "Only one volume id provide to shrink"
    # NUMBER_AND_ID_NOT_AVAILABLE = "Either journal 'id' or 'number' must be provided."
