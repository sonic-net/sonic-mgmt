from enum import Enum


class SDSBStorageNodeValidationMsg(Enum):

    BAD_ENTRY = "Entries specified in the input might be wrong, please check them and run again."
    ID_MISSING_FOR_MAINTENANCE = "Required field id is missing for this operation."
    BOTH_ID_AND_NAME_NONE = (
        "Both id and name fields are null, you must specify one of them."
    )
    WRONG_NODE_ID = "Wrong node id given, did not find storage node with that ID."
    STORAGE_NODE_NOT_FOUND = "Did not find storage node named {}."
