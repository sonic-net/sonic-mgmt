from enum import Enum


class SDSBUserValidationMsg(Enum):

    ID_USER_GROUP_IDS_REQD = "Id and user_groups_ids are required for {} operation."
    FIELD_MISSING_FOR_EDIT_USER = (
        "To edit user information, you must specify password, is_enabled, or both."
    )
