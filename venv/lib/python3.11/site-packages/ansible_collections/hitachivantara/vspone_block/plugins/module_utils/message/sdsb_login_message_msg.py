from enum import Enum


class SDSBLoginMessageValidationMsg(Enum):
    NO_SPEC = "Message field is required for updating login message"
    INVALID_CHAR = "Message contains invalid characters: {}"
    MESSAGE_LIMIT = "Message exceeds 6144 character limit"
    MESSAGE_STR = "Message must be a string"
