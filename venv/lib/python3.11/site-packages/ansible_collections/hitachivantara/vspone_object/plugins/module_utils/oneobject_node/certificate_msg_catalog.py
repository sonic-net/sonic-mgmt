from enum import Enum


class CertificateMsgCatalog(Enum):
    ERR_ADD = "Failed to add certificate. Error: {}."
    ERR_DELETE = "Failed to delete certificate. Error: {}."
    ERR_INVALID_SUBJECT_DN = "\'subject_dn\' field is required."
    ERR_INVALID_DN_VALUE = "subject_dn \'{}\' is invalid."
    ERR_CERT_NOT_FOUND = "Could not find certificate with subject_dn \'{}\'"
    ERR_CERT_OP_SPEC = "You must provide either a non-empty 'cert_file_path' or \'delete_cert_dn\'"
    ERR_CERT_OP_MUTUAL_EXCLUSIVE = "Parameters 'cert_file_path' and 'delete_cert_dn' are mutually exclusive. Please provide only one."
    ERR_CERT_OP_STATE = "Invalid spec parameter \'{}\' provided for the state \'{}\'"
