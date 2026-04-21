import os


# PROJECT DETAILS
NAMESPACE = "hitachivantara"
PROJECT_NAME = "vspone_block"


# LOGGING CONSTANTS
ANSIBLE_LOG_PATH = os.environ.get(
    "HV_ANSIBLE_LOG_PATH",
    os.path.expanduser(f"~/logs/{NAMESPACE}/ansible/{PROJECT_NAME}"),
)
LOGGER_LEVEL = os.getenv("HV_ANSIBLE_LOG_LEVEL", "INFO").upper()
LOGFILE_NAME = os.getenv("HV_ANSIBLE_LOG_FILE", "hv_vspone_block_modules.log")
AUDIT_LOGFILE_NAME = os.getenv("HV_ANSIBLE_AUDIT_LOG_FILE", "hv_vspone_block_audit.log")
ROOT_LEVEL = os.getenv("HV_ANSIBLE_ROOT_LEVEL", "INFO").upper()
ENABLE_TELEMETRY = os.getenv("HV_ENABLE_TELEMETRY", "False").lower()
TELEMETRY_FILE_PATH = os.getenv(
    "HV_TELEMETRY_FILE_PATH",
    os.path.expanduser(f"~/ansible/{NAMESPACE}/{PROJECT_NAME}/usages"),
)
REGISTRATION_FILE_PATH = os.getenv(
    "HV_REGISTRATION_FILE_PATH",
    os.path.expanduser(f"~/ansible/{NAMESPACE}/{PROJECT_NAME}/registration"),
)

USER_CONSENT_FILE_PATH = os.getenv(
    "HV_REGISTRATION_FILE_PATH",
    os.path.expanduser(f"~/ansible/{NAMESPACE}/{PROJECT_NAME}/user_consent"),
)

ENABLE_AUDIT_LOG = os.getenv("HV_ENABLE_AUDIT_LOG", "true").lower() in (
    "true",
    "1",
    "yes",
)

# File Name Constants
TELEMETRY_FILE_NAME = "usages.json"
REGISTRATION_FILE_NAME = "registration.txt"
CONSENT_FILE_NAME = "user_consent.json"
APIG_URL = os.getenv(
    "HV_APIG_URL",
    "https://5v56roefvl.execute-api.us-west-2.amazonaws.com/api/update_telemetry",
)
