import os


# PROJECT DETAILS
NAMESPACE = "hitachivantara"
PROJECT_NAME = "vspone_object"


# LOGGING CONSTANTS
ANSIBLE_LOG_PATH = os.environ.get(
    "HV_ANSIBLE_LOG_PATH",
    os.path.expanduser(f"~/logs/{NAMESPACE}/ansible/{PROJECT_NAME}"))
LOGGER_LEVEL = os.getenv('HV_ANSIBLE_LOG_LEVEL', 'DEBUG').upper()
LOGFILE_NAME = os.getenv('HV_ANSIBLE_LOG_FILE', "hv_vspone_object_modules.log")
ROOT_LEVEL = os.getenv('HV_ANSIBLE_ROOT_LEVEL', "DEBUG").upper()
LOGFILE_MAX_SIZE = int(os.getenv('HV_ANSIBLE_LOGFILE_MAX_SIZE', 5242880))
LOGFILE_BACKUP_COUNT = int(os.getenv('HV_ANSIBLE_LOGFILE_BACKUP_COUNT', 20))


# MAPI CONSTANTS
MAPI_FULL_URL_TEMPLATE_HTTPS = "https://admin.{region}.{cluster_name}"
MAPI_FULL_URL_TEMPLATE_HTTP = "http://admin.{region}.{cluster_name}"

# TELEMERTY CONSTANTS
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

# File Name Constants
TELEMETRY_FILE_NAME = "usages.json"
REGISTRATION_FILE_NAME = "registration.txt"
CONSENT_FILE_NAME = "user_consent.json"
APIG_URL = os.getenv(
    "HV_APIG_URL",
    "https://71bhx41we0.execute-api.us-west-2.amazonaws.com/api/update_telemetry",
)
# MODULE CONSTANTS
DEFAULT_STORAGE_CLASS_PAGE_SIZE = 100
DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE = 100
DEFAULT_JOBS_PAGE_SIZE = 1000
