import fcntl
import uuid
import json
import re
import os
import time
import inspect
from ansible.module_utils.urls import open_url as open_request
from datetime import datetime
import threading

try:
    from ..common.hv_log import Log
    from ..common.vsp_constants import Endpoints
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common_constants import (
        TELEMETRY_FILE_PATH,
        TELEMETRY_FILE_NAME,
        USER_CONSENT_FILE_PATH,
        CONSENT_FILE_NAME,
        APIG_URL,
        ENABLE_AUDIT_LOG,
    )
    from ..common.uaig_constants import Endpoints as UAIGEndpoints
    from ..model.common_base_models import APIGRequestModel
    from ..common.hv_constants import IGNORED_APIS
except ImportError:
    from common.hv_log import Log
    from common.vsp_constants import Endpoints
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common_constants import (
        TELEMETRY_FILE_PATH,
        TELEMETRY_FILE_NAME,
        USER_CONSENT_FILE_PATH,
        CONSENT_FILE_NAME,
        APIG_URL,
        ENABLE_AUDIT_LOG,
    )
    from common.uaig_constants import Endpoints as UAIGEndpoints
    from model.common_base_models import APIGRequestModel
    from common.hv_constants import IGNORED_APIS

MODEL_INFO = None

AWS_UPDATE_THREADS = []
AUDIT_THREADS = []

USER_CONSENT, CONSENT_FILE_PRESENT = False, False
SITE_ID = "common_site_id"

logger = Log()


def open_url(*args, **kwargs):

    telemetry = OpenUrlWithTelemetry()
    return telemetry.open(*args, **kwargs)


class OpenUrlWithTelemetry:
    """
    A wrapper for the `open_url` function that tracks its usage,
    including success, failure, and average time taken, if telemetry is enabled.
    """

    log = Log()

    def __init__(self):
        self.output_file = os.path.join(
            TELEMETRY_FILE_PATH, TELEMETRY_FILE_NAME
        )  # nosec
        self.data = {}
        self.class_map = {
            "VSPConnectionManager": "directConnectTasks",
            "SDSBConnectionManager": "sdsBlockTasks",
            # "UAIGConnectionManager": "gatewayTasks",
        }
        self.storage_map = {
            "VSPConnectionManager": "directConnectStorageSystems",
            "SDSBConnectionManager": "sdsBlockStorageSystems",
            # "UAIGConnectionManager": "gatewayStorageSystems",
        }
        self.skip_methods = ["getAuthToken"]
        self.storage_info_methods = ["get_storage_details"]
        self.model_info = None
        self.ignore_apis = IGNORED_APIS

    def _extract_module_name(self, file_names):
        """
        Extracts the module name from a list of file paths based on specific criteria.
        """
        valid_subdirs = ["/vsp/", "/sds_block/"]

        for file in file_names:
            if (
                "hv" in file
                and "/modules/" in file
                and any(subdir in file for subdir in valid_subdirs)
                and file.endswith(".py")
            ):
                match = re.search(r"/([^/]+)\.py$", file)
                if match:
                    return match.group(1)
        return None

    def _dig_calling_class(self, stack):
        for i in range(6):
            class_name = type(stack[i].frame.f_locals.get("self", None)).__name__
            if class_name in self.class_map.keys():
                return class_name
        return "CommonConnectionManager"

    def open(self, *args, **kwargs):
        """
        Wrapper for the `open_url` function that tracks its usage, unless telemetry is disabled.
        """

        url = kwargs.get("url", "")
        # Check if any ignore API is a substring of the URL
        if any(ignored in url for ignored in self.ignore_apis):
            return open_request(*args, **kwargs)

        start_time = time.time()
        success = True
        exception_message = Exception()

        # Backtrack calling context
        stack = inspect.stack()
        file_names = [stack.filename for stack in stack]
        module_name = self._extract_module_name(file_names)
        is_old_module = any("hv_http_client.py" in filename for filename in file_names)

        try:
            gateway_method = stack[6].function

            class_name = self._dig_calling_class(stack)
            task_type = (
                self.class_map.get(class_name, "unknown")
                if not is_old_module
                else "gatewayTasks"
            )
            storage_list_name = (
                self.storage_map.get(class_name, "unknown")
                if not is_old_module
                else "gatewayStorageSystems"
            )
        except Exception:
            task_type, gateway_method, storage_list_name = (
                "Unknown",
                "Unknown",
                "Unknown",
            )
        # Attempt to call    `open_url`
        try:
            result = open_request(*args, **kwargs)
        except Exception as e:
            success = False
            exception_message = e
            result = None

        end_time = time.time()
        elapsed_time = float(f"{end_time - start_time:.2f}")

        # Update tracking data
        self._load_existing_data()
        if task_type not in self.data:
            self.data[task_type] = {}
        if gateway_method not in self.skip_methods:
            task_key_name = f"{module_name}.{gateway_method}"
            if task_key_name not in self.data[task_type]:
                self.data[task_type][task_key_name] = {
                    "success": 0,
                    "failure": 0,
                    "averageTimeInSec": 0,
                }

            method_data = self.data[task_type][task_key_name]

            if success:
                method_data["success"] += 1
            else:
                method_data["failure"] += 1

            if not MODEL_INFO:
                model_details = self._fetch_storage_info(
                    storage_list_name, *args, **kwargs
                )

                try:
                    if model_details and model_details not in self.data.get(
                        storage_list_name, []
                    ):
                        if isinstance(self.data.get(storage_list_name), list):
                            self.data[storage_list_name].append(model_details)
                        else:  # If the data is not a list, create a new list with the model details
                            self.data[storage_list_name] = [model_details]
                except Exception as e:
                    self.log.writeDebug(
                        f"Error fetching storage info in the telemetry: {e}"
                    )
                    pass
            try:
                total_calls = method_data["success"] + method_data["failure"]
                method_data["averageTimeInSec"] = round(
                    (
                        (method_data["averageTimeInSec"] * (total_calls - 1))
                        + elapsed_time
                    )
                    / total_calls,
                    2,
                )
            except ZeroDivisionError:
                method_data["averageTimeInSec"] = 0

            if MODEL_INFO:
                apig_request = APIGRequestModel(
                    module_name=module_name,
                    operation_name=gateway_method,
                    storage_model=MODEL_INFO.get("model", ""),
                    storage_serial=int(MODEL_INFO.get("serialNumber", None)),
                    storage_type=(
                        0 if storage_list_name == "sdsBlockStorageSystems" else 1
                    ),
                    connection_type=1 if task_type == "directConnectTasks" else 0,
                    operation_status=1 if success else 0,
                    process_time=elapsed_time,
                )
                # will update the threading part later
                thread = threading.Thread(target=process_request, args=(apig_request,))
                AWS_UPDATE_THREADS.append(thread)
                # thread.daemon = True
                thread.start()
                # Write updated data to file
                self._write_to_file()

            if ENABLE_AUDIT_LOG:
                # write_to_audit_log(url=url, kwargs=kwargs)
                audit_thread = threading.Thread(
                    target=write_to_audit_log, args=(url, kwargs, result)
                )
                AUDIT_THREADS.append(audit_thread)
                audit_thread.daemon = True
                audit_thread.start()
            if not success:
                raise exception_message  # Exception(f"open_url failed: {exception_message}")

            return result
        else:
            return result

    def _fetch_storage_info(self, storage_type, *args, **kwargs):
        """
        Parses the result of a storage info request to extract the model and serial number.
        """
        global MODEL_INFO
        try:
            exiting_url = kwargs.get("url", "")
            ep = ""
            ip_address = ""
            if storage_type == "sdsBlockStorageSystems":
                ep = f"/ConfigurationManager/simple/{SDSBlockEndpoints.GET_STORAGE_CLUSTER}"
            elif storage_type == "directConnectStorageSystems":
                ep = f"/ConfigurationManager/{Endpoints.GET_STORAGE_INFO}"
            else:
                match = re.search(r"storage-([a-f0-9]{32})", exiting_url)
                if match:
                    storage_id = match.group(0)
                    ep = "/porcelain/" + UAIGEndpoints.GET_STORAGE_DEVICE_BY_ID.format(
                        storage_id
                    )

            regex = (
                r"https?://([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+|\d{1,3}(?:\.\d{1,3}){3})"
            )
            match = re.search(regex, exiting_url)

            ex_method = kwargs.get("method")
            kwargs["method"] = "GET"

            if match:
                ip_address = match.group(1)

            URL = f"https://{ip_address}{ep}"
            kwargs["url"] = URL
            if kwargs.get("data"):
                kwargs["data"] = None
            if ip_address and ep:
                ex_content_type = kwargs.get("headers").get("Content-Type", "")
                kwargs["headers"]["Content-Type"] = "application/json"
                result = open_request(*args, **kwargs)
                result_content = json.loads(result.read().decode("utf-8"))
                if storage_type == "sdsBlockStorageSystems":
                    MODEL_INFO = {
                        "address": ip_address,
                        "serialNumber": result_content.get("internalId", ""),
                    }
                elif storage_type == "directConnectStorageSystems":
                    MODEL_INFO = {
                        "model": result_content.get("model", ""),
                        "serialNumber": result_content.get("serialNumber", ""),
                    }
                else:
                    data = result_content.get("data", {})
                    MODEL_INFO = {
                        "model": data.get("model", ""),
                        "serialNumber": data.get("serialNumber", ""),
                    }
                kwargs["method"] = ex_method
                kwargs["url"] = exiting_url
                kwargs["headers"]["Content-Type"] = ex_content_type
                return MODEL_INFO
            else:
                return None
        except Exception as e:
            self.log.writeDebug(f"Error fetching storage info in the telemetry: {e}")
            return None

    def _load_existing_data(self):
        """
        Loads existing data from the JSON file if it exists.
        If the file is invalid, it is moved to a backup directory, and a new empty file is created.
        """
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, "r") as file:
                    self.data = json.load(file)
            except json.JSONDecodeError as e:
                if os.path.getsize(self.output_file) == 0:
                    self.log.writeDebug(f"Empty file {self.output_file}")
                    self.data = {}
                    return
                else:
                    self.log.writeDebug(f"Invalid JSON in file {self.output_file}: {e}")
                    self._handle_corrupted_file(True)
            except Exception as e:
                self.log.writeDebug(f"Unexpected error reading {self.output_file}: {e}")
                self._handle_corrupted_file(True)
        else:
            # If the file does not exist, initialize with empty data
            self.data = {}

    def _write_to_file(self):
        """
        Writes the current tracking data to the JSON file safely using a unique hidden temp file.
        Ensures atomic writes and handles concurrent replace operations using a lock file.
        """
        lock_file = f"{self.output_file}.lock"
        temp_file = f"{self.output_file}.hidden.{uuid.uuid4().hex}.tmp"

        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

            # Write data to a hidden temporary file (no lock yet)
            with open(temp_file, "w") as file:
                json.dump(self.data, file, indent=4)

            # Lock only during the replacement step
            with open(lock_file, "w") as lock:
                fcntl.flock(
                    lock, fcntl.LOCK_EX
                )  # Acquire lock for the critical section
                os.replace(
                    temp_file, self.output_file
                )  # Atomic replacement of the file
                fcntl.flock(lock, fcntl.LOCK_UN)  # Release the lock

        except Exception as e:
            self.log.writeDebug(f"Error writing to file {self.output_file}: {e}")
            self._handle_corrupted_file()

        finally:
            # Clean up any leftover temporary file
            if os.path.exists(temp_file):
                os.remove(temp_file)

            # Optionally, clean up the lock file if no longer needed
            if os.path.exists(lock_file):
                os.remove(lock_file)

    def _handle_corrupted_file(self, corrupted=False):
        """
        Handles issues with the JSON file by moving it to a backup directory
        and creating a new empty JSON file. This is used for both read and write operations.
        """
        # Generate a timestamped backup file name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            filename = (
                f"corrupted_{timestamp}.json"
                if corrupted
                else f"usage_backup{timestamp}.json"
            )
            # Create backup directory
            backup_dir = os.path.join(
                os.path.dirname(self.output_file), "backup"
            )  # nosec
            os.makedirs(backup_dir, exist_ok=True)

            backup_file = os.path.join(backup_dir, filename)  # nosec

            # Move the corrupted file to the backup directory
            os.rename(self.output_file, backup_file)
            self.log.writeDebug(f"Moved corrupted file to {backup_file}")

            # Create a new empty JSON file
            self.data = {}
            with open(self.output_file, "w") as file:
                json.dump(self.data, file, indent=4)
            self.log.writeDebug(f"Created a new empty JSON file at {self.output_file}")
        except Exception as e:
            self.log.writeDebug(
                f"Failed to handle corrupted file {self.output_file}: {e}"
            )


def process_request(apig_body):
    log = Log()
    # Set the site_id for the request
    if not get_consent_flag():
        return
    apig_body.site = SITE_ID
    try:
        # Prepare the request body
        body = json.dumps(apig_body.to_dict())
        # # log.writeDebug(f"Processing request... {body}")
        log.writeDebug(f"Processing request APIG_URL {APIG_URL}")
        # log.writeDebug(f"Processing request body {body}")

        # Make a request using open_url from Ansible module
        response = open_request(
            url=APIG_URL,
            method="POST",
            data=body,
            headers={
                "Content-Type": "application/json",
                "user-agent": "ansible",
            },
            use_proxy=False,
            validate_certs=False,  # Set to True in production for security
            timeout=60,
        )

        response_data = response.read().decode()

        # Handle response
        if response.status != 200:
            log.writeError(f"Failed request. Status: {response.status}")
        else:
            log.writeDebug(
                f"Request processed successfully for {apig_body.operation_name}"
            )
            log.writeDebug(f"Response: {response_data}")

    except Exception as e:
        log.writeError(f"Error processing request: {e}")


def get_consent_flag():
    # Get API key
    global USER_CONSENT, CONSENT_FILE_PRESENT, SITE_ID

    if not CONSENT_FILE_PRESENT and os.path.exists(
        os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME)  # nosec
    ):
        CONSENT_FILE_PRESENT = True
    if not USER_CONSENT and os.path.exists(
        os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME)  # nosec
    ):
        with open(
            os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME), "r"  # nosec
        ) as file:  # nosec
            consent_data = json.load(file)
            if consent_data.get("user_consent_accepted", False):
                SITE_ID = consent_data.get("site_id")
                USER_CONSENT = True

    if USER_CONSENT and CONSENT_FILE_PRESENT:
        return True
    return False


def write_to_audit_log(url, request, response):
    """
    Writes the API call details to the audit log if enabled.
    """

    logger.writeAudit(
        f'API: {url}, Method: {request.get("method")}, Data: {request.get("data", None)}, Response Status: {response.status}'
    )
