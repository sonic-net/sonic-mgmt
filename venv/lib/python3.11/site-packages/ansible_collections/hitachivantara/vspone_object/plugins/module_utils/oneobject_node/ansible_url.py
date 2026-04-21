import fcntl
import uuid
import json
import re
import os
import inspect
from ansible.module_utils.urls import open_url as open_request
from datetime import datetime
from urllib.parse import urlparse
from ..common.hv_utilities import StringUtilities as strutil


try:
    from ..common.hv_log import Log
    from ..common.ansible_common_constants import (
        TELEMETRY_FILE_PATH,
        TELEMETRY_FILE_NAME,
        USER_CONSENT_FILE_PATH,
        CONSENT_FILE_NAME,
        APIG_URL,
    )
    from ..common.hv_common_base_models import APIGRequestModel
except ImportError:
    from common.hv_log import Log
    from common.ansible_common_constants import (
        TELEMETRY_FILE_PATH,
        TELEMETRY_FILE_NAME,
        USER_CONSENT_FILE_PATH,
        CONSENT_FILE_NAME,
        APIG_URL,
    )

MODEL_INFO = None

AWS_UPDATE_THREADS = []

USER_CONSENT, CONSENT_FILE_PRESENT = False, False
SITE_ID = "common_site_id"


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
        self.output_file = os.path.join(TELEMETRY_FILE_PATH, TELEMETRY_FILE_NAME)
        self.data = {}
        self.class_map = {
            "VSPConnectionManager": "directConnectTasks",
            "SDSBConnectionManager": "sdsBlockTasks",
            "UAIGConnectionManager": "gatewayTasks",
        }
        self.storage_map = {
            "VSPConnectionManager": "directConnectStorageSystems",
            "SDSBConnectionManager": "sdsBlockStorageSystems",
            "UAIGConnectionManager": "gatewayStorageSystems",
        }
        self.skip_methods = ["getAuthToken"]
        self.storage_info_methods = ["get_storage_details"]
        self.model_info = None
        # self.ignore_apis = IGNORED_APIS

    def _extract_module_name(self, file_names):
        """
        Extracts the module name from a list of file paths based on specific criteria.
        """
        valid_subdirs = ["/oneobject_node/"]

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
        serial_number = kwargs.pop("serial_number", "N/A")
        elapsed_time = kwargs.pop("elapsed_time", 0)
        success = kwargs.pop("operation_status", False)

        # Backtrack calling context
        stack = inspect.stack()
        file_names = [stack.filename for stack in stack]
        module_name = self._extract_module_name(file_names)
        self.log.writeDebug(f"Module name: {module_name}")
        self.log.writeDebug(f"File names: {file_names}")
        operation_name = ""

        try:
            self.log.writeDebug(f"stack : {stack}")
            for stack_element in stack:
                self.log.writeDebug(f"stack functions: {stack_element.function} filename: {stack_element.filename}")
            gateway_index = next(
                (i for i, frame in enumerate(stack) if "gateway_oo.py" in frame.filename),
                None
            )
            operation_name = stack[gateway_index + 1].function
        except Exception as e:
            self.log.writeDebug("Cannot get stack :{}".format(e))
        region, cluster_name = extract_region_and_cluster(url)

        # Update tracking data
        self._load_existing_data()

        self.log.writeDebug(f"Data: {self.data}")

        self.data["vsponeobject_stats"] = self.data.get("vsponeobject_stats", {})

        vsponeobject_stats = self.data["vsponeobject_stats"]
        vsponeobject_stats[cluster_name] = vsponeobject_stats.get(cluster_name, {})
        vsponeobject_stats[cluster_name]["region"] = vsponeobject_stats[cluster_name].get(
            "region", region
        )
        vsponeobject_stats[cluster_name]["serial"] = vsponeobject_stats[cluster_name].get(
            "serial", "N/A"
        )
        method_data_all = vsponeobject_stats[cluster_name].get("MAPITasks", {})
        operation_name = strutil.snake_to_camel(operation_name)
        method_data = method_data_all.get(module_name + "." + operation_name, {})

        method_data["success"] = method_data.get("success", 0)
        method_data["failure"] = method_data.get("failure", 0)
        method_data["averageTimeInSec"] = method_data.get("averageTimeInSec", 0)
        self.log.writeDebug("success : {}".format(success))
        # if self.data is not None or self.data != {}:
        #     method_data = self.data["mapi_tasks"].get(module_name, {})

        if success:
            method_data["success"] = method_data.get("success", 0) + 1
        else:
            method_data["failure"] = method_data.get("failure", 0) + 1

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
        self.log.writeDebug(f"Method data: {method_data}")
        method_data_all[module_name + "." + operation_name] = method_data
        vsponeobject_stats[cluster_name]["MAPITasks"] = method_data_all
        vsponeobject_stats[cluster_name]["serial"] = serial_number
        self.data["vsponeobject_stats"] = vsponeobject_stats
        self.log.writeDebug(f"Data at the end: {self.data}")

        apig_request = APIGRequestModel(
            module_name=module_name,
            operation_name=operation_name,
            process_time=elapsed_time,
            operation_status=1 if success else 0,
            serial=serial_number,
            region=region,
            cluster_name=cluster_name
        )
        telemetry_response = process_request(apig_request)
        self._write_to_file()
        return telemetry_response

        # if not success:
        #     self.log.writeDebug("no success")
        # return result

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
            backup_dir = os.path.join(os.path.dirname(self.output_file), "backup")
            os.makedirs(backup_dir, exist_ok=True)

            backup_file = os.path.join(backup_dir, filename)

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
        log.writeDebug("no consent")
        return
    apig_body.site = SITE_ID
    response_data = None
    try:
        # Prepare the request body
        body = json.dumps(apig_body.to_dict())
        # # log.writeDebug(f"Processing request... {body}")
        log.writeDebug(f"Processing request APIG_URL... {APIG_URL}")

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
            log.writeDebug("status: {}".format(response.status))
            log.writeDebug(
                f"Request processed successfully for {apig_body.operation_name}"
            )
            log.writeDebug(f"Response: {response_data}")

    except Exception as e:
        log.writeError(f"Error processing request: {e}")

    return response_data


def get_consent_flag():
    # Get API key
    global USER_CONSENT, CONSENT_FILE_PRESENT, SITE_ID

    if not CONSENT_FILE_PRESENT and os.path.exists(
        os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME)
    ):
        CONSENT_FILE_PRESENT = True
    if not USER_CONSENT and os.path.exists(
        os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME)
    ):
        with open(os.path.join(USER_CONSENT_FILE_PATH, CONSENT_FILE_NAME), "r") as file:
            consent_data = json.load(file)
            if consent_data.get("user_consent_accepted", False):
                SITE_ID = consent_data.get("site_id")
                USER_CONSENT = True

    if USER_CONSENT and CONSENT_FILE_PRESENT:
        return True
    return False


def extract_region_and_cluster(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname  # Extracts 'admin.us-west-2b.vsp1o-2-k8s.scl.sie.hds.com'

    parts = hostname.split('.')

    if len(parts) < 3:
        raise ValueError("Invalid URL format")

    region = parts[1]  # The second part is the region
    cluster_name = '.'.join(parts[2:])  # Everything after region is the cluster name

    return region, cluster_name
