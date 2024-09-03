import pytest
import logging
import json
import os
import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

SYNCD_CONTAINER = "syncd"
QUERY_ASIC_SCRIPT = "query-asic.py"
LIBSAIREDIS_DEB = "libsairedis.deb"
PYTHON3_PYSAIREDIS_DEB = "python3-pysairedis.deb"
DUT_DST_PATH_HOST = "/tmp/consistency-checker"
DUT_DST_PATH_CONTAINER = "/consistency-checker"

DUT_SCRIPT_PATH_SRC = os.path.dirname(__file__) + "/" + QUERY_ASIC_SCRIPT
DUT_SCRIPT_PATH_DST_HOST = DUT_DST_PATH_HOST + "/" + QUERY_ASIC_SCRIPT
DUT_SCRIPT_PATH_DST_CONTAINER = DUT_DST_PATH_CONTAINER + "/" + QUERY_ASIC_SCRIPT


class ConsistencyChecker:

    def __init__(self, duthost, libsairedis_download_url=None, python3_pysairedis_download_url=None):
        """
        If the libsairedis_download_url and python3_pysairedis_download_url are provided, then these artifacts
        are downloaded and installed on the DUT, otherwise it's assumed that the environment is already setup
        for the consistency checker.
        """
        self._duthost = duthost
        self._libsairedis_download_url = libsairedis_download_url
        self._python3_pysairedis_download_url = python3_pysairedis_download_url

    def __enter__(self):
        logger.info("Setting up consistency checker on dut...")

        # TODO: Check that the files don't currently exist on the dut, if so indicative
        # of a concurrent or previous run that didn't cleanup properly

        self._duthost.shell(f"mkdir -p {DUT_DST_PATH_HOST}")
        self._duthost.copy(src=DUT_SCRIPT_PATH_SRC, dest=DUT_SCRIPT_PATH_DST_HOST)

        if self._libsairedis_download_url is not None:
            self._duthost.shell(f"curl -o {DUT_DST_PATH_HOST}/{LIBSAIREDIS_DEB} {self._libsairedis_download_url}")
        if self._python3_pysairedis_download_url is not None:
            self._duthost.shell(f"curl -o {DUT_DST_PATH_HOST}/{PYTHON3_PYSAIREDIS_DEB} {self._python3_pysairedis_download_url}")

        # Move everything into syncd container...
        self._duthost.shell((
            f"docker cp {DUT_DST_PATH_HOST} {SYNCD_CONTAINER}:/ && "
            f"rm -rf {DUT_DST_PATH_HOST}"
        ))

        if self._python3_pysairedis_download_url is not None:
            # Install python3-sairedis in syncd container
            self._duthost.shell((f"docker exec {SYNCD_CONTAINER} bash -c "
                                f"'cd {DUT_DST_PATH_CONTAINER} && dpkg --install {DUT_DST_PATH_CONTAINER}/{PYTHON3_PYSAIREDIS_DEB}'"))

        if self._libsairedis_download_url is not None:
            # Extract the libsairedis deb
            self._duthost.shell((f"docker exec {SYNCD_CONTAINER} bash -c "
                                f"'cd {DUT_DST_PATH_CONTAINER} && dpkg --extract {DUT_DST_PATH_CONTAINER}/{LIBSAIREDIS_DEB} libsairedis-temp'"))

        logger.info("Consistency checker setup complete.")

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.info("Cleaning up consistency checker on dut...")

        if self._python3_pysairedis_download_url is not None:
            # Uninstall python3-sairedis in syncd container
            self._duthost.shell(f"docker exec {SYNCD_CONTAINER} dpkg --remove python3-pysairedis")

        # Remove all the files from the syncd container
        self._duthost.shell(f"docker exec {SYNCD_CONTAINER} rm -rf {DUT_DST_PATH_CONTAINER}")

        logger.info("Consistency checker cleanup complete.")

    def get_db_and_asic_peers(self, keys=["*"]) -> dict:
        """
        Use cases:
         - Bulk query ASIC data that exists in the ASIC_DB. Caller is free to do what they wish with the result i.e. custom asserts
        This takes in an optional list of glob search strings that correspond to the --key arg of sonic-db-dump. sonic-db-dump doesn't take multiple keys, so a list is passed in to support multiple keys at the API level.
        For every object returned from the sonic-db-dump the ASIC is queried.

        Return val:
            {
                "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:oid:0x1900000000154f": {
                    "SAI_BUFFER_PROFILE_ATTR_POOL_ID": {
                        "dbValue": "oid:0x1800000000154a",
                        "asicValue": "oid:0x1800000000154a",
                        "asicQuerySuccess": true
                    },
                    "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": {
                        "dbValue": "0",
                        "asicValue": -1,
                        "asicQuerySuccess": false,
                        "asicQueryErrorMsg": "Failed to query attribute value"
                    },
                    "SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE": {
                        "dbValue": "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC",
                        "asicValue": "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC",
                        "asicQuerySuccess": true
                    },
                    ...
                },
                ...
            }
        """

        db_attributes = self._get_db_attributes(keys)
        asic_attributes = self._get_asic_attributes_from_db_results(db_attributes)

        results = defaultdict(dict)

        for object in db_attributes:
            db_object = db_attributes[object]
            asic_object = asic_attributes[object]

            for attr in db_object["value"].keys():
                db_value = db_object["value"][attr]
                asic_value = asic_object[attr]["asicValue"]

                if db_value.startswith("oid:0x"):
                    # Convert the asic one to the same format
                    try:
                        asic_value = f"oid:{hex(int(asic_value))}"
                    except Exception:
                        # keep the value as is
                        pass

                results[object][attr] = {
                    "dbValue": db_value,
                    "asicValue": asic_value,
                    "asicQuerySuccess": asic_object[attr]["success"]
                }

                if not asic_object[attr]["success"]:
                    results[object][attr]["asicQueryErrorMsg"] = asic_object[attr]["error"]

        return dict(results)

    def check_consistency(self, keys=["*"]) -> dict:
        """
        Use cases:
        -	Get the out-of-sync ASIC_DB and ASIC attributes. Caller can assert that there are no differences or print them for example. Differences are indicative of an error state.
        Same arg style as the get_objects function but returns a list of objects that don’t match or couldn’t be queried from the ASIC. If it was successfully queried and has a matching value, then it won’t be included in the response.

        Return val (matching):
            {}

        Return val (mismatch):
            {
                "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:oid:0x1900000000154f": {
                    "attributes": {
                        "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": {
                            "dbValue": "0",
                            "asicValue": -1,
                        },
                        "SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE": {
                            "dbValue": "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC",
                            "asicValue": "SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC"
                        },
                        ...
                    },
                    "failedToQueryAsic": [
                        {"SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": "Failed to query attribute value"}
                    ],
                    "mismatchedAttributes": ["SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE"]
                },
                ...
            }
        """

        db_attributes = self._get_db_attributes(keys)
        asic_attributes = self._get_asic_attributes_from_db_results(db_attributes)

        inconsistencies = defaultdict(lambda: {
            "attributes": {},
            "failedToQueryAsic": [],
            "mismatchedAttributes": []
        })

        for object in db_attributes:
            db_object = db_attributes[object]
            asic_object = asic_attributes[object]

            for attr in db_object["value"].keys():
                db_value = db_object["value"][attr]
                asic_value = asic_object[attr]["asicValue"]
                asic_query_success = asic_object[attr]["success"]

                if asic_query_success and db_value == asic_value:
                    continue

                if db_value.startswith("oid:0x"):
                    # Convert the asic one to the same format
                    try:
                        asic_value = f"oid:{hex(int(asic_value))}"
                        if db_value == asic_value:
                            continue
                    except Exception:
                        # true error - let below code handle it
                        pass

                inconsistencies[object]["attributes"][attr] = {
                    "dbValue": db_value,
                    "asicValue": asic_value
                }

                if asic_query_success:
                        inconsistencies[object]["mismatchedAttributes"].append(attr)
                else:
                    inconsistencies[object]["failedToQueryAsic"].append({attr: asic_object[attr]["error"]})

        return dict(inconsistencies)


    def get_asic_attribute(oid, attr_value) -> dict:
        """
        Use cases:
        -	Get a known attribute of an object oid that doesn't exist in the ASIC_DB but does exist in the ASIC. Can be used in an assert somewhere.
        Not all attributes that exist on an object down at the ASIC level are in the Redis DB (i.e. SAI_OBJECT_TYPE_SWITCH’s attribute SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS), this method provides a way to retrieve them.
        The oid is the hexadecimal int form i.e. 0x21000000000000.
        We need to be careful here to validate the user provided oid actually exists, else syncd will restart. The implementation will validate that it’s present in ASIC_DB before attempting to retrieve.

        """
        raise NotImplementedError


    def _get_db_attributes(self, keys: list) -> dict:
        """
        Fetchs and merges the attributes of the objects returned by the search key from the DB.
        """
        db_attributes = {}
        for key in keys:
            result = self._duthost.shell(f"sonic-db-dump -k '{key}' -n ASIC_DB")
            if result['rc'] != 0:
                raise Exception(f"Failed to fetch attributes for key '{key}' from ASIC_DB. Return code: {result['rc']}, stdout: {result['stdout']}, stderr: {result['stderr']}")

            query_result = json.loads(result['stdout'])
            db_attributes.update(query_result)

        return db_attributes

    def _get_asic_attributes_from_db_results(self, db_attributes: dict) -> dict:
        """
        Queries the ASIC for the attributes of the objects in db_attributes which are the results
        from the ASIC DB query.

        Example return value:
            {
                "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:oid:0x18000000000628": {
                    "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE": {
                        "asicValue": "SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC",
                        "success": true
                    },
                    "SAI_BUFFER_POOL_ATTR_SIZE": {
                        "success" false,
                        "error": "Failed to query attribute value"
                    },
                    "SAI_BUFFER_POOL_ATTR_TYPE": {
                        "asicValue": "SAI_BUFFER_POOL_TYPE_EGRESS",
                        "success": true
                    }
                },
                ...
            }
        """
        # Map to format expected by the dut script
        asic_query = {k: list(v["value"].keys()) for k, v in db_attributes.items()}
        asic_query_input_filename = f"query-input-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        with open(f"/tmp/{asic_query_input_filename}", 'w') as f:
            json.dump(asic_query, f)

        # Copy the input file to the syncd container
        self._duthost.copy(src=f"/tmp/{asic_query_input_filename}", dest=f"/tmp/{asic_query_input_filename}")
        self._duthost.shell((f"docker cp /tmp/{asic_query_input_filename} {SYNCD_CONTAINER}:{DUT_DST_PATH_CONTAINER} && "
                            f"rm /tmp/{asic_query_input_filename}"))

        ld_lib_path_arg = f"LD_LIBRARY_PATH=libsairedis-temp/usr/lib/x86_64-linux-gnu" if self._libsairedis_download_url is not None else ""

        res = self._duthost.shell((f"docker exec {SYNCD_CONTAINER} bash -c "
                                  f"'cd {DUT_DST_PATH_CONTAINER} && "
                                  f"{ld_lib_path_arg} python3 {DUT_SCRIPT_PATH_DST_CONTAINER} --input {asic_query_input_filename}'"))
        if res['rc'] != 0:
            raise Exception(f"Failed to query ASIC attributes. Return code: {res['rc']}, stdout: {res['stdout']}, stderr: {res['stderr']}")
        asic_results = json.loads(res['stdout'])

        return asic_results


class ConsistencyCheckerProvider:
    def is_consistency_check_supported(self, dut) -> bool:
        """
        Initially constrain to support versions 202311, 202405, master
        and skus 7060, 7260 (t0)
        """

        platform = dut.facts['platform']
        if platform not in ["x86_64-arista_7060_cx32s", "x86_64-arista_7260cx3_64"]:
            return False

        # TODO: Support 202405 and master
        version = dut.image_facts()['ansible_facts']['ansible_image_facts']['current']
        if "202305" not in version and "202311" not in version:
            return False

        return True

    def get_consistency_checker(self, dut, libsairedis_download_url=None, python3_pysairedis_download_url=None) -> ConsistencyChecker:
        return ConsistencyChecker(dut, libsairedis_download_url, python3_pysairedis_download_url)


@pytest.fixture
def consistency_checker_provider():
    return ConsistencyCheckerProvider()
