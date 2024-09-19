#!/usr/bin/env python3

import logging
import sys
import argparse
import json
from collections import defaultdict
from parser import extract_attr_value
from sairedis import pysairedis

logger = logging.getLogger(__name__)

# Results get written to stdout, so we want to log errors to stderr to avoid mixing them up
logger.addHandler(logging.StreamHandler(sys.stderr))

HELP_TEXT = """
Query ASIC using the json provided in the --input file. The expected format is as follows:
    {
        "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:oid:0x18000000000628": [
            "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE",
            "SAI_BUFFER_POOL_ATTR_SIZE",
            "SAI_BUFFER_POOL_ATTR_TYPE"
        ],
        ...
    }

The results will be printed to stdout, in the following format:
    {
        "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:oid:0x18000000000628": {
            "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE": {
                "asicValue": "SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC",
                "success": true
            },
            "SAI_BUFFER_POOL_ATTR_SIZE": {
                "asicValue": null,
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


def load_input(input_file: argparse.FileType) -> dict:
    """
    Read the opened input JSON file with contents like so:
    {
        "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:oid:0x18000000000628": [
            "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE",
            "SAI_BUFFER_POOL_ATTR_SIZE",
            "SAI_BUFFER_POOL_ATTR_TYPE"
        ],
        ...
    }

    Closes the file after reading.

    :param input_file: Path to the input JSON file
    :return: The loaded JSON data
    """
    with input_file as f:
        return json.load(f)


def get_numeric_oid_from_label(oid_label: str) -> int:
    """
    From a label like "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:oid:0x18000000000628",
    extracts and returns the numeric oid part 0x18000000000628.

    NOTE: There's also another form like so:
    ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{\"bvid\":\"oid:0x260000000008da\",\"mac\":\"98:03:9B:03:22:14\",\"switch_id\":\"oid:0x21000000000000\"}
    which isn't currently supported.

    :param oid_label: The label to extract the oid from
    :return: The numeric oid value
    """
    # Extract the value segment e.g. oid:0x18000000000628
    value_segment = oid_label.split(":", 2)[2]
    if not value_segment.startswith("oid:"):
        raise NotImplementedError(f"Unsupported oid format: {oid_label}")

    oid_value = value_segment.split(":", 1)[1]
    return int(oid_value, 16)


def lookup_attribute_value_in_pysairedis(attr: str) -> int:
    """
    Given an attribute name like "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE", return the corresponding
    attribute oid from pysairedis.

    :param attr: The attribute name
    :return: The attribute oid value
    """
    return getattr(pysairedis, attr)


# Generate a one-time lookup table for all SAI status codes in the query results
sai_status_map = {
    "single": {},
    "range": defaultdict(list),
}
for key, value in vars(pysairedis).items():
    if key.startswith("SAI_STATUS_"):
        key = key.replace("SAI_STATUS_", "")
        if key.endswith("_0") or key.endswith("_MAX"):
            # Range
            range_key = key[:-2] if key.endswith("_0") else key[:-4]
            sai_status_map["range"][range_key].append(value)  # Add to end of list
            sai_status_map["range"][range_key].sort()  # Only ever 0-2 elements, so this won't be expensive
        else:
            # Single value
            sai_status_map["single"][value] = key


def map_sai_status_to_str(status_code: int) -> str:
    """
    Given a SAI status code e.g. -196608, return the string representation e.g. SAI_STATUS_ATTR_NOT_SUPPORTED

    :param status_code: The numeric SAI status code
    :return: The string representation of the status code
    """
    if status_code in sai_status_map["single"]:
        return sai_status_map["single"][status_code]

    # See if it falls in range of any status
    for status_str, status_code_range in sai_status_map["range"].items():
        if status_code_range[0] <= status_code and status_code <= status_code_range[1]:
            return status_str

    return "UNKNOWN_SAI_STATUS"


def get_attribute_value_from_asic(oid, attribute_oid):
    """
    Given an oid and attribute_oid, query the ASIC for the attribute value. The attribute value
    is transformed to match the format of the ASIC_DB.

    :param oid: The oid of the object to query
    :param attribute_oid: The attribute oid of the object to query
    :return: The attribute value from the ASIC in the format of the ASIC_DB
    """

    oid_type = pysairedis.sai_object_type_query(oid)
    object_type_name = pysairedis.sai_metadata_get_object_type_name(oid_type).replace("SAI_OBJECT_TYPE_", "")
    class_name = object_type_name.lower()
    # Handle special cases where the class name is different
    if object_type_name in ["BUFFER_POOL", "BUFFER_PROFILE"]:
        class_name = "buffer"
    api = getattr(pysairedis, f"sai_{class_name}_api_t")()
    status = getattr(pysairedis, f"sai_get_{class_name}_api")(api)
    assert status == pysairedis.SAI_STATUS_SUCCESS, (f"Failed to get sai API {api}. "
                                                     f"Status: {map_sai_status_to_str(status)} ({status})")

    attr_metadata = pysairedis.sai_metadata_get_attr_metadata(oid_type, attribute_oid)

    attr = pysairedis.sai_attribute_t()
    attr.id = attribute_oid
    if attr_metadata.attrvaluetype == pysairedis.SAI_ATTR_VALUE_TYPE_UINT32_LIST:
        # Extra initialization for reading into a list
        attr.value.u32list.count = 32
        attr.value.u32list.list = pysairedis.new_uint32_t_arr(attr.value.u32list.count)

    # Read the attribute from the ASIC into attr
    func_name = f"get_{object_type_name.lower()}_attribute"
    status = getattr(api, func_name)(oid, 1, attr)
    assert status == pysairedis.SAI_STATUS_SUCCESS, \
        (f"Failed to call SAI API {func_name} for oid {oid} and attribute "
         f"{attribute_oid}. Status: {map_sai_status_to_str(status)} ({status})")

    # Extract the attribute value from attr
    attr_value = extract_attr_value(attr_metadata, attr)
    return attr_value


def query_asic_objects(query_objects) -> dict:
    """
    Query the ASIC for the attributes of the objects provided in deserialized JSON input file format.

    :param query_objects: The deserialized JSON input file format
    :return: The deserialized JSON output format
    """

    results = defaultdict(dict)

    for oid_label_key, attributes in query_objects.items():
        try:
            logger.debug(f"Querying ASIC for object key {oid_label_key}")
            oid = get_numeric_oid_from_label(oid_label_key)
        except Exception as e:
            err_msg = f"Failed to extract oid from label '{oid_label_key}': {e}"
            logger.warning(err_msg)
            for attribute in attributes:
                results[oid_label_key][attribute] = {"success": False, "error": err_msg, "asicValue": None}
            continue

        for attribute in attributes:
            try:
                logger.debug(f"Querying ASIC object {oid_label_key} ({oid}) for attribute {attribute}")
                attribute_oid = lookup_attribute_value_in_pysairedis(attribute)
                asic_value = get_attribute_value_from_asic(oid, attribute_oid)

                # Convert to str to match how values are represented in ASIC_DB
                if asic_value in [True, False]:
                    # ASIC_DB represents these as lowercase
                    asic_value = str(asic_value).lower()
                elif asic_value is None:
                    asic_value = "NULL"
                else:
                    asic_value = str(asic_value)

                # Success
                results[oid_label_key][attribute] = {"asicValue": asic_value, "success": True}
                logger.debug((f"Got ASIC object {oid_label_key} ({oid}) -> attribute {attribute} ({attribute_oid}) "
                              f"value {asic_value}"))

            except Exception as e:
                err_msg = f"Failed to lookup attribute '{attribute}': {e}"
                logger.warning(err_msg)
                results[oid_label_key][attribute] = {"success": False, "error": err_msg, "asicValue": None}

    return dict(results)


def initialize_sai_api():
    """
    Initialize the SAI API
    """
    logger.info("Initializing SAI API")
    profileMap = dict()
    profileMap[pysairedis.SAI_REDIS_KEY_ENABLE_CLIENT] = "true"
    status = pysairedis.sai_api_initialize(0, profileMap)
    assert status == pysairedis.SAI_STATUS_SUCCESS, "Failed to initialize SAI API"
    logger.info("SAI API initialized")


def uninitialize_sai_api():
    """
    Uninitialize the SAI API
    """
    logger.info("Uninitializing SAI API")
    status = pysairedis.sai_api_uninitialize()
    assert status == pysairedis.SAI_STATUS_SUCCESS, "Failed to uninitialize SAI API"
    logger.info("SAI API uninitialized")


def main(args):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=HELP_TEXT)
    parser.add_argument("-i", "--input", type=argparse.FileType("r"), help="Input JSON file", required=True)
    args = parser.parse_args(args)

    try:
        query_objects = load_input(args.input)
    except Exception as e:
        sys.exit(f"Failed to parse JSON input file {args.input}: {e}")

    initialize_sai_api()

    try:
        results = query_asic_objects(query_objects)
    finally:
        uninitialize_sai_api()

    print(json.dumps(results))


if __name__ == "__main__":
    main(sys.argv[1:])
