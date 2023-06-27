"""
This file scans SAI header
"""

import json
import os
import sys

from pyclibrary import CParser

from constant import (IGNORE_HEADER_FILE_LIST, PRIORI_RESULT_SAVE_DIR,
                      SAI_HEADER_FILENAME, SAI_HEADER_FILENAME_UPLOAD)
from data_model.sai_interface_header import SAIInterfaceHeader
from sai_report_utils import store_result


def parse(dir_path):
    """
    Parse SAI hearder files to a json file

    Args:
        dir_path: path of SAI headers
    """
    sai_apis = dict()
    sai_apis_upload = list()
    for (root, _, filenames) in os.walk(dir_path):
        for filename in filenames:
            if filename.endswith(".h") and filename not in IGNORE_HEADER_FILE_LIST:
                parser = CParser([root + "/" + filename])
                for key in parser.defs['structs']:
                    if "api" in key:
                        sai_api_list = _parse_api_list_struct(parser, key)
                        intf_groupname = "SAI_API_" + \
                            filename.split(".")[0].split("sai")[1].upper()
                        intf_groupalias = key[1:]
                        filename = filename.split(".")[0]
                        sai_apis = generate_sai_header_json(
                            intf_groupname, intf_groupalias, sai_api_list, filename, sai_apis)
                        generate_sai_header_upload_json(
                            intf_groupname, intf_groupalias, sai_api_list, filename, sai_apis_upload)
    os.makedirs(PRIORI_RESULT_SAVE_DIR, exist_ok=True)
    store_result(sai_apis, os.path.join(
        PRIORI_RESULT_SAVE_DIR, SAI_HEADER_FILENAME))
    store_result(sai_apis_upload, os.path.join(
        PRIORI_RESULT_SAVE_DIR, SAI_HEADER_FILENAME_UPLOAD))


def generate_sai_header_json(intf_groupname, intf_groupalias, intf_list, filename, sai_apis):
    """
    Generate SAI header json file

    Args:
        dir_path: path of SAI headers
    """
    for element in intf_list:
        for (intf_alias, intf_name) in element.items():
            sai_intf = SAIInterfaceHeader(
                intf_groupname, intf_groupalias, intf_alias, filename)
            sai_apis[intf_name] = sai_intf.__dict__

    return sai_apis


def generate_sai_header_upload_json(intf_groupname, intf_groupalias, intf_list, filename, sai_apis):
    """
    Generate SAI header json file

    Args:
        dir_path: path of SAI headers
    """
    for element in intf_list:
        for (intf_alias, _) in element.items():
            sai_intf = SAIInterfaceHeader(
                intf_groupname, intf_groupalias, intf_alias, filename)
            sai_apis.append(sai_intf.__dict__)


def _parse_api_list_struct(parser, key):
    """
    Parse SAI header

    Args:
        parser: CParser result
        key: be like _sai_scheduler_group_api_t
    """
    print("processing: " + key)
    original_parser_str = parser.defs['structs'][key].__str__()

    rindex_bracket = original_parser_str.rindex(")")

    new_str = original_parser_str[0:rindex_bracket] + \
        "]" + original_parser_str[rindex_bracket + 1:]

    ret_str = new_str.replace("'", "\"").replace("Struct(", "[").replace(
        "\", Type(", "\":").replace(", None)", "").replace("(", "{").replace(")", "}")

    return json.loads(ret_str)


if __name__ == '__main__':
    header_path = sys.argv[1]
    parse(header_path)
