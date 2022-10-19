import os
import json
import sys
from saitest_report_base import *
from pyclibrary import CParser


def parse(dir_path):
    sai_apis = dict()
    for (root, _, filenames) in os.walk(dir_path):
        for filename in filenames:
            if filename.endswith(".h") and filename not in IGNORE_HEADER_FILE_LIST:
                parser = CParser([root + "/" + filename])
                for key in parser.defs['structs']:
                    if "api" in key:
                        sai_api_list = _parse_api_list_struct(parser, key)
                        intf_groupname = "SAI_API_" + filename.split(".")[0].split("sai")[1].upper()
                        intf_groupalias = key[1:]
                        filename = filename.split(".")[0]
                        sai_apis = generate_intr_json(intf_groupname, intf_groupalias, sai_api_list, filename, sai_apis)
    store_result(sai_apis, SAI_INTF_TARGET_FILENAME)


def generate_intr_json(intf_groupname, intf_groupalias, intf_list, filename, sai_apis):
    for element in intf_list:
        for (intf_alias, intf_name) in element.items():
            sai_intf = SAIInterfaceHeader(
                intf_groupname, intf_groupalias, intf_name, intf_alias, filename)
            sai_apis[intf_name] = sai_intf.__dict__

    return sai_apis


def _parse_api_list_struct(parser, key):
    print("processing: " + key)
    original_parser_str = parser.defs['structs'][key].__str__()

    rindex_bracket = original_parser_str.rindex(")")

    new_str = original_parser_str[0:rindex_bracket] + "]" + original_parser_str[rindex_bracket + 1:]

    ret_str = new_str.replace("'", "\"").replace("Struct(", "[").replace(
        "\", Type(", "\":").replace(", None)", "").replace("(", "{").replace(")", "}")

    return json.loads(ret_str)


if __name__ == '__main__':
    header_path = sys.argv[1]
    parse(header_path)
