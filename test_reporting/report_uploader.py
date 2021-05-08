import argparse
import json
import sys
import uuid

from junit_xml_parser import (
    validate_junit_json_file,
    validate_junit_xml_path,
    parse_test_result
)
from report_data_storage import KustoConnector
from utilities import validate_json_file


def _run_script():
    parser = argparse.ArgumentParser(
        description="Upload test reports to Kusto.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
python3 report_uploader.py tests/files/sample_tr.xml -e TRACKING_ID#22
""",
    )
    parser.add_argument("path_list", metavar="path", nargs="+", type=str, help="list of file/directory to upload.")
    parser.add_argument("db_name", metavar="database", type=str, help="The Kusto DB to upload to.")
    parser.add_argument(
        "--external_id", "-e", type=str, help="An external tracking ID to append to the report.",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Load an existing test result JSON file from path_name.",
    )
    parser.add_argument(
        "--category", "-c", type=str, help="Type of data to upload (i.e. test_result, reachability, etc.)"
    )

    args = parser.parse_args()
    kusto_db = KustoConnector(args.db_name)

    if args.category == "test_result":
        tracking_id = args.external_id if args.external_id else ""
        report_guid = str(uuid.uuid4())
        for path_name in args.path_list:
            is_reboot_report = "reboot_report" in path_name
            if is_reboot_report:
                test_result_json = validate_json_file(path_name)
                kusto_db.upload_reboot_report(test_result_json, report_guid)
            else:
                if args.json:
                    test_result_json = validate_junit_json_file(path_name)
                else:
                    roots = validate_junit_xml_path(path_name)
                    test_result_json = parse_test_result(roots)
                kusto_db.upload_report(test_result_json, tracking_id, report_guid)
    elif args.category == "reachability":
        reachability_data = []
        for path_name in args.path_list:
            with open(path_name) as f:
                reachability_data.extend(json.load(f))

        kusto_db.upload_reachability_data(reachability_data)
    elif args.category == "pdu_status":
        pdu_data = []
        for path_name in args.path_list:
            with open(path_name) as f:
                pdu_data.extend(json.load(f))

        kusto_db.upload_pdu_status_data(pdu_data)
    else:
        print('Unknown category "{}"'.format(args.category))
        sys.exit(1)


if __name__ == "__main__":
    _run_script()
