import argparse

from junit_xml_parser import (
    validate_junit_json_file,
    validate_junit_xml_path,
    parse_test_result
)
from report_data_storage import KustoConnector


def _run_script():
    parser = argparse.ArgumentParser(
        description="Upload test reports to Kusto.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
python3 report_uploader.py tests/files/sample_tr.xml -e TRACKING_ID#22
""",
    )
    parser.add_argument("path_name", metavar="path", type=str, help="A file/directory to upload.")
    parser.add_argument("db_name", metavar="database", type=str, help="The Kusto DB to upload to.")
    parser.add_argument(
        "--external_id", "-e", type=str, help="An external tracking ID to append to the report.",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Load an existing test result JSON file from path_name.",
    )

    args = parser.parse_args()

    if args.json:
        test_result_json = validate_junit_json_file(args.path_name)
    else:
        roots = validate_junit_xml_path(args.path_name)
        test_result_json = parse_test_result(roots)

    tracking_id = args.external_id if args.external_id else ""

    kusto_db = KustoConnector(args.db_name)
    kusto_db.upload_report(test_result_json, tracking_id)


if __name__ == "__main__":
    _run_script()
