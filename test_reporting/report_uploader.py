import argparse
import os
import sys

from junit_xml_parser import (
    validate_junit_xml_file,
    validate_junit_xml_archive,
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

    args = parser.parse_args()

    path = args.path_name

    if not os.path.exists(path):
        print(f"{path} not found")
        sys.exit(1)

    # FIXME: This interface is actually really clunky, should just have one method and check file
    # v. dir internally. Fix in the next PR.
    if os.path.isfile(path):
        roots = [validate_junit_xml_file(path)]
    else:
        roots = validate_junit_xml_archive(path)

    test_result_json = parse_test_result(roots)
    tracking_id = args.external_id if args.external_id else ""

    kusto_db = KustoConnector(args.db_name)
    kusto_db.upload_report(test_result_json, tracking_id)


if __name__ == "__main__":
    _run_script()
