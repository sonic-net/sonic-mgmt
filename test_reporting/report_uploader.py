import argparse
import glob
import json
import sys
import uuid
import re
import os

from junit_xml_parser import (
    validate_junit_json_file,
    validate_junit_xml_path,
    parse_test_result
)
from report_data_storage import KustoConnector


def _parse_os_version(image_url):
    """Parse os version from image url"""
    os_version = ''
    items = image_url.split("/")
    if "public" in items or "master" in items:
        os_version = "master"
    elif "internal" in items:
        os_version = "internal"
    else:
        # For other images, such as 202012, there is internal-202012 in url.
        for item in items:
            if "internal" in item:
                os_version = item.split("-")[-1]
    return os_version if os_version else "UNKNOWN"


def _warn_skipped_xml_files(directory_name, roots):
    """Print a warning for the XML files under directory_name that are not in roots; return True if any."""
    # Looks for every XML file in any case (regular files only, not directories named *.xml), while
    # validate_junit_xml_archive only parses lower-case *.xml and skips invalid ones.
    pattern = os.path.join(directory_name, "**", "*.[xX][mM][lL]")
    xml_files = {path for path in glob.glob(pattern, recursive=True) if os.path.isfile(path)}
    skipped = sorted(xml_files - {document for _, document in roots})
    if skipped:
        names = ", ".join(os.path.relpath(document, directory_name) for document in skipped[:20])
        if len(skipped) > 20:
            names += " ..."
        print(f"WARNING: skipped {len(skipped)} of {len(xml_files)} XML file(s) under '{directory_name}': {names}")
    return bool(skipped)


def _run_script():
    parser = argparse.ArgumentParser(
        description="Upload test reports to Kusto.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
python3 report_uploader.py tests/files/sample_tr.xml -e TRACKING_ID#22
""",
    )
    parser.add_argument("path_list", metavar="path", nargs="+",
                        type=str, help="list of file/directory to upload.")
    parser.add_argument("db_name", metavar="database",
                        type=str, help="The Kusto DB to upload to.")
    parser.add_argument(
        "--external_id", "-e", type=str, help="An external tracking ID to append to the report.",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Load an existing test result JSON file from path_name.",
    )
    parser.add_argument(
        "--category", "-c", type=str, help="Type of data to upload (i.e. test_result, reachability, etc.)"
    )
    parser.add_argument(
        "--testbed", "-t", type=str, help="Name of testbed."
    )
    parser.add_argument(
        "--auth_method", "-a", type=str,
        choices=["appKey", "managedId", "interactive", "azureCli",
                 "deviceCode", "userToken", "appToken", "defaultCred"],
        default="appKey",
        help="Authentication method for Kusto connection."
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="test_result only: exit 1 if any path fails to parse or queue, or yields no test results\n"
             "(some data may already be queued); exit 3 if every path was queued but some XML files\n"
             "under a folder were skipped. Without it, errors are printed and the exit code is 0."
    )
    os_version = parser.add_mutually_exclusive_group(required=False)
    os_version.add_argument(
        "--image_url", "-i", type=str,
        help="Image url. If has this argument, will ignore version. They are mutually exclusive."
    )
    os_version.add_argument(
        "--version", "-o", type=str,
        help="OS version. If has this argument, will ignore image_url. They are mutually exclusive."
    )

    args = parser.parse_args()

    try:
        kusto_db = KustoConnector(args.db_name, args.auth_method)
    except Exception as e:
        print(f"Failed to create KustoConnector: {e}")
        import traceback
        traceback.print_exc()
        raise

    if args.category == "test_result":
        tracking_id = args.external_id if args.external_id else ""
        report_guid = str(uuid.uuid4())
        testbed = args.testbed
        if args.image_url:
            version = _parse_os_version(args.image_url)
        elif args.version:
            version = args.version
        else:
            version = "UNKNOWN"
        failed_paths = []
        skipped_paths = []
        for path_name in args.path_list:
            try:
                reboot_data_regex = re.compile(
                    '.*test.*_(reboot|sad|upgrade_path).*_(summary|report).json')
                if reboot_data_regex.match(path_name):
                    kusto_db.upload_reboot_report(path_name, tracking_id, report_guid)
                else:
                    if args.json:
                        test_result_json = validate_junit_json_file(path_name)
                    else:
                        roots = validate_junit_xml_path(path_name)
                        test_result_json = parse_test_result(roots)
                    if args.strict and not test_result_json:
                        raise ValueError(f"no test results found in '{path_name}'")
                    kusto_db.upload_report(test_result_json, tracking_id, report_guid, testbed, version)
                    if args.strict and not args.json and os.path.isdir(path_name):
                        if _warn_skipped_xml_files(path_name, roots):
                            skipped_paths.append(path_name)
            except Exception as e:
                failed_paths.append(path_name)
                print(f"Failed to upload report '{path_name}', exception: {repr(e)}")
                import traceback
                traceback.print_exc()
        if args.strict:
            if failed_paths:
                print(f"ERROR: {len(failed_paths)} of {len(args.path_list)} path(s) failed: {', '.join(failed_paths)}")
                sys.exit(1)
            if skipped_paths:
                sys.exit(3)
    elif args.category == "reachability":
        reachability_data = []
        for path_name in args.path_list:
            try:
                with open(path_name) as f:
                    reachability_data.extend(json.load(f))
            except Exception as e:
                print("Failed to parse reachability data '{}', exception: {}".format(path_name, repr(e)))

        kusto_db.upload_reachability_data(reachability_data)
    elif args.category == "pdu_status":
        pdu_data = []
        for path_name in args.path_list:
            try:
                with open(path_name) as f:
                    pdu_data.extend(json.load(f))
            except Exception as e:
                print("Failed to parse pdu status data '{}', exception: {}".format(path_name, repr(e)))

        kusto_db.upload_pdu_status_data(pdu_data)
    elif args.category == 'expected_runs':
        expected_runs = []
        for path_name in args.path_list:
            try:
                with open(path_name) as f:
                    expected_runs.extend(json.load(f))
            except Exception as e:
                print("Failed to parse expected runs data '{}', exception: {}".format(path_name, repr(e)))
        kusto_db.upload_expected_runs(expected_runs)
    elif args.category == 'case_numbers':
        case_numbers = []
        for path_name in args.path_list:
            with open(path_name) as f:
                case_numbers.extend(json.load(f))
        kusto_db.upload_case_numbers(case_numbers)
    elif args.category == "case_invoc":
        for path_name in args.path_list:
            fns = os.listdir(path_name)
            count = 0
            for fn in fns:
                try:
                    fn = os.path.join(path_name, fn)
                    kusto_db._upload_case_invoc_report_file(fn)
                    count += 1
                    print("Ingested file {}, {}/{}".format(fn, count, len(fns)))
                except Exception as e:
                    print("Failed to ingest file '{}', exception: {}".format(fn, repr(e)))
    elif args.category == "sai_header_def":
        for path_name in args.path_list:
            try:
                kusto_db.upload_sai_header_def_report_file(path_name)
            except Exception as e:
                print("Failed to ingest file '{}', exception: {}".format(path_name, repr(e)))

    else:
        print('Unknown category "{}"'.format(args.category))
        sys.exit(1)


if __name__ == "__main__":
    _run_script()
