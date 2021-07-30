# SONiC Test Reporting

## Setup and Sanity Check
In the sonic-mgmt container:
```
source /var/johnar/env-python3/bin/activate
pytest
```

On a Linux host (verified against Ubuntu 20.04, but should work anywhere python3/virtualenv are supported):
```
virtualenv env
source env/bin/activate
pip3 install -r requirements.txt
pytest
```

## Uploading test results to a Kusto/Azure Data Explorer (ADX) cluster
You need to add the following environment variables first:
- TEST_REPORT_INGEST_KUSTO_CLUSTER: The ingest URL of your kusto/ADX cluster
- TEST_REPORT_AAD_TENANT_ID: The tenant ID of your Azure Active Directory (AAD) tenant
- TEST_REPORT_AAD_CLIENT_ID: The client ID for your AAD application
- TEST_REPORT_AAD_CLIENT_KEY: The secret key for your AAD application

Check out [this doc from Kusto](https://docs.microsoft.com/en-us/azure/data-explorer/provision-azure-ad-app) for more details about setting up AAD client applications for accessing Kusto.

Once these have been added, you can use the `report_uploader.py` script to upload test report data to Kusto:
```
% python3 report_uploader.py -c "test_result" <path to JUnit XML files produced by pytest> <database name>
```

For example:
```
% python3 report_uploader.py -c "test_result" ../results SonicTestData
```

Optionally you can add an external/tracking ID that will be uploaded as well:
```
% python3 report_uploader.py -c "test_result" -e PR#1995 ../results SonicTestData
```

## Components

### Report Uploader
Reports are uploaded to Kusto using the report_uploader script.
```
 % python3 report_uploader.py -h
usage: report_uploader.py [-h] [--external_id EXTERNAL_ID] [--json] [--category CATEGORY] path [path ...] database

Upload test reports to Kusto.

positional arguments:
  path                  list of file/directory to upload.
  database              The Kusto DB to upload to.

optional arguments:
  -h, --help            show this help message and exit
  --external_id EXTERNAL_ID, -e EXTERNAL_ID
                        An external tracking ID to append to the report.
  --json, -j            Load an existing test result JSON file from path_name.
  --category CATEGORY, -c CATEGORY
                        Type of data to upload (i.e. test_result, reachability, etc.)

Examples:
python3 report_uploader.py tests/files/sample_tr.xml -e TRACKING_ID#22
```

### XML Parser
JUnit XML test results will be converted to JSON for long-term storage. This functionality currently lives in `junit_xml_parser.py`.
```
 % python3 junit_xml_parser.py -h
usage: junit_xml_parser.py [-h] [--validate-only] [--compact] [--output-file OUTPUT_FILE] [--directory] [--strict] [--json] file

Validate and convert SONiC JUnit XML files into JSON.

positional arguments:
  file                  A file to validate/parse.

optional arguments:
  -h, --help            show this help message and exit
  --validate-only       Validate without parsing the file.
  --compact, -c         Output the JSON in a compact form.
  --output-file OUTPUT_FILE, -o OUTPUT_FILE
                        A file to store the JSON output in.
  --directory, -d       Provide a directory instead of a single file.
  --strict, -s          Fail validation checks if ANY file in a given directory is not parseable.
  --json, -j            Load an existing test result JSON file from path_name. Will perform validation only regardless of --validate-only option.

Examples:
python3 junit_xml_parser.py tests/files/sample_tr.xml
```

The script can be run directly from the CLI, which can also be helpful for development and debugging purposes. It also exposes several public functions for validating and parsing JUnit XML files and streams into JSON format from other Python scripts.
