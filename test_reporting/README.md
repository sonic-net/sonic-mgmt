# SONiC Test Reporting

## Setup and Sanity Check
**Note:** These instructions currently only work _outside_ the management container (the Docker image needs to be updated to include pip3).
```
virtualenv env
source env/bin/activate
pip3 install -r requirements.txt
pytest
```

## Components

### XML Parser
JUnit XML test results will be converted to JSON for long-term storage. This functionality currently lives in `junit_xml_parser.py`.
```
% python3 junit_xml_parser.py -h
usage: junit_xml_parser.py [-h] [--validate-only] [--compact] [--output-file OUTPUT_FILE] file

Validate and convert SONiC JUnit XML files into JSON.

positional arguments:
file                  A file to validate/parse.

optional arguments:
-h, --help            show this help message and exit
--validate-only       Validate without parsing the file.
--compact, -c         Output the JSON in a compact form.
--output-file OUTPUT_FILE, -o OUTPUT_FILE
                        A file to store the JSON output in.

Examples:
python3 junit_xml_parser.py tests/files/sample_tr.xml
```

The script can be run directly from the CLI, which can also be helpful for development and debugging purposes. It also exposes several public functions for validating and parsing JUnit XML files and streams into JSON format from other Python scripts.
