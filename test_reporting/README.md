# SONiC Test Reporting

## Setup environment

There are several options to run the test reporting scripts:
1. Inside the sonic-mgmt container (recommended for Linux)
2. On a Windows host with Python virtual environment
3. On a Linux host with Python virtual environment

### Option 1: Inside the sonic-mgmt container (recommended for Linux)
Go to this folder in the sonic-mgmt container:
```bash
cd <your_path_to_sonic-mgmt>/test_reporting
```

### Option 2: On a Windows host
On Windows (verified with Windows 10/11, requires Python 3.7+):

1. **Create and activate virtual environment:**
```cmd
cd <your_path_to_sonic-mgmt>\test_reporting
python -m venv .venv
.venv\Scripts\activate
```

2. **Install dependencies:**
```cmd
pip install -r requirements.txt
```

### Option 3: On a Linux host
On Linux (verified against Ubuntu 20.04, but should work anywhere python3/virtualenv are supported):

1. **Create and activate virtual environment:**
```bash
cd <your_path_to_sonic-mgmt>/test_reporting
python3 -m venv .venv
source .venv/bin/activate
```

2. **Install dependencies:**
```bash
pip3 install -r requirements.txt
```

## Test Results Files
Place JUnit XML test result files in a directory (e.g., `../results`). Subdirectories are supported. All `.xml` files will be automatically processed.

## Authentication Methods

The report uploader supports multiple authentication methods for connecting to Kusto/Azure Data Explorer:

**⚠️ IMPORTANT:** All authentication methods require this environment variable:
- `TEST_REPORT_INGEST_KUSTO_CLUSTER`: The ingest URL of your Kusto/ADX cluster

### 1. Application Key (appKey) - Default
**Additional environment variables required:**
- `TEST_REPORT_AAD_TENANT_ID`: The tenant ID of your Azure Active Directory (AAD) tenant
- `TEST_REPORT_AAD_CLIENT_ID`: The client ID for your AAD application
- `TEST_REPORT_AAD_CLIENT_KEY`: The secret key for your AAD application

**Usage:**
```bash
python report_uploader.py -a appKey -c "test_result" ../results <database>
```

### 2. Default Azure Credential (defaultCred) - Recommended for local development
This method automatically discovers credentials from multiple sources in this order:
- Environment variables
- Managed Identity (when running on Azure)
- Visual Studio Code (when logged in)
- Azure CLI (when logged in)
- Interactive browser authentication (as fallback)

**Requirements:**
```bash
pip install azure-identity
```

**Setup (choose one):**
```bash
# Option A: Azure CLI (recommended)
az login

# Option B: Visual Studio Code with Azure extension (login in VS Code)
# Option C: Interactive browser (will prompt automatically)
```

**Usage:**
```bash
python report_uploader.py -a defaultCred -c "test_result" ../results <database>
```

### 3. Managed Service Identity (managedId)
For Azure VMs with managed identity enabled.

**Optional environment variable:**
- `TEST_REPORT_AAD_MANAGED_IDENTITY_CLIENT_ID`: Client ID for user-assigned managed identity (leave unset for system-assigned)

**Usage:**
```bash
python report_uploader.py -a managedId -c "test_result" ../results <database>
```

### 4. Interactive Browser (interactive)
After running the command, a browser window will open automatically where you need to authenticate with your Azure credentials, then the script will continue execution.

**Usage:**
```bash
python report_uploader.py -a interactive -c "test_result" ../results <database>
```

### 5. Azure CLI (azureCli)
Uses credentials from Azure CLI.

**Setup:**
```bash
az login
```

**Usage:**
```bash
python report_uploader.py -a azureCli -c "test_result" ../results <database>
```

### 6. Device Code (deviceCode)
For environments without a web browser (displays a code to enter on another device).

The script will prompt user to open an URL on another device, enter the displayed code and authenticate.

**Usage:**
```bash
python report_uploader.py -a azureCli -c "test_result" ../results <database>
```

### 7. User Token (userToken)
Uses a user access token obtained from Azure CLI.

**⚠️ NOTICE:** Obtaining access tokens may be blocked by your tenant's access policy. If you encounter permission errors, contact your Azure administrator or use an alternative authentication method.

**Setup:**
```bash
# Login to Azure CLI
az login

# Get user access token and set environment variable
# Windows (Command Prompt)
for /f "tokens=*" %i in ('az account get-access-token --resource https://kusto.kusto.windows.net --query accessToken --output tsv') do set TEST_REPORT_AAD_USER_TOKEN=%i

# Windows (PowerShell)
$env:TEST_REPORT_AAD_USER_TOKEN = (az account get-access-token --resource https://kusto.kusto.windows.net --query accessToken --output tsv)

# Linux/macOS
export TEST_REPORT_AAD_USER_TOKEN=$(az account get-access-token --resource https://kusto.kusto.windows.net --query accessToken --output tsv)
```

**Additional environment variables required:**
- `TEST_REPORT_AAD_USER_TOKEN`: A valid user access token

**Usage:**
```bash
python report_uploader.py -a userToken -c "test_result" ../results <database>
```

### 8. Application Token (appToken)
Uses a pre-obtained application access token.

**Additional environment variable required:**
- `TEST_REPORT_AAD_APP_TOKEN`: A valid application access token

**Usage:**
```bash
python report_uploader.py -a appToken -c "test_result" ../results <database>
```

Check out [this doc from Kusto](https://docs.microsoft.com/en-us/azure/data-explorer/provision-azure-ad-app) for more details about setting up AAD client applications for accessing Kusto.

## Uploading test results to a Kusto/Azure Data Explorer (ADX) cluster

If you want to upload data into a new table, please add the related create table commands in setup.kql file and run them manually in Kusto.
Make sure the table is created and mapping is generated successfully.

### Basic Usage

**Using Default Azure Credential (recommended for development):**
```bash
# Windows
python report_uploader.py -c "test_result" -a defaultCred ../results <database_name>

# Linux
python3 report_uploader.py -c "test_result" -a defaultCred ../results <database_name>
```

**Using Application Key:**
```bash
# Windows
python report_uploader.py -c "test_result" -a appKey ../results <database_name>

# Linux
python3 report_uploader.py -c "test_result" -a appKey ../results <database_name>
```

### Examples

**Upload test results with default authentication:**
```bash
# Windows
python report_uploader.py -c "test_result" -a defaultCred ../results SonicTestData

# Linux
python3 report_uploader.py -c "test_result" -a defaultCred ../results SonicTestData
```

**Upload with external tracking ID:**
```bash
# Windows
python report_uploader.py -c "test_result" -a defaultCred -e PR#1995 ../results SonicTestData

# Linux
python3 report_uploader.py -c "test_result" -a defaultCred -e PR#1995 ../results SonicTestData
```

**Upload with testbed and version information:**
```bash
# Windows
python report_uploader.py -c "test_result" -a defaultCred -t "vms-kvm-t0" -o "master" ../results SonicTestData

# Linux
python3 report_uploader.py -c "test_result" -a defaultCred -t "vms-kvm-t0" -o "master" ../results SonicTestData
```

**Upload using Azure CLI authentication:**
```bash
# First login to Azure CLI
az login

# Windows
python report_uploader.py -c "test_result" -a azureCli ../results SonicTestData

# Linux
python3 report_uploader.py -c "test_result" -a azureCli ../results SonicTestData
```

## Run sanity check
This folder contains some test code for junit XML parser. If any change was made to the parser, please do remember to update the tests and run tests as well to ensure that there is no regression.

To run the tests, install additional development dependencies:

**Windows:**
```cmd
# Make sure you're in the virtual environment
.venv\Scripts\activate
pip install -r requirements_dev.txt
```

**Linux:**
```bash
# Make sure you're in the virtual environment
source .venv/bin/activate
pip3 install -r requirements_dev.txt
```

Run tests using pytest:

**Windows:**
```cmd
pytest
```

**Linux:**
```bash
pytest
```

## Troubleshooting

### Common Issues

**1. Permission denied errors on Windows:**
- Make sure you're running the command prompt as Administrator if needed
- Ensure the virtual environment is activated
- Check that the Azure CLI or Visual Studio Code is properly authenticated

**2. Authentication failures:**
- For `defaultCred`: Ensure you're logged into Azure CLI (`az login`) or Visual Studio Code
- For `appKey`: Verify all required environment variables are set correctly
- Check that your user/application has the necessary ingestor permissions on the Kusto database

**3. Module not found errors:**
- Make sure you've activated the virtual environment
- Reinstall requirements: `pip install -r requirements.txt`

**4. Kusto ingestor permissions:**
If you get permission errors, add your user/application to the ingestor role:
```kusto
.add database <YourDatabaseName> ingestors ('aaduser=<your-email@domain.com>')
```
or for service principals:
```kusto
.add database <YourDatabaseName> ingestors ('aadapp=<application-id>')
```

### Virtual Environment Commands Reference

**Windows:**
```cmd
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# Deactivate virtual environment
deactivate

# Install packages
pip install -r requirements.txt
```

**Linux:**
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Deactivate virtual environment
deactivate

# Install packages
pip3 install -r requirements.txt
```

## Components

### Report Uploader
Reports are uploaded to Kusto using the report_uploader script.

**Windows:**
```cmd
python report_uploader.py -h
```

**Linux:**
```bash
python3 report_uploader.py -h
```

```
usage: report_uploader.py [-h] [--external_id EXTERNAL_ID] [--json]
                          [--category CATEGORY] [--testbed TESTBED]
                          [--auth_method {appKey,managedId,interactive,azureCli,deviceCode,userToken,appToken,defaultCred}]
                          [--image_url IMAGE_URL | --version VERSION]
                          path [path ...] database

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
  --testbed TESTBED, -t TESTBED
                        Name of testbed.
  --auth_method {appKey,managedId,interactive,azureCli,deviceCode,userToken,appToken,defaultCred}, -a {appKey,managedId,interactive,azureCli,deviceCode,userToken,appToken,defaultCred}
                        Authentication method for Kusto connection.
  --image_url IMAGE_URL, -i IMAGE_URL
                        Image url. If has this argument, will ignore version. They are mutually exclusive.
  --version VERSION, -o VERSION
                        OS version. If has this argument, will ignore image_url. They are mutually exclusive.

Examples:
python3 report_uploader.py tests/files/sample_tr.xml -e TRACKING_ID#22
```

### XML Parser
JUnit XML test results will be converted to JSON for long-term storage. This functionality currently lives in `junit_xml_parser.py`.

**Windows:**
```cmd
python junit_xml_parser.py -h
```

**Linux:**
```bash
python3 junit_xml_parser.py -h
```

```
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
# Windows
python junit_xml_parser.py tests\files\sample_tr.xml

# Linux
python3 junit_xml_parser.py tests/files/sample_tr.xml
```

The script can be run directly from the CLI, which can also be helpful for development and debugging purposes. It also exposes several public functions for validating and parsing JUnit XML files and streams into JSON format from other Python scripts.
