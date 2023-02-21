* [Background](#Background)
* [Pipeline](#Pipeline)
* [Usage](#Usage)
  * [1. Get scanning results](#1-get-scanning-results)
  * [2. Upload results to Kusto](#2-upload-results-to-kusto)


# Background
This doc introduces the usage of scanning and uploading the case invocation report.

# Pipeline
1. Scan header files, generating `sai_header_scan_result.json`
2. Scan SAI API definitions, generating `sai_adapter_scan_result.json`
3. Parse and filter, generating compressed JSON result files
4. Upload JSON result files to Kusto


# Usage

## 1. Get scanning results

```bash
# 1. Scan SAI header files, generating sai_header_scan_result.json
python3 test_reporting/sai_coverage/sai_header_scanner.py inc

# 2. Scan SAI definitions in sai_adapter, generating sai_adapter_scan_result.json (static scanning)
python3 test_reporting/sai_coverage/sai_adapter_scanner.py src/sonic_sairedis/sai/sai_adapter

# 3. Generate the compressed result
python3 test_reporting/sai_coverage/case_scanner.py -p sai_test
python3 test_reporting/sai_coverage/case_scanner.py -p ptf
```

## 2. Upload results to Kusto

### a) Upload CaseInvocationCoverage

Firstly, the corresponding table and mapping should be created in Kusto by the following Kusto commands.
```kql
.create table CaseInvocationCoverage
(
id: string,
is_azure_used: bool,
file_name: string,
case_name: string,
class_name: string,
case_invoc: string,
sai_header: string,
saiintf_id: string,
saiintf_method_table: string,
sai_feature: string,
sai_api: string,
saiintf_alias: string,
test_set: string,
test_platform: string,
sai_obj_attr_key: string,
sai_obj_attr_value: string,
runnable: bool,
sai_folder: string,
upload_time: string
)


.create table CaseInvocationCoverage ingestion json mapping
'CaseInvocationCoverageMapping' '['
'{"column":"id","Properties":{"path":"$.id"}},'
'{"column":"is_azure_used","Properties":{"path":"$.is_azure_used"}},'
'{"column":"file_name","Properties":{"path":"$.file_name"}},'
'{"column":"case_name","Properties":{"path":"$.case_name"}},'
'{"column":"class_name","Properties":{"path":"$.class_name"}},'
'{"column":"case_invoc","Properties":{"path":"$.case_invoc"}},'
'{"column":"sai_header","Properties":{"path":"$.sai_header"}},'
'{"column":"saiintf_id","Properties":{"path":"$.saiintf_id"}},'
'{"column":"saiintf_method_table","Properties":{"path":"$.saiintf_method_table"}},'
'{"column":"sai_feature","Properties":{"path":"$.sai_feature"}},'
'{"column":"sai_api","Properties":{"path":"$.sai_api"}},'
'{"column":"saiintf_alias","Properties":{"path":"$.saiintf_alias"}},'
'{"column":"test_set","Properties":{"path":"$.test_set"}},'
'{"column":"test_platform","Properties":{"path":"$.test_platform"}},'
'{"column":"sai_obj_attr_key","Properties":{"path":"$.sai_obj_attr_key"}},'
'{"column":"sai_obj_attr_value","Properties":{"path":"$.sai_obj_attr_value"}},'
'{"column":"runnable","Properties":{"path":"$.runnable"}},'
'{"column":"sai_folder","Properties":{"path":"$.sai_folder"}},'
'{"column":"upload_time","Properties":{"path":"$.upload_time"}}]'
```

Then, connect to the `CaseInvocationCoverage` table and ingest data into it.
```bash
# 4. upload the results (json files) to Kusto
python3 test_reporting/report_uploader.py result/scan SaiTestData -c case_invoc
```

### b) Upload SAIHeaderDefinition

Firstly, the corresponding table and mapping should be created in Kusto by the following Kusto commands.

```kql
.create table SAIHeaderDefinition
(
sai_header: string,
sai_id: string,
sai_method_table: string,
sai_feature: string,
sai_api: string,
sai_alias: string,
branchName: string
)

.create table SAIHeaderDefinition ingestion json mapping
'SAIHeaderDefinitionMapping' '['
'{"column":"sai_header","Properties":{"path":"$.sai_header"}},'
'{"column":"sai_id","Properties":{"path":"$.sai_id"}},'
'{"column":"sai_method_table","Properties":{"path":"$.sai_method_table"}},'
'{"column":"sai_feature","Properties":{"path":"$.sai_feature"}},'
'{"column":"sai_api","Properties":{"path":"$.sai_api"}},'
'{"column":"sai_alias","Properties":{"path":"$.sai_alias"}}]'
```

Then, connect to the `SAIHeaderDefinition` table and ingest data into it.
```bash
# 4. upload the results (json files) to Kusto
python3 test_reporting/report_uploader.py result/sai_header_scan_result_test.json SaiTestData -c sai_header_def
```
