# 1. Scan SAI header files, generating sai_header_scan_result.json
python3 test_reporting/sai_coverage/sai_header_scanner.py inc

# 2. Scan SAI definitions in sai_adapter, generating sai_adapter_scan_result.json (static scanning)
python3 test_reporting/sai_coverage/sai_adapter_scanner.py src/sonic_sairedis/sai/sai_adapter

# 3. Generate the compressed result
python3 test_reporting/sai_coverage/case_scanner.py -p sai_test
python3 test_reporting/sai_coverage/case_scanner.py -p ptf

# 4. upload the results (json files) to Kusto
python3 test_reporting/report_uploader.py result/scan SaiTestData -c case_invoc
