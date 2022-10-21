# 1. generate saiintf_target.json
python3 test_reporting/sai_coverage/saiintf_target_scanner.py inc

# 2. generate sai_adaptor.json (static scanning)
python3 test_reporting/sai_coverage/saiintf_def_scanner.py src/sonic_sairedis/sai/sai_adapter

# 3. generate compressed.json and flatten.json
python3 test_reporting/sai_coverage/saiintf_case_scanner.py -p sai_test -cp compressed_runnable.json -fp flatten_runnable.json
python3 test_reporting/sai_coverage/saiintf_case_scanner.py -p ptf -cp compressed_saiptf.json -fp flatten_saiptf.json

# 4. upload flatten_runnable.json and flatten_saiptf.json to Kusto
python3 test_reporting/report_uploader.py flatten_runnable.json flatten_saiptf.json SaiTestData -c case_invoc
