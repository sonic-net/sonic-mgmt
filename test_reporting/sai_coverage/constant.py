"""
This file defines SAI qualification report constant variables
"""

PRIORI_RESULT_SAVE_DIR = "result"
FINAL_RESULT_SAVE_DIR = "result/scan"

SAI_API_PREFIX = "sai_thrift"
IGNORE_FILE_LIST = ["sai_adapter.py",
                    "sai_utils.py", "__init__.py"]
IGNORE_HEADER_FILE_LIST = ["sai.h", "saiobject.h", "saistatus.h", "saitypes.h"]

SAI_HEADER_FILENAME = "sai_header_scan_result.json"
SAI_ADAPTER_FILENAME = "sai_adapter_scan_result.json"

UNRUNNABLE_TAG_LIST = ["draft"]
