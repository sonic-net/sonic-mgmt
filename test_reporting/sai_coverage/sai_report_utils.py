"""
This file defines SAI qualification report utils
"""

import json
import os

from constant import PRIORI_RESULT_SAVE_DIR, SAI_ADAPTER_FILENAME


def store_result(data, file_name):
    """
    Save result to json file

    Args:
        data: result data to save
        file_name: file name
    """
    with open(file_name, 'w+') as f:
        json.dump(data, f, indent=4)


def seach_defalt_parms(sai_interface, idx):
    """
    Search the default parameters in sai_adapter

    Args:
        sai_interface: SAI interface name
        idx: the index of attribute

    Return:
        the name of attribute
    """
    file_name = os.path.join(PRIORI_RESULT_SAVE_DIR, SAI_ADAPTER_FILENAME)
    with open(file_name, 'r') as rf:
        dic = json.load(rf)
        if sai_interface in dic:
            return dic[sai_interface][idx - 1]
    return "unknown"
