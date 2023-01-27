"""
This file scans sai_adapter, generating the attribute name and value pairs in SAI interface
"""

import argparse
import ast
import json
import os

from constant import PRIORI_RESULT_SAVE_DIR, SAI_ADAPTER_FILENAME


def get_parser(description="SAI Adapter Scanner"):
    """
    Parse command line
    """
    parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("path_list", metavar="path", nargs="+",
                        type=str, help="list of file/directory to scan.")
    args = parser.parse_args()
    return args


def seach_defalt_parms(root_path, save_path):
    """
    Scan the definitions in sai_adapter

    Args:
        root_path: sai_adapter path
        save_path: path to save result
    """
    good_file = (file for file in os.listdir(root_path)
                 if file[-3:] == '.py' and file != '__init__.py')
    functions = {}

    with open(save_path, 'w') as wf:
        for file in good_file:
            with open(os.path.join(root_path, file), 'r') as f:
                module = ast.parse(f.read(), filename='<string>')

            for node in module.body:
                if isinstance(node, ast.FunctionDef):
                    args = []
                    for a in node.args.args:
                        if a.arg == 'client' or a.arg == 'self':
                            continue
                        args.append(a.arg)
                    if node.name not in functions:
                        functions[node.name] = args

        json.dump(functions, wf)


if __name__ == "__main__":
    parser = get_parser("Static Scanning SAI Definition")
    os.makedirs(PRIORI_RESULT_SAVE_DIR, exist_ok=True)
    save_path = os.path.join(PRIORI_RESULT_SAVE_DIR, SAI_ADAPTER_FILENAME)
    for root_path in parser.path_list:
        seach_defalt_parms(root_path, save_path)  # Static Scanning
